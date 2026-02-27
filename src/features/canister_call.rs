/// Generic inter-canister call tool with skill-defined allowlists.
///
/// The `canister_call_tool` function is the runtime entry point for the `canister_call`
/// agent tool.  Before dispatching an outbound call it:
///
/// 1. Parses and validates the target `canister_id` as an IC `Principal`.
/// 2. Checks `(canister_id, method)` against the union of `allowed_canister_calls`
///    across all currently-enabled [`SkillRecord`]s.  If no active skill grants
///    permission the call is rejected.
/// 3. Parses `args_candid` (Candid text format) via `candid_parser` and encodes it
///    to binary Candid.
/// 4. Issues a bounded inter-canister call (`Call::bounded_wait`, 300 s default).
/// 5. Decodes the response bytes back to Candid text, truncates, and wraps the result
///    with untrusted-content framing before returning it to the agent.
use crate::sanitize::frame_untrusted_content;
use crate::storage::stable;
use candid::Principal;
use serde::Deserialize;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum character count for the Candid text returned to the agent.
const MAX_CANISTER_CALL_OUTPUT_CHARS: usize = 4_000;

// ── Argument types ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CanisterCallArgs {
    /// IC principal of the target canister (text format, e.g. `"um5iw-rqaaa-aaaaq-qaaba-cai"`).
    canister_id: String,
    /// Method name to invoke (e.g. `"icrc1_balance_of"`).
    method: String,
    /// Arguments in Candid text format, e.g. `"(record { owner = principal \"aaaaa-aa\"; subaccount = null })"`.
    args_candid: String,
}

// ── Tool entry point ─────────────────────────────────────────────────────────

/// Execute the `canister_call` tool — validate allowlist, parse Candid, call, decode.
///
/// Returns framed untrusted content with the Candid text-formatted response,
/// truncated to [`MAX_CANISTER_CALL_OUTPUT_CHARS`].
pub async fn canister_call_tool(args_json: &str) -> Result<String, String> {
    let args: CanisterCallArgs = serde_json::from_str(args_json)
        .map_err(|e| format!("invalid canister_call args: {e}"))?;

    // 1. Parse and validate the target canister principal.
    let canister_id = Principal::from_text(&args.canister_id)
        .map_err(|e| format!("invalid canister principal \"{}\": {e}", args.canister_id))?;

    // 2. Check (canister_id, method) against all active skills' allowed_canister_calls.
    let permitted = stable::list_skills()
        .into_iter()
        .filter(|s| s.enabled)
        .flat_map(|s| s.allowed_canister_calls)
        .any(|p| {
            Principal::from_text(&p.canister_id)
                .map(|id| id == canister_id)
                .unwrap_or(false)
                && p.method == args.method
        });
    if !permitted {
        return Err(format!(
            "canister_call to {}.{} not permitted by any active skill",
            args.canister_id, args.method
        ));
    }

    call_canister_raw(canister_id, &args.method, &args.args_candid, &args.canister_id).await
}

/// Parse Candid text args, make the bounded inter-canister call, decode and frame the response.
///
/// Separated from the allowlist check so the wasm32 and test implementations share the
/// same decoding and framing logic.
async fn call_canister_raw(
    canister_id: Principal,
    method: &str,
    args_candid: &str,
    canister_id_text: &str,
) -> Result<String, String> {
    // 3. Parse Candid text args → binary encoding.
    let idl_args = candid_parser::parse_idl_args(args_candid)
        .map_err(|e| format!("candid parse error in args_candid: {e}"))?;
    let encoded = idl_args
        .to_bytes()
        .map_err(|e| format!("candid encode error: {e}"))?;

    // 4. Issue the call (bounded wait, 300 s default timeout).
    let response_bytes = do_call(canister_id, method, encoded).await.map_err(|e| e)?;

    // 5. Decode response bytes → Candid text.
    let decoded = candid::IDLArgs::from_bytes(&response_bytes)
        .map_err(|e| format!("candid decode error in response: {e}"))?;
    let result_text = decoded.to_string();

    // 6. Truncate and wrap with untrusted-content framing.
    let truncated = if result_text.chars().count() > MAX_CANISTER_CALL_OUTPUT_CHARS {
        let cut: String = result_text.chars().take(MAX_CANISTER_CALL_OUTPUT_CHARS).collect();
        format!(
            "{}... [truncated, {} total chars]",
            cut,
            result_text.len()
        )
    } else {
        result_text
    };

    Ok(frame_untrusted_content(
        &format!("canister:{canister_id_text}.{method}"),
        &truncated,
    ))
}

// ── Platform implementations ──────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
async fn do_call(
    canister_id: Principal,
    method: &str,
    encoded_args: Vec<u8>,
) -> Result<Vec<u8>, String> {
    use ic_cdk::call::{Call, CallFailed};

    Call::bounded_wait(canister_id, method)
        .take_raw_args(encoded_args)
        .await
        .map(|response| response.into_bytes())
        .map_err(|err| match &err {
            CallFailed::InsufficientLiquidCycleBalance(e) => format!(
                "insufficient cycles: available={} required={}",
                e.available, e.required
            ),
            CallFailed::CallPerformFailed(e) => {
                format!("call_perform failed (system error): {e:?}")
            }
            CallFailed::CallRejected(e) => format!(
                "call rejected: code={} msg={}",
                e.raw_reject_code(),
                e.reject_message()
            ),
        })
}

#[cfg(not(target_arch = "wasm32"))]
async fn do_call(
    _canister_id: Principal,
    _method: &str,
    _encoded_args: Vec<u8>,
) -> Result<Vec<u8>, String> {
    #[cfg(test)]
    {
        MOCK_CANISTER_CALL.with(|m| {
            m.borrow()
                .as_ref()
                .map(|f| f(_canister_id, _method, &_encoded_args))
                .unwrap_or_else(|| {
                    Err(format!(
                        "no mock registered for {_canister_id}.{_method}"
                    ))
                })
        })
    }
    #[cfg(not(test))]
    {
        Err("canister_call unavailable on non-wasm32 targets".to_string())
    }
}

// ── Test mock infrastructure ──────────────────────────────────────────────────

#[cfg(test)]
thread_local! {
    /// Thread-local mock for `do_call` in unit tests.
    ///
    /// Set via [`set_mock_canister_call`]; cleared between tests with [`clear_mock_canister_call`].
    static MOCK_CANISTER_CALL: std::cell::RefCell<
        Option<Box<dyn Fn(Principal, &str, &[u8]) -> Result<Vec<u8>, String>>>,
    > = std::cell::RefCell::new(None);
}

#[cfg(test)]
pub fn set_mock_canister_call(
    f: impl Fn(Principal, &str, &[u8]) -> Result<Vec<u8>, String> + 'static,
) {
    MOCK_CANISTER_CALL.with(|m| *m.borrow_mut() = Some(Box::new(f)));
}

#[cfg(test)]
pub fn clear_mock_canister_call() {
    MOCK_CANISTER_CALL.with(|m| *m.borrow_mut() = None);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{CanisterCallPermission, CanisterCallType, SkillRecord};
    use crate::storage::stable;
    use std::future::Future;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    /// Minimal single-threaded async executor for use in tests (no tokio required).
    fn block_on_with_spin<F: Future>(future: F) -> F::Output {
        unsafe fn clone(_ptr: *const ()) -> RawWaker {
            dummy_raw_waker()
        }
        unsafe fn wake(_ptr: *const ()) {}
        unsafe fn wake_by_ref(_ptr: *const ()) {}
        unsafe fn drop(_ptr: *const ()) {}
        fn dummy_raw_waker() -> RawWaker {
            static VTABLE: RawWakerVTable =
                RawWakerVTable::new(clone, wake, wake_by_ref, drop);
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        let waker = unsafe { Waker::from_raw(dummy_raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(output) => return output,
                Poll::Pending => {}
            }
        }
    }

    fn make_skill(canister_id: &str, method: &str, enabled: bool) -> SkillRecord {
        SkillRecord {
            name: "test-skill".to_string(),
            description: "Test".to_string(),
            instructions: "test".to_string(),
            enabled,
            mutable: true,
            allowed_canister_calls: vec![CanisterCallPermission {
                canister_id: canister_id.to_string(),
                method: method.to_string(),
                call_type: CanisterCallType::Query,
            }],
        }
    }

    #[test]
    fn rejects_call_when_no_skill_grants_permission() {
        stable::init_storage();
        // No skills loaded → any call must be rejected.
        let result = block_on_with_spin(canister_call_tool(
            r#"{"canister_id":"aaaaa-aa","method":"some_method","args_candid":"()"}"#,
        ));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("not permitted by any active skill"),
            "expected allowlist rejection"
        );
    }

    #[test]
    fn rejects_call_when_skill_is_disabled() {
        stable::init_storage();
        stable::upsert_skill(&make_skill("aaaaa-aa", "some_method", false));
        let result = block_on_with_spin(canister_call_tool(
            r#"{"canister_id":"aaaaa-aa","method":"some_method","args_candid":"()"}"#,
        ));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not permitted by any active skill"));
    }

    #[test]
    fn rejects_call_when_method_not_in_skill() {
        stable::init_storage();
        stable::upsert_skill(&make_skill("aaaaa-aa", "allowed_method", true));
        let result = block_on_with_spin(canister_call_tool(
            r#"{"canister_id":"aaaaa-aa","method":"other_method","args_candid":"()"}"#,
        ));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not permitted by any active skill"));
    }

    #[test]
    fn returns_framed_response_on_success() {
        stable::init_storage();
        stable::upsert_skill(&make_skill("aaaaa-aa", "ping", true));

        // Mock returns Candid-encoded `(42 : nat)`.
        set_mock_canister_call(|_, _, _| {
            let args = candid_parser::parse_idl_args("(42 : nat)").unwrap();
            Ok(args.to_bytes().unwrap())
        });

        let result = block_on_with_spin(canister_call_tool(
            r#"{"canister_id":"aaaaa-aa","method":"ping","args_candid":"()"}"#,
        ));
        clear_mock_canister_call();

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        let output = result.unwrap();
        assert!(output.contains("[UNTRUSTED_CONTENT"), "expected framing");
        assert!(output.contains("42"), "expected decoded value in output");
    }

    #[test]
    fn rejects_invalid_canister_id() {
        stable::init_storage();
        let result = block_on_with_spin(canister_call_tool(
            r#"{"canister_id":"not-a-principal","method":"foo","args_candid":"()"}"#,
        ));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid canister principal"));
    }

    #[test]
    fn rejects_malformed_candid_args() {
        stable::init_storage();
        stable::upsert_skill(&make_skill("aaaaa-aa", "foo", true));
        let result = block_on_with_spin(canister_call_tool(
            r#"{"canister_id":"aaaaa-aa","method":"foo","args_candid":"not valid candid {"}"#,
        ));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("candid parse error"));
    }
}
