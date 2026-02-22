use crate::domain::cycle_admission::{
    affordability_requirements, can_afford, estimate_operation_cost, OperationClass,
    DEFAULT_RESERVE_FLOOR_CYCLES, DEFAULT_SAFETY_MARGIN_BPS,
};
use crate::storage::stable;
use serde::Deserialize;

#[cfg(target_arch = "wasm32")]
use candid::Nat;
#[cfg(target_arch = "wasm32")]
use ic_cdk::management_canister::{http_request, HttpMethod, HttpRequestArgs};

const HTTP_FETCH_MAX_RESPONSE_BYTES: u64 = 64 * 1024;
const HTTP_FETCH_MAX_OUTPUT_CHARS: usize = 8_000;

#[derive(Deserialize)]
struct HttpFetchArgs {
    url: String,
}

pub async fn http_fetch_tool(args_json: &str) -> Result<String, String> {
    let args = parse_http_fetch_args(args_json)?;
    let host = extract_https_host(&args.url)?;
    ensure_host_allowed(&host, &args.url)?;
    ensure_http_fetch_affordable(
        u64::try_from(args.url.len().saturating_add(128)).unwrap_or(u64::MAX),
        HTTP_FETCH_MAX_RESPONSE_BYTES,
    )?;

    let body = http_get(&args.url, HTTP_FETCH_MAX_RESPONSE_BYTES).await?;
    let body =
        String::from_utf8(body).unwrap_or_else(|_| "binary response (not UTF-8)".to_string());
    let (truncated, was_truncated) = truncate_utf8_chars(&body, HTTP_FETCH_MAX_OUTPUT_CHARS);
    if was_truncated {
        Ok(format!(
            "{}... [truncated, {} total bytes]",
            truncated,
            body.len()
        ))
    } else {
        Ok(truncated)
    }
}

fn parse_http_fetch_args(args_json: &str) -> Result<HttpFetchArgs, String> {
    let args: HttpFetchArgs = serde_json::from_str(args_json)
        .map_err(|error| format!("invalid http_fetch args json: {error}"))?;
    if args.url.trim().is_empty() {
        return Err("missing required field: url".to_string());
    }
    Ok(args)
}

fn ensure_host_allowed(host: &str, url: &str) -> Result<(), String> {
    if !stable::is_http_allowlist_enforced() {
        return Ok(());
    }
    let allowed = stable::list_allowed_http_domains();
    if allowed.is_empty() {
        return Err("no domains allowed".to_string());
    }
    if allowed
        .iter()
        .any(|domain| host == domain || host.ends_with(&format!(".{domain}")))
    {
        Ok(())
    } else {
        Err(format!("domain not in allowlist: {url}"))
    }
}

fn extract_https_host(raw_url: &str) -> Result<String, String> {
    let trimmed = raw_url.trim();
    let remainder = trimmed
        .strip_prefix("https://")
        .ok_or_else(|| "only HTTPS URLs are allowed".to_string())?;
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() {
        return Err("could not parse host".to_string());
    }
    if authority.contains('@') {
        return Err("user info is not allowed in URL".to_string());
    }
    if authority.starts_with('[') {
        return Err("IPv6 hosts are not supported".to_string());
    }

    let host = authority
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if host.is_empty() {
        return Err("could not parse host".to_string());
    }
    if host.starts_with('.') || host.ends_with('.') {
        return Err("host is invalid".to_string());
    }

    for label in host.split('.') {
        if label.is_empty() {
            return Err("host is invalid".to_string());
        }
        let bytes = label.as_bytes();
        if !bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !bytes
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err("host is invalid".to_string());
        }
    }

    Ok(host)
}

fn ensure_http_fetch_affordable(
    request_size_bytes: u64,
    max_response_bytes: u64,
) -> Result<(), String> {
    let operation = OperationClass::HttpOutcall {
        request_size_bytes,
        max_response_bytes,
    };
    let estimated = estimate_operation_cost(&operation)?;
    let requirements = affordability_requirements(
        estimated,
        DEFAULT_SAFETY_MARGIN_BPS,
        DEFAULT_RESERVE_FLOOR_CYCLES,
    );
    let liquid = liquid_cycle_balance();
    if !can_afford(liquid, &requirements) {
        return Err("insufficient cycles for HTTP fetch".to_string());
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn liquid_cycle_balance() -> u128 {
    ic_cdk::api::canister_liquid_cycle_balance()
}

#[cfg(not(target_arch = "wasm32"))]
fn liquid_cycle_balance() -> u128 {
    u128::MAX
}

#[cfg(target_arch = "wasm32")]
async fn http_get(url: &str, max_response_bytes: u64) -> Result<Vec<u8>, String> {
    let request = HttpRequestArgs {
        url: url.to_string(),
        max_response_bytes: Some(max_response_bytes),
        method: HttpMethod::GET,
        headers: vec![],
        body: None,
        transform: None,
        is_replicated: Some(false),
    };

    let response = http_request(&request)
        .await
        .map_err(|error| format!("HTTP fetch failed: {error}"))?;
    let status = nat_to_u16(&response.status)?;
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status} from {url}"));
    }
    Ok(response.body)
}

#[cfg(not(target_arch = "wasm32"))]
async fn http_get(url: &str, _max_response_bytes: u64) -> Result<Vec<u8>, String> {
    if url.contains("coingecko") {
        Ok(br#"{"stub":"coingecko"}"#.to_vec())
    } else {
        Ok(br#"{"stub":"ok"}"#.to_vec())
    }
}

#[cfg(target_arch = "wasm32")]
fn nat_to_u16(status: &Nat) -> Result<u16, String> {
    status
        .to_string()
        .parse::<u16>()
        .map_err(|error| format!("invalid HTTP status {status}: {error}"))
}

fn truncate_utf8_chars(input: &str, max_chars: usize) -> (String, bool) {
    let Some((cutoff, _)) = input.char_indices().nth(max_chars) else {
        return (input.to_string(), false);
    };
    (input[..cutoff].to_string(), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn block_on_with_spin<F: Future>(future: F) -> F::Output {
        unsafe fn clone(_ptr: *const ()) -> RawWaker {
            dummy_raw_waker()
        }
        unsafe fn wake(_ptr: *const ()) {}
        unsafe fn wake_by_ref(_ptr: *const ()) {}
        unsafe fn drop(_ptr: *const ()) {}

        fn dummy_raw_waker() -> RawWaker {
            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
            RawWaker::new(std::ptr::null(), &VTABLE)
        }

        let waker = unsafe { Waker::from_raw(dummy_raw_waker()) };
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);

        for _ in 0..10_000 {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::hint::spin_loop(),
            }
        }

        panic!("future did not complete in test polling loop");
    }

    #[test]
    fn extract_https_host_rejects_non_https_urls() {
        assert!(extract_https_host("http://example.com").is_err());
        assert!(extract_https_host("example.com").is_err());
    }

    #[test]
    fn http_fetch_tool_allows_any_domain_by_default() {
        stable::init_storage();

        let out = block_on_with_spin(http_fetch_tool(r#"{"url":"https://example.com/anything"}"#))
            .expect("without configured allowlist any https host should pass");
        assert!(out.contains("stub"));
    }

    #[test]
    fn http_fetch_tool_uses_allowlist_when_configured() {
        stable::init_storage();
        stable::set_http_allowed_domains(vec!["api.coingecko.com".to_string()])
            .expect("allowlist should set");

        let out = block_on_with_spin(http_fetch_tool(
            r#"{"url":"https://api.coingecko.com/api/v3/ping"}"#,
        ))
        .expect("host stub request should pass");
        assert!(out.contains("stub"));

        let err = block_on_with_spin(http_fetch_tool(
            r#"{"url":"https://example.com/forbidden"}"#,
        ))
        .expect_err("non-allowlisted host should fail");
        assert!(err.contains("domain not in allowlist"));
    }

    #[test]
    fn http_fetch_tool_blocks_when_allowlist_is_enforced_but_empty() {
        stable::init_storage();
        stable::set_http_allowed_domains(vec![]).expect("empty allowlist should be valid");

        let err = block_on_with_spin(http_fetch_tool(r#"{"url":"https://example.com"}"#))
            .expect_err("configured empty allowlist should block all hosts");
        assert!(err.contains("no domains allowed"));
    }
}
