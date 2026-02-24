/// Controlled HTTPS GET tool with allowlist enforcement and response-size limits.
///
/// The `http_fetch_tool` function is the runtime entry point for the `http_fetch`
/// agent tool.  Before dispatching an outbound request it:
/// 1. Validates the URL is HTTPS and parses the hostname.
/// 2. Checks the hostname against the configurable domain allowlist (when enforced).
/// 3. Verifies the canister has enough liquid cycles to pay for the outcall.
/// 4. Optionally extracts structured content (`json_path` or `regex`) from the
///    response body.
/// 5. Truncates output to `HTTP_FETCH_MAX_OUTPUT_CHARS` and wraps it with
///    untrusted-content framing before returning it to the agent.
// ── Imports ──────────────────────────────────────────────────────────────────
use crate::domain::cycle_admission::{
    affordability_requirements, can_afford, estimate_operation_cost, OperationClass,
    DEFAULT_RESERVE_FLOOR_CYCLES, DEFAULT_SAFETY_MARGIN_BPS,
};
use crate::sanitize::frame_untrusted_content;
use crate::storage::stable;
use regex::RegexBuilder;
use serde::Deserialize;
use serde_json::Value;

#[cfg(target_arch = "wasm32")]
use candid::Nat;
#[cfg(target_arch = "wasm32")]
use ic_cdk::management_canister::{http_request, HttpMethod, HttpRequestArgs};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of bytes the IC HTTPS outcall may return — 64 KiB.
const HTTP_FETCH_MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// Maximum number of UTF-8 characters returned to the agent after fetching.
/// Responses are truncated at this boundary with a `[truncated, N total bytes]` suffix.
const HTTP_FETCH_MAX_OUTPUT_CHARS: usize = 8_000;
const HTTP_FETCH_REGEX_MAX_PATTERN_CHARS: usize = 256;
const HTTP_FETCH_REGEX_SIZE_LIMIT_BYTES: usize = 256 * 1024;
const HTTP_FETCH_REGEX_DFA_SIZE_LIMIT_BYTES: usize = 256 * 1024;

// ── Tool entry point ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct HttpFetchArgs {
    url: String,
    #[serde(default)]
    extract: Option<ExtractionMode>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode")]
enum ExtractionMode {
    #[serde(rename = "json_path")]
    JsonPath { path: String },
    #[serde(rename = "regex")]
    Regex { pattern: String },
}

/// Execute the `http_fetch` tool — parse args, enforce allowlist, check cycles, fetch.
///
/// Returns framed untrusted content with either the full response body or an
/// extracted value (depending on `extract` mode), truncated to
/// `HTTP_FETCH_MAX_OUTPUT_CHARS`. Binary bodies are represented as the literal
/// string `"binary response (not UTF-8)"`.
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
    let extracted = extract_http_fetch_content(&body, args.extract.as_ref())?;
    let output = truncate_http_fetch_output(&extracted);
    Ok(frame_untrusted_content("http_fetch", &output))
}

fn parse_http_fetch_args(args_json: &str) -> Result<HttpFetchArgs, String> {
    let args: HttpFetchArgs = serde_json::from_str(args_json)
        .map_err(|error| format!("invalid http_fetch args json: {error}"))?;
    if args.url.trim().is_empty() {
        return Err("missing required field: url".to_string());
    }
    Ok(args)
}

fn extract_http_fetch_content(
    body: &str,
    extract: Option<&ExtractionMode>,
) -> Result<String, String> {
    match extract {
        Some(ExtractionMode::JsonPath { path }) => extract_json_path(body, path),
        Some(ExtractionMode::Regex { pattern }) => extract_regex_lines(body, pattern),
        None => Ok(body.to_string()),
    }
}

fn extract_json_path(body: &str, path: &str) -> Result<String, String> {
    let trimmed_path = path.trim();
    if trimmed_path.is_empty() {
        return Err("json_path extraction failed: missing required field: path".to_string());
    }

    let root: Value = serde_json::from_str(body).map_err(|error| {
        format!("json_path extraction failed: response is not valid JSON: {error}")
    })?;

    let segments = trimmed_path.split('.').collect::<Vec<_>>();
    if segments.iter().any(|segment| segment.trim().is_empty()) {
        return Err(format!(
            "json_path extraction failed: invalid path `{trimmed_path}`"
        ));
    }
    if segments
        .iter()
        .any(|segment| segment.contains('[') || segment.contains(']'))
    {
        return Err("json_path extraction failed: array indexing is not supported".to_string());
    }

    let mut current = &root;
    for segment in segments {
        let segment = segment.trim();
        current = current.get(segment).ok_or_else(|| {
            format!("json_path extraction failed: path `{trimmed_path}` not found")
        })?;
    }

    match current {
        Value::String(value) => Ok(value.clone()),
        value => serde_json::to_string(value).map_err(|error| {
            format!("json_path extraction failed: could not serialize extracted value: {error}")
        }),
    }
}

fn extract_regex_lines(body: &str, pattern: &str) -> Result<String, String> {
    let trimmed_pattern = pattern.trim();
    if trimmed_pattern.is_empty() {
        return Err("regex extraction failed: missing required field: pattern".to_string());
    }
    if trimmed_pattern.chars().count() > HTTP_FETCH_REGEX_MAX_PATTERN_CHARS {
        return Err(format!(
            "regex extraction failed: pattern exceeds max length of {HTTP_FETCH_REGEX_MAX_PATTERN_CHARS} characters"
        ));
    }

    let regex = RegexBuilder::new(trimmed_pattern)
        .size_limit(HTTP_FETCH_REGEX_SIZE_LIMIT_BYTES)
        .dfa_size_limit(HTTP_FETCH_REGEX_DFA_SIZE_LIMIT_BYTES)
        .build()
        .map_err(|error| format!("regex extraction failed: invalid pattern: {error}"))?;

    let matched_lines = body
        .lines()
        .filter(|line| regex.is_match(line))
        .collect::<Vec<_>>();
    if matched_lines.is_empty() {
        return Err("regex extraction failed: no matching lines".to_string());
    }

    Ok(matched_lines.join("\n"))
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

fn truncate_http_fetch_output(content: &str) -> String {
    let (truncated, was_truncated) = truncate_utf8_chars(content, HTTP_FETCH_MAX_OUTPUT_CHARS);
    if was_truncated {
        format!(
            "{}... [truncated, {} total bytes]",
            truncated,
            content.len()
        )
    } else {
        truncated
    }
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
        assert!(out.starts_with("[UNTRUSTED_CONTENT source=http_fetch]"));
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
        assert!(out.starts_with("[UNTRUSTED_CONTENT source=http_fetch]"));
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

    #[test]
    fn parse_http_fetch_args_accepts_json_path_extract_mode() {
        let args = parse_http_fetch_args(
            r#"{"url":"https://example.com","extract":{"mode":"json_path","path":"data.price"}}"#,
        )
        .expect("json_path extract args should parse");
        assert_eq!(args.url, "https://example.com");
        assert_eq!(
            args.extract,
            Some(ExtractionMode::JsonPath {
                path: "data.price".to_string()
            })
        );
    }

    #[test]
    fn http_fetch_tool_json_path_extracts_and_frames_value() {
        stable::init_storage();

        let out = block_on_with_spin(http_fetch_tool(
            r#"{"url":"https://example.com/anything","extract":{"mode":"json_path","path":"stub"}}"#,
        ))
        .expect("json_path extraction should succeed");
        assert!(out.starts_with("[UNTRUSTED_CONTENT source=http_fetch]"));
        assert!(out.contains("\n---\nok\n---\n"));
    }

    #[test]
    fn http_fetch_tool_json_path_reports_invalid_json() {
        let err = extract_json_path("not json", "stub")
            .expect_err("invalid json input should fail json_path extraction");
        assert!(err.contains("response is not valid JSON"));
    }

    #[test]
    fn http_fetch_tool_json_path_reports_missing_path() {
        let err = extract_json_path(r#"{"data":{"price":42}}"#, "data.missing")
            .expect_err("missing path should fail json_path extraction");
        assert!(err.contains("path `data.missing` not found"));
    }

    #[test]
    fn http_fetch_tool_regex_extracts_matching_lines() {
        let out = extract_regex_lines("alpha\nprice:42\nbeta", r"^price:\d+$")
            .expect("regex extraction should return matching lines");
        assert_eq!(out, "price:42");
    }

    #[test]
    fn http_fetch_tool_regex_reports_invalid_pattern() {
        let err =
            extract_regex_lines("price:42", "(").expect_err("invalid regex pattern should fail");
        assert!(err.contains("invalid pattern"));
    }

    #[test]
    fn http_fetch_tool_regex_reports_no_matches() {
        let err = extract_regex_lines("alpha\nbeta", "price")
            .expect_err("regex extraction without matches should fail");
        assert!(err.contains("no matching lines"));
    }
}
