use crate::domain::types::{
    AbiArtifact, AbiArtifactKey, AbiFunctionSpec, AbiSelectorAssertion, AbiTypeSpec,
    TemplateVersion,
};
use crate::storage::stable;
use alloy_primitives::keccak256;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize)]
struct RawAbiEntry {
    #[serde(rename = "type")]
    entry_type: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    inputs: Vec<RawAbiParam>,
    #[serde(default)]
    outputs: Vec<RawAbiParam>,
    #[serde(rename = "stateMutability", default)]
    state_mutability: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct RawAbiParam {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    components: Vec<RawAbiParam>,
}

pub fn normalize_abi_artifact(
    key: AbiArtifactKey,
    abi_json: &str,
    source_ref: &str,
    codehash: Option<String>,
    selector_assertions: &[AbiSelectorAssertion],
    now_ns: u64,
) -> Result<AbiArtifact, String> {
    validate_abi_artifact_key(&key)?;
    if source_ref.trim().is_empty() {
        return Err("source_ref must be provided".to_string());
    }
    let entries = decode_abi_entries(abi_json)?;
    let mut functions: Vec<(String, AbiFunctionSpec)> = Vec::new();
    for entry in entries {
        if entry.entry_type != "function" {
            continue;
        }
        let name = entry
            .name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "function entry must include a non-empty name".to_string())?
            .to_string();
        let inputs = entry
            .inputs
            .iter()
            .map(normalize_raw_param)
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = entry
            .outputs
            .iter()
            .map(normalize_raw_param)
            .collect::<Result<Vec<_>, _>>()?;
        let signature = canonical_signature(&name, &inputs)?;
        let selector_hex = recompute_selector_hex(&signature);
        let spec = AbiFunctionSpec {
            role: key.role.clone(),
            name,
            selector_hex,
            inputs,
            outputs,
            state_mutability: entry
                .state_mutability
                .unwrap_or_else(|| "nonpayable".to_string()),
        };
        functions.push((signature, spec));
    }

    if functions.is_empty() {
        return Err("abi artifact must include at least one function".to_string());
    }

    let mut selector_by_signature: BTreeMap<String, String> = BTreeMap::new();
    for (signature, spec) in &functions {
        if selector_by_signature
            .insert(signature.clone(), spec.selector_hex.clone())
            .is_some()
        {
            return Err(format!(
                "duplicate function signature detected: {signature}"
            ));
        }
    }

    verify_selector_assertions(&selector_by_signature, selector_assertions)?;

    functions.sort_by(|left, right| left.0.cmp(&right.0));
    let functions = functions
        .into_iter()
        .map(|(_signature, spec)| spec)
        .collect();

    Ok(AbiArtifact {
        key,
        source_ref: source_ref.trim().to_string(),
        codehash,
        abi_json: abi_json.to_string(),
        functions,
        created_at_ns: now_ns,
        updated_at_ns: now_ns,
    })
}

pub fn normalize_and_store_abi_artifact(
    key: AbiArtifactKey,
    abi_json: &str,
    source_ref: &str,
    codehash: Option<String>,
    selector_assertions: &[AbiSelectorAssertion],
    now_ns: u64,
) -> Result<AbiArtifact, String> {
    let artifact = normalize_abi_artifact(
        key,
        abi_json,
        source_ref,
        codehash,
        selector_assertions,
        now_ns,
    )?;
    stable::upsert_abi_artifact(artifact)
}

pub fn verify_function_selector(spec: &AbiFunctionSpec) -> Result<String, String> {
    let signature = canonical_signature(&spec.name, &spec.inputs)?;
    let recomputed = recompute_selector_hex(&signature);
    let normalized = normalize_selector_hex(&spec.selector_hex)?;
    if recomputed != normalized {
        return Err(format!(
            "selector mismatch for {signature}: declared={normalized} recomputed={recomputed}"
        ));
    }
    Ok(signature)
}

pub fn canonical_signature(function_name: &str, inputs: &[AbiTypeSpec]) -> Result<String, String> {
    let trimmed_name = function_name.trim();
    if trimmed_name.is_empty() {
        return Err("function name must be non-empty".to_string());
    }
    let mut normalized_args = Vec::with_capacity(inputs.len());
    for input in inputs {
        normalized_args.push(canonicalize_type_spec(input)?);
    }
    Ok(format!("{trimmed_name}({})", normalized_args.join(",")))
}

pub fn recompute_selector_hex(signature: &str) -> String {
    let hash = keccak256(signature.as_bytes());
    format!("0x{}", hex::encode(&hash.as_slice()[..4]))
}

fn verify_selector_assertions(
    selector_by_signature: &BTreeMap<String, String>,
    selector_assertions: &[AbiSelectorAssertion],
) -> Result<(), String> {
    for assertion in selector_assertions {
        let signature = normalize_signature_string(&assertion.signature)?;
        let expected_selector = normalize_selector_hex(&assertion.selector_hex)?;
        let actual_selector = selector_by_signature.get(&signature).ok_or_else(|| {
            format!("selector assertion references unknown signature: {signature}")
        })?;
        if actual_selector != &expected_selector {
            return Err(format!(
                "selector mismatch for {signature}: expected={expected_selector} actual={actual_selector}"
            ));
        }
    }
    Ok(())
}

fn validate_abi_artifact_key(key: &AbiArtifactKey) -> Result<(), String> {
    if key.protocol.trim().is_empty() {
        return Err("abi artifact protocol must be non-empty".to_string());
    }
    if key.chain_id == 0 {
        return Err("abi artifact chain_id must be greater than zero".to_string());
    }
    if key.role.trim().is_empty() {
        return Err("abi artifact role must be non-empty".to_string());
    }
    validate_template_version(&key.version)
}

fn validate_template_version(version: &TemplateVersion) -> Result<(), String> {
    if version.major == 0 && version.minor == 0 && version.patch == 0 {
        return Err("template version must not be 0.0.0".to_string());
    }
    Ok(())
}

fn decode_abi_entries(abi_json: &str) -> Result<Vec<RawAbiEntry>, String> {
    let value: Value =
        serde_json::from_str(abi_json).map_err(|error| format!("invalid abi json: {error}"))?;
    let entries_value = if value.is_array() {
        value
    } else if let Some(array) = value.get("abi") {
        array.clone()
    } else {
        return Err("abi json must be an array or object containing an `abi` array".to_string());
    };
    serde_json::from_value(entries_value).map_err(|error| format!("invalid abi format: {error}"))
}

fn normalize_raw_param(raw: &RawAbiParam) -> Result<AbiTypeSpec, String> {
    let normalized_kind = normalize_raw_kind(&raw.kind)?;
    if normalized_kind.starts_with("tuple") {
        if raw.components.is_empty() {
            return Err("tuple parameter must provide components".to_string());
        }
        let components = raw
            .components
            .iter()
            .map(normalize_raw_param)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AbiTypeSpec {
            kind: normalized_kind,
            components,
        })
    } else {
        Ok(AbiTypeSpec {
            kind: normalized_kind,
            components: Vec::new(),
        })
    }
}

fn normalize_raw_kind(raw_kind: &str) -> Result<String, String> {
    let compact = raw_kind
        .chars()
        .filter(|char| !char.is_whitespace())
        .collect::<String>()
        .to_lowercase();
    if compact.is_empty() {
        return Err("abi type must be non-empty".to_string());
    }

    if let Some(suffix) = compact.strip_prefix("tuple") {
        validate_array_suffix(suffix)?;
        return Ok(format!("tuple{suffix}"));
    }

    let (base, suffix) = split_base_and_suffix(&compact);
    validate_array_suffix(suffix)?;
    let canonical_base = match base {
        "uint" => "uint256".to_string(),
        "int" => "int256".to_string(),
        _ => base.to_string(),
    };
    if canonical_base.is_empty() {
        return Err("abi type base must be non-empty".to_string());
    }
    Ok(format!("{canonical_base}{suffix}"))
}

fn canonicalize_type_spec(spec: &AbiTypeSpec) -> Result<String, String> {
    let normalized_kind = normalize_raw_kind(&spec.kind)?;
    if let Some(suffix) = normalized_kind.strip_prefix("tuple") {
        if spec.components.is_empty() {
            return Err("tuple type spec must include components".to_string());
        }
        let mut components = Vec::with_capacity(spec.components.len());
        for component in &spec.components {
            components.push(canonicalize_type_spec(component)?);
        }
        return Ok(format!("({}){suffix}", components.join(",")));
    }
    Ok(normalized_kind)
}

fn normalize_signature_string(raw_signature: &str) -> Result<String, String> {
    let normalized = raw_signature
        .chars()
        .filter(|char| !char.is_whitespace())
        .collect::<String>();
    if normalized.is_empty() {
        return Err("signature assertion must be non-empty".to_string());
    }
    Ok(normalized)
}

fn normalize_selector_hex(raw_selector: &str) -> Result<String, String> {
    let compact = raw_selector.trim().to_lowercase();
    let normalized = compact.strip_prefix("0x").unwrap_or(&compact);
    if normalized.len() != 8 {
        return Err("selector must be exactly 4 bytes hex".to_string());
    }
    if !normalized.chars().all(|char| char.is_ascii_hexdigit()) {
        return Err("selector must be valid hex".to_string());
    }
    Ok(format!("0x{normalized}"))
}

fn split_base_and_suffix(kind: &str) -> (&str, &str) {
    if let Some(start) = kind.find('[') {
        (&kind[..start], &kind[start..])
    } else {
        (kind, "")
    }
}

fn validate_array_suffix(raw_suffix: &str) -> Result<(), String> {
    if raw_suffix.is_empty() {
        return Ok(());
    }
    let bytes = raw_suffix.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'[' {
            return Err(format!("invalid array suffix in abi type: {raw_suffix}"));
        }
        index = index.saturating_add(1);
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index = index.saturating_add(1);
        }
        if index >= bytes.len() || bytes[index] != b']' {
            return Err(format!("invalid array suffix in abi type: {raw_suffix}"));
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_signature, normalize_abi_artifact, recompute_selector_hex,
        verify_function_selector,
    };
    use crate::domain::types::{
        AbiArtifactKey, AbiFunctionSpec, AbiSelectorAssertion, AbiTypeSpec, TemplateVersion,
    };

    fn sample_artifact_key() -> AbiArtifactKey {
        AbiArtifactKey {
            protocol: "erc20".to_string(),
            chain_id: 8453,
            role: "token".to_string(),
            version: TemplateVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
        }
    }

    #[test]
    fn normalize_abi_artifact_recomputes_selectors_and_canonicalizes_types() {
        let abi_json = r#"
        [
          {
            "type": "function",
            "name": "transfer",
            "stateMutability": "nonpayable",
            "inputs": [
              {"name": "to", "type": "address"},
              {"name": "amount", "type": "uint"}
            ],
            "outputs": [{"type": "bool"}]
          }
        ]
        "#;
        let artifact = normalize_abi_artifact(
            sample_artifact_key(),
            abi_json,
            "https://example.com/deployments",
            None,
            &[AbiSelectorAssertion {
                signature: "transfer(address,uint256)".to_string(),
                selector_hex: "0xa9059cbb".to_string(),
            }],
            42,
        )
        .expect("abi artifact should normalize");

        assert_eq!(artifact.functions.len(), 1);
        let transfer = &artifact.functions[0];
        assert_eq!(transfer.name, "transfer");
        assert_eq!(transfer.selector_hex, "0xa9059cbb");
        assert_eq!(transfer.inputs[1].kind, "uint256");
        assert_eq!(transfer.state_mutability, "nonpayable");
    }

    #[test]
    fn normalize_abi_artifact_rejects_missing_source_ref() {
        let err = normalize_abi_artifact(sample_artifact_key(), "[]", " ", None, &[], 1)
            .expect_err("source_ref is mandatory");
        assert!(
            err.contains("source_ref"),
            "expected source_ref validation error but got {err}"
        );
    }

    #[test]
    fn normalize_abi_artifact_rejects_selector_assertion_mismatch() {
        let abi_json = r#"
        [
          {
            "type": "function",
            "name": "approve",
            "stateMutability": "nonpayable",
            "inputs": [{"type": "address"}, {"type": "uint256"}],
            "outputs": [{"type": "bool"}]
          }
        ]
        "#;
        let err = normalize_abi_artifact(
            sample_artifact_key(),
            abi_json,
            "https://example.com",
            Some("0xabc".to_string()),
            &[AbiSelectorAssertion {
                signature: "approve(address,uint256)".to_string(),
                selector_hex: "0xffffffff".to_string(),
            }],
            1,
        )
        .expect_err("mismatched selector assertion must fail");
        assert!(
            err.contains("selector mismatch"),
            "expected selector mismatch error but got {err}"
        );
    }

    #[test]
    fn verify_function_selector_rejects_mismatch() {
        let spec = AbiFunctionSpec {
            role: "router".to_string(),
            name: "swapExactInputSingle".to_string(),
            selector_hex: "0xdeadbeef".to_string(),
            inputs: vec![
                AbiTypeSpec {
                    kind: "address".to_string(),
                    components: Vec::new(),
                },
                AbiTypeSpec {
                    kind: "uint256".to_string(),
                    components: Vec::new(),
                },
            ],
            outputs: Vec::new(),
            state_mutability: "nonpayable".to_string(),
        };
        let err = verify_function_selector(&spec).expect_err("selector mismatch should fail");
        assert!(
            err.contains("selector mismatch"),
            "expected mismatch error but got {err}"
        );
    }

    #[test]
    fn canonical_signature_supports_tuple_and_arrays() {
        let signature = canonical_signature(
            "foo",
            &[AbiTypeSpec {
                kind: "tuple[]".to_string(),
                components: vec![
                    AbiTypeSpec {
                        kind: "address".to_string(),
                        components: Vec::new(),
                    },
                    AbiTypeSpec {
                        kind: "uint".to_string(),
                        components: Vec::new(),
                    },
                ],
            }],
        )
        .expect("tuple[] signature should normalize");
        assert_eq!(signature, "foo((address,uint256)[])");
    }

    #[test]
    fn recompute_selector_hex_matches_known_transfer_selector() {
        assert_eq!(
            recompute_selector_hex("transfer(address,uint256)"),
            "0xa9059cbb"
        );
    }
}
