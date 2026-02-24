/// IC threshold ECDSA signing adapter.
///
/// `ThresholdSignerAdapter` implements `SignerPort` by delegating to the IC
/// management canister's `sign_with_ecdsa` endpoint (secp256k1, EVM derivation
/// path `b"evm"`).
///
/// On non-wasm32 targets (unit/integration tests) the adapter produces a
/// deterministic mock signature so that tests can verify the signing path
/// without an actual IC replica.
///
/// The EVM address associated with the ECDSA key is derived once at startup
/// via `derive_and_cache_evm_address` and cached in stable storage so it is
/// available synchronously during agent turns.
// ── Imports ──────────────────────────────────────────────────────────────────
use crate::storage::stable;
use crate::tools::SignerPort;
use async_trait::async_trait;
use sha3::{Digest, Keccak256};

#[cfg(target_arch = "wasm32")]
use crate::domain::cycle_admission::{
    affordability_requirements, can_afford, estimate_operation_cost, OperationClass,
    DEFAULT_RESERVE_FLOOR_CYCLES, DEFAULT_SAFETY_MARGIN_BPS,
};
#[cfg(target_arch = "wasm32")]
use ic_cdk::management_canister::{
    ecdsa_public_key, sign_with_ecdsa, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs,
    SignWithEcdsaArgs,
};

// ── Constants ────────────────────────────────────────────────────────────────

// BIP-32 derivation path component used for the EVM key — the same path is
// used for both `ecdsa_public_key` and `sign_with_ecdsa` so the addresses match.
#[cfg(target_arch = "wasm32")]
const EVM_DERIVATION_PATH: &[u8] = b"evm";

// ── Adapter ──────────────────────────────────────────────────────────────────

/// Production implementation of `SignerPort` backed by IC threshold ECDSA.
///
/// Holds the ECDSA key name (e.g. `"dfx_test_key"` or `"key_1"`) that maps
/// to a key managed by the IC subnet.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[derive(Clone, Debug)]
pub struct ThresholdSignerAdapter {
    key_name: String,
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
impl ThresholdSignerAdapter {
    /// Create a new adapter for the given ECDSA `key_name`.
    pub fn new(key_name: String) -> Self {
        Self { key_name }
    }
}

#[async_trait(?Send)]
impl SignerPort for ThresholdSignerAdapter {
    /// Sign a 32-byte message hash with the threshold ECDSA key.
    ///
    /// Returns the compact 64-byte signature (r || s) as a 0x-prefixed hex string.
    /// Fails if the EVM address has not yet been derived (call
    /// `derive_and_cache_evm_address` at canister init) or if the canister
    /// has insufficient liquid cycles to pay for the signing request.
    async fn sign_message(&self, message_hash: &str) -> Result<String, String> {
        if stable::get_evm_address().is_none() {
            return Err("evm address not derived yet; retry next turn".to_string());
        }

        let parsed_hash = parse_message_hash(message_hash)?;
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = &self.key_name;
            let mut mock_signature = vec![0u8; 64];
            mock_signature[..32].copy_from_slice(&parsed_hash);
            return Ok(format!("0x{}", hex::encode(mock_signature)));
        }

        #[cfg(target_arch = "wasm32")]
        {
            let operation = OperationClass::ThresholdSign {
                key_name: self.key_name.clone(),
                ecdsa_curve: u32::from(EcdsaCurve::Secp256k1),
            };
            let estimated = estimate_operation_cost(&operation)?;
            let requirements = affordability_requirements(
                estimated,
                DEFAULT_SAFETY_MARGIN_BPS,
                DEFAULT_RESERVE_FLOOR_CYCLES,
            );
            let liquid = ic_cdk::api::canister_liquid_cycle_balance();
            if !can_afford(liquid, &requirements) {
                return Err(format!(
                    "insufficient cycles for threshold sign: need {} liquid, have {}",
                    requirements.required_cycles, liquid
                ));
            }

            let response = sign_with_ecdsa(&SignWithEcdsaArgs {
                message_hash: parsed_hash.to_vec(),
                derivation_path: vec![EVM_DERIVATION_PATH.to_vec()],
                key_id: EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: self.key_name.clone(),
                },
            })
            .await
            .map_err(|error| format!("sign_with_ecdsa failed: {error}"))?;

            Ok(format!("0x{}", hex::encode(response.signature)))
        }
    }
}

// ── Address derivation ───────────────────────────────────────────────────────

/// Derive the Ethereum address for `key_name` and cache it in stable storage.
///
/// Should be called once during canister `init` / `post_upgrade` so the
/// address is available synchronously on subsequent agent turns without
/// requiring an inter-canister call.
///
/// - wasm32: calls `ecdsa_public_key`, converts the SEC1 compressed public key
///   to an Ethereum address via Keccak256(uncompressed_pubkey[1..]).
/// - non-wasm32: deterministically derives a mock address from `key_name`
///   for use in tests.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub async fn derive_and_cache_evm_address(key_name: &str) -> Result<String, String> {
    if key_name.trim().is_empty() {
        return Err("ecdsa key name cannot be empty".to_string());
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let digest = Keccak256::digest(key_name.as_bytes());
        let address = format!("0x{}", hex::encode(&digest[12..32]));
        stable::set_evm_address(Some(address.clone()))?;
        Ok(address)
    }

    #[cfg(target_arch = "wasm32")]
    {
        let response = ecdsa_public_key(&EcdsaPublicKeyArgs {
            canister_id: None,
            derivation_path: vec![EVM_DERIVATION_PATH.to_vec()],
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: key_name.to_string(),
            },
        })
        .await
        .map_err(|error| format!("ecdsa_public_key failed: {error}"))?;

        let address = ethereum_address_from_sec1_public_key(&response.public_key)?;
        stable::set_evm_address(Some(address.clone()))?;
        Ok(address)
    }
}

fn parse_message_hash(raw: &str) -> Result<[u8; 32], String> {
    let hash = raw.trim();
    let without_prefix = hash
        .strip_prefix("0x")
        .or_else(|| hash.strip_prefix("0X"))
        .ok_or_else(|| "message_hash must be 0x-prefixed hex".to_string())?;
    if without_prefix.len() != 64 {
        return Err("message_hash must be exactly 32 bytes".to_string());
    }

    let mut out = [0u8; 32];
    hex::decode_to_slice(without_prefix, &mut out)
        .map_err(|error| format!("message_hash is not valid hex: {error}"))?;
    Ok(out)
}

#[cfg(target_arch = "wasm32")]
fn ethereum_address_from_sec1_public_key(sec1: &[u8]) -> Result<String, String> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::PublicKey;

    let public_key = PublicKey::from_sec1_bytes(sec1)
        .map_err(|error| format!("invalid sec1 public key from ecdsa_public_key: {error}"))?;
    let uncompressed = public_key.to_encoded_point(false);
    let bytes = uncompressed.as_bytes();
    if bytes.len() != 65 || bytes.first().copied() != Some(0x04) {
        return Err("unexpected uncompressed public key format".to_string());
    }

    let digest = Keccak256::digest(&bytes[1..]);
    Ok(format!("0x{}", hex::encode(&digest[12..32])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_message_hash_requires_prefixed_32_byte_hex() {
        assert!(parse_message_hash("deadbeef").is_err());
        assert!(parse_message_hash("0xdeadbeef").is_err());
        assert!(parse_message_hash(
            "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        )
        .is_err());
        assert!(parse_message_hash(
            "0x1111111111111111111111111111111111111111111111111111111111111111"
        )
        .is_ok());
    }
}
