use crate::tools::SignerPort;

#[allow(dead_code)]
pub trait SignerAdapter: SignerPort {
    fn derive_address(&self) -> String;
}

#[derive(Clone)]
pub struct MockSignerAdapter {
    _address: String,
}

impl MockSignerAdapter {
    pub fn new() -> Self {
        Self {
            _address: "0x0000000000000000000000000000000000000000".to_string(),
        }
    }
}

impl SignerPort for MockSignerAdapter {
    fn sign_message(&self, message: &str) -> Result<String, String> {
        Ok(format!("mock-signature-{message}"))
    }
}

impl SignerAdapter for MockSignerAdapter {
    fn derive_address(&self) -> String {
        self._address.clone()
    }
}

#[allow(dead_code)]
pub struct StubSignerAdapter;

impl SignerPort for StubSignerAdapter {
    fn sign_message(&self, _message: &str) -> Result<String, String> {
        Err("stub signer adapter disabled in v1".to_string())
    }
}

impl SignerAdapter for StubSignerAdapter {
    fn derive_address(&self) -> String {
        "0x0000000000000000000000000000000000000000".to_string()
    }
}
