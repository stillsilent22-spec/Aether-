use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Debug)]
pub struct DataKey {
    bytes: [u8; 32],
}

impl DataKey {
    pub fn derive(password: &str, salt: &str, username: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"aether/datakey/v1|");
        hasher.update(username.as_bytes());
        hasher.update(b"|");
        hasher.update(salt.as_bytes());
        hasher.update(b"|");
        hasher.update(password.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest[..32]);
        Self { bytes }
    }

    pub fn fork(&self) -> Self {
        Self { bytes: self.bytes }
    }

    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.bytes);
        hasher.update(b"|aether/fingerprint/v1");
        let digest = hasher.finalize();
        digest[..12]
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for DataKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
