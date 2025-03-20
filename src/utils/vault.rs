use aes_gcm::aead::{rand_core::RngCore, Aead, OsRng};
use aes_gcm::{Aes256Gcm, KeyInit as AesKeyInit, Nonce};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use serde_derive::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct SecretVault {
    secrets: HashMap<String, Vec<u8>>,
}

impl SecretVault {
    pub fn new() -> Self {
        SecretVault {
            secrets: HashMap::new(),
        }
    }

    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let data = fs::read(path)?;
        let vault: SecretVault = bincode::deserialize(&data)?;
        Ok(vault)
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let data = bincode::serialize(&self)?;
        fs::write(path, data)?;
        Ok(())
    }

    pub fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 32];

        // Using fully qualified syntax to avoid ambiguity
        let mut mac: Hmac<Sha256> = <Hmac<Sha256> as Mac>::new_from_slice(passphrase.as_bytes())
            .expect("HMAC initialization failed");

        // Use the pbkdf2 function from the `pbkdf2` crate
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, 10000, &mut key);

        key
    }

    pub fn add_secret(
        encryption_key: &[u8; 32],
        key: String,
        secret: String,
    ) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(encryption_key).unwrap();

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce); // Use fill_bytes() for nonce generation

        let encrypted_secret = cipher.encrypt(&nonce.into(), secret.as_bytes()).unwrap();

        let mut combined = nonce.to_vec();
        combined.extend(encrypted_secret);

        combined
    }

    pub fn get_secret(&self, encryption_key: &[u8; 32], key: &str) -> Option<String> {
        if let Some(data) = self.secrets.get(key) {
            let cipher = Aes256Gcm::new_from_slice(encryption_key).unwrap();
            let (nonce, encrypted_secret) = data.split_at(12);

            if let Ok(decrypted_secret) = cipher.decrypt(Nonce::from_slice(nonce), encrypted_secret)
            {
                return String::from_utf8(decrypted_secret).ok();
            }
        }
        None
    }

    pub fn remove_secret(&mut self, encryption_key: &[u8; 32], key: &str) -> Option<String> {
        if let Some(data) = self.secrets.remove(key) {
            let cipher = Aes256Gcm::new_from_slice(encryption_key).unwrap();
            let (nonce, encrypted_secret) = data.split_at(12);

            if let Ok(decrypted_secret) = cipher.decrypt(Nonce::from_slice(nonce), encrypted_secret)
            {
                return String::from_utf8(decrypted_secret).ok();
            }
        }
        None
    }
}
