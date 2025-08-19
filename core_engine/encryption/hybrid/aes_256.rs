use ring::{aead, pbkdf2};
use std::num::NonZeroU32;
use zeroize::Zeroize;

const SALT: &[u8] = b"BIC_Advanced_SALT_";
const ITERATIONS: u32 = 100_000;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub struct QuantumResistantEncryptor {
    sealing_key: aead::SealingKey,
    opening_key: aead::OpeningKey,
}

impl QuantumResistantEncryptor {
    pub fn new(master_key: &[u8]) -> Self {
        // Derive key using PBKDF2 with SHA-384
        let mut derived_key = [0u8; 48];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA384,
            NonZeroU32::new(ITERATIONS).unwrap(),
            SALT,
            master_key,
            &mut derived_key
        );

        // Split into encryption and authentication keys
        let (enc_key, auth_key) = derived_key.split_at(32);

        // Create AES-256-GCM keys
        let unbound_sealing_key = aead::UnboundKey::new(&aead::AES_256_GCM, enc_key)
            .expect("Invalid key length");
        let unbound_opening_key = aead::UnboundKey::new(&aead::AES_256_GCM, enc_key)
            .expect("Invalid key length");

        let sealing_key = aead::SealingKey::new(unbound_sealing_key, auth_key);
        let opening_key = aead::OpeningKey::new(unbound_opening_key, auth_key);

        // Securely wipe derived key
        derived_key.zeroize();

        Self { sealing_key, opening_key }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // Generate random nonce
        let mut nonce = [0u8; NONCE_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut nonce)
            .expect("Failed to generate nonce");

        // Prepare in-place encryption
        let mut in_out = plaintext.to_vec();
        in_out.extend_from_slice(&[0u8; TAG_LEN]);

        // Perform encryption
        let sealing_key = aead::LessSafeKey::new(self.sealing_key.unbound_key().clone());
        sealing_key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut in_out
        ).expect("Encryption failed");

        // Combine nonce + ciphertext + tag
        let mut result = nonce.to_vec();
        result.extend_from_slice(&in_out);
        result
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() < NONCE_LEN + TAG_LEN {
            return None;
        }

        // Split into nonce and ciphertext
        let nonce = &ciphertext[..NONCE_LEN];
        let mut in_out = ciphertext[NONCE_LEN..].to_vec();

        // Perform decryption
        let opening_key = aead::LessSafeKey::new(self.opening_key.unbound_key().clone());
        let plaintext = opening_key.open_in_place(
            aead::Nonce::try_assume_unique_for_key(nonce).ok()?,
            aead::Aad::empty(),
            &mut in_out
        ).ok()?;

        Some(plaintext.to_vec())
    }
}

impl Drop for QuantumResistantEncryptor {
    fn drop(&mut self) {
        // Securely wipe keys from memory
        self.sealing_key.zeroize();
        self.opening_key.zeroize();
    }
}