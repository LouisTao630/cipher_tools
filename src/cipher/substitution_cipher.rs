use super::Cipher;
use super::CipherOperationError;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::info;
use log::warn;

pub struct SubstitutionCipher {
    alphabet: Vec<u8>,
}

impl SubstitutionCipher {
    pub fn new() -> Self {
        let alphabet = (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .chain(b'0'..=b'9')
            .collect::<Vec<u8>>();
        info!("Show alphabet: {:?}", alphabet);
        SubstitutionCipher { alphabet }
    }

    fn substitute(&self, text: &[u8], key: &[u8]) -> Vec<u8> {
        // Assume `key` is a shuffled version of the alphabet.
        let mut result = Vec::new();
        for &ch in text {
            if let Some(position) = self.alphabet.iter().position(|&x| x == ch) {
                info!(
                    "The char {} will be substitute to key position {}",
                    ch, position
                );
                result.push(key[position]); // Substitute with the key's value.
            } else {
                result.push(ch); // If not a letter, leave it unchanged.
                warn!("The {} is invalid letter.", ch)
            }
        }
        result
    }
}

impl Cipher for SubstitutionCipher {
    fn encrypt(&self, plain: &[u8], key: &[u8]) -> Result<Vec<u8>, CipherOperationError> {
        // Ensure the key is valid (must be a permutation of the alphabet)
        if key.len() != self.alphabet.len() {
            return Err(CipherOperationError::InvalidKeySize(key.len()));
        }

        // Encrypt using substitution.
        let encrypted = self.substitute(plain, key);
        Ok(encrypted)
    }

    fn encrypt_and_base64(&self, plain: &[u8], key: &[u8]) -> Result<String, CipherOperationError> {
        let result = self.encrypt(plain, key);
        match result {
            Err(e) => Err(e),
            Ok(msg) => Ok(STANDARD.encode(msg)),
        }
    }

    fn decrypt(&self, encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, CipherOperationError> {
        // Ensure the key is valid (must be a permutation of the alphabet)
        if key.len() != self.alphabet.len() {
            return Err(CipherOperationError::InvalidKeySize(key.len()));
        }

        // Reverse the key for decryption (substitute back).
        let mut reverse_key = vec![0; key.len()];
        for (i, &byte) in key.iter().enumerate() {
            if let Some(position) = self.alphabet.iter().position(|&x| x == byte) {
                reverse_key[position] = self.alphabet[i];
            }
        }

        // Decrypt using the reversed key.
        let decrypted = self.substitute(encrypted, &reverse_key);
        Ok(decrypted)
    }
}
