pub mod transposition_cipher;
use crate::padding::PaddingValidationError;
use thiserror::Error;

/// Error type for cipher operations.
#[derive(Debug, Error)]
pub enum CipherOperationError {
    #[error("Key size is invalid: {0}")]
    InvalidKeySize(usize), // More descriptive error
    #[error("Padding validation failed: {0}")]
    PaddingValidationError(PaddingValidationError),
    #[error("Encrypted message has an invalid length")]
    InvalidEncryptedMessageLength,
}

/// Trait for encryption algorithms (e.g., BlockCipher).
pub trait EncryptionAlgorithm {
    /// Encrypts a plaintext message using a cipher algorithm.
    ///
    /// # Arguments
    ///
    /// * `plain` - The plaintext to encrypt.
    /// * `key` - The encryption key.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The encrypted data.
    /// * `Err(CipherOperationError)` - Error if encryption fails.
    fn encrypt(&self, plain: &[u8], key: &[u8]) -> Result<Vec<u8>, CipherOperationError>;

    /// Decrypts an encrypted message.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted data.
    /// * `key` - The decryption key.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The decrypted data.
    /// * `Err(CipherOperationError)` - Error if decryption fails.
    fn decrypt(&self, encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, CipherOperationError>;

    /// Ensures that the key is valid (not empty).
    fn ensure_valid_key(&self, key: &[u8]) -> Result<(), CipherOperationError> {
        if key.is_empty() {
            return Err(CipherOperationError::InvalidKeySize(0)); // Return a more specific error
        }
        Ok(())
    }
}
