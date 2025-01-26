use super::{CipherOperationError, EncryptionAlgorithm};
use crate::padding::PaddingStrategy;

/// Struct that handles Transposition Cipher with PKCS#7 Padding.
pub struct TranspositionCipher {
    padding_strategy: Box<dyn PaddingStrategy>,
}

impl TranspositionCipher {
    pub fn new(padding_strategy: Box<dyn PaddingStrategy>) -> Self {
        TranspositionCipher { padding_strategy }
    }
}

impl EncryptionAlgorithm for TranspositionCipher {
    /// Encrypts a message using the transposition cipher with PKCS#7 padding.
    ///
    /// # Arguments
    /// * `plaintext` - The plaintext message to encrypt.
    /// * `key` - The encryption key (must be non-empty).
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The encrypted message.
    /// * `Err(CipherError)` - An error if encryption fails.
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, CipherOperationError> {
        if key.is_empty() {
            return Err(CipherOperationError::InvalidKeySize(0));
        }

        // Apply PKCS#7 padding to the plaintext.
        let padded_data = self
            .padding_strategy
            .apply_padding(plaintext, key.len() as u32)
            .map_err(|e| CipherOperationError::PaddingValidationError(e))?;

        // Build the transposition matrix.
        let matrix = create_transposition_matrix(&padded_data, key.len());

        // Get the sorted key indices based on the key's values.
        let sorted_key_indices = get_sorted_key_indices(key);

        // Read matrix column-wise based on sorted key.
        let encrypted_message: Vec<u8> = sorted_key_indices
            .iter()
            .flat_map(|&index| matrix.iter().map(move |row| row[index]))
            .collect();

        Ok(encrypted_message)
    }

    /// Decrypts a message using the transposition cipher with PKCS#7 padding removal.
    ///
    /// # Arguments
    /// * `encrypted_message` - The encrypted message.
    /// * `key` - The decryption key (must be non-empty).
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The decrypted plaintext.
    /// * `Err(CipherError)` - An error if decryption fails.
    fn decrypt(
        &self,
        encrypted_message: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, CipherOperationError> {
        if key.is_empty() {
            return Err(CipherOperationError::InvalidKeySize(0));
        }

        let key_length = key.len();
        if encrypted_message.len() % key_length != 0 {
            return Err(CipherOperationError::InvalidEncryptedMessageLength);
        }

        let num_rows = encrypted_message.len() / key_length;
        let mut matrix = vec![vec![0; key_length]; num_rows];

        // Get the sorted key indices based on the key's values.
        let sorted_key_indices = get_sorted_key_indices(key);

        // Fill the matrix column by column based on sorted key.
        let mut index = 0;
        for &col_index in &sorted_key_indices {
            for row in 0..num_rows {
                matrix[row][col_index] = encrypted_message[index];
                index += 1;
            }
        }

        // Flatten the matrix and remove padding.
        let flattened: Vec<u8> = matrix.into_iter().flatten().collect();
        self.padding_strategy
            .strip_padding(&flattened, key_length as u32)
            .map_err(CipherOperationError::PaddingValidationError)
    }
}

/// Builds a matrix from the given data with the specified column size.
///
/// # Arguments
/// * `data` - The data to be organized into a matrix.
/// * `column_size` - The number of columns in the matrix.
///
/// # Returns
/// * `Vec<Vec<u8>>` - A matrix representation of the data.
fn create_transposition_matrix(data: &[u8], column_size: usize) -> Vec<Vec<u8>> {
    let num_rows = (data.len() + column_size - 1) / column_size;
    let mut matrix = Vec::with_capacity(num_rows);

    // Organize data into rows, padding with zeros if necessary
    for chunk in data.chunks(column_size) {
        let mut row = vec![0; column_size];
        row[..chunk.len()].copy_from_slice(chunk);
        matrix.push(row);
    }

    matrix
}

/// Generates the sorted indices of a key.
///
/// # Arguments
/// * `key` - The key for which sorted indices need to be generated.
///
/// # Returns
/// * `Vec<usize>` - Indices sorted by key values.
fn get_sorted_key_indices(key: &[u8]) -> Vec<usize> {
    let mut key_with_indices: Vec<(usize, &u8)> = key.iter().enumerate().collect();
    key_with_indices.sort_by_key(|&(_, value)| *value);
    key_with_indices
        .into_iter()
        .map(|(index, _)| index)
        .collect()
}
