//! This module handles PKCS#7 padding.

use super::{PaddingStrategy, PaddingValidationError};

pub struct Pkcs7Padding;

impl PaddingStrategy for Pkcs7Padding {
    /// Applies PKCS#7 padding to the given data.
    ///
    /// # Arguments
    ///
    /// * `data` - The input data to pad.
    /// * `block_size` - The block size for padding (must be greater than 0 and less than 256).
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The padded data.
    /// * `Err(PaddingValidationError)` - An error if padding cannot be applied.
    fn apply_padding(
        &self,
        data: &[u8],
        block_size: u32,
    ) -> Result<Vec<u8>, PaddingValidationError> {
        // Validate parameters
        if data.is_empty() {
            return Err(PaddingValidationError::ParameterError(
                "Data must not be empty",
            ));
        }
        if block_size == 0 || block_size > u8::MAX as u32 {
            return Err(PaddingValidationError::ParameterError(
                "Block size must be greater than 0 and smaller than 256",
            ));
        }

        // Calculate the padding value
        let padding_value = (block_size - data.len() as u32 % block_size) as u8;

        // Append padding to the data
        let mut padded_data = data.to_vec();
        padded_data.extend(std::iter::repeat(padding_value).take(padding_value as usize));

        Ok(padded_data)
    }

    /// Removes PKCS#7 padding from the given data.
    ///
    /// # Arguments
    ///
    /// * `data` - The padded data to strip.
    /// * `block_size` - The block size used for padding (must be greater than 0 and less than 256).
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The unpadded data.
    /// * `Err(PaddingValidationError)` - An error if padding cannot be removed.
    fn strip_padding(
        &self,
        data: &[u8],
        block_size: u32,
    ) -> Result<Vec<u8>, PaddingValidationError> {
        // Validate parameters
        if data.is_empty() {
            return Err(PaddingValidationError::ParameterError(
                "Data must not be empty",
            ));
        }
        if block_size == 0 || block_size > u8::MAX as u32 {
            return Err(PaddingValidationError::ParameterError(
                "Block size must be greater than 0 and smaller than 256",
            ));
        }

        if data.len() % block_size as usize != 0 {
            return Err(PaddingValidationError::ParameterError(
                "Data length must be a multiple of block size",
            ));
        }

        // Check the validity of padding
        self.validate_padding(data, block_size as u8)?;

        // Get padding value from the last byte
        let padding_value = data[data.len() - 1];

        // Remove padding
        let unpadded_data = data[0..data.len() - padding_value as usize].to_vec();

        Ok(unpadded_data)
    }

    /// Validates whether the PKCS#7 padding in the given data is correct.
    ///
    /// # Arguments
    ///
    /// * `data` - The padded data.
    /// * `block_size` - The block size used for padding (must be greater than 0).
    ///
    /// # Returns
    ///
    /// * `Ok(())` if padding is valid.
    /// * `Err(PaddingValidationError)` if padding is invalid.
    fn validate_padding(&self, data: &[u8], block_size: u8) -> Result<(), PaddingValidationError> {
        // Get the padding value from the last byte
        let padding_value = data[data.len() - 1];

        // Validate the padding value range
        if padding_value == 0 || padding_value > block_size {
            return Err(PaddingValidationError::PaddingError(format!(
                "Padding value must be greater than 0 and not greater than block size. Found: {}",
                padding_value
            )));
        }

        // Validate the padding content
        let padding_start = data.len() - padding_value as usize;
        if !data[padding_start..]
            .iter()
            .all(|&byte| byte == padding_value)
        {
            return Err(PaddingValidationError::PaddingError(
                "Padding content is invalid".to_string(),
            ));
        }

        Ok(())
    }
}
