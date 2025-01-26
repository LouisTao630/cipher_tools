use thiserror::Error;

pub mod pkcs7;

#[derive(Debug, Error)]
pub enum PaddingValidationError {
    #[error("Block length must be greater than zero")]
    InvalidBlockLength,

    #[error("Padding validation error: {0}")]
    PaddingError(String),

    #[error("The length of the encrypted message is invalid")]
    InvalidMessageLength,

    #[error("Padding parameter error: {0}")]
    ParameterError(&'static str),
}

/// Trait for different padding strategies like PKCS7.
pub trait PaddingStrategy {
    /// Applies padding to the data to match the block size.
    ///
    /// # Arguments
    ///
    /// * `data` - The input data to pad.
    /// * `block_length` - The size of the blocks.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The padded data.
    /// * `Err(PaddingValidationError)` - An error if padding cannot be applied.
    fn apply_padding(
        &self,
        data: &[u8],
        block_length: u32,
    ) -> Result<Vec<u8>, PaddingValidationError>;

    /// Strips padding from the data.
    ///
    /// # Arguments
    ///
    /// * `data` - The padded data to remove padding from.
    /// * `block_length` - The block size used to pad the data.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The unpadded data.
    /// * `Err(PaddingValidationError)` - An error if padding cannot be removed.
    fn strip_padding(
        &self,
        data: &[u8],
        block_length: u32,
    ) -> Result<Vec<u8>, PaddingValidationError>;

    fn validate_padding(&self, data: &[u8], block_size: u8) -> Result<(), PaddingValidationError>;
}
