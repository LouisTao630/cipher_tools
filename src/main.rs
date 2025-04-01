use chrono::Local;
use ciper_tools::cipher::substitution_cipher::SubstitutionCipher;
use ciper_tools::cipher::Cipher;
use env_logger::Builder;
use log::{error, info, LevelFilter};
use std::io::Write;

use ciper_tools::cipher::transposition_cipher::TranspositionCipher;
use ciper_tools::padding::pkcs7::Pkcs7Padding;

fn main() {
    // Initialize the logger with custom formatting
    Builder::new()
        .filter(None, LevelFilter::Info)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .init();

    info!("Application started");

    let mut key = "hello";
    let message = "Happy new year!x";

    info!("Original message: {}", message);

    // Encrypt and decrypt the message
    if let Err(e) = encrypt_decrypt_message(message, key) {
        error!("Error occurred: {}", e);
    } else {
        info!("Application finished successfully");
    }

    key = "qazxswedcvfrtgbnhyujmkiolp";
    if let Err(e) = encrypt_and_decrypted_with_subtitution_cipher(message, key) {
        error!("Error occurred: {}", e);
    } else {
        info!("Application finished successfully");
    }
}

/// Encrypts and then decrypts a message, logging the results.
fn encrypt_decrypt_message(message: &str, key: &str) -> Result<(), String> {
    let pkcs7 = Pkcs7Padding;
    let cipher = TranspositionCipher::new(Box::new(pkcs7));

    // Encrypt message
    let encrypted_message = cipher
        .encrypt(message.as_bytes(), key.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    info!("Encrypted message: {:?}", encrypted_message);

    // Decrypt message
    let decrypted_message = cipher
        .decrypt(&encrypted_message, key.as_bytes())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    info!(
        "Decrypted message: {:?}",
        String::from_utf8_lossy(&decrypted_message)
    );

    Ok(())
}

fn encrypt_and_decrypted_with_subtitution_cipher(message: &str, key: &str) -> Result<(), String> {
    let cipher: Box<dyn Cipher> = Box::new(SubstitutionCipher::new());
    let encrypted_msg = cipher
        .encrypt(message.as_bytes(), key.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let decrypted_message = cipher
        .decrypt(&encrypted_msg, key.as_bytes())
        .map_err(|op| format!("Encryption failed: {}", op))?;

    info!(
        "Decrypted message: {:?}",
        String::from_utf8_lossy(&decrypted_message)
    );

    Ok(())
}
