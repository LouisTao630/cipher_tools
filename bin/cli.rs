use ciper_tools::cipher::{
    substitution_cipher::SubstitutionCipher, transposition_cipher::TranspositionCipher, Cipher,
};
use ciper_tools::padding::pkcs7::Pkcs7Padding;
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(version,about,long_about=None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Transposition {
        #[command(subcommand)]
        command: Option<TranspositionCommand>,
    },
    Substitution {
        #[command(subcommand)]
        command: Option<SubstitutionCommand>,
    },
}

#[derive(Clone, ValueEnum)]
enum Padding {
    Pkcs7,
}

#[derive(Subcommand)]
enum TranspositionCommand {
    /// Encrypt plain text with key.
    Encrypt {
        #[arg(short, long, value_enum, default_value_t = Padding::Pkcs7)]
        padding: Padding,

        /// The key to be used in encryption.
        #[arg(short, long)]
        key: String,

        /// Plain text to be encrypted
        plain_text: String,
    },
    /// Decrypt message with key.
    Decrypt {
        #[arg(short, long, value_enum, default_value_t = Padding::Pkcs7)]
        padding: Padding,

        /// The key to be used in encryption.
        #[arg(short, long)]
        key: String,

        /// Encrypted text to be decrypted
        #[arg(short = 'm', long = "msg")]
        encrypted_text: String,
    },
}

#[derive(Subcommand)]
enum SubstitutionCommand {
    /// Encrypt plain text with key.
    Encrypt {
        /// The key to be used in encryption.
        #[arg(short, long)]
        key: String,

        /// Plain text to be encrypted
        #[arg(short, long)]
        plain_text: String,
    },
    Decrypt {
        /// The key to be used in encryption.
        #[arg(short, long)]
        key: String,

        /// Encrypted text to be decrypted
        #[arg(short, long)]
        encrypted_text: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Some(Commands::Transposition { command }) => match command {
            Some(TranspositionCommand::Encrypt {
                padding,
                key,
                plain_text,
            }) => {
                let pad = match padding {
                    Padding::Pkcs7 => Pkcs7Padding,
                };

                let cipher = TranspositionCipher::new(Box::new(pad));
                let result = cipher.encrypt_and_base64(plain_text.as_bytes(), key.as_bytes());
                println!("Transposition cipher encrypted: {}", result.unwrap());
            }
            Some(TranspositionCommand::Decrypt {
                padding,
                key,
                encrypted_text,
            }) => {
                let pad = match padding {
                    Padding::Pkcs7 => Pkcs7Padding,
                };

                let cipher = TranspositionCipher::new(Box::new(pad));
                let result = cipher.decrypt(encrypted_text.as_bytes(), key.as_bytes());
                let hex_string = result
                    .unwrap()
                    .iter()
                    .map(|byte| format!("{:02x}", byte))
                    .collect::<String>();
                print!("{}", hex_string);
            }
            None => {}
        },
        Some(Commands::Substitution { command }) => match command {
            Some(SubstitutionCommand::Encrypt { key, plain_text }) => {
                let cipher = SubstitutionCipher::new();
                let result = cipher.encrypt_and_base64(plain_text.as_bytes(), key.as_bytes());
                println!("Substitution cipher encrypted: {}", result.unwrap());
            }
            Some(SubstitutionCommand::Decrypt {
                key,
                encrypted_text,
            }) => {
                let cipher = SubstitutionCipher::new();
                let result = cipher.decrypt(encrypted_text.as_bytes(), key.as_bytes());
                let hex_string = result
                    .unwrap()
                    .iter()
                    .map(|byte| format!("{:02x}", byte))
                    .collect::<String>();
                print!("{}", hex_string);
            }
            None => {}
        },
        None => {}
    }
}
