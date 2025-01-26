// tests/padding/pcsk_test.rs
use ciper_tools::padding::{pkcs7::Pkcs7Padding, PaddingStrategy};

#[test]
fn test_append_padding_valid() {
    let data = vec![1, 2, 3];
    let block_size = 4;

    let pkcs7 = Pkcs7Padding;
    let padded_data = pkcs7.apply_padding(&data, block_size).unwrap();
    assert_eq!(padded_data, vec![1, 2, 3, 1]); // 1-byte padding
}

#[test]
fn test_remove_padding_valid() {
    let data = vec![1, 2, 3, 1];
    let block_size = 4;
    let pkcs7 = Pkcs7Padding;
    let unpadded_data = pkcs7.strip_padding(&data, block_size).unwrap();
    assert_eq!(unpadded_data, vec![1, 2, 3]);
}
