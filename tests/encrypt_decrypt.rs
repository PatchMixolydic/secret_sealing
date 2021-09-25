use std::str;
use secret_sealing::{encrypt, decrypt};

static KEY: &[u8; 32] = b"32-byte randomized key for u! :)";
static NONCE: &[u8; 12] = b"ECONNREFUSED";
static MESSAGE: &str = "hello, world!";

#[test]
fn encrypt_decrypt_test() {
    let encrypted_message = encrypt(KEY, NONCE, MESSAGE.as_bytes()).unwrap();
    let decrypted_message = decrypt(KEY, NONCE, encrypted_message.as_ref()).unwrap();
    let decrypted_message_str = str::from_utf8(&decrypted_message).unwrap();
    assert_eq!(decrypted_message_str, MESSAGE);
}
