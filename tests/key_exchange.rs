use secret_sealing::{decrypt, encrypt, key_exchange::*, non_password::derive_key};
use std::{
    str,
    sync::mpsc::{self, Receiver, Sender},
    thread,
};

static NONCE: &[u8; 12] = b"lisreal 2401";
static CONTEXT: &str = "secret_sealing key_exchange integration test";

fn alice(
    public_key_receiver: Receiver<PublicKey>,
    ciphertext_sender: Sender<Ciphertext>,
    message_receiver: Receiver<Vec<u8>>,
) {
    let main_public_key = public_key_receiver.recv().unwrap();
    let (ciphertext, shared_secret) = create_encrypted_shared_secret(main_public_key).unwrap();
    ciphertext_sender.send(ciphertext).unwrap();

    let encrypted_message = message_receiver.recv().unwrap();
    // TODO: is this correct?
    let key = derive_key(CONTEXT, shared_secret.as_ref());
    let message = decrypt(&key, NONCE, encrypted_message.as_ref()).unwrap();
    let message_str = str::from_utf8(&message).unwrap();

    assert_eq!(message_str, "hello alice");
}

#[test]
fn key_exchange_test() {
    let (public_key_sender, public_key_receiver) = mpsc::channel();
    let (ciphertext_sender, ciphertext_receiver) = mpsc::channel();
    let (message_sender, message_receiver) = mpsc::channel();
    let alice = thread::spawn(|| alice(public_key_receiver, ciphertext_sender, message_receiver));

    let (public_key, private_key) = generate_initiator_keys().unwrap();
    public_key_sender.send(public_key).unwrap();
    let ciphertext = ciphertext_receiver.recv().unwrap();
    let shared_secret = decrypt_shared_secret(private_key, ciphertext).unwrap();

    // TODO: is this correct?
    let key = derive_key(CONTEXT, shared_secret.as_ref());
    let message = encrypt(&key, NONCE, b"hello alice".as_ref()).unwrap();
    message_sender.send(message).unwrap();
    alice.join().unwrap();
}
