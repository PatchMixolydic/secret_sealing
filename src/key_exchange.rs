//! Provides functions to perform a key exchange, allowing two parties to establish a
//! shared secret across an untrusted connection.
//!
//! ## Usage example
//! Alice and Marisa want to send each other love letters in the mail.
//! However, they don't want any adversaries to be able to read them, even if they somehow
//! acquire a quantum computer. To freely express their lesbian love, they take the
//! following steps:
//!
//! * Alice calls [`generate_initiator_keys`]. She sends the public key to Marisa and
//!   keeps the private key secret.
//! * Marisa receives Alice's public keys and calls [`create_encrypted_shared_secret`].
//!   She sends Alice the ciphertext and keeps the shared secret secret.
//! * Alice receives the ciphertext and calls [`decrypt_shared_secret`]. She receives
//!   the shared secret and can now securely communicate with Marisa so long as the
//!   shared secret remains secret.
//!
//! ## Algorithm
//! This module currently uses [SikeP751] internally.
//!
//! [SikeP751]: https://sike.org/

use oqs::{
    kem::{Algorithm, Kem},
    Error as OqsError,
};

pub use oqs::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

use crate::init_oqs_if_needed;

/// Creates a pair of public and private keys. Step 1 in the key exchange.
pub fn generate_initiator_keys() -> Result<(PublicKey, SecretKey), OqsError> {
    init_oqs_if_needed();
    let kem = Kem::new(Algorithm::SikeP751)?;

    // The `oqs` documentation shows the public key being signed.
    // However, that's not very useful without pre-exchanging signing keys.
    // The public key can be signed and verified outside of these functions
    // if necessary.
    kem.keypair()
}

/// Given a public key, produce a shared secret. Step 2 in the key exchange.
///
/// The [`Ciphertext`] is an encrypted copy of the shared secret and should be
/// sent to the initiator.
pub fn create_encrypted_shared_secret(
    initiator_public_key: PublicKey,
) -> Result<(Ciphertext, SharedSecret), OqsError> {
    init_oqs_if_needed();
    let kem = Kem::new(Algorithm::SikeP751)?;
    kem.encapsulate(&initiator_public_key)
}

/// Using a private key, decrypt an encrypted shared secret. Step 3 in the key exchange.
pub fn decrypt_shared_secret(
    initiator_private_key: SecretKey,
    encrypted_shared_secret: Ciphertext,
) -> Result<SharedSecret, OqsError> {
    init_oqs_if_needed();
    let kem = Kem::new(Algorithm::SikeP751)?;

    // Produce the shared secret
    kem.decapsulate(&initiator_private_key, &encrypted_shared_secret)
}
