//! Provides methods to create [digital signatures], allowing users to validate
//! the origin of a message.
//!
//! [digital signatures]: https://en.wikipedia.org/wiki/Digital_signature
//!
//! ## Algorithm
//! This module currently uses [Falcon1024] internally.
//!
//! [Falcon1024]: https://falcon-sign.info/

use oqs::{
    sig::{Algorithm, Sig, Signature},
    Error as OqsError,
};

use crate::init_oqs_if_needed;

pub use oqs::sig::{PublicKey, SecretKey};

/// Generate a public and private keypair.
pub fn generate_signing_keys() -> Result<(PublicKey, SecretKey), OqsError> {
    init_oqs_if_needed();
    let sig = Sig::new(Algorithm::Falcon1024)?;
    sig.keypair()
}

/// Sign a given message using the given private key.
pub fn sign(private_key: &SecretKey, message: &[u8]) -> Result<Signature, OqsError> {
    init_oqs_if_needed();
    let sig = Sig::new(Algorithm::Falcon1024)?;
    sig.sign(message, private_key)
}

/// Verify a signed message given the message, the signature, and the sender's public key.
pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), OqsError> {
    init_oqs_if_needed();
    let sig = Sig::new(Algorithm::Falcon1024)?;
    sig.verify(message, signature, public_key)
}
