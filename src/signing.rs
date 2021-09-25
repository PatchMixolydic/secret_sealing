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

/// A struct containing state for the signing algorithm.
///
/// Used to avoid reallocations when calling [`SigningContext::sign`]
/// and [`SigningContext::verify`] repeatedly.
///
/// ## Safety
/// This struct must be constructed with [`SigningContext::new`] so
/// that it can initialize [`oqs`] if necessary. Otherwise, undefined
/// behaviour may occur. This should only be a concern for unsafe code.
pub struct SigningContext {
    signature_scheme: Sig,
}

impl SigningContext {
    pub fn new() -> Result<Self, OqsError> {
        init_oqs_if_needed();

        Ok(Self {
            signature_scheme: Sig::new(Algorithm::Falcon1024)?,
        })
    }

    /// Generate a public and private keypair.
    pub fn generate_signing_keys(&self) -> Result<(PublicKey, SecretKey), OqsError> {
        self.signature_scheme.keypair()
    }

    /// Sign a given message using the given private key.
    pub fn sign(&self, private_key: &SecretKey, message: &[u8]) -> Result<Signature, OqsError> {
        self.signature_scheme.sign(message, private_key)
    }

    /// Verify a signed message given the message, the signature, and the sender's public key.
    pub fn verify(
        &self,
        public_key: &PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), OqsError> {
        self.signature_scheme.verify(message, signature, public_key)
    }
}
