//! A slow cryptographic hash algorithm meant for passwords.
//!
//! To hash regular data, the [`non_password`] module should be
//! used instead.
//!
//! ## Algorithm
//! This module currently uses the [Argon2] hashing algorithm internally.
//!
//! [`non_password`]: super::non_password
//! [Argon2]: https://en.wikipedia.org/wiki/Argon2

use argon2::{
    password_hash::{Error as PasswordHashError, SaltString},
    Argon2, PasswordHasher, PasswordVerifier,
};
use rand_core::OsRng;
use std::convert::TryInto;

/// Hash a password, producing a [PHC string] containing the hash
/// as well as parameters for the underlying algorithm.
///
/// [PHC string]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#specification
pub fn hash(password: &[u8]) -> Result<String, PasswordHashError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password, &salt)
        .map(|hash| hash.to_string())
}

/// Validate that a password matches a given hash.
///
/// The hash must be formatted as a [PHC string].
///
/// [PHC string]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#specification
pub fn verify(password: &[u8], hash: &str) -> Result<(), PasswordHashError> {
    let argon2 = Argon2::default();
    argon2.verify_password(password, &hash.try_into()?)
}
