//! A simple toolkit that provides wrappers and re-exports for modern
//! cryptographic algorithms.
//!
//! This crate tries to provide modern ciphers and hash algorithms
//! wrapped in convenient functions. However, some of the algorithms
//! involved are bleeding-edge (such as [SIKEP751]), and because of this,
//! the underlying libraries might have security flaws. **Use this crate
//! at your own risk.**
//!
//! Namely, the following modules use bleeding-edge algorithms intended
//! to be [secure against attacks by quantum computers][quantum-safe]:
//! * [`key_exchange`] - Uses [SikeP751] via the [`oqs`] crate.
//! * [`signing`] - Uses [Falcon1024] via the [`oqs`] crate.
//!
//! On the other hand, the following modules and functions use more
//! well-known algorithms with more trustworthy implementations:
//! * [`non_password`] - Uses [BLAKE3] via the [`blake3`] crate.
//! * [`password`] - Uses [Argon2] via the [`argon2`] crate.
//! * [`encrypt`] and [`decrypt`] - Use [ChaCha20Poly1305] via the
//!   [`chacha20poly1305`] crate.
//!
//! [quantum-safe]: https://en.wikipedia.org/wiki/Post-quantum_cryptography
//! [SikeP751]: https://sike.org/
//! [Falcon1024]: https://falcon-sign.info/
//! [BLAKE3]: https://en.wikipedia.org/wiki/BLAKE3
//! [Argon2]: https://en.wikipedia.org/wiki/Argon2
//! [ChaCha20Poly1305]: https://datatracker.ietf.org/doc/html/rfc8439

pub mod key_exchange;
pub mod password;
pub mod signing;

/// A fast cryptographic hash algorithm meant for data
/// (not passwords).
///
/// To hash passwords, the [`password`] module should be used
/// instead.
///
/// ## Algorithm
/// This module currently uses the [BLAKE3] hashing algorithm internally.
///
/// [BLAKE3]: https://en.wikipedia.org/wiki/BLAKE3
pub mod non_password {
    pub use blake3::{derive_key, hash, keyed_hash, Hasher};
}

use chacha20poly1305::{
    aead::{Aead, NewAead},
    ChaCha20Poly1305,
};
use std::sync::Once;

pub use argon2::{self, password_hash::Error as PasswordHashError};
pub use blake3;
pub use chacha20poly1305::{
    self,
    aead::{Error as AeadError, Payload as AeadPayload},
};
pub use oqs::{self, Error as OqsError};

/// Calls [`oqs::init`] exactly once.
///
/// This isn't strictly necessary when using
/// `std`, but might be beneficial if a `no_std`
/// mode is ever added to this crate.
fn init_oqs_if_needed() {
    static INIT_ONCE: Once = Once::new();
    INIT_ONCE.call_once(oqs::init);
}

/// Encrypt a given payload, such as a byte slice, using the given
/// key and nonce.
///
/// The payload can be either a byte slice or an [`AeadPayload`].
/// The difference is that the latter can carry additional associated
/// data, which may be used to authenticate data transmitted in plaintext
/// alongside the ciphertext and to ensure that the ciphertext only
/// appears in the correct context. For more information, see
/// [the `aead` crate's documentation] and [this article about authenticated encryption].
///
/// [the `aead` crate's documentation]: chacha20poly1305::aead
/// [this article about authenticated encryption]: https://en.wikipedia.org/wiki/Authenticated_encryption
///
/// ## Algorithm
/// This function currently uses the [ChaCha20Poly1305]
/// cipher internally.
///
/// [ChaCha20Poly1305]: https://datatracker.ietf.org/doc/html/rfc8439
pub fn encrypt<'msg, 'aad>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: impl Into<AeadPayload<'msg, 'aad>>,
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher.encrypt(nonce.into(), plaintext.into())
}

/// Decrypt a given payload, such as a byte slice, using the given
/// key and nonce.
///
/// The payload can be either a byte slice or an [`AeadPayload`].
/// The difference is that the latter can carry additional associated
/// data, which may be used to authenticate data transmitted in plaintext
/// alongside the ciphertext and to ensure that the ciphertext only
/// appears in the correct context. For more information, see
/// [the `aead` crate's documentation] and [this article about authenticated encryption].
///
/// [the `aead` crate's documentation]: chacha20poly1305::aead
/// [this article about authenticated encryption]: https://en.wikipedia.org/wiki/Authenticated_encryption
///
/// ## Algorithm
/// This function currently uses the [ChaCha20Poly1305]
/// cipher internally.
///
/// [ChaCha20Poly1305]: https://datatracker.ietf.org/doc/html/rfc8439
pub fn decrypt<'msg, 'aad>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: impl Into<AeadPayload<'msg, 'aad>>,
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher.decrypt(nonce.into(), ciphertext.into())
}
