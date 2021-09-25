# secret_sealing
[![secret_sealing on crates.io](https://img.shields.io/crates/v/secret_sealing)](https://crates.io/crates/secret_sealing)
[![Latest documentation on docs.rs](https://docs.rs/secret_sealing/badge.svg)](https://docs.rs/secret_sealing)
![License information for secret_sealing](https://img.shields.io/crates/l/secret_sealing)

A simple toolkit that provides wrappers and re-exports for modern cryptographic algorithms.

This crate tries to provide modern ciphers and hash algorithms wrapped in convenient functions.
However, some of the algorithms involved are bleeding-edge (such as [SIKEP751]),
and because of this, the underlying libraries might have security flaws. Further, this crate,
as well as some of its constituents, have not been audited for correctness or security. In
particular, private keys are not specifically stored in secure memory, which may pose a security
risk if your threat model includes someone reading arbitrary memory from your machine (such as by
a [cold boot attack]). Therefore, this crate is more of a grounds for personal experimentation than
anything production-ready. **Use this crate at your own risk.**

## Algorithms
The following modules use bleeding-edge algorithms intended to be
[secure against attacks by quantum computers][quantum-safe]. They are thus more resistant
to cracking theoretically, but the algorithms or implementations may contain bugs.
* `key_exchange` - Provides methods for exchanging a shared secret over an untrusted connection.
  Uses [SikeP751] via the [`oqs`] crate.
* `signing` - Provides methods for creating digital signatures. Uses [Falcon1024] via the [`oqs`] crate.

On the other hand, the following modules and functions use more well-known algorithms with more
trustworthy implementations:
* `non_password` - Provides general cryptographic hashing. Uses [BLAKE3] via the `blake3` crate.
* `password` - Provides cryptographic password hashing. Uses [Argon2] via the `argon2` crate.
* `crate::encrypt` and `crate::decrypt` - Provide general encryption of data. These use [ChaCha20Poly1305]
  via the `chacha20poly1305` crate.

[SikeP751]: https://sike.org/
[cold boot attack]: https://en.wikipedia.org/wiki/Cold_boot_attack
[quantum-safe]: https://en.wikipedia.org/wiki/Post-quantum_cryptography
[`oqs`]: https://github.com/open-quantum-safe/liboqs-rust
[Falcon1024]: https://falcon-sign.info/
[BLAKE3]: https://en.wikipedia.org/wiki/BLAKE3
[Argon2]: https://en.wikipedia.org/wiki/Argon2
[ChaCha20Poly1305]: https://datatracker.ietf.org/doc/html/rfc8439
