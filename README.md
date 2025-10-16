## libbbs-rs

[![Rust](https://github.com/ilumary/libbbs-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/ilumary/libbbs-rs/actions/workflows/rust.yml)

An implementation of BBS Signatures in pure Rust, following [draft-irtf-cfrg-bbs-signatures-09](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/).

libbbs-rs provides an implementation of pairing-based BBS signatures, enabling signing multiple messages with a single signature and zero-knowledge proofs of possession with selective disclosure of messages.

All cryptographic operations are implemented in pure Rust with no `unsafe` code and validated against the provided rfc test vectors.

### Key Features & Scope

libbbs-rs is still in a very early development stage and purely intended for research at this point. Through the use of Rust with no `unsafe` blocks, memory safety can be relied upon, however the codebase has not yet been tested against any kind of attack vectors.
Currently implemented are:
- [x] sign
- [x] verify
- [ ] proof_gen
- [ ] proof_verify

Upon completion of the basic features, I plan on adding the extension for per-verifier linkability as introduced in [this draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-per-verifier-linkability/).

### Core Concepts

BBS signatures are built over two pairing-friendly elliptic curves and rely on a bilinear map:

``e: G_1 \times G_2 \rightarrow G_T``

where:
- ``G_1, G_2`` are elliptic curve subgroups of prime order `` r ``
- ``G_T`` is a multiplicative subgroup of a finite field extension
- ``e`` satisfies bilinearity: ``e(aP, bQ) = e(P, Q)^{ab}``

#### Signature

The signer computes a random challenge scalar ``e`` from all messages and context:

``e = H_2(SK, m_1, \ldots, m_L, \text{domain})``

Then constructs:
``B = P_1 + Q_1 \cdot \text{domain} + \sum_i H_i \cdot m_i``
``A = B \cdot (SK + e)^{-1}``

The signature is the pair ``(A, e)``.

#### Verification

Verification checks the bilinear pairing equation:

``e(A, W) \cdot e(A \cdot e - B, BP_2) = I(G_T)``

If this holds, the signature is valid. Due to the bilinearity of ``e``, a more efficient formula can be used:

``e(A, W + BP_2 \cdot e) \cdot e(B, -BP_2) = I(G_T)``

### Implementation Details

- Rust lib [bls12_381](https://docs.rs/bls12_381/latest/bls12_381) for curve operations
- Rust lib [sha2](https://docs.rs/sha2/latest/sha2/) for hashing, specifially for `expand_message_xmd()`

No other external cryptographic dependencies are used. As mentioned previously, libbbs-rs does not make use of any `unsafe` code blocks. All used functions from `bls12_381` are constant time.
Building requires a recent version of rustc: >= 1.90.0
All unix-style platforms are supported. Windows is not.

### Testing

All components are tested against the test vectors from the BBS draft. Github's CI is set up to run a build and test on every commit.

### License

Apache-2.0 license

