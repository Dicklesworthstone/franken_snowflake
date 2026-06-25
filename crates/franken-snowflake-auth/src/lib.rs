//! `franken-snowflake-auth` — secret-safe Snowflake auth construction.
//!
//! Owns header construction for the supported auth lanes, in implementation
//! order: programmatic access token (PAT) bearer headers, key-pair RS256 JWT
//! signing and rotation metadata, OAuth bearer pass-through, and workload
//! identity federation placeholder types. Secret source descriptors reference
//! environment variable names or external secret handles — **never** raw secret
//! values.
//!
//! Auth constructors return redacted `Debug` output by default; the env var name
//! is `#[serde(skip_serializing)]`; and the compile-time credential `Debug`-leak
//! gate (`docs/security_model.md`, bead
//! `fsnow-native-snowflake-connector-w0i.5`) fails the build if any
//! credential-shaped field carries a derived `Debug`.
//!
//! The key-pair JWT path is pinned to `jsonwebtoken` with
//! `default-features = false, features = ["rust_crypto", "use_pem"]` (pure-Rust
//! RSA/SHA-2 RS256 — no OpenSSL, no ring signing, no Tokio). See the "Auth Crypto
//! Path" section of the plan.
//!
//! Status: Phase 0 skeleton. Implemented across
//! `fsnow-native-snowflake-connector-w0i.2` (JWT signer) and
//! `fsnow-auth-foundations-kdw` (PAT/OAuth + signer integration).

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
