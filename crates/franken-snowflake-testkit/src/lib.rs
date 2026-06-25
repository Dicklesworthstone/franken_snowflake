//! `franken-snowflake-testkit` — deterministic, no-account proof harness.
//!
//! Owns two test lanes plus shared infrastructure:
//!
//! - **Primary deterministic lane (no socket):** the `Http1Client::request<IO>`
//!   codec driven over a `VirtualTcpStream` pair under `LabRuntime`, with DPOR
//!   exploration of cancellation/retry interleavings and obligation-leak /
//!   quiescence oracles asserting zero leaked connections, statements, or
//!   partition fetchers after a cancel. Canned fixtures cover 200 result sets,
//!   202 running, 429 backoff, 422 failure, gzip partitions, and the
//!   multi-statement refusal.
//! - **Integration lane:** a mock SQL API server built on `fastapi_rust`
//!   (Asupersync-native, dev-dependency only) for stateful end-to-end CLI ↔ HTTP
//!   flows, with auth-header redaction inspection and an opt-in live smoke
//!   harness that refuses clearly when credentials are absent.
//!
//! Shared infrastructure: key-sorted JSON golden files with time/host/hash
//! fields canonicalized (IEEE-754 bits reported on float mismatch), an injected
//! clock for deterministic backoff/TTL, canary-secret leak guards, and the
//! forbidden-dependency scan. `fastapi_rust` is a testkit dependency, never a
//! production core dependency. See `docs/proof_lanes.md`.
//!
//! Status: Phase 0 skeleton. Built out by `fsnow-deterministic-testkit-bak`,
//! the shared harness `fsnow-native-snowflake-connector-w0i.15`, and the
//! VirtualTcp/DPOR suite `fsnow-native-snowflake-connector-w0i.4`.

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
