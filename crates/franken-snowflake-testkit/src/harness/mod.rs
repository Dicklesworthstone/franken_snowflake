//! The shared, generic test + observability harness.
//!
//! This module implements the "comprehensive tests with detailed logging"
//! substrate **once**, so every crate's unit tests and every proof lane consume
//! it as a dev-dependency instead of re-inventing golden comparison, structured
//! logging, deterministic time, or secret-leak scanning per bead.
//!
//! It is deliberately **generic**: no Snowflake protocol knowledge, no live
//! network, no `asupersync` runtime coupling. The Snowflake fixtures and the
//! `fastapi_rust` mock server (`fsnow-deterministic-testkit-bak`) and the
//! VirtualTcp/DPOR race suite (`fsnow-native-snowflake-connector-w0i.4`) build
//! on top of these primitives.
//!
//! Four cooperating pieces, each its own submodule:
//!
//! - [`golden`] — the deterministic golden framework: key-sorted canonical JSON,
//!   canonicalization that zeroes volatile time/host/hash/run-id fields,
//!   structural byte-exact comparison, IEEE-754-bit reporting on float
//!   mismatch, and the cross-platform CRLF/`eol=lf` discipline helpers.
//! - [`logger`] — the structured JSON-line run logger: one event per step
//!   (`trace_id`/`command_id`/`seq`/timing/outcome, plus expected-vs-actual on
//!   failure) written to a per-run artifacts directory, with a human-readable
//!   run summary.
//! - [`clock`] — the injected/deterministic [`clock::Clock`], a seeded
//!   [`clock::DeterministicRng`], and a reproducible [`clock::backoff_schedule`]
//!   for backoff/TTL.
//! - [`canary`] — the canary-secret leak guard: planted fake-but-detectable
//!   secrets scanned across every output channel (stdout/stderr/files), reusing
//!   the single shared secret-needle list from `franken_snowflake_core::redact`
//!   so the guard and the production redactor cannot drift.
//!
//! See `docs/proof_lanes.md` ("Cross-Cutting Standards") and
//! `docs/security_model.md` ("The Two Anti-Leak Mechanisms") for the normative
//! contracts these pieces implement.

pub mod canary;
pub mod clock;
pub mod golden;
pub mod logger;
