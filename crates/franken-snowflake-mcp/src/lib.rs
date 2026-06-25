//! Feature-gated MCP server surface for franken_snowflake.
//!
//! `franken-snowflake mcp serve [--stdio | --http <addr>]` exposes every read
//! verb as an MCP tool that shares the CLI read-verb handlers and contract (a
//! thin adapter, not a parallel implementation). The real `fastmcp_rust`-backed
//! surface lands under bead `fsnow-native-snowflake-connector-w0i.1`.
//!
//! This skeleton exists so the `crates/franken-snowflake-mcp` workspace member
//! resolves and `cargo check --workspace` is not poisoned while w0i.1 is in
//! progress.

#![allow(dead_code)]

/// Marker for the (currently unimplemented) MCP serve surface.
///
/// Replaced by the real `serve(...)` entrypoint under w0i.1.
pub const MCP_SURFACE_STATUS: &str = "skeleton: w0i.1 in progress";
