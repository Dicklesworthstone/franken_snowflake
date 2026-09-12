# Dependency Upgrade Log

**Date:** 2026-09-11
**Project:** franken_snowflake
**Language:** Rust
**Manifest:** Cargo.toml / Cargo.lock

---

## Summary

| Metric | Count |
|--------|-------|
| **Total dependencies evaluated** | 29 |
| **Updated** | 28 |
| **Preserved / Pinned** | 1 (`asupersync = "=0.3.5"` per workspace architecture rules) |
| **Failed (rolled back)** | 0 |
| **Requires attention** | 0 |

---

## Successfully Updated

- **bitflags**: `2.13.1` → `2.13.2`
- **bon** / **bon-macros**: `3.9.3` → `3.10.1`
- **crossbeam-channel**: `0.5.16` → `0.5.17`
- **crossbeam-deque**: `0.8.7` → `0.8.8`
- **crossbeam-epoch**: `0.9.20` → `0.9.21`
- **crossbeam-queue**: `0.3.13` → `0.3.14`
- **crossbeam-utils**: `0.8.22` → `0.8.23`
- **darling** / **darling_core** / **darling_macro**: `0.21.3` → `0.24.1`
- **encoding_rs**: `0.8.35` → `0.8.41`
- **flate2**: `1.1.9` → `1.1.10`
- **indexmap**: `2.14.0` → `2.14.2`
- **io-uring**: `0.7.14` → `0.7.15`
- **js-sys**: `0.3.104` → `0.3.105`
- **jsonwebtoken**: `10.3.0` → `10.4.0`
- **lru**: `0.18.2` → `0.18.4`
- **miniz_oxide**: `0.8.9` → `0.9.1`
- **mio**: `1.2.2` → `1.2.3`
- **prettyplease**: `0.2.37` → `0.3.0`
- **rustls**: `0.23.43` → `0.23.44`
- **smallvec**: `1.15.2` → `1.16.1`
- **syn**: `3.0.4` → `3.0.5`
- **toml**: `1.1.4` → `1.1.6`
- **uuid**: `1.25.0` → `1.26.1`
- **wasm-bindgen** / **wasm-bindgen-futures** / **wasm-bindgen-macro** / **wasm-bindgen-shared**: `0.2.127` → `0.2.128`
- **web-sys**: `0.3.104` → `0.3.105`
- **zerocopy** / **zerocopy-derive**: `0.8.56` → `0.8.57`

---

## Architecture Constraints Verified

- **asupersync single-version gate**: Preserved at `=0.3.5` (exactly 1 resolved package in `Cargo.lock`).
- **Dependency admissibility**: Zero forbidden crates (`tokio`, `reqwest`, `hyper`, `axum`, `tower`, `sqlx`, `diesel`, etc.).
- **Golden LF & CR checks**: 0 CRLF violations across all fixtures.
- **Formatting**: `cargo fmt --all -- --check` verified clean.
- **Lint policy**: `cargo clippy --workspace --all-targets --locked -- -D warnings` passed with 0 warnings.
- **Test suite**: 100% test pass rate across all 14 crates in the workspace.
