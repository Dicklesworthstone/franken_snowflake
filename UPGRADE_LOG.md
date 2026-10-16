# Dependency Upgrade Log

**Date:** 2026-10-14 (most recent audit; migrated to Asupersync `=0.5.0` on 2026-09-27 in `cc4da01`)
**Project:** franken_snowflake (`0.0.6`)
**Language:** Rust (edition 2024, `rust-version = "1.95"`)
**Manifest:** Cargo.toml / Cargo.lock

---

## 2026-09-27 → 2026-10-14 Currency State (`v0.0.6` + `Unreleased`)

### Summary

| Metric | Count |
|--------|-------|
| **Workspace crates** | 14 |
| **Pinned runtime** | 1 (`asupersync = "=0.5.0"` + `asupersync-macros = "0.5.0"`) |
| **Production admissibility lanes scanned** | 64 (`0` forbidden crates, `0` single-version violations) |

### FrankenSuite & Core Dependency Versions in `Cargo.lock`

- **asupersync** / **asupersync-macros**: `=0.3.5` → `=0.5.0` (`cc4da01`)
- **fastmcp** / **fastmcp-core** / **fastmcp-derive** / **fastmcp-protocol** / **fastmcp-server** / **fastmcp-transport**: `0.2.1` → `0.10.0`
- **frankensqlite (`fsqlite*` family)**: `0.1.16` → `0.1.24` (uniform across all `fsqlite*` crates; builds cleanly on Windows and Unix)
- **sqlmodel** / **sqlmodel-core** / **sqlmodel-frankensqlite** / **sqlmodel-macros** / **sqlmodel-query** / **sqlmodel-schema** / **sqlmodel-session**: `0.1.8` → `0.1.16`
- **frankensearch** / **frankensearch-core** / **frankensearch-index** / **frankensearch-lexical**: `0.1.8` → `0.1.14` (`hash` + `lexical` tiers only; no ML/vector crates)
- **frankenpandas (`fp-columnar`, `fp-types`)**: `0.1.6` → `0.1.7` (focused columnar/types crates only; `fp-io` excluded)
- **frankentui (`ftui*` family)**: `0.1.6` → `0.2.0`
- **tru (`toon` CLI/library)**: `0.2.3` → `0.2.4`

### Architecture Constraints Verified (2026-10-14)

- **asupersync single-version gate**: `scripts/check-asupersync-single-version.sh` verified `asupersync = "=0.5.0"` (single resolved version in `Cargo.lock`).
- **Dependency admissibility**: `python3 scripts/check-dependency-admissibility.py` scanned 64 lanes (`lanes_scanned: 64, lanes_skipped: 0, violation_count: 0`).

---

## 2026-09-11 Upgrade Wave (`v0.0.4`)

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
