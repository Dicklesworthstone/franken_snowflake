//! `franken-snowflake` — the canonical binary name. The whole CLI lives in the
//! `franken_snowflake_cli` library so the `fsnow` alias shares one compiled body
//! instead of building (and testing) `main.rs` twice.

use std::process::ExitCode;

fn main() -> ExitCode {
    franken_snowflake_cli::run()
}
