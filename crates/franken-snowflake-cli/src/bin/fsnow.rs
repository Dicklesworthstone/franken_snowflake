//! `fsnow` — the short agent-ergonomic alias of `franken-snowflake` (same entry
//! point, identical contract; agents type the connector name constantly).

use std::process::ExitCode;

fn main() -> ExitCode {
    franken_snowflake_cli::run()
}
