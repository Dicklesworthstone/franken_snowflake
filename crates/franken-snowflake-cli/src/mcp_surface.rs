//! Feature-gated CLI shim for the `franken-snowflake-mcp` crate.

use crate::execute_cli_contract;

/// Run `franken-snowflake mcp serve` on stdio or HTTP.
pub fn run_mcp_serve_process(mode: Option<String>) -> ! {
    franken_snowflake_mcp::run_mcp_serve_process(mode, run_cli_contract)
}

fn run_cli_contract(args: Vec<String>) -> franken_snowflake_mcp::CliContractOutput {
    let output = execute_cli_contract(args);
    franken_snowflake_mcp::CliContractOutput {
        exit_code: output.exit_code,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}
