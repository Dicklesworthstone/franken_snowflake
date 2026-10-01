//! Feature-gated CLI shim for the `franken-snowflake-mcp` crate.

use crate::{McpHttpArgs, execute_cli_contract};
use franken_snowflake_mcp::{HttpServeOptions, McpServeMode};

/// Run `franken-snowflake mcp serve` on stdio (`None`) or the secured HTTP
/// transport (`Some`).
pub fn run_mcp_serve_process(http: Option<McpHttpArgs>) -> ! {
    let mode = match http {
        None => McpServeMode::Stdio,
        Some(args) => McpServeMode::Http(HttpServeOptions {
            addr: args.addr,
            allowed_origins: args.allowed_origins,
            extra_tools: args.extra_tools,
            allow_remote: args.allow_remote,
        }),
    };
    franken_snowflake_mcp::run_mcp_serve_process(mode, run_cli_contract)
}

/// Run one CLI invocation for an MCP tool call; a statement it starts is
/// cancelled (remote cancel included) when the MCP request is.
fn run_cli_contract(
    args: Vec<String>,
    cancel: franken_snowflake_mcp::CancelProbe,
) -> franken_snowflake_mcp::CliContractOutput {
    let output = crate::with_external_cancel(cancel, || execute_cli_contract(args));
    franken_snowflake_mcp::CliContractOutput {
        exit_code: output.exit_code,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}
