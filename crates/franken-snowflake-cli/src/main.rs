//! `franken-snowflake` — the agent-ergonomic CLI binary.
//!
//! The target command surface (`capabilities`, `agent-handbook`/`robot-docs`,
//! `doctor`, `selftest`, `profile validate`, `catalog scan`, `catalog graph`,
//! `dataset inspect`/`describe-operator`, `query plan`/`run`/`cancel`,
//! `receipt show`, `export`, `tui`, `mcp serve`) and its deterministic JSON
//! envelope, exit-code dictionary, and `--json`/`--toon` output modes are
//! specified in `docs/agent_cli_contract.md`. Stdout is data; stderr is
//! diagnostics.
//!
//! Status: Phase 0 skeleton. The command surface is implemented in Phase 4
//! (`fsnow-agent-ergonomic-cli-mpk`). This entrypoint intentionally does nothing
//! yet so the workspace builds as an empty skeleton.

fn main() {}
