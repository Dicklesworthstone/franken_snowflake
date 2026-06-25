//! `franken-snowflake` — the agent-ergonomic CLI binary.
//!
//! This crate owns the public command contract described in
//! `docs/agent_cli_contract.md`. The live Snowflake handlers are still blocked on
//! lower-level beads, but the CLI surface, deterministic envelope, error-code
//! registry, and `--json`/`--toon` output switch are intentionally implemented
//! early so downstream panes can target one stable shape.

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

const ENVELOPE_SCHEMA_VERSION: &str = "fsnow.envelope.v1";
const CLI_CONTRACT_VERSION: &str = "fsnow.cli.contract.v1";
const DEFAULT_TIME: &str = "1970-01-01T00:00:00Z";

fn main() -> ExitCode {
    write_outcome(execute(env::args().skip(1).collect()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFormat {
    Json,
    Toon,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExitStatus {
    Success = 0,
    Findings = 1,
    SafetyRefusal = 2,
    Usage = 64,
    Io = 74,
}

impl ExitStatus {
    fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GraphOutput {
    Json,
    Toon,
    Mermaid,
    Svg,
}

#[derive(Debug)]
enum Command {
    Help,
    Capabilities,
    RobotDocsGuide,
    AgentHandbook,
    Doctor,
    Selftest,
    ProfileValidate {
        profile: String,
    },
    ProfileDoctor {
        profile: String,
        online: bool,
    },
    CatalogScan {
        profile: String,
        database: Option<String>,
        schema: Option<String>,
    },
    CatalogGraph {
        profile: String,
        graph_output: GraphOutput,
    },
    DatasetInspect {
        dataset_id: String,
    },
    DatasetProfile {
        dataset_id: String,
    },
    DatasetDescribeOperator {
        operator: String,
    },
    QueryPlan {
        profile: Option<String>,
        sql: Option<String>,
    },
    QueryRun {
        profile: Option<String>,
        sql: Option<String>,
    },
    QueryCancel {
        statement_handle: String,
    },
    ReceiptShow {
        receipt_hash: String,
    },
    ExportPlan,
    Tui {
        profile: Option<String>,
    },
    McpServe {
        mode: Option<String>,
    },
}

#[derive(Debug)]
struct Invocation {
    args_for_request_id: Vec<String>,
    command: Command,
    output: OutputFormat,
}

#[derive(Clone, Debug)]
enum Json {
    Null,
    Bool(bool),
    Number(i64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(&'static str, Json)>),
}

#[derive(Clone, Debug)]
struct ErrorInfo {
    code: &'static str,
    message: String,
    retryable: bool,
    policy_boundary: &'static str,
    evidence: Vec<Json>,
}

#[derive(Clone, Debug)]
struct Envelope {
    ok: bool,
    outcome_kind: &'static str,
    command_id: &'static str,
    output_contract_id: &'static str,
    data_source: &'static str,
    profile_id: Option<String>,
    request_id: String,
    query_id: Option<String>,
    statement_handle: Option<String>,
    receipt_hash: Option<String>,
    warnings: Vec<Json>,
    safe_next_commands: Vec<String>,
    repair_commands: Vec<String>,
    did_you_mean: Vec<String>,
    budget_consumed: Json,
    redactions_applied: Vec<String>,
    data: Json,
    error: Option<ErrorInfo>,
}

#[derive(Debug)]
struct Outcome {
    status: ExitStatus,
    body: Body,
}

#[derive(Debug)]
enum Body {
    Envelope {
        envelope: Envelope,
        format: OutputFormat,
    },
    Raw {
        data: String,
    },
}

#[derive(Clone, Copy)]
struct CommandSpec {
    id: &'static str,
    invocation: &'static str,
    output_contract_id: &'static str,
    description: &'static str,
    read_only: bool,
    provider_network: bool,
    mutates_local_state: bool,
    sensitive_output: bool,
}

struct ErrorSpec {
    code: &'static str,
    exit_code: u8,
    description: &'static str,
    retryable: bool,
    policy_boundary: &'static str,
    safe_next_commands: &'static [&'static str],
    repair_commands: &'static [&'static str],
}

const ERROR_SPECS: &[ErrorSpec] = &[
    ErrorSpec {
        code: "FSNOW_USAGE",
        exit_code: 64,
        description: "The invocation was syntactically invalid or incomplete.",
        retryable: false,
        policy_boundary: "cli_parser",
        safe_next_commands: &["franken-snowflake capabilities --json"],
        repair_commands: &["franken-snowflake --help"],
    },
    ErrorSpec {
        code: "FSNOW_USAGE_UNKNOWN_COMMAND",
        exit_code: 64,
        description: "The top-level command is not recognized.",
        retryable: false,
        policy_boundary: "cli_parser",
        safe_next_commands: &["franken-snowflake capabilities --json"],
        repair_commands: &["franken-snowflake --help"],
    },
    ErrorSpec {
        code: "FSNOW_USAGE_UNKNOWN_FLAG",
        exit_code: 64,
        description: "A flag is not recognized by the draft CLI surface.",
        retryable: false,
        policy_boundary: "cli_parser",
        safe_next_commands: &["franken-snowflake capabilities --json"],
        repair_commands: &["franken-snowflake --help"],
    },
    ErrorSpec {
        code: "FSNOW_NOT_IMPLEMENTED",
        exit_code: 2,
        description: "The command is reserved by the public contract, but its live handler is blocked by lower-level beads.",
        retryable: true,
        policy_boundary: "implementation_phase",
        safe_next_commands: &["franken-snowflake capabilities --json"],
        repair_commands: &["franken-snowflake doctor --json"],
    },
    ErrorSpec {
        code: "FSNOW_PROFILE_STORE_UNAVAILABLE",
        exit_code: 3,
        description: "The profile registry/storage implementation is not linked yet.",
        retryable: true,
        policy_boundary: "local_cli_slice",
        safe_next_commands: &["franken-snowflake capabilities --json"],
        repair_commands: &["franken-snowflake doctor --json"],
    },
    ErrorSpec {
        code: "FSNOW_PROFILE_DOCTOR_UNAVAILABLE",
        exit_code: 3,
        description: "Profile doctor needs the profile registry and optional live transport.",
        retryable: true,
        policy_boundary: "local_cli_slice",
        safe_next_commands: &["franken-snowflake profile validate <profile> --json"],
        repair_commands: &["franken-snowflake doctor --json"],
    },
    ErrorSpec {
        code: "FSNOW_TUI_FEATURE_DISABLED",
        exit_code: 2,
        description: "The optional TUI is not enabled in the default build.",
        retryable: false,
        policy_boundary: "feature_gate",
        safe_next_commands: &["franken-snowflake capabilities --json"],
        repair_commands: &["franken-snowflake capabilities --json"],
    },
    ErrorSpec {
        code: "FSNOW_MCP_FEATURE_DISABLED",
        exit_code: 2,
        description: "The optional MCP server is not enabled in this CLI slice.",
        retryable: false,
        policy_boundary: "feature_gate",
        safe_next_commands: &["franken-snowflake capabilities --json"],
        repair_commands: &["franken-snowflake capabilities --json"],
    },
    ErrorSpec {
        code: "FSNOW_UNKNOWN_OPERATOR",
        exit_code: 64,
        description: "The requested dataset filter operator is not in the draft operator registry.",
        retryable: false,
        policy_boundary: "operator_catalog",
        safe_next_commands: &["franken-snowflake dataset describe-operator between --jsonschema"],
        repair_commands: &["franken-snowflake dataset describe-operator between --jsonschema"],
    },
    ErrorSpec {
        code: "FSNOW_SQL_MULTIPLE_STATEMENTS_REFUSED",
        exit_code: 2,
        description: "Multiple SQL statements are refused by default.",
        retryable: false,
        policy_boundary: "sql_safety",
        safe_next_commands: &[
            "franken-snowflake query plan --profile <profile> --sql \"select 1\" --json",
        ],
        repair_commands: &["franken-snowflake query plan --profile <profile> --sql <sql> --json"],
    },
    ErrorSpec {
        code: "FSNOW_SQL_NON_SELECT_REFUSED",
        exit_code: 2,
        description: "Only read-style SQL statements are accepted in the MVP.",
        retryable: false,
        policy_boundary: "sql_safety",
        safe_next_commands: &[
            "franken-snowflake query plan --profile <profile> --sql \"select 1\" --json",
        ],
        repair_commands: &["franken-snowflake query plan --profile <profile> --sql <sql> --json"],
    },
    ErrorSpec {
        code: "FSNOW_SQL_SAFETY_REFUSAL",
        exit_code: 2,
        description: "A query run request failed the local read-only safety check.",
        retryable: false,
        policy_boundary: "sql_safety",
        safe_next_commands: &[
            "franken-snowflake query plan --profile <profile> --sql <sql> --json",
        ],
        repair_commands: &["franken-snowflake query plan --profile <profile> --sql <sql> --json"],
    },
];

const COMMAND_SPECS: &[CommandSpec] = &[
    CommandSpec {
        id: "capabilities",
        invocation: "franken-snowflake capabilities --json",
        output_contract_id: "fsnow.capabilities.v1",
        description: "Return the complete machine-readable command registry.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "robot-docs.guide",
        invocation: "franken-snowflake robot-docs guide",
        output_contract_id: "fsnow.robot_docs.guide.v1",
        description: "Return an embedded agent guide for first-contact usage.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "agent-handbook",
        invocation: "franken-snowflake agent-handbook --json",
        output_contract_id: "fsnow.agent_handbook.v1",
        description: "Return envelope keys, exit codes, recovery commands, and non-goals.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "doctor",
        invocation: "franken-snowflake doctor --json",
        output_contract_id: "fsnow.doctor.v1",
        description: "Run local, non-live readiness checks.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "selftest",
        invocation: "franken-snowflake selftest --json",
        output_contract_id: "fsnow.selftest.v1",
        description: "Run no-account protocol fixtures once the testkit is linked.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "profile.validate",
        invocation: "franken-snowflake profile validate <profile> --json",
        output_contract_id: "fsnow.profile.validate.v1",
        description: "Validate profile shape and referenced environment variables without live I/O.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "profile.doctor",
        invocation: "franken-snowflake profile doctor <profile> --json",
        output_contract_id: "fsnow.profile.doctor.v1",
        description: "Inspect profile readiness; --online will later attempt a minimal live probe.",
        read_only: true,
        provider_network: true,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "catalog.scan",
        invocation: "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json",
        output_contract_id: "fsnow.catalog.scan.v1",
        description: "Discover catalog metadata through Information Schema.",
        read_only: true,
        provider_network: true,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "catalog.graph",
        invocation: "franken-snowflake catalog graph <profile> --mermaid",
        output_contract_id: "fsnow.catalog.graph.v1",
        description: "Render catalog lineage as JSON, TOON, Mermaid, or SVG.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "dataset.inspect",
        invocation: "franken-snowflake dataset inspect <dataset-id> --json",
        output_contract_id: "fsnow.dataset.inspect.v1",
        description: "Return a dataset manifest and column/operator catalogs.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "dataset.profile",
        invocation: "franken-snowflake dataset profile <dataset-id> --json",
        output_contract_id: "fsnow.dataset.profile.v1",
        description: "Plan pushed-down APPROX_* column profiling for a dataset.",
        read_only: true,
        provider_network: true,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "dataset.describe_operator",
        invocation: "franken-snowflake dataset describe-operator <operator> --jsonschema",
        output_contract_id: "fsnow.dataset.operator_schema.v1",
        description: "Return JSON Schema 2020-12 for a supported filter operator.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "query.plan",
        invocation: "franken-snowflake query plan --profile <profile> --sql <sql> --json",
        output_contract_id: "fsnow.query.plan.v1",
        description: "Validate and explain a read-only SQL plan without submitting it.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: true,
    },
    CommandSpec {
        id: "query.run",
        invocation: "franken-snowflake query run --profile <profile> --sql <sql> --json",
        output_contract_id: "fsnow.query.run.v1",
        description: "Submit a SQL API statement once the statement lifecycle lands.",
        read_only: true,
        provider_network: true,
        mutates_local_state: false,
        sensitive_output: true,
    },
    CommandSpec {
        id: "query.cancel",
        invocation: "franken-snowflake query cancel <statement-handle> --json",
        output_contract_id: "fsnow.query.cancel.v1",
        description: "Cancel a remote SQL API statement handle.",
        read_only: false,
        provider_network: true,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "receipt.show",
        invocation: "franken-snowflake receipt show <receipt-hash> --json",
        output_contract_id: "fsnow.receipt.show.v1",
        description: "Look up a content-addressed query receipt.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "export.plan",
        invocation: "franken-snowflake export plan --json",
        output_contract_id: "fsnow.export.plan.v1",
        description: "Draft COPY INTO or local CSV/JSONL export plans; execution is deferred.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: true,
    },
    CommandSpec {
        id: "tui",
        invocation: "franken-snowflake tui --profile <profile>",
        output_contract_id: "fsnow.tui.launch.v1",
        description: "Opt-in interactive TUI behind the future tui feature.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: false,
    },
    CommandSpec {
        id: "mcp.serve",
        invocation: "franken-snowflake mcp serve [--stdio | --http <addr>]",
        output_contract_id: "fsnow.mcp.serve.v1",
        description: "Feature-gated MCP server using the same handlers and envelope contract.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: false,
    },
];

fn execute(raw_args: Vec<String>) -> Outcome {
    match parse_invocation(raw_args) {
        Ok(invocation) => dispatch(invocation),
        Err(outcome) => outcome,
    }
}

fn parse_invocation(raw_args: Vec<String>) -> Result<Invocation, Outcome> {
    let (output, args) = extract_output_format(raw_args);
    let args_for_request_id = args.clone();

    validate_known_flags(output, &args)?;

    if args.is_empty() {
        return Ok(Invocation {
            args_for_request_id,
            command: Command::Help,
            output,
        });
    }

    if has_any(&args, &["--help", "-h", "help"]) {
        return Ok(Invocation {
            args_for_request_id,
            command: Command::Help,
            output,
        });
    }

    let command = match args[0].as_str() {
        "capabilities" => Command::Capabilities,
        "robot-docs" => parse_robot_docs(&args, output)?,
        "agent-handbook" => Command::AgentHandbook,
        "doctor" => Command::Doctor,
        "selftest" => Command::Selftest,
        "profile" => parse_profile(&args, output)?,
        "catalog" => parse_catalog(&args, output)?,
        "dataset" => parse_dataset(&args, output)?,
        "query" => parse_query(&args, output)?,
        "receipt" => parse_receipt(&args, output)?,
        "export" => Command::ExportPlan,
        "tui" => Command::Tui {
            profile: value_after(&args, "--profile"),
        },
        "mcp" => parse_mcp(&args, output)?,
        other => {
            let suggestions = did_you_mean(other, &top_level_commands());
            return Err(error_outcome(
                output,
                "help",
                "fsnow.help.v1",
                ExitStatus::Usage,
                "error",
                ErrorInfo {
                    code: "FSNOW_USAGE_UNKNOWN_COMMAND",
                    message: format!("Unknown command `{other}`."),
                    retryable: false,
                    policy_boundary: "cli_parser",
                    evidence: vec![json_string(format!("command={other}"))],
                },
                vec!["franken-snowflake capabilities --json".to_string()],
                vec!["franken-snowflake --help".to_string()],
                suggestions,
            ));
        }
    };

    Ok(Invocation {
        args_for_request_id,
        command,
        output,
    })
}

fn parse_robot_docs(args: &[String], output: OutputFormat) -> Result<Command, Outcome> {
    if args.get(1).map(String::as_str) == Some("guide") {
        Ok(Command::RobotDocsGuide)
    } else {
        Err(usage_error(
            output,
            "robot-docs.guide",
            "fsnow.robot_docs.guide.v1",
            "Expected `franken-snowflake robot-docs guide`.",
            vec!["franken-snowflake robot-docs guide".to_string()],
            vec![],
        ))
    }
}

fn parse_profile(args: &[String], output: OutputFormat) -> Result<Command, Outcome> {
    match args.get(1).map(String::as_str) {
        Some("validate") => match args.get(2) {
            Some(profile) => Ok(Command::ProfileValidate {
                profile: profile.clone(),
            }),
            None => Err(usage_error(
                output,
                "profile.validate",
                "fsnow.profile.validate.v1",
                "Missing profile name for `profile validate`.",
                vec!["franken-snowflake profile validate <profile> --json".to_string()],
                vec![],
            )),
        },
        Some("doctor") => match args.get(2) {
            Some(profile) => Ok(Command::ProfileDoctor {
                profile: profile.clone(),
                online: has_flag(args, "--online"),
            }),
            None => Err(usage_error(
                output,
                "profile.doctor",
                "fsnow.profile.doctor.v1",
                "Missing profile name for `profile doctor`.",
                vec!["franken-snowflake profile doctor <profile> --json".to_string()],
                vec![],
            )),
        },
        Some(other) => Err(usage_error(
            output,
            "profile",
            "fsnow.profile.v1",
            &format!("Unknown profile subcommand `{other}`."),
            vec![
                "franken-snowflake profile validate <profile> --json".to_string(),
                "franken-snowflake profile doctor <profile> --json".to_string(),
            ],
            did_you_mean(other, &["validate", "doctor"]),
        )),
        None => Err(usage_error(
            output,
            "profile",
            "fsnow.profile.v1",
            "Missing profile subcommand.",
            vec![
                "franken-snowflake profile validate <profile> --json".to_string(),
                "franken-snowflake profile doctor <profile> --json".to_string(),
            ],
            vec![],
        )),
    }
}

fn parse_catalog(args: &[String], output: OutputFormat) -> Result<Command, Outcome> {
    match args.get(1).map(String::as_str) {
        Some("scan") => match args.get(2) {
            Some(profile) => {
                let database = value_after(args, "--database");
                let schema = value_after(args, "--schema");
                if database.is_none() {
                    return Err(usage_error(
                        output,
                        "catalog.scan",
                        "fsnow.catalog.scan.v1",
                        "Missing --database for `catalog scan`.",
                        vec![
                            "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                                .to_string(),
                        ],
                        vec![],
                    ));
                }
                if schema.is_none() {
                    return Err(usage_error(
                        output,
                        "catalog.scan",
                        "fsnow.catalog.scan.v1",
                        "Missing --schema for `catalog scan`.",
                        vec![
                            "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                                .to_string(),
                        ],
                        vec![],
                    ));
                }

                Ok(Command::CatalogScan {
                    profile: profile.clone(),
                    database,
                    schema,
                })
            }
            None => Err(usage_error(
                output,
                "catalog.scan",
                "fsnow.catalog.scan.v1",
                "Missing profile for `catalog scan`.",
                vec![
                    "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                        .to_string(),
                ],
                vec![],
            )),
        },
        Some("graph") => match args.get(2) {
            Some(profile) => {
                let graph_output = if has_flag(args, "--mermaid") {
                    GraphOutput::Mermaid
                } else if has_flag(args, "--svg") {
                    GraphOutput::Svg
                } else if output == OutputFormat::Toon {
                    GraphOutput::Toon
                } else {
                    GraphOutput::Json
                };
                Ok(Command::CatalogGraph {
                    profile: profile.clone(),
                    graph_output,
                })
            }
            None => Err(usage_error(
                output,
                "catalog.graph",
                "fsnow.catalog.graph.v1",
                "Missing profile for `catalog graph`.",
                vec!["franken-snowflake catalog graph <profile> --mermaid".to_string()],
                vec![],
            )),
        },
        Some(other) => Err(usage_error(
            output,
            "catalog",
            "fsnow.catalog.v1",
            &format!("Unknown catalog subcommand `{other}`."),
            vec![
                "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                    .to_string(),
                "franken-snowflake catalog graph <profile> --mermaid".to_string(),
            ],
            did_you_mean(other, &["scan", "graph"]),
        )),
        None => Err(usage_error(
            output,
            "catalog",
            "fsnow.catalog.v1",
            "Missing catalog subcommand.",
            vec![
                "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                    .to_string(),
                "franken-snowflake catalog graph <profile> --mermaid".to_string(),
            ],
            vec![],
        )),
    }
}

fn parse_dataset(args: &[String], output: OutputFormat) -> Result<Command, Outcome> {
    match args.get(1).map(String::as_str) {
        Some("inspect") => match args.get(2) {
            Some(dataset_id) => Ok(Command::DatasetInspect {
                dataset_id: dataset_id.clone(),
            }),
            None => Err(usage_error(
                output,
                "dataset.inspect",
                "fsnow.dataset.inspect.v1",
                "Missing dataset id for `dataset inspect`.",
                vec!["franken-snowflake dataset inspect <dataset-id> --json".to_string()],
                vec![],
            )),
        },
        Some("profile") => match args.get(2) {
            Some(dataset_id) => Ok(Command::DatasetProfile {
                dataset_id: dataset_id.clone(),
            }),
            None => Err(usage_error(
                output,
                "dataset.profile",
                "fsnow.dataset.profile.v1",
                "Missing dataset id for `dataset profile`.",
                vec!["franken-snowflake dataset profile <dataset-id> --json".to_string()],
                vec![],
            )),
        },
        Some("describe-operator") => match args.get(2) {
            Some(operator) => Ok(Command::DatasetDescribeOperator {
                operator: operator.clone(),
            }),
            None => Err(usage_error(
                output,
                "dataset.describe_operator",
                "fsnow.dataset.operator_schema.v1",
                "Missing operator for `dataset describe-operator`.",
                vec![
                    "franken-snowflake dataset describe-operator between --jsonschema".to_string(),
                ],
                vec![],
            )),
        },
        Some(other) => Err(usage_error(
            output,
            "dataset",
            "fsnow.dataset.v1",
            &format!("Unknown dataset subcommand `{other}`."),
            vec![
                "franken-snowflake dataset inspect <dataset-id> --json".to_string(),
                "franken-snowflake dataset profile <dataset-id> --json".to_string(),
                "franken-snowflake dataset describe-operator between --jsonschema".to_string(),
            ],
            did_you_mean(other, &["inspect", "profile", "describe-operator"]),
        )),
        None => Err(usage_error(
            output,
            "dataset",
            "fsnow.dataset.v1",
            "Missing dataset subcommand.",
            vec![
                "franken-snowflake dataset inspect <dataset-id> --json".to_string(),
                "franken-snowflake dataset profile <dataset-id> --json".to_string(),
                "franken-snowflake dataset describe-operator between --jsonschema".to_string(),
            ],
            vec![],
        )),
    }
}

fn parse_query(args: &[String], output: OutputFormat) -> Result<Command, Outcome> {
    match args.get(1).map(String::as_str) {
        Some(value) if value.starts_with("--") && value_after(args, "--sql").is_some() => {
            Ok(Command::QueryRun {
                profile: value_after(args, "--profile"),
                sql: value_after(args, "--sql"),
            })
        }
        Some("plan") => Ok(Command::QueryPlan {
            profile: value_after(args, "--profile"),
            sql: value_after(args, "--sql"),
        }),
        Some("run") => Ok(Command::QueryRun {
            profile: value_after(args, "--profile"),
            sql: value_after(args, "--sql"),
        }),
        Some("cancel") => match args.get(2) {
            Some(statement_handle) => Ok(Command::QueryCancel {
                statement_handle: statement_handle.clone(),
            }),
            None => Err(usage_error(
                output,
                "query.cancel",
                "fsnow.query.cancel.v1",
                "Missing statement handle for `query cancel`.",
                vec!["franken-snowflake query cancel <statement-handle> --json".to_string()],
                vec![],
            )),
        },
        Some(other) => Err(usage_error(
            output,
            "query",
            "fsnow.query.v1",
            &format!("Unknown query subcommand `{other}`."),
            vec![
                "franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string(),
                "franken-snowflake query run --profile <profile> --sql <sql> --json".to_string(),
                "franken-snowflake query cancel <statement-handle> --json".to_string(),
            ],
            did_you_mean(other, &["plan", "run", "cancel"]),
        )),
        None => Err(usage_error(
            output,
            "query",
            "fsnow.query.v1",
            "Missing query subcommand.",
            vec![
                "franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string(),
                "franken-snowflake query run --profile <profile> --sql <sql> --json".to_string(),
                "franken-snowflake query cancel <statement-handle> --json".to_string(),
            ],
            vec![],
        )),
    }
}

fn parse_receipt(args: &[String], output: OutputFormat) -> Result<Command, Outcome> {
    if args.get(1).map(String::as_str) != Some("show") {
        return Err(usage_error(
            output,
            "receipt.show",
            "fsnow.receipt.show.v1",
            "Expected `franken-snowflake receipt show <receipt-hash> --json`.",
            vec!["franken-snowflake receipt show <receipt-hash> --json".to_string()],
            match args.get(1) {
                Some(value) => did_you_mean(value, &["show"]),
                None => vec![],
            },
        ));
    }

    match args.get(2) {
        Some(receipt_hash) => Ok(Command::ReceiptShow {
            receipt_hash: receipt_hash.clone(),
        }),
        None => Err(usage_error(
            output,
            "receipt.show",
            "fsnow.receipt.show.v1",
            "Missing receipt hash for `receipt show`.",
            vec!["franken-snowflake receipt show <receipt-hash> --json".to_string()],
            vec![],
        )),
    }
}

fn parse_mcp(args: &[String], output: OutputFormat) -> Result<Command, Outcome> {
    if args.get(1).map(String::as_str) != Some("serve") {
        return Err(usage_error(
            output,
            "mcp.serve",
            "fsnow.mcp.serve.v1",
            "Expected `franken-snowflake mcp serve [--stdio | --http <addr>]`.",
            vec!["franken-snowflake mcp serve --stdio".to_string()],
            match args.get(1) {
                Some(value) => did_you_mean(value, &["serve"]),
                None => vec![],
            },
        ));
    }

    let mode = if has_flag(args, "--stdio") {
        Some("stdio".to_string())
    } else {
        value_after(args, "--http").map(|addr| format!("http:{addr}"))
    };
    Ok(Command::McpServe { mode })
}

fn dispatch(invocation: Invocation) -> Outcome {
    let request_id = stable_request_id(&invocation.args_for_request_id.join("\u{1f}"));

    match invocation.command {
        Command::Help => success(
            invocation.output,
            "help",
            "fsnow.help.v1",
            request_id,
            help_data(),
            vec![],
            vec!["franken-snowflake capabilities --json".to_string()],
        ),
        Command::Capabilities => success(
            invocation.output,
            "capabilities",
            "fsnow.capabilities.v1",
            request_id,
            capabilities_data(),
            vec![],
            vec!["franken-snowflake agent-handbook --json".to_string()],
        ),
        Command::RobotDocsGuide => success(
            invocation.output,
            "robot-docs.guide",
            "fsnow.robot_docs.guide.v1",
            request_id,
            robot_docs_data(),
            vec![],
            vec!["franken-snowflake capabilities --json".to_string()],
        ),
        Command::AgentHandbook => success(
            invocation.output,
            "agent-handbook",
            "fsnow.agent_handbook.v1",
            request_id,
            agent_handbook_data(),
            vec![],
            vec!["franken-snowflake doctor --json".to_string()],
        ),
        Command::Doctor => findings(
            invocation.output,
            "doctor",
            "fsnow.doctor.v1",
            request_id,
            doctor_data(),
            vec![json_string(
                "live transport and testkit checks are pending lower-level beads",
            )],
            vec!["franken-snowflake selftest --json".to_string()],
        ),
        Command::Selftest => findings(
            invocation.output,
            "selftest",
            "fsnow.selftest.v1",
            request_id,
            selftest_data(),
            vec![json_string(
                "no-account testkit is not linked yet; protocol fixtures are pending",
            )],
            vec!["franken-snowflake doctor --json".to_string()],
        ),
        Command::ProfileValidate { profile } => {
            profile_validate_outcome(invocation.output, request_id, profile)
        }
        Command::ProfileDoctor { profile, online } => {
            profile_doctor_outcome(invocation.output, request_id, profile, online)
        }
        Command::CatalogScan {
            profile,
            database,
            schema,
        } => not_implemented_with_data(
            invocation.output,
            "catalog.scan",
            "fsnow.catalog.scan.v1",
            request_id,
            Some(profile),
            json_object(vec![
                ("requested_database", option_json(database)),
                ("requested_schema", option_json(schema)),
                (
                    "requires",
                    json_array(vec![
                        json_string("catalog crate"),
                        json_string("live SQL API transport"),
                    ]),
                ),
            ]),
            vec![
                "franken-snowflake query plan --profile <profile> --sql \"select 1\" --json"
                    .to_string(),
            ],
        ),
        Command::CatalogGraph {
            profile,
            graph_output,
        } => catalog_graph_outcome(invocation.output, request_id, profile, graph_output),
        Command::DatasetInspect { dataset_id } => not_implemented_with_data(
            invocation.output,
            "dataset.inspect",
            "fsnow.dataset.inspect.v1",
            request_id,
            None,
            json_object(vec![
                ("dataset_id", json_string(dataset_id)),
                (
                    "requires",
                    json_array(vec![json_string("dataset manifest model")]),
                ),
            ]),
            vec![
                "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                    .to_string(),
            ],
        ),
        Command::DatasetProfile { dataset_id } => not_implemented_with_data(
            invocation.output,
            "dataset.profile",
            "fsnow.dataset.profile.v1",
            request_id,
            None,
            json_object(vec![
                ("dataset_id", json_string(dataset_id)),
                (
                    "planned_sql_shape",
                    json_string("SELECT APPROX_COUNT_DISTINCT(...), COUNT_IF(...), COUNT(*) ..."),
                ),
                ("local_stats_computation", Json::Bool(false)),
            ]),
            vec!["franken-snowflake dataset inspect <dataset-id> --json".to_string()],
        ),
        Command::DatasetDescribeOperator { operator } => {
            operator_schema_outcome(invocation.output, request_id, operator)
        }
        Command::QueryPlan { profile, sql } => {
            query_plan_outcome(invocation.output, request_id, profile, sql)
        }
        Command::QueryRun { profile, sql } => {
            query_run_outcome(invocation.output, request_id, profile, sql)
        }
        Command::QueryCancel { statement_handle } => not_implemented_with_data(
            invocation.output,
            "query.cancel",
            "fsnow.query.cancel.v1",
            request_id,
            None,
            json_object(vec![
                ("statement_handle", json_string(statement_handle)),
                (
                    "requires",
                    json_array(vec![json_string("statement lifecycle cancel handler")]),
                ),
            ]),
            vec!["franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string()],
        ),
        Command::ReceiptShow { receipt_hash } => not_implemented_with_data(
            invocation.output,
            "receipt.show",
            "fsnow.receipt.show.v1",
            request_id,
            None,
            json_object(vec![
                ("receipt_hash", json_string(receipt_hash)),
                ("requires", json_array(vec![json_string("receipt store")])),
            ]),
            vec!["franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string()],
        ),
        Command::ExportPlan => not_implemented_with_data(
            invocation.output,
            "export.plan",
            "fsnow.export.plan.v1",
            request_id,
            None,
            json_object(vec![
                ("execution_enabled", Json::Bool(false)),
                (
                    "safe_alternative",
                    json_string("future `export plan --json` before any write path"),
                ),
            ]),
            vec!["franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string()],
        ),
        Command::Tui { profile } => feature_disabled(
            invocation.output,
            "tui",
            "fsnow.tui.launch.v1",
            request_id,
            profile,
            "FSNOW_TUI_FEATURE_DISABLED",
            "The TUI is default-off until its cargo-tree and cross-platform proofs land.",
            vec!["franken-snowflake capabilities --json".to_string()],
        ),
        Command::McpServe { mode } => feature_disabled(
            invocation.output,
            "mcp.serve",
            "fsnow.mcp.serve.v1",
            request_id,
            mode,
            "FSNOW_MCP_FEATURE_DISABLED",
            "The MCP server is feature-gated and not linked in this CLI slice.",
            vec!["franken-snowflake capabilities --json".to_string()],
        ),
    }
}

fn success(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    data: Json,
    warnings: Vec<Json>,
    safe_next_commands: Vec<String>,
) -> Outcome {
    let envelope = base_envelope(
        true,
        "success",
        command_id,
        output_contract_id,
        request_id,
        data,
    )
    .with_warnings(warnings)
    .with_safe_next_commands(safe_next_commands);
    Outcome {
        status: ExitStatus::Success,
        body: Body::Envelope { envelope, format },
    }
}

fn findings(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    data: Json,
    warnings: Vec<Json>,
    safe_next_commands: Vec<String>,
) -> Outcome {
    let envelope = base_envelope(
        true,
        "partial_success",
        command_id,
        output_contract_id,
        request_id,
        data,
    )
    .with_warnings(warnings)
    .with_safe_next_commands(safe_next_commands);
    Outcome {
        status: ExitStatus::Findings,
        body: Body::Envelope { envelope, format },
    }
}

fn not_implemented_with_data(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    profile_id: Option<String>,
    data: Json,
    safe_next_commands: Vec<String>,
) -> Outcome {
    let mut envelope = base_envelope(
        false,
        "refusal",
        command_id,
        output_contract_id,
        request_id,
        data,
    );
    envelope.profile_id = profile_id;
    envelope.error = Some(ErrorInfo {
        code: "FSNOW_NOT_IMPLEMENTED",
        message: "This command surface is reserved, but its live handler is blocked by lower-level beads."
            .to_string(),
        retryable: true,
        policy_boundary: "implementation_phase",
        evidence: vec![json_string("contract-first CLI skeleton")],
    });
    envelope.safe_next_commands = safe_next_commands;
    envelope.repair_commands = vec!["franken-snowflake doctor --json".to_string()];
    Outcome {
        status: ExitStatus::SafetyRefusal,
        body: Body::Envelope { envelope, format },
    }
}

fn feature_disabled(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    context: Option<String>,
    code: &'static str,
    message: &'static str,
    safe_next_commands: Vec<String>,
) -> Outcome {
    let mut envelope = base_envelope(
        false,
        "refusal",
        command_id,
        output_contract_id,
        request_id,
        json_object(vec![
            ("feature_enabled", Json::Bool(false)),
            ("context", option_json(context)),
        ]),
    );
    envelope.error = Some(ErrorInfo {
        code,
        message: message.to_string(),
        retryable: false,
        policy_boundary: "feature_gate",
        evidence: vec![json_string("default build omits this feature")],
    });
    envelope.safe_next_commands = safe_next_commands;
    envelope.repair_commands = vec!["franken-snowflake capabilities --json".to_string()];
    Outcome {
        status: ExitStatus::SafetyRefusal,
        body: Body::Envelope { envelope, format },
    }
}

fn error_outcome(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    status: ExitStatus,
    outcome_kind: &'static str,
    error: ErrorInfo,
    safe_next_commands: Vec<String>,
    repair_commands: Vec<String>,
    did_you_mean_values: Vec<String>,
) -> Outcome {
    let safe_next_commands = if safe_next_commands.is_empty() {
        default_safe_next_commands(error.code)
    } else {
        safe_next_commands
    };
    let repair_commands = if repair_commands.is_empty() {
        default_repair_commands(error.code)
    } else {
        repair_commands
    };
    let mut envelope = base_envelope(
        false,
        outcome_kind,
        command_id,
        output_contract_id,
        stable_request_id(command_id),
        json_object(vec![]),
    );
    envelope.error = Some(error);
    envelope.safe_next_commands = safe_next_commands;
    envelope.repair_commands = repair_commands;
    envelope.did_you_mean = did_you_mean_values;
    Outcome {
        status,
        body: Body::Envelope { envelope, format },
    }
}

fn usage_error(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    message: &str,
    repair_commands: Vec<String>,
    did_you_mean_values: Vec<String>,
) -> Outcome {
    error_outcome(
        format,
        command_id,
        output_contract_id,
        ExitStatus::Usage,
        "error",
        ErrorInfo {
            code: "FSNOW_USAGE",
            message: message.to_string(),
            retryable: false,
            policy_boundary: "cli_parser",
            evidence: vec![],
        },
        vec!["franken-snowflake capabilities --json".to_string()],
        repair_commands,
        did_you_mean_values,
    )
}

fn default_safe_next_commands(code: &str) -> Vec<String> {
    find_error_spec(code)
        .map(|spec| {
            spec.safe_next_commands
                .iter()
                .map(|cmd| (*cmd).to_string())
                .collect()
        })
        .unwrap_or_else(|| vec!["franken-snowflake capabilities --json".to_string()])
}

fn default_repair_commands(code: &str) -> Vec<String> {
    find_error_spec(code)
        .map(|spec| {
            spec.repair_commands
                .iter()
                .map(|cmd| (*cmd).to_string())
                .collect()
        })
        .unwrap_or_else(|| vec!["franken-snowflake doctor --json".to_string()])
}

fn find_error_spec(code: &str) -> Option<&'static ErrorSpec> {
    ERROR_SPECS.iter().find(|spec| spec.code == code)
}

impl Envelope {
    fn with_warnings(mut self, warnings: Vec<Json>) -> Self {
        self.warnings = warnings;
        self
    }

    fn with_safe_next_commands(mut self, commands: Vec<String>) -> Self {
        self.safe_next_commands = commands;
        self
    }
}

fn base_envelope(
    ok: bool,
    outcome_kind: &'static str,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    data: Json,
) -> Envelope {
    Envelope {
        ok,
        outcome_kind,
        command_id,
        output_contract_id,
        data_source: "empty",
        profile_id: None,
        request_id,
        query_id: None,
        statement_handle: None,
        receipt_hash: None,
        warnings: vec![],
        safe_next_commands: vec![],
        repair_commands: vec![],
        did_you_mean: vec![],
        budget_consumed: json_object(vec![
            ("deadline_ms", Json::Number(0)),
            ("polls", Json::Number(0)),
            ("rows", Json::Number(0)),
        ]),
        redactions_applied: vec![],
        data,
        error: None,
    }
}

fn envelope_json(envelope: &Envelope) -> Json {
    json_object(vec![
        ("ok", Json::Bool(envelope.ok)),
        ("outcome_kind", json_string(envelope.outcome_kind)),
        ("command_id", json_string(envelope.command_id)),
        (
            "output_contract_id",
            json_string(envelope.output_contract_id),
        ),
        ("schema_version", json_string(ENVELOPE_SCHEMA_VERSION)),
        ("data_source", json_string(envelope.data_source)),
        ("profile_id", option_json(envelope.profile_id.clone())),
        ("request_id", json_string(envelope.request_id.clone())),
        ("query_id", option_json(envelope.query_id.clone())),
        (
            "statement_handle",
            option_json(envelope.statement_handle.clone()),
        ),
        ("receipt_hash", option_json(envelope.receipt_hash.clone())),
        ("started_at", json_string(DEFAULT_TIME)),
        ("finished_at", json_string(DEFAULT_TIME)),
        ("duration_ms", Json::Number(0)),
        ("warnings", Json::Array(envelope.warnings.clone())),
        (
            "safe_next_commands",
            string_array(envelope.safe_next_commands.clone()),
        ),
        (
            "repair_commands",
            string_array(envelope.repair_commands.clone()),
        ),
        ("did_you_mean", string_array(envelope.did_you_mean.clone())),
        ("budget_consumed", envelope.budget_consumed.clone()),
        (
            "redactions_applied",
            string_array(envelope.redactions_applied.clone()),
        ),
        ("data", envelope.data.clone()),
        ("error", error_json(envelope.error.clone())),
    ])
}

fn error_json(error: Option<ErrorInfo>) -> Json {
    match error {
        Some(info) => json_object(vec![
            ("code", json_string(info.code)),
            ("message", json_string(info.message)),
            ("retryable", Json::Bool(info.retryable)),
            ("policy_boundary", json_string(info.policy_boundary)),
            ("evidence", Json::Array(info.evidence)),
        ]),
        None => Json::Null,
    }
}

fn write_outcome(outcome: Outcome) -> ExitCode {
    let status = outcome.status;
    match outcome.body {
        Body::Envelope { envelope, format } => {
            if !envelope.ok {
                let diagnostic = match &envelope.error {
                    Some(error) => format!("{}: {}\n", error.code, error.message),
                    None => "FSNOW_ERROR: command failed\n".to_string(),
                };
                let _ignored = write_stderr(&diagnostic);
            }
            let rendered = match format {
                OutputFormat::Json => render_json(&envelope_json(&envelope)),
                OutputFormat::Toon => render_toon(&envelope_json(&envelope)),
            };
            match write_stdout(&rendered) {
                Ok(()) => ExitCode::from(status.code()),
                Err(()) => ExitCode::from(ExitStatus::Io.code()),
            }
        }
        Body::Raw { data } => match write_stdout(&data) {
            Ok(()) => ExitCode::from(status.code()),
            Err(()) => ExitCode::from(ExitStatus::Io.code()),
        },
    }
}

fn write_stdout(data: &str) -> Result<(), ()> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(data.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .map_err(|_err| ())
}

fn write_stderr(data: &str) -> Result<(), ()> {
    let mut stderr = io::stderr().lock();
    stderr.write_all(data.as_bytes()).map_err(|_err| ())
}

fn capabilities_data() -> Json {
    json_object(vec![
        ("tool_name", json_string("franken-snowflake")),
        ("crate_name", json_string(env!("CARGO_PKG_NAME"))),
        ("version", json_string(env!("CARGO_PKG_VERSION"))),
        ("contract_version", json_string(CLI_CONTRACT_VERSION)),
        ("schema_version", json_string(ENVELOPE_SCHEMA_VERSION)),
        ("default_output", json_string("json")),
        ("alternate_outputs", string_array(vec!["toon".to_string()])),
        (
            "feature_flags",
            json_object(vec![
                ("live", Json::Bool(false)),
                ("testkit", Json::Bool(false)),
                ("mcp", Json::Bool(false)),
                ("tui", Json::Bool(false)),
                ("toon", Json::Bool(true)),
            ]),
        ),
        ("commands", Json::Array(command_registry())),
        ("exit_codes", exit_code_json()),
        ("error_registry", error_registry_json()),
        ("envelope_keys", envelope_key_json()),
        (
            "non_goals",
            string_array(vec![
                "no third-party Snowflake Rust driver".to_string(),
                "no Tokio/reqwest/hyper production dependency".to_string(),
                "no mutation without the future write-intent ladder".to_string(),
                "no live credential access in this skeleton".to_string(),
            ]),
        ),
    ])
}

fn command_registry() -> Vec<Json> {
    COMMAND_SPECS.iter().map(command_spec_json).collect()
}

fn command_spec_json(spec: &CommandSpec) -> Json {
    json_object(vec![
        ("command_id", json_string(spec.id)),
        ("invocation", json_string(spec.invocation)),
        ("description", json_string(spec.description)),
        (
            "input_schema",
            json_object(vec![
                (
                    "$schema",
                    json_string("https://json-schema.org/draft/2020-12/schema"),
                ),
                ("type", json_string("object")),
                ("additionalProperties", Json::Bool(false)),
            ]),
        ),
        ("output_contract_id", json_string(spec.output_contract_id)),
        ("error_families", string_array(error_codes())),
        (
            "examples",
            Json::Array(vec![json_object(vec![(
                "command",
                json_string(spec.invocation),
            )])]),
        ),
        (
            "safety",
            json_object(vec![
                ("mutates_local_state", Json::Bool(spec.mutates_local_state)),
                ("provider_network", Json::Bool(spec.provider_network)),
                ("read_only", Json::Bool(spec.read_only)),
                ("sensitive_output", Json::Bool(spec.sensitive_output)),
            ]),
        ),
    ])
}

fn agent_handbook_data() -> Json {
    json_object(vec![
        ("contract_version", json_string(CLI_CONTRACT_VERSION)),
        (
            "envelope_schema_version",
            json_string(ENVELOPE_SCHEMA_VERSION),
        ),
        ("first_commands", string_array(first_commands())),
        ("exit_codes", exit_code_json()),
        ("envelope_keys", envelope_key_json()),
        ("error_registry", error_registry_json()),
        (
            "error_recovery",
            json_object(vec![
                (
                    "FSNOW_USAGE",
                    json_string(
                        "Run `franken-snowflake capabilities --json` and retry with the shown invocation.",
                    ),
                ),
                (
                    "FSNOW_NOT_IMPLEMENTED",
                    json_string(
                        "Use `query plan` or `capabilities`; live handlers land in dependent beads.",
                    ),
                ),
                (
                    "FSNOW_PROFILE_STORE_UNAVAILABLE",
                    json_string(
                        "Run `franken-snowflake doctor --json`; profile registry is not linked yet.",
                    ),
                ),
            ]),
        ),
        (
            "non_goals",
            string_array(vec![
                "do not store raw secrets in profiles".to_string(),
                "do not silently use fixtures when live data is required".to_string(),
                "do not run DDL/DML without a future write-intent ladder".to_string(),
            ]),
        ),
    ])
}

fn robot_docs_data() -> Json {
    json_object(vec![
        ("title", json_string("franken-snowflake agent guide")),
        ("contract_version", json_string(CLI_CONTRACT_VERSION)),
        (
            "guide_markdown",
            json_string(
                "# franken-snowflake agent guide\n\n1. Start with `franken-snowflake capabilities --json`.\n2. Use `franken-snowflake agent-handbook --json` for envelope and exit-code details.\n3. Use `franken-snowflake query plan --profile <profile> --sql <sql> --json` before any live query.\n4. Prefer `--toon` for large payloads only after validating parity with `--json`.\n",
            ),
        ),
        ("first_commands", string_array(first_commands())),
    ])
}

fn help_data() -> Json {
    json_object(vec![
        (
            "usage",
            json_string("franken-snowflake <command> [--json|--toon]"),
        ),
        ("contract_version", json_string(CLI_CONTRACT_VERSION)),
        ("first_commands", string_array(first_commands())),
        (
            "commands",
            string_array(
                COMMAND_SPECS
                    .iter()
                    .map(|spec| spec.invocation.to_string())
                    .collect(),
            ),
        ),
    ])
}

fn doctor_data() -> Json {
    json_object(vec![
        ("status", json_string("findings")),
        (
            "checks",
            Json::Array(vec![
                check_json(
                    "cli_contract",
                    "pass",
                    "command registry and envelope renderer are linked",
                ),
                check_json(
                    "live_transport",
                    "not_checked",
                    "blocked until SQL API transport lands",
                ),
                check_json(
                    "testkit",
                    "not_checked",
                    "blocked until deterministic no-account testkit lands",
                ),
                check_json(
                    "profile_registry",
                    "not_checked",
                    "blocked until profile storage lands",
                ),
            ]),
        ),
    ])
}

fn selftest_data() -> Json {
    json_object(vec![
        ("status", json_string("not_available")),
        ("offline", Json::Bool(true)),
        (
            "fixtures",
            Json::Array(vec![
                check_json("json_envelope_contract", "pass", "renderer available"),
                check_json("sqlapi_protocol", "not_checked", "testkit bead pending"),
                check_json("secret_redaction", "not_checked", "guardrail bead pending"),
            ]),
        ),
    ])
}

fn check_json(name: &'static str, status: &'static str, detail: &'static str) -> Json {
    json_object(vec![
        ("name", json_string(name)),
        ("status", json_string(status)),
        ("detail", json_string(detail)),
    ])
}

fn check_json_owned(name: &'static str, status: &'static str, detail: String) -> Json {
    json_object(vec![
        ("name", json_string(name)),
        ("status", json_string(status)),
        ("detail", json_string(detail)),
    ])
}

fn profile_validate_outcome(format: OutputFormat, request_id: String, profile: String) -> Outcome {
    let syntax_valid = is_valid_profile_id(&profile);
    let warnings = if syntax_valid {
        vec![json_string(
            "profile registry is not linked yet; only offline profile-id and env-handle contract checks ran",
        )]
    } else {
        vec![json_string(
            "profile id contains unsupported characters for stable handles",
        )]
    };
    let status = if syntax_valid {
        "offline_validated"
    } else {
        "findings"
    };
    let mut envelope = base_envelope(
        true,
        "partial_success",
        "profile.validate",
        "fsnow.profile.validate.v1",
        request_id,
        profile_diagnostics_data(&profile, false, status),
    )
    .with_warnings(warnings)
    .with_safe_next_commands(vec![
        format!("franken-snowflake profile doctor {profile} --json"),
        format!("franken-snowflake query plan --profile {profile} --sql \"select 1\" --json"),
    ]);
    envelope.profile_id = Some(profile);
    Outcome {
        status: ExitStatus::Findings,
        body: Body::Envelope { envelope, format },
    }
}

fn profile_doctor_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    online: bool,
) -> Outcome {
    let syntax_valid = is_valid_profile_id(&profile);
    let warning = if online {
        "online profile probe requested but not attempted because live transport is not linked"
    } else {
        "profile doctor ran offline only; live transport is not linked"
    };
    let mut envelope = base_envelope(
        true,
        "partial_success",
        "profile.doctor",
        "fsnow.profile.doctor.v1",
        request_id,
        profile_diagnostics_data(
            &profile,
            online,
            if syntax_valid {
                "offline_findings"
            } else {
                "findings"
            },
        ),
    )
    .with_warnings(vec![json_string(warning)])
    .with_safe_next_commands(vec![
        format!("franken-snowflake profile validate {profile} --json"),
        "franken-snowflake doctor --json".to_string(),
    ]);
    envelope.profile_id = Some(profile);
    Outcome {
        status: ExitStatus::Findings,
        body: Body::Envelope { envelope, format },
    }
}

fn profile_diagnostics_data(profile: &str, online: bool, status: &'static str) -> Json {
    let env_prefix = profile_env_prefix(profile);
    let syntax_detail = if is_valid_profile_id(profile) {
        "profile id is a stable handle"
    } else {
        "profile id must be 1-128 ASCII letters, digits, dot, dash, or underscore"
    };

    json_object(vec![
        ("profile_id", json_string(profile)),
        ("status", json_string(status)),
        ("offline_only", Json::Bool(true)),
        ("profile_registry_linked", Json::Bool(false)),
        ("profile_config_loaded", Json::Bool(false)),
        ("live_probe_requested", Json::Bool(online)),
        ("live_probe_attempted", Json::Bool(false)),
        ("secret_values_read", Json::Bool(false)),
        (
            "redaction_policy",
            json_string("env var names only; token/private-key values are never emitted"),
        ),
        ("profile_env_prefix", json_string(env_prefix.clone())),
        (
            "supported_auth_lanes",
            string_array(vec![
                "programmatic_access_token".to_string(),
                "key_pair_jwt".to_string(),
                "oauth_bearer_token".to_string(),
            ]),
        ),
        (
            "expected_env_handles",
            Json::Array(profile_env_handle_sets(&env_prefix)),
        ),
        (
            "checks",
            Json::Array(vec![
                check_json_owned(
                    "profile_id_syntax",
                    if is_valid_profile_id(profile) {
                        "pass"
                    } else {
                        "fail"
                    },
                    syntax_detail.to_string(),
                ),
                check_json(
                    "profile_registry",
                    "not_checked",
                    "profile storage lands in a lower-level bead",
                ),
                check_json(
                    "credential_handles",
                    "not_checked",
                    "profile registry has not supplied env var names yet",
                ),
                check_json(
                    "live_probe",
                    "not_checked",
                    "live transport is not linked in this CLI slice",
                ),
            ]),
        ),
    ])
}

fn profile_env_handle_sets(env_prefix: &str) -> Vec<Json> {
    let account = format!("{env_prefix}_ACCOUNT");
    let user = format!("{env_prefix}_USER");
    vec![
        json_object(vec![
            ("auth_lane", json_string("programmatic_access_token")),
            (
                "env_vars",
                string_array(vec![
                    account.clone(),
                    user.clone(),
                    format!("{env_prefix}_PAT"),
                ]),
            ),
        ]),
        json_object(vec![
            ("auth_lane", json_string("key_pair_jwt")),
            (
                "env_vars",
                string_array(vec![
                    account.clone(),
                    user.clone(),
                    format!("{env_prefix}_PRIVATE_KEY_PEM"),
                    format!("{env_prefix}_PRIVATE_KEY_PASSPHRASE"),
                ]),
            ),
        ]),
        json_object(vec![
            ("auth_lane", json_string("oauth_bearer_token")),
            (
                "env_vars",
                string_array(vec![account, user, format!("{env_prefix}_OAUTH_BEARER")]),
            ),
        ]),
    ]
}

fn is_valid_profile_id(profile: &str) -> bool {
    !profile.is_empty()
        && profile.len() <= 128
        && profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn profile_env_prefix(profile: &str) -> String {
    let mut suffix = String::new();
    for byte in profile.bytes() {
        if byte.is_ascii_alphanumeric() {
            suffix.push(byte.to_ascii_uppercase() as char);
        } else if matches!(byte, b'.' | b'-' | b'_') {
            suffix.push('_');
        }
    }
    if suffix.is_empty() {
        "FRANKEN_SNOWFLAKE_PROFILE".to_string()
    } else {
        format!("FRANKEN_SNOWFLAKE_{suffix}")
    }
}

fn operator_schema_outcome(format: OutputFormat, request_id: String, operator: String) -> Outcome {
    let lower = operator.to_ascii_lowercase();
    let schema = match lower.as_str() {
        "between" => json_object(vec![
            (
                "$schema",
                json_string("https://json-schema.org/draft/2020-12/schema"),
            ),
            ("title", json_string("between")),
            ("type", json_string("object")),
            (
                "required",
                string_array(vec!["lower".to_string(), "upper".to_string()]),
            ),
            (
                "properties",
                json_object(vec![
                    (
                        "lower",
                        json_object(vec![(
                            "type",
                            string_array(vec!["number".to_string(), "string".to_string()]),
                        )]),
                    ),
                    (
                        "upper",
                        json_object(vec![(
                            "type",
                            string_array(vec!["number".to_string(), "string".to_string()]),
                        )]),
                    ),
                ]),
            ),
        ]),
        "equals" | "eq" => json_object(vec![
            (
                "$schema",
                json_string("https://json-schema.org/draft/2020-12/schema"),
            ),
            ("title", json_string("equals")),
            ("type", json_string("object")),
            ("required", string_array(vec!["value".to_string()])),
            (
                "properties",
                json_object(vec![("value", json_object(vec![]))]),
            ),
        ]),
        _ => {
            return error_outcome(
                format,
                "dataset.describe_operator",
                "fsnow.dataset.operator_schema.v1",
                ExitStatus::Usage,
                "error",
                ErrorInfo {
                    code: "FSNOW_UNKNOWN_OPERATOR",
                    message: format!("Unknown operator `{operator}`."),
                    retryable: false,
                    policy_boundary: "operator_catalog",
                    evidence: vec![json_string("known operators: between, equals")],
                },
                vec![
                    "franken-snowflake dataset describe-operator between --jsonschema".to_string(),
                ],
                vec![
                    "franken-snowflake dataset describe-operator between --jsonschema".to_string(),
                ],
                did_you_mean(&operator, &["between", "equals"]),
            );
        }
    };

    success(
        format,
        "dataset.describe_operator",
        "fsnow.dataset.operator_schema.v1",
        request_id,
        json_object(vec![
            ("operator", json_string(operator)),
            ("json_schema", schema),
        ]),
        vec![],
        vec!["franken-snowflake dataset inspect <dataset-id> --json".to_string()],
    )
}

fn query_plan_outcome(
    format: OutputFormat,
    request_id: String,
    profile: Option<String>,
    sql: Option<String>,
) -> Outcome {
    if profile.is_none() {
        return usage_error(
            format,
            "query.plan",
            "fsnow.query.plan.v1",
            "Missing --profile for `query plan`.",
            vec!["franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string()],
            vec![],
        );
    }

    let Some(sql_text) = sql else {
        return usage_error(
            format,
            "query.plan",
            "fsnow.query.plan.v1",
            "Missing --sql for `query plan`.",
            vec!["franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string()],
            vec![],
        );
    };

    if has_multiple_statements(&sql_text) {
        return refusal(
            format,
            "query.plan",
            "fsnow.query.plan.v1",
            request_id,
            profile,
            "FSNOW_SQL_MULTIPLE_STATEMENTS_REFUSED",
            "Multiple SQL statements are refused by default.",
            vec![
                "franken-snowflake query plan --profile <profile> --sql \"select 1\" --json"
                    .to_string(),
            ],
        );
    }

    if !is_select_like(&sql_text) {
        return refusal(
            format,
            "query.plan",
            "fsnow.query.plan.v1",
            request_id,
            profile,
            "FSNOW_SQL_NON_SELECT_REFUSED",
            "Only SELECT/WITH/SHOW/DESCRIBE/EXPLAIN-style read statements are accepted in the MVP.",
            vec![
                "franken-snowflake query plan --profile <profile> --sql \"select 1\" --json"
                    .to_string(),
            ],
        );
    }

    success(
        format,
        "query.plan",
        "fsnow.query.plan.v1",
        request_id,
        json_object(vec![
            ("profile_id", option_json(profile.clone())),
            ("statement_kind", json_string("read")),
            ("provider_network", Json::Bool(false)),
            ("will_submit", Json::Bool(false)),
            ("requires_live_transport", Json::Bool(false)),
            (
                "normalized_sql_preview",
                json_string(compact_sql(&sql_text)),
            ),
            (
                "plan_steps",
                string_array(vec![
                    "parse SQL safety class".to_string(),
                    "attach request_id as SQL API idempotency key".to_string(),
                    "submit through statement lifecycle handler when available".to_string(),
                ]),
            ),
        ]),
        vec![],
        vec!["franken-snowflake query run --profile <profile> --sql <sql> --json".to_string()],
    )
}

fn query_run_outcome(
    format: OutputFormat,
    request_id: String,
    profile: Option<String>,
    sql: Option<String>,
) -> Outcome {
    if profile.is_none() {
        return usage_error(
            format,
            "query.run",
            "fsnow.query.run.v1",
            "Missing --profile for `query run`.",
            vec!["franken-snowflake query run --profile <profile> --sql <sql> --json".to_string()],
            vec![],
        );
    }

    let Some(sql_text) = sql else {
        return usage_error(
            format,
            "query.run",
            "fsnow.query.run.v1",
            "Missing --sql for `query run`.",
            vec!["franken-snowflake query run --profile <profile> --sql <sql> --json".to_string()],
            vec![],
        );
    };

    if has_multiple_statements(&sql_text) || !is_select_like(&sql_text) {
        return refusal(
            format,
            "query.run",
            "fsnow.query.run.v1",
            request_id,
            profile,
            "FSNOW_SQL_SAFETY_REFUSAL",
            "The MVP query runner accepts one read-only statement; use `query plan` to inspect refusals.",
            vec!["franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string()],
        );
    }

    not_implemented_with_data(
        format,
        "query.run",
        "fsnow.query.run.v1",
        request_id,
        profile,
        json_object(vec![
            ("sql_accepted_by_local_safety_check", Json::Bool(true)),
            (
                "requires",
                json_array(vec![json_string(
                    "statement lifecycle submit/poll/partition handler",
                )]),
            ),
        ]),
        vec!["franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string()],
    )
}

fn refusal(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    profile_id: Option<String>,
    code: &'static str,
    message: &'static str,
    safe_next_commands: Vec<String>,
) -> Outcome {
    let mut envelope = base_envelope(
        false,
        "refusal",
        command_id,
        output_contract_id,
        request_id,
        json_object(vec![]),
    );
    envelope.profile_id = profile_id;
    envelope.error = Some(ErrorInfo {
        code,
        message: message.to_string(),
        retryable: false,
        policy_boundary: "sql_safety",
        evidence: vec![json_string("local SQL safety check")],
    });
    envelope.safe_next_commands = safe_next_commands;
    envelope.repair_commands =
        vec!["franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string()];
    Outcome {
        status: ExitStatus::SafetyRefusal,
        body: Body::Envelope { envelope, format },
    }
}

fn catalog_graph_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    graph_output: GraphOutput,
) -> Outcome {
    match graph_output {
        GraphOutput::Mermaid => Outcome {
            status: ExitStatus::Success,
            body: Body::Raw {
                data: "graph TD\n  EMPTY[\"catalog graph requires catalog scan fixtures\"]".to_string(),
            },
        },
        GraphOutput::Svg => Outcome {
            status: ExitStatus::Success,
            body: Body::Raw {
                data: "<svg xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" aria-label=\"empty catalog graph\"></svg>"
                    .to_string(),
            },
        },
        GraphOutput::Json | GraphOutput::Toon => success(
            if graph_output == GraphOutput::Toon {
                OutputFormat::Toon
            } else {
                format
            },
            "catalog.graph",
            "fsnow.catalog.graph.v1",
            request_id,
            json_object(vec![
                ("profile_id", json_string(profile)),
                ("nodes", json_array(vec![])),
                ("edges", json_array(vec![])),
                ("mermaid", json_string("graph TD\n  EMPTY[\"catalog graph requires catalog scan fixtures\"]")),
            ]),
            vec![],
            vec!["franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json".to_string()],
        ),
    }
}

fn exit_code_json() -> Json {
    Json::Array(vec![
        exit_code_entry(0, "success, including empty-but-valid results"),
        exit_code_entry(1, "completed with non-fatal findings or warnings"),
        exit_code_entry(2, "safety refusal"),
        exit_code_entry(3, "credential or profile error"),
        exit_code_entry(4, "upstream Snowflake error"),
        exit_code_entry(5, "network or retry budget exhausted"),
        exit_code_entry(6, "query still running"),
        exit_code_entry(7, "local cache or metadata error"),
        exit_code_entry(64, "usage error"),
        exit_code_entry(74, "I/O error"),
    ])
}

fn error_registry_json() -> Json {
    Json::Array(
        ERROR_SPECS
            .iter()
            .map(|spec| {
                json_object(vec![
                    ("code", json_string(spec.code)),
                    ("exit_code", Json::Number(i64::from(spec.exit_code))),
                    ("description", json_string(spec.description)),
                    ("retryable", Json::Bool(spec.retryable)),
                    ("policy_boundary", json_string(spec.policy_boundary)),
                    (
                        "safe_next_commands",
                        string_array(
                            spec.safe_next_commands
                                .iter()
                                .map(|cmd| (*cmd).to_string())
                                .collect(),
                        ),
                    ),
                    (
                        "repair_commands",
                        string_array(
                            spec.repair_commands
                                .iter()
                                .map(|cmd| (*cmd).to_string())
                                .collect(),
                        ),
                    ),
                ])
            })
            .collect(),
    )
}

fn error_codes() -> Vec<String> {
    ERROR_SPECS
        .iter()
        .map(|spec| spec.code.to_string())
        .collect()
}

fn exit_code_entry(code: i64, meaning: &'static str) -> Json {
    json_object(vec![
        ("code", Json::Number(code)),
        ("meaning", json_string(meaning)),
    ])
}

fn envelope_key_json() -> Json {
    string_array(vec![
        "ok".to_string(),
        "outcome_kind".to_string(),
        "command_id".to_string(),
        "output_contract_id".to_string(),
        "schema_version".to_string(),
        "data_source".to_string(),
        "profile_id".to_string(),
        "request_id".to_string(),
        "query_id".to_string(),
        "statement_handle".to_string(),
        "receipt_hash".to_string(),
        "started_at".to_string(),
        "finished_at".to_string(),
        "duration_ms".to_string(),
        "warnings".to_string(),
        "safe_next_commands".to_string(),
        "repair_commands".to_string(),
        "did_you_mean".to_string(),
        "budget_consumed".to_string(),
        "redactions_applied".to_string(),
        "data".to_string(),
        "error".to_string(),
    ])
}

fn first_commands() -> Vec<String> {
    vec![
        "franken-snowflake capabilities --json".to_string(),
        "franken-snowflake agent-handbook --json".to_string(),
        "franken-snowflake robot-docs guide".to_string(),
        "franken-snowflake doctor --json".to_string(),
        "franken-snowflake selftest --json".to_string(),
        "franken-snowflake profile validate <profile> --json".to_string(),
        "franken-snowflake query plan --profile <profile> --sql \"select 1\" --json".to_string(),
        "franken-snowflake dataset describe-operator between --jsonschema".to_string(),
        "franken-snowflake catalog graph <profile> --mermaid".to_string(),
        "franken-snowflake query cancel <statement-handle> --json".to_string(),
    ]
}

fn extract_output_format(raw_args: Vec<String>) -> (OutputFormat, Vec<String>) {
    let mut output = OutputFormat::Json;
    let mut filtered = Vec::new();
    for arg in raw_args {
        match arg.as_str() {
            "--json" => output = OutputFormat::Json,
            "--toon" => output = OutputFormat::Toon,
            "--no-color" => {}
            _ => filtered.push(arg),
        }
    }
    (output, filtered)
}

fn validate_known_flags(output: OutputFormat, args: &[String]) -> Result<(), Outcome> {
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }

        if !arg.starts_with('-') {
            continue;
        }

        let flag_name = arg
            .split_once('=')
            .map_or(arg.as_str(), |(name, _value)| name);
        if known_flags().iter().any(|known| known == &flag_name) {
            if flag_requires_value(flag_name) && !arg.contains('=') {
                skip_next = true;
            }
            continue;
        }

        return Err(error_outcome(
            output,
            "help",
            "fsnow.help.v1",
            ExitStatus::Usage,
            "error",
            ErrorInfo {
                code: "FSNOW_USAGE_UNKNOWN_FLAG",
                message: format!("Unknown flag `{arg}`."),
                retryable: false,
                policy_boundary: "cli_parser",
                evidence: vec![json_string(format!("flag={arg}"))],
            },
            vec!["franken-snowflake capabilities --json".to_string()],
            vec!["franken-snowflake --help".to_string()],
            did_you_mean(flag_name, &known_flags()),
        ));
    }

    Ok(())
}

fn known_flags() -> Vec<&'static str> {
    vec![
        "--as-of",
        "--confirm",
        "--database",
        "--dataset",
        "--dry-run",
        "--entity",
        "--from",
        "--help",
        "--http",
        "--json",
        "--jsonschema",
        "--limit",
        "--mermaid",
        "--no-color",
        "--online",
        "--profile",
        "--role",
        "--schema",
        "--sql",
        "--stdio",
        "--svg",
        "--to",
        "--toon",
        "--warehouse",
        "-h",
    ]
}

fn flag_requires_value(flag: &str) -> bool {
    matches!(
        flag,
        "--as-of"
            | "--confirm"
            | "--database"
            | "--dataset"
            | "--entity"
            | "--from"
            | "--http"
            | "--limit"
            | "--profile"
            | "--role"
            | "--schema"
            | "--sql"
            | "--to"
            | "--warehouse"
    )
}

fn has_any(args: &[String], needles: &[&str]) -> bool {
    args.iter()
        .any(|arg| needles.iter().any(|needle| arg == needle))
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn value_after(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair.first().map(String::as_str) == Some(flag))
        .and_then(|pair| pair.get(1).cloned())
}

fn has_multiple_statements(sql: &str) -> bool {
    let trimmed = sql.trim();
    match trimmed.strip_suffix(';') {
        Some(without_trailing) => without_trailing.contains(';'),
        None => trimmed.contains(';'),
    }
}

fn is_select_like(sql: &str) -> bool {
    let lower = sql.trim_start().to_ascii_lowercase();
    ["select", "with", "show", "describe", "desc", "explain"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

fn compact_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn top_level_commands() -> Vec<&'static str> {
    vec![
        "capabilities",
        "robot-docs",
        "agent-handbook",
        "doctor",
        "selftest",
        "profile",
        "catalog",
        "dataset",
        "query",
        "receipt",
        "export",
        "tui",
        "mcp",
    ]
}

fn did_you_mean(value: &str, candidates: &[&str]) -> Vec<String> {
    let mut matches = Vec::new();
    for candidate in candidates {
        if levenshtein(value, candidate) <= 2 {
            matches.push((*candidate).to_string());
        }
    }
    matches
}

fn levenshtein(a: &str, b: &str) -> usize {
    let b_len = b.chars().count();
    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0; b_len + 1];

    for (i, ac) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, bc) in b.chars().enumerate() {
            let substitution = if ac == bc { prev[j] } else { prev[j] + 1 };
            let insertion = curr[j] + 1;
            let deletion = prev[j + 1] + 1;
            curr[j + 1] = substitution.min(insertion).min(deletion);
        }
        prev.clone_from(&curr);
    }

    prev[b_len]
}

fn stable_request_id(seed: &str) -> String {
    let h1 = fnv1a64(seed.as_bytes(), 0xcbf29ce484222325);
    let h2 = fnv1a64(seed.as_bytes(), 0x84222325cbf29ce4);
    let hex = format!("{h1:016x}{h2:016x}");
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn fnv1a64(bytes: &[u8], seed: u64) -> u64 {
    let mut hash = seed;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn json_string(value: impl Into<String>) -> Json {
    Json::String(value.into())
}

fn json_array(values: Vec<Json>) -> Json {
    Json::Array(values)
}

fn json_object(entries: Vec<(&'static str, Json)>) -> Json {
    Json::Object(entries)
}

fn string_array(values: Vec<String>) -> Json {
    Json::Array(values.into_iter().map(Json::String).collect())
}

fn option_json(value: Option<String>) -> Json {
    match value {
        Some(value) => json_string(value),
        None => Json::Null,
    }
}

fn render_json(value: &Json) -> String {
    let mut out = String::new();
    render_json_into(value, &mut out);
    out
}

fn render_json_into(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Json::Number(value) => out.push_str(&value.to_string()),
        Json::String(value) => {
            out.push('"');
            out.push_str(&escape_json_string(value));
            out.push('"');
        }
        Json::Array(values) => {
            out.push('[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                render_json_into(item, out);
            }
            out.push(']');
        }
        Json::Object(entries) => {
            out.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&escape_json_string(key));
                out.push_str("\":");
                render_json_into(item, out);
            }
            out.push('}');
        }
    }
}

fn escape_json_string(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

fn render_toon(value: &Json) -> String {
    let mut out = String::new();
    render_toon_into(value, 0, &mut out);
    out.trim_end().to_string()
}

fn render_toon_into(value: &Json, indent: usize, out: &mut String) {
    match value {
        Json::Object(entries) => {
            for (key, item) in entries {
                push_indent(indent, out);
                out.push_str(key);
                match item {
                    Json::Object(_) | Json::Array(_) => {
                        out.push_str(":\n");
                        render_toon_into(item, indent + 2, out);
                    }
                    _ => {
                        out.push_str(": ");
                        render_toon_scalar(item, out);
                        out.push('\n');
                    }
                }
            }
        }
        Json::Array(values) => {
            for item in values {
                push_indent(indent, out);
                out.push_str("- ");
                match item {
                    Json::Object(_) | Json::Array(_) => {
                        out.push('\n');
                        render_toon_into(item, indent + 2, out);
                    }
                    _ => {
                        render_toon_scalar(item, out);
                        out.push('\n');
                    }
                }
            }
        }
        _ => {
            push_indent(indent, out);
            render_toon_scalar(value, out);
            out.push('\n');
        }
    }
}

fn render_toon_scalar(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Json::Number(value) => out.push_str(&value.to_string()),
        Json::String(value) => {
            out.push('"');
            out.push_str(&escape_json_string(value));
            out.push('"');
        }
        Json::Array(_) | Json::Object(_) => render_toon_into(value, 0, out),
    }
}

fn push_indent(indent: usize, out: &mut String) {
    for _ in 0..indent {
        out.push(' ');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope_for(args: &[&str]) -> Json {
        match execute(args.iter().map(|arg| (*arg).to_string()).collect()).body {
            Body::Envelope { envelope, .. } => envelope_json(&envelope),
            Body::Raw { data } => json_object(vec![("raw", json_string(data))]),
        }
    }

    #[test]
    fn capabilities_lists_every_required_surface() {
        let rendered = render_json(&envelope_for(&["capabilities", "--json"]));
        assert!(rendered.contains("\"command_id\":\"capabilities\""));
        assert!(rendered.contains("\"command_id\":\"query.run\""));
        assert!(rendered.contains("\"command_id\":\"mcp.serve\""));
        assert!(rendered.contains("\"alternate_outputs\":[\"toon\"]"));
        assert!(rendered.contains("\"error_registry\""));
        assert!(rendered.contains("FSNOW_USAGE_UNKNOWN_FLAG"));
    }

    #[test]
    fn query_plan_refuses_multiple_statements() {
        let outcome = execute(vec![
            "query".to_string(),
            "plan".to_string(),
            "--profile".to_string(),
            "demo".to_string(),
            "--sql".to_string(),
            "select 1; select 2".to_string(),
        ]);
        assert_eq!(outcome.status.code(), 2);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("FSNOW_SQL_MULTIPLE_STATEMENTS_REFUSED"));
    }

    #[test]
    fn toon_renderer_uses_same_envelope_keys() {
        let envelope = envelope_for(&["agent-handbook", "--toon"]);
        let rendered = render_toon(&envelope);
        assert!(rendered.contains("ok: true"));
        assert!(rendered.contains("output_contract_id: \"fsnow.agent_handbook.v1\""));
        assert!(rendered.contains("exit_codes:"));
        assert!(rendered.contains("error_registry:"));
    }

    #[test]
    fn did_you_mean_catches_near_miss() {
        let suggestions = did_you_mean("capabilties", &["capabilities", "catalog"]);
        assert_eq!(suggestions, vec!["capabilities".to_string()]);
    }

    #[test]
    fn unknown_flag_teaches_json_typo() {
        let outcome = execute(vec!["capabilities".to_string(), "--jsno".to_string()]);
        assert_eq!(outcome.status.code(), 64);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("FSNOW_USAGE_UNKNOWN_FLAG"));
        assert!(rendered.contains("--json"));
    }

    #[test]
    fn parse_errors_keep_requested_toon_format() {
        let outcome = execute(vec![
            "profile".to_string(),
            "validate".to_string(),
            "--toon".to_string(),
        ]);
        let is_toon = match outcome.body {
            Body::Envelope { format, .. } => format == OutputFormat::Toon,
            Body::Raw { .. } => false,
        };
        assert!(is_toon);
    }

    #[test]
    fn query_shorthand_maps_to_run_surface() {
        let outcome = execute(vec![
            "query".to_string(),
            "--profile".to_string(),
            "demo".to_string(),
            "--sql".to_string(),
            "select 1".to_string(),
        ]);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("\"command_id\":\"query.run\""));
        assert!(rendered.contains("sql_accepted_by_local_safety_check"));
    }

    #[test]
    fn query_plan_requires_profile() {
        let outcome = execute(vec![
            "query".to_string(),
            "plan".to_string(),
            "--sql".to_string(),
            "select 1".to_string(),
        ]);
        assert_eq!(outcome.status.code(), 64);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("Missing --profile for `query plan`."));
        assert!(rendered.contains("franken-snowflake query plan --profile"));
    }

    #[test]
    fn catalog_scan_requires_database_and_schema() {
        let outcome = execute(vec![
            "catalog".to_string(),
            "scan".to_string(),
            "demo".to_string(),
            "--database".to_string(),
            "ANALYTICS".to_string(),
        ]);
        assert_eq!(outcome.status.code(), 64);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("Missing --schema for `catalog scan`."));
        assert!(
            rendered.contains("catalog scan &lt;profile&gt;")
                || rendered.contains("catalog scan <profile>")
        );
    }

    #[test]
    fn profile_validate_is_offline_and_secret_safe() {
        let outcome = execute(vec![
            "profile".to_string(),
            "validate".to_string(),
            "demo-prod".to_string(),
        ]);
        assert_eq!(outcome.status.code(), 1);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("\"command_id\":\"profile.validate\""));
        assert!(rendered.contains("\"profile_registry_linked\":false"));
        assert!(rendered.contains("\"secret_values_read\":false"));
        assert!(rendered.contains("FRANKEN_SNOWFLAKE_DEMO_PROD_PAT"));
    }

    #[test]
    fn profile_doctor_online_never_attempts_live_probe_in_mvp() {
        let outcome = execute(vec![
            "profile".to_string(),
            "doctor".to_string(),
            "demo".to_string(),
            "--online".to_string(),
        ]);
        assert_eq!(outcome.status.code(), 1);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("\"command_id\":\"profile.doctor\""));
        assert!(rendered.contains("\"live_probe_requested\":true"));
        assert!(rendered.contains("\"live_probe_attempted\":false"));
        assert!(rendered.contains("FRANKEN_SNOWFLAKE_DEMO_OAUTH_BEARER"));
    }

    #[test]
    fn operator_schema_uses_json_schema_type_array() {
        let rendered = render_json(&envelope_for(&["dataset", "describe-operator", "between"]));
        assert!(rendered.contains("\"type\":[\"number\",\"string\"]"));
    }

    #[test]
    fn error_registry_entries_have_default_recovery() {
        for spec in ERROR_SPECS {
            assert!(!spec.safe_next_commands.is_empty());
            assert!(!spec.repair_commands.is_empty());
        }
    }

    #[test]
    fn json_string_escape_is_deterministic() {
        assert_eq!(
            escape_json_string("a\"b\\c\n"),
            "a\\\"b\\\\c\\n".to_string()
        );
    }
}
