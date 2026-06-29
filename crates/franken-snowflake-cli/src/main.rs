//! `franken-snowflake` — the agent-ergonomic CLI binary.
//!
//! This crate owns the public command contract described in
//! `docs/agent_cli_contract.md`. Read commands (`query run`, `catalog scan`,
//! `profile doctor --online`) drive the real Snowflake SQL API under the `live`
//! feature; mutations run through `query write`, which executes directly once a
//! profile sets `WRITE_ENABLED` (`--dry-run` stays available as an optional
//! preview, and the dry-run/confirm ceremony becomes mandatory only when a
//! profile opts in with `WRITE_REQUIRE_CONFIRM`). The
//! deterministic envelope, error-code registry, and `--json`/`--toon` output
//! switch give every surface one stable shape.

// The CLI returns its rich `Outcome`/`Envelope` (a full response body) by value
// as the command-dispatch currency rather than boxing it: `result_large_err`
// (handlers returning `Result<_, Outcome>`) and `large_enum_variant` (the `Body`
// enum, constructed/matched at 30+ sites) are size/shape style lints on that
// deliberate design, not correctness issues.
#![allow(clippy::result_large_err, clippy::large_enum_variant)]

use franken_snowflake_core::error::SnowflakeErrorCode;
use franken_snowflake_core::exit::ExitCode as CoreExitCode;
use franken_snowflake_core::ids::RequestId;
use franken_snowflake_core::redact::redact;
use franken_snowflake_core::write_intent::{
    ConfirmationToken, StatementAllowlistEntry, WriteIntentDecision, WriteIntentMode,
    WriteIntentPlan, WriteIntentPolicy, WriteIntentRefusal, WriteIntentRefusalCode,
    WriteIntentRequest, WriteSafetyClass, WriteStatementKind, classify_write_statement,
    evaluate_write_intent,
};

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

const ENVELOPE_SCHEMA_VERSION: &str = "fsnow.envelope.v1";
const CLI_CONTRACT_VERSION: &str = "fsnow.cli.contract.v1";
const DEFAULT_TIME: &str = "1970-01-01T00:00:00Z";
const CLI_REDACTION_MARKER: &str = "core.redact";

fn main() -> ExitCode {
    write_outcome(execute(env::args().skip(1).collect()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFormat {
    Json,
    Toon,
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
    Onboard,
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
        database: Option<String>,
        schema: Option<String>,
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
    QueryWrite {
        profile: Option<String>,
        sql: Option<String>,
        dry_run: bool,
        confirm: Option<String>,
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
    code: SnowflakeErrorCode,
    message: String,
    retryable: bool,
    policy_boundary: bool,
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
    status: CoreExitCode,
    body: Body,
}

#[derive(Debug)]
enum Body {
    Envelope {
        envelope: Envelope,
        format: OutputFormat,
    },
    // Only constructed by the live `catalog graph` Mermaid/SVG renderers. Without
    // the `live` feature the no-account build never produces raw output (it
    // refuses with a JSON envelope), so the variant is legitimately unused there.
    #[cfg_attr(not(feature = "live"), allow(dead_code))]
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

const COMMAND_SPECS: &[CommandSpec] = &[
    CommandSpec {
        id: "onboard",
        invocation: "franken-snowflake onboard --json",
        output_contract_id: "fsnow.onboard.v1",
        description: "Mega-command: capabilities + exit codes + first commands + health in one call.",
        read_only: true,
        provider_network: false,
        mutates_local_state: false,
        sensitive_output: false,
    },
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
        invocation: "franken-snowflake catalog graph <profile> --database <db> --mermaid",
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
        invocation: "franken-snowflake query [run] --profile <profile> --sql <sql> --json",
        output_contract_id: "fsnow.query.run.v1",
        description: "Submit a SQL API statement; `query --sql` shorthand maps to this surface.",
        read_only: true,
        provider_network: true,
        mutates_local_state: false,
        sensitive_output: true,
    },
    CommandSpec {
        id: "query.write",
        invocation: "franken-snowflake query write --profile <profile> --sql <sql> [--dry-run | --confirm <token>] --json",
        output_contract_id: "fsnow.query.write.v1",
        description: "Execute a mutation. Once the profile sets WRITE_ENABLED, a bare `query write` runs DML/COPY INTO/PUT directly and returns the live receipt; --dry-run previews and emits a confirmation token; --confirm <token> executes a previewed write. Set WRITE_REQUIRE_CONFIRM=true to require the dry-run/confirm ceremony; DDL needs WRITE_ALLOW_DDL.",
        read_only: false,
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
    let outcome = match parse_invocation(raw_args) {
        Ok(invocation) => dispatch(invocation),
        Err(outcome) => outcome,
    };
    sanitize_outcome(outcome)
}

fn parse_invocation(raw_args: Vec<String>) -> Result<Invocation, Outcome> {
    let request_id = stable_request_id(&raw_args.join("\u{1f}"));
    let (output, explicit_json, args) = extract_output_format(raw_args);
    let args_for_request_id = args.clone();

    if output == OutputFormat::Toon && !toon_output_available() {
        return Err(toon_feature_disabled(request_id));
    }

    validate_known_flags(output, &args)?;

    if args.is_empty() {
        return Ok(Invocation {
            args_for_request_id,
            command: Command::Help,
            output,
        });
    }

    if has_any(&args, &["--help", "-h"]) || args.first().is_some_and(|arg| arg == "help") {
        return Ok(Invocation {
            args_for_request_id,
            command: Command::Help,
            output,
        });
    }

    let command = match args[0].as_str() {
        "onboard" => Command::Onboard,
        "capabilities" => Command::Capabilities,
        "robot-docs" => parse_robot_docs(&args, output)?,
        "agent-handbook" => Command::AgentHandbook,
        "doctor" => Command::Doctor,
        "selftest" => Command::Selftest,
        "profile" => parse_profile(&args, output)?,
        "catalog" => parse_catalog(&args, output, explicit_json)?,
        "dataset" => parse_dataset(&args, output)?,
        "query" => parse_query(&args, output)?,
        // Top-level `write` alias for `query write` — same dispatch style as the
        // `query --sql` shorthand maps to `query run`.
        "write" => Command::QueryWrite {
            profile: resolve_profile(value_after(&args, "--profile")),
            sql: raw_value_after(&args, "--sql"),
            dry_run: has_flag(&args, "--dry-run"),
            confirm: value_after(&args, "--confirm"),
        },
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
                CoreExitCode::Usage,
                "error",
                error_info(
                    SnowflakeErrorCode::UnknownCommand,
                    format!("Unknown command `{other}`."),
                    vec![json_string(format!("command={other}"))],
                ),
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
        Some("validate") => match resolve_profile(positional_profile(args)) {
            Some(profile) => Ok(Command::ProfileValidate { profile }),
            None => Err(usage_error(
                output,
                "profile.validate",
                "fsnow.profile.validate.v1",
                "Missing profile for `profile validate`. Pass <profile> or set FRANKEN_SNOWFLAKE_DEFAULT_PROFILE.",
                vec!["franken-snowflake profile validate <profile> --json".to_string()],
                vec![],
            )),
        },
        Some("doctor") => match resolve_profile(positional_profile(args)) {
            Some(profile) => Ok(Command::ProfileDoctor {
                profile,
                online: has_flag(args, "--online"),
            }),
            None => Err(usage_error(
                output,
                "profile.doctor",
                "fsnow.profile.doctor.v1",
                "Missing profile for `profile doctor`. Pass <profile> or set FRANKEN_SNOWFLAKE_DEFAULT_PROFILE.",
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

fn parse_catalog(
    args: &[String],
    output: OutputFormat,
    explicit_json: bool,
) -> Result<Command, Outcome> {
    match args.get(1).map(String::as_str) {
        Some("scan") => match resolve_profile(positional_profile(args)) {
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
                    profile,
                    database,
                    schema,
                })
            }
            None => Err(usage_error(
                output,
                "catalog.scan",
                "fsnow.catalog.scan.v1",
                "Missing profile for `catalog scan`. Pass <profile> or set FRANKEN_SNOWFLAKE_DEFAULT_PROFILE.",
                vec![
                    "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                        .to_string(),
                ],
                vec![],
            )),
        },
        Some("graph") => match resolve_profile(positional_profile(args)) {
            Some(profile) => {
                let wants_mermaid = has_flag(args, "--mermaid");
                let wants_svg = has_flag(args, "--svg");
                let raw_output_count =
                    (if wants_mermaid { 1 } else { 0 }) + (if wants_svg { 1 } else { 0 });
                if raw_output_count > 1
                    || (explicit_json && raw_output_count > 0)
                    || (output == OutputFormat::Toon && raw_output_count > 0)
                {
                    return Err(usage_error(
                        output,
                        "catalog.graph",
                        "fsnow.catalog.graph.v1",
                        "Conflicting catalog graph output formats; choose exactly one of --json, --toon, --mermaid, or --svg.",
                        vec![
                            "franken-snowflake catalog graph <profile> --json".to_string(),
                            "franken-snowflake catalog graph <profile> --toon".to_string(),
                            "franken-snowflake catalog graph <profile> --mermaid".to_string(),
                            "franken-snowflake catalog graph <profile> --svg".to_string(),
                        ],
                        vec![],
                    ));
                }
                let graph_output = if wants_mermaid {
                    GraphOutput::Mermaid
                } else if wants_svg {
                    GraphOutput::Svg
                } else if output == OutputFormat::Toon {
                    GraphOutput::Toon
                } else {
                    GraphOutput::Json
                };
                Ok(Command::CatalogGraph {
                    profile,
                    database: value_after(args, "--database"),
                    schema: value_after(args, "--schema"),
                    graph_output,
                })
            }
            None => Err(usage_error(
                output,
                "catalog.graph",
                "fsnow.catalog.graph.v1",
                "Missing profile for `catalog graph`. Pass <profile> or set FRANKEN_SNOWFLAKE_DEFAULT_PROFILE.",
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
        // Guard with `raw_value_after` to match the `raw_value_after` extraction
        // below: a `--sql` whose value legitimately starts with `-` (e.g. SQL
        // opening with a `--` line comment) must still route through the shorthand,
        // exactly as `query run --sql ...` / `query plan --sql ...` already do.
        // Using `value_after` (which rejects flag-like values) here made such SQL
        // fall through to the "unknown query subcommand `--sql`" error.
        Some(value) if value.starts_with("--") && raw_value_after(args, "--sql").is_some() => {
            Ok(Command::QueryRun {
                profile: resolve_profile(value_after(args, "--profile")),
                sql: raw_value_after(args, "--sql"),
            })
        }
        Some("plan") => Ok(Command::QueryPlan {
            profile: resolve_profile(value_after(args, "--profile")),
            sql: raw_value_after(args, "--sql"),
        }),
        Some("run") => Ok(Command::QueryRun {
            profile: resolve_profile(value_after(args, "--profile")),
            sql: raw_value_after(args, "--sql"),
        }),
        Some("write") => Ok(Command::QueryWrite {
            profile: resolve_profile(value_after(args, "--profile")),
            sql: raw_value_after(args, "--sql"),
            dry_run: has_flag(args, "--dry-run"),
            confirm: value_after(args, "--confirm"),
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
                "franken-snowflake query write --profile <profile> --sql <sql> --json"
                    .to_string(),
                "franken-snowflake query cancel <statement-handle> --json".to_string(),
            ],
            did_you_mean(other, &["plan", "run", "write", "cancel"]),
        )),
        None => Err(usage_error(
            output,
            "query",
            "fsnow.query.v1",
            "Missing query subcommand.",
            vec![
                "franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string(),
                "franken-snowflake query run --profile <profile> --sql <sql> --json".to_string(),
                "franken-snowflake query write --profile <profile> --sql <sql> --json"
                    .to_string(),
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

    let wants_stdio = has_flag(args, "--stdio");
    let http_present = flag_present(args, "--http");
    let http_addr = value_after(args, "--http");

    if wants_stdio && http_present {
        return Err(usage_error(
            output,
            "mcp.serve",
            "fsnow.mcp.serve.v1",
            "Conflicting MCP serve modes; choose exactly one of --stdio or --http <addr>.",
            vec![
                "franken-snowflake mcp serve --stdio".to_string(),
                "franken-snowflake mcp serve --http 127.0.0.1:3000".to_string(),
            ],
            vec![],
        ));
    }

    if http_present && http_addr.is_none() {
        return Err(usage_error(
            output,
            "mcp.serve",
            "fsnow.mcp.serve.v1",
            "Missing address for `mcp serve --http`.",
            vec!["franken-snowflake mcp serve --http 127.0.0.1:3000".to_string()],
            vec![],
        ));
    }

    let mode = if wants_stdio {
        Some("stdio".to_string())
    } else {
        http_addr.map(|addr| format!("http:{addr}"))
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
        Command::Onboard => success(
            invocation.output,
            "onboard",
            "fsnow.onboard.v1",
            request_id,
            onboard_data(),
            vec![],
            vec![
                "franken-snowflake capabilities --json".to_string(),
                "franken-snowflake profile validate <profile> --json".to_string(),
            ],
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
        Command::Doctor => readiness_outcome(
            invocation.output,
            "doctor",
            "fsnow.doctor.v1",
            request_id,
            doctor_data(),
            vec!["franken-snowflake selftest --json".to_string()],
        ),
        Command::Selftest => readiness_outcome(
            invocation.output,
            "selftest",
            "fsnow.selftest.v1",
            request_id,
            selftest_data(),
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
        } => catalog_scan_dispatch(invocation.output, request_id, profile, database, schema),
        Command::CatalogGraph {
            profile,
            database,
            schema,
            graph_output,
        } => catalog_graph_outcome(
            invocation.output,
            request_id,
            profile,
            database,
            schema,
            graph_output,
        ),
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
        Command::QueryWrite {
            profile,
            sql,
            dry_run,
            confirm,
        } => query_write_outcome(invocation.output, request_id, profile, sql, dry_run, confirm),
        Command::QueryCancel { statement_handle } => live_transport_required_with_data(
            invocation.output,
            "query.cancel",
            "fsnow.query.cancel.v1",
            request_id,
            None,
            json_object(vec![
                ("statement_handle", json_string(statement_handle)),
                (
                    "requires",
                    json_array(vec![
                        json_string("live SQL API transport"),
                        json_string("profile credential handles"),
                    ]),
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
            SnowflakeErrorCode::UsageError,
            "The TUI is default-off until its cargo-tree and cross-platform proofs land.",
            vec!["franken-snowflake capabilities --json".to_string()],
        ),
        Command::McpServe { mode } => {
            #[cfg(feature = "mcp")]
            {
                run_mcp_serve_process(mode)
            }
            #[cfg(not(feature = "mcp"))]
            {
                feature_disabled(
                    invocation.output,
                    "mcp.serve",
                    "fsnow.mcp.serve.v1",
                    request_id,
                    mode,
                    SnowflakeErrorCode::UsageError,
                    "The MCP server is feature-gated and not linked in this CLI slice.",
                    vec!["franken-snowflake capabilities --json".to_string()],
                )
            }
        }
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
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

/// A successful envelope that also carries the top-level `profile_id`.
///
/// The envelope contract (`docs/agent_cli_contract.md`) defines `profile_id` as
/// "Profile used", so any command that ran against a profile must populate it —
/// not only the refusal/error paths. Commands like `query plan` and `catalog
/// graph` previously surfaced the profile only inside `data` on success, leaving
/// the top-level field `null` exactly when the command succeeded (while their
/// refusal paths set it), so an agent keyed on `profile_id` lost it on success.
#[allow(clippy::too_many_arguments)]
fn success_with_profile(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    profile_id: Option<String>,
    data: Json,
    warnings: Vec<Json>,
    safe_next_commands: Vec<String>,
) -> Outcome {
    let mut outcome = success(
        format,
        command_id,
        output_contract_id,
        request_id,
        data,
        warnings,
        safe_next_commands,
    );
    if let Body::Envelope { envelope, .. } = &mut outcome.body {
        envelope.profile_id = profile_id;
    }
    outcome
}

// True when any check object in `items` reports an actual problem (`fail`/`warn`).
// A `pass` or `not_checked` status (a feature pending lower-level beads) is not a
// failure — so a health gate doesn't trip on it.
fn checks_have_failure(items: &[Json]) -> bool {
    items.iter().any(|item| {
        let Json::Object(fields) = item else {
            return false;
        };
        fields.iter().any(|(field_key, field_value)| {
            *field_key == "status"
                && matches!(field_value, Json::String(status) if status == "fail" || status == "warn")
        })
    })
}

// True when a readiness payload reports any failing check. Doctor lists checks
// under `checks`; selftest lists them under `fixtures` — both are inspected so a
// failure in either is detected (an earlier version only looked at `checks`,
// silently ignoring selftest fixture failures).
fn data_has_failed_check(data: &Json) -> bool {
    let Json::Object(entries) = data else {
        return false;
    };
    entries.iter().any(|(key, value)| {
        (*key == "checks" || *key == "fixtures")
            && matches!(value, Json::Array(items) if checks_have_failure(items))
    })
}

// A data-level `status` consistent with the readiness exit: `ok` when every check
// passed (or is pending), `findings` when one failed.
fn readiness_status(items: &[Json]) -> &'static str {
    if checks_have_failure(items) {
        "findings"
    } else {
        "ok"
    }
}

// `doctor`/`selftest` exit 0 when every local readiness check passed, so an agent
// can use them as a clean health gate (`fsnow doctor --json && proceed`). Only an
// actual fail/warn check yields exit 1; `not_checked` (pending features) stays
// informational in `data.checks`, never an exit-affecting warning.
fn readiness_outcome(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    data: Json,
    safe_next_commands: Vec<String>,
) -> Outcome {
    if data_has_failed_check(&data) {
        findings(
            format,
            command_id,
            output_contract_id,
            request_id,
            data,
            vec![json_string(
                "one or more local readiness checks reported a problem",
            )],
            safe_next_commands,
        )
    } else {
        success(
            format,
            command_id,
            output_contract_id,
            request_id,
            data,
            vec![],
            safe_next_commands,
        )
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
        status: CoreExitCode::Findings,
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
    envelope.error = Some(error_info(
        SnowflakeErrorCode::SurfaceReserved,
        "This command surface is reserved, but its live handler is blocked by lower-level beads.",
        vec![json_string("contract-first CLI skeleton")],
    ));
    envelope.safe_next_commands = safe_next_commands;
    envelope.repair_commands = vec!["franken-snowflake doctor --json".to_string()];
    // A reserved-but-unimplemented surface is a deliberate refusal (exit 2),
    // not an I/O fault (74) — the previous `Internal` mapping read as a real
    // failure to an agent. The error code (FSNOW-9002) and exit code now agree.
    Outcome {
        status: SnowflakeErrorCode::SurfaceReserved.exit_code(),
        body: Body::Envelope { envelope, format },
    }
}

fn live_transport_required_with_data(
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
    envelope.error = Some(error_info(
        SnowflakeErrorCode::RequireLiveRefused,
        "This command requires live SQL API transport and profile credential handles; the CLI did not substitute fixture or empty data.",
        vec![json_string("live transport boundary")],
    ));
    envelope.safe_next_commands = safe_next_commands;
    envelope.repair_commands = vec![
        "franken-snowflake profile validate <profile> --json".to_string(),
        "franken-snowflake profile doctor <profile> --json".to_string(),
    ];
    Outcome {
        status: SnowflakeErrorCode::RequireLiveRefused.exit_code(),
        body: Body::Envelope { envelope, format },
    }
}

#[allow(clippy::too_many_arguments)]
fn feature_disabled(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    context: Option<String>,
    code: SnowflakeErrorCode,
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
    envelope.error = Some(error_info(
        code,
        message,
        vec![json_string("this build omits this feature")],
    ));
    envelope.safe_next_commands = safe_next_commands;
    envelope.repair_commands = vec!["franken-snowflake capabilities --json".to_string()];
    Outcome {
        status: code.exit_code(),
        body: Body::Envelope { envelope, format },
    }
}

fn toon_feature_disabled(request_id: String) -> Outcome {
    feature_disabled(
        OutputFormat::Json,
        "help",
        "fsnow.help.v1",
        request_id,
        Some("toon".to_string()),
        SnowflakeErrorCode::UsageError,
        "TOON output is feature-gated and not linked in this CLI build; retry with --json or rebuild with the `toon` feature.",
        vec!["franken-snowflake capabilities --json".to_string()],
    )
}

#[allow(clippy::too_many_arguments)]
fn error_outcome(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    status: CoreExitCode,
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
        CoreExitCode::Usage,
        "error",
        error_info(SnowflakeErrorCode::UsageError, message, vec![]),
        vec!["franken-snowflake capabilities --json".to_string()],
        repair_commands,
        did_you_mean_values,
    )
}

fn error_info(
    code: SnowflakeErrorCode,
    message: impl Into<String>,
    evidence: Vec<Json>,
) -> ErrorInfo {
    ErrorInfo {
        code,
        message: message.into(),
        retryable: code.retryable(),
        policy_boundary: code.policy_boundary(),
        evidence,
    }
}

fn default_safe_next_commands(code: SnowflakeErrorCode) -> Vec<String> {
    code.entry()
        .safe_next_commands
        .iter()
        .map(|cmd| (*cmd).to_string())
        .collect()
}

fn default_repair_commands(code: SnowflakeErrorCode) -> Vec<String> {
    code.entry()
        .repair_commands
        .iter()
        .map(|cmd| (*cmd).to_string())
        .collect()
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

fn sanitize_outcome(mut outcome: Outcome) -> Outcome {
    match &mut outcome.body {
        Body::Envelope { envelope, .. } => sanitize_envelope(envelope),
        Body::Raw { data } => {
            let redacted = redact(data).into_owned();
            if redacted != *data {
                *data = redacted;
            }
        }
    }
    outcome
}

fn sanitize_envelope(envelope: &mut Envelope) {
    let mut changed = false;
    changed |= redact_option_string(&mut envelope.profile_id);
    changed |= redact_option_string(&mut envelope.query_id);
    changed |= redact_option_string(&mut envelope.statement_handle);
    changed |= redact_option_string(&mut envelope.receipt_hash);
    changed |= redact_string(&mut envelope.request_id);
    changed |= redact_string_vec(&mut envelope.safe_next_commands);
    changed |= redact_string_vec(&mut envelope.repair_commands);
    changed |= redact_string_vec(&mut envelope.did_you_mean);
    changed |= redact_json_values(&mut envelope.warnings);
    changed |= redact_json_value(&mut envelope.budget_consumed);
    changed |= redact_json_value(&mut envelope.data);
    if let Some(error) = &mut envelope.error {
        changed |= redact_string(&mut error.message);
        changed |= redact_json_values(&mut error.evidence);
    }

    if changed
        && !envelope
            .redactions_applied
            .iter()
            .any(|marker| marker == CLI_REDACTION_MARKER)
    {
        envelope
            .redactions_applied
            .push(CLI_REDACTION_MARKER.to_string());
    }
}

fn redact_option_string(value: &mut Option<String>) -> bool {
    match value {
        Some(value) => redact_string(value),
        None => false,
    }
}

fn redact_string_vec(values: &mut [String]) -> bool {
    let mut changed = false;
    for value in values {
        changed |= redact_string(value);
    }
    changed
}

fn redact_json_values(values: &mut [Json]) -> bool {
    let mut changed = false;
    for value in values {
        changed |= redact_json_value(value);
    }
    changed
}

fn redact_json_value(value: &mut Json) -> bool {
    match value {
        Json::Null | Json::Bool(_) | Json::Number(_) => false,
        Json::String(value) => redact_string(value),
        Json::Array(values) => {
            let mut changed = false;
            for value in values {
                changed |= redact_json_value(value);
            }
            changed
        }
        Json::Object(entries) => {
            let mut changed = false;
            for (_key, value) in entries {
                changed |= redact_json_value(value);
            }
            changed
        }
    }
}

fn redact_string(value: &mut String) -> bool {
    let redacted = redact(value).into_owned();
    if redacted == *value {
        false
    } else {
        *value = redacted;
        true
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
            ("code", json_string(info.code.stable_code())),
            ("message", json_string(info.message)),
            ("retryable", Json::Bool(info.retryable)),
            ("policy_boundary", Json::Bool(info.policy_boundary)),
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
                    Some(error) => format!("{}: {}\n", error.code.stable_code(), error.message),
                    None => format!(
                        "{}: command failed\n",
                        SnowflakeErrorCode::Internal.stable_code()
                    ),
                };
                let _ignored = write_stderr(&diagnostic);
            }
            let rendered = render_envelope(&envelope, format);
            match write_stdout(&rendered) {
                Ok(()) => process_exit_code(status),
                Err(()) => process_exit_code(CoreExitCode::Io),
            }
        }
        Body::Raw { data } => match write_stdout(&data) {
            Ok(()) => process_exit_code(status),
            Err(()) => process_exit_code(CoreExitCode::Io),
        },
    }
}

fn process_exit_code(status: CoreExitCode) -> ExitCode {
    ExitCode::from(status.code() as u8)
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

// `onboard` is the mega-command (Σ): a single call that collapses what would
// otherwise be four round-trips (capabilities + agent-handbook + doctor + the
// first-commands list) into one envelope, so a cold agent can orient in one
// tool-call. It reuses the same data builders the individual surfaces emit, so
// it can never drift from them.
fn onboard_data() -> Json {
    let commands_brief: Vec<Json> = COMMAND_SPECS
        .iter()
        .map(|spec| {
            json_object(vec![
                ("command_id", json_string(spec.id)),
                ("invocation", json_string(spec.invocation)),
                ("read_only", Json::Bool(spec.read_only)),
            ])
        })
        .collect();
    json_object(vec![
        ("tool_name", json_string("franken-snowflake")),
        ("binary_aliases", string_array(vec!["fsnow".to_string()])),
        ("version", json_string(env!("CARGO_PKG_VERSION"))),
        ("contract_version", json_string(CLI_CONTRACT_VERSION)),
        ("schema_version", json_string(ENVELOPE_SCHEMA_VERSION)),
        ("default_output", json_string("json")),
        ("alternate_outputs", string_array(alternate_outputs())),
        ("feature_flags", feature_flags_json()),
        ("exit_codes", exit_code_json()),
        ("first_commands", string_array(first_commands())),
        ("commands", Json::Array(commands_brief)),
        ("environment", environment_docs()),
        ("health", doctor_data()),
        (
            "getting_started",
            string_array(vec![
                "0. export FRANKEN_SNOWFLAKE_DEFAULT_PROFILE=<profile>  (optional; makes --profile optional on every command)"
                    .to_string(),
                "1. franken-snowflake capabilities --json  (full machine-readable contract)"
                    .to_string(),
                "2. franken-snowflake profile validate <profile> --json  (check a profile's env handles)"
                    .to_string(),
                "3. franken-snowflake query plan --profile <profile> --sql \"select 1\" --json  (dry-run a read)"
                    .to_string(),
                "4. franken-snowflake query run --profile <profile> --sql \"...\" --json  (run it; live build only)"
                    .to_string(),
                "5. franken-snowflake query write --profile <profile> --sql \"insert ...\" --json  (writes directly once WRITE_ENABLED; add --dry-run only to preview)"
                    .to_string(),
            ]),
        ),
        (
            "non_goals",
            string_array(vec![
                "no third-party Snowflake Rust driver".to_string(),
                "no Tokio/reqwest/hyper production dependency".to_string(),
                "no mutation unless the profile sets WRITE_ENABLED (DDL needs WRITE_ALLOW_DDL)"
                    .to_string(),
            ]),
        ),
    ])
}

/// Documented environment variables that influence command resolution. Shared by
/// `capabilities`, `onboard`, `agent-handbook`, and `--help` so every discovery
/// surface advertises `FRANKEN_SNOWFLAKE_DEFAULT_PROFILE` identically.
fn environment_docs() -> Json {
    json_array(vec![json_object(vec![
        ("name", json_string("FRANKEN_SNOWFLAKE_DEFAULT_PROFILE")),
        (
            "description",
            json_string(
                "Default profile used when --profile (or the positional <profile>) is omitted; an explicit profile always wins. Set it to make --profile optional.",
            ),
        ),
        (
            "applies_to",
            string_array(vec![
                "query plan".to_string(),
                "query run".to_string(),
                "query write".to_string(),
                "catalog scan".to_string(),
                "catalog graph".to_string(),
                "profile validate".to_string(),
                "profile doctor".to_string(),
            ]),
        ),
    ])])
}

fn capabilities_data() -> Json {
    json_object(vec![
        ("tool_name", json_string("franken-snowflake")),
        ("binary_aliases", string_array(vec!["fsnow".to_string()])),
        ("crate_name", json_string(env!("CARGO_PKG_NAME"))),
        ("version", json_string(env!("CARGO_PKG_VERSION"))),
        ("contract_version", json_string(CLI_CONTRACT_VERSION)),
        ("schema_version", json_string(ENVELOPE_SCHEMA_VERSION)),
        ("default_output", json_string("json")),
        ("alternate_outputs", string_array(alternate_outputs())),
        ("feature_flags", feature_flags_json()),
        ("commands", Json::Array(command_registry())),
        ("exit_codes", exit_code_json()),
        ("error_registry", error_registry_json()),
        ("envelope_keys", envelope_key_json()),
        ("environment", environment_docs()),
        (
            "non_goals",
            string_array(vec![
                "no third-party Snowflake Rust driver".to_string(),
                "no Tokio/reqwest/hyper production dependency".to_string(),
                "no mutation unless the profile sets WRITE_ENABLED (writes execute directly; WRITE_REQUIRE_CONFIRM re-arms the dry-run/confirm ceremony)"
                    .to_string(),
                "no DDL without the explicit per-profile WRITE_ALLOW_DDL opt-in".to_string(),
                "no live transport without the `live` feature and a profile's credential handles"
                    .to_string(),
            ]),
        ),
    ])
}

fn alternate_outputs() -> Vec<String> {
    if toon_output_available() {
        vec!["toon".to_string()]
    } else {
        vec![]
    }
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
        ("environment", environment_docs()),
        (
            "error_recovery",
            json_object(vec![
                (
                    SnowflakeErrorCode::UsageError.stable_code(),
                    json_string(
                        "Run `franken-snowflake capabilities --json` and retry with the shown invocation. For a Missing-profile usage error, pass --profile <profile> or set FRANKEN_SNOWFLAKE_DEFAULT_PROFILE.",
                    ),
                ),
                (
                    SnowflakeErrorCode::Internal.stable_code(),
                    json_string(
                        "Use `query plan` or `capabilities`; live handlers land in dependent beads.",
                    ),
                ),
                (
                    SnowflakeErrorCode::ProfileInvalid.stable_code(),
                    json_string(
                        "Run `franken-snowflake doctor --json`; profile registry is not linked yet.",
                    ),
                ),
                (
                    SnowflakeErrorCode::SurfaceReserved.stable_code(),
                    json_string(
                        "This surface is reserved/not implemented yet; run `franken-snowflake capabilities --json` for the live surfaces.",
                    ),
                ),
                (
                    SnowflakeErrorCode::WriteDisabled.stable_code(),
                    json_string(
                        "Writes are disabled for this profile; set FRANKEN_SNOWFLAKE_<PROFILE>_WRITE_ENABLED=true, then run `query write` directly (it executes once write-enabled; add --dry-run only to preview).",
                    ),
                ),
                (
                    SnowflakeErrorCode::WriteConfirmationRequired.stable_code(),
                    json_string(
                        "This profile opted into the confirm ceremony (WRITE_REQUIRE_CONFIRM=true): run `query write --dry-run` to get the confirmation token, then re-run with `--confirm <token>`.",
                    ),
                ),
                (
                    SnowflakeErrorCode::WriteDdlRefused.stable_code(),
                    json_string(
                        "DDL is opt-in; set FRANKEN_SNOWFLAKE_<PROFILE>_WRITE_ALLOW_DDL=true to allow CREATE/ALTER/DROP/TRUNCATE/GRANT/REVOKE.",
                    ),
                ),
            ]),
        ),
        (
            "non_goals",
            string_array(vec![
                "do not store raw secrets in profiles".to_string(),
                "do not silently use fixtures when live data is required".to_string(),
                "do not mutate unless the profile sets WRITE_ENABLED; DDL stays behind an explicit WRITE_ALLOW_DDL opt-in"
                    .to_string(),
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
        ("usage", json_string(output_mode_usage())),
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
        ("environment", environment_docs()),
    ])
}

fn doctor_data() -> Json {
    // Status is derived from the checks so it can never disagree with the exit
    // code (`ok` here, since every check passes or is pending; `findings` only if
    // one fails). A `not_checked` item is a feature pending lower-level beads, not
    // a failure.
    let checks = vec![
        check_json(
            "cli_contract",
            "pass",
            "command registry and envelope renderer are linked",
        ),
        check_json(
            "cli_required_surfaces",
            "pass",
            "capabilities, robot-docs, agent-handbook, doctor, profile validate, query plan/run/cancel, and mcp serve are registered",
        ),
        check_json(
            "security_guardrails",
            "pass",
            "core redaction, rights, and cost guardrails are linked",
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
    ];
    json_object(vec![
        ("status", json_string(readiness_status(&checks))),
        ("checks", Json::Array(checks)),
    ])
}

fn selftest_data() -> Json {
    let fixtures = vec![
        check_json("json_envelope_contract", "pass", "renderer available"),
        check_json("sqlapi_protocol", "not_checked", "testkit bead pending"),
        check_json(
            "secret_redaction",
            "pass",
            "core redactor and credential canary needle list are linked",
        ),
        check_json(
            "credential_debug_gate",
            "pass",
            "auth credential Debug leak gate is linked through the checked workspace",
        ),
    ];
    json_object(vec![
        ("status", json_string(readiness_status(&fixtures))),
        ("offline", Json::Bool(true)),
        ("fixtures", Json::Array(fixtures)),
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
    // A structurally-valid profile is success (exit 0): the offline contract
    // checks passed and the "registry not linked yet" scope note lives in the
    // data (`status: offline_validated`), not as an exit-affecting warning — so an
    // agent gating on `profile validate` isn't blocked by a clean profile. An
    // invalid profile id is a real finding (exit 1).
    let (outcome_kind, exit, status, warnings) = if syntax_valid {
        ("success", CoreExitCode::Success, "offline_validated", vec![])
    } else {
        (
            "partial_success",
            CoreExitCode::Findings,
            "findings",
            vec![json_string(
                "profile id contains unsupported characters for stable handles",
            )],
        )
    };
    let mut envelope = base_envelope(
        true,
        outcome_kind,
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
        status: exit,
        body: Body::Envelope { envelope, format },
    }
}

fn profile_doctor_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    online: bool,
) -> Outcome {
    profile_doctor_dispatch(format, request_id, profile, online)
}

/// Live build: an explicit `--online` request runs a real credential probe; the
/// offline path is shared with the default build so its diagnostics envelope
/// (and goldens) stay byte-identical.
#[cfg(feature = "live")]
fn profile_doctor_dispatch(
    format: OutputFormat,
    request_id: String,
    profile: String,
    online: bool,
) -> Outcome {
    if online {
        live::profile_doctor_online_outcome(format, request_id, profile)
    } else {
        profile_doctor_offline_outcome(format, request_id, profile, online)
    }
}

/// Default (no-account) build: the probe cannot run, so report offline-only
/// findings (an `--online` request is recorded as requested-but-not-attempted).
#[cfg(not(feature = "live"))]
fn profile_doctor_dispatch(
    format: OutputFormat,
    request_id: String,
    profile: String,
    online: bool,
) -> Outcome {
    profile_doctor_offline_outcome(format, request_id, profile, online)
}

fn profile_doctor_offline_outcome(
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
        status: CoreExitCode::Findings,
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
        (
            "credential_lifetime_warnings",
            Json::Array(credential_lifetime_warnings()),
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

fn credential_lifetime_warnings() -> Vec<Json> {
    vec![
        json_object(vec![
            ("auth_lane", json_string("programmatic_access_token")),
            ("severity", json_string("warning")),
            (
                "message",
                json_string(
                    "PAT profiles should track the administrator expiry window; warn before the default 15-day lifetime ends",
                ),
            ),
            ("secret_values_read", Json::Bool(false)),
        ]),
        json_object(vec![
            ("auth_lane", json_string("key_pair_jwt")),
            ("severity", json_string("warning")),
            (
                "message",
                json_string(
                    "JWT exp values beyond the one-hour cap are refused or capped by the signer before submission",
                ),
            ),
            ("secret_values_read", Json::Bool(false)),
        ]),
        json_object(vec![
            ("auth_lane", json_string("oauth_bearer_token")),
            ("severity", json_string("warning")),
            (
                "message",
                json_string(
                    "OAuth bearer profiles should refresh before short-lived access tokens approach their roughly 10-minute lifetime",
                ),
            ),
            ("secret_values_read", Json::Bool(false)),
        ]),
    ]
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
                CoreExitCode::Usage,
                "error",
                error_info(
                    SnowflakeErrorCode::UsageError,
                    format!("Unknown operator `{operator}`."),
                    vec![json_string("known operators: between, equals")],
                ),
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
            "Missing --profile for `query plan`. Pass --profile <profile> or set FRANKEN_SNOWFLAKE_DEFAULT_PROFILE.",
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
            profile.clone(),
            SnowflakeErrorCode::MultiStatementRefused,
            "Multiple SQL statements are refused by default.",
            vec![plan_example(profile.as_deref())],
        );
    }

    if !is_select_like(&sql_text) {
        return refusal(
            format,
            "query.plan",
            "fsnow.query.plan.v1",
            request_id,
            profile.clone(),
            SnowflakeErrorCode::MutationRefused,
            "`query plan` validates read statements (SELECT/WITH/SHOW/DESCRIBE/EXPLAIN). To execute a mutation, use `query write` (direct once the profile sets WRITE_ENABLED).",
            vec![
                plan_example(profile.as_deref()),
                write_example(profile.as_deref()),
            ],
        );
    }

    success_with_profile(
        format,
        "query.plan",
        "fsnow.query.plan.v1",
        request_id,
        profile.clone(),
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
                    "submit through live SQL API transport when profile credentials are available"
                        .to_string(),
                ]),
            ),
        ]),
        vec![],
        vec![run_hint(profile.as_deref(), &sql_text)],
    )
}

// Build a copy-pasteable `query plan` command using the agent's ACTUAL profile
// and SQL (compacted; the envelope redaction pass scrubs any secret in it),
// instead of literal `<profile>`/`<sql>` placeholders. `<profile>` is only used
// as a last resort when no profile is in scope.
fn plan_hint(profile: Option<&str>, sql: &str) -> String {
    let profile = profile.unwrap_or("<profile>");
    format!(
        "franken-snowflake query plan --profile {profile} --sql \"{}\" --json",
        compact_sql(sql)
    )
}

// `query run` form with the agent's actual profile + SQL — suggested after a
// successful `query plan` so the next step is one copy-paste away.
fn run_hint(profile: Option<&str>, sql: &str) -> String {
    let profile = profile.unwrap_or("<profile>");
    format!(
        "franken-snowflake query run --profile {profile} --sql \"{}\" --json",
        compact_sql(sql)
    )
}

// `query plan` form carrying the agent's actual profile but a neutral example
// SQL — used in refusals where re-suggesting the rejected SQL would be unhelpful.
fn plan_example(profile: Option<&str>) -> String {
    let profile = profile.unwrap_or("<profile>");
    format!("franken-snowflake query plan --profile {profile} --sql \"select 1\" --json")
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
            "Missing --profile for `query run`. Pass --profile <profile> or set FRANKEN_SNOWFLAKE_DEFAULT_PROFILE.",
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

    // a3y: distinguish the two refusal reasons instead of one conflated message.
    // A multi-statement request and an unrecognized/typo'd SELECT are different
    // problems and an agent needs to know which one it hit.
    if has_multiple_statements(&sql_text) {
        return refusal(
            format,
            "query.run",
            "fsnow.query.run.v1",
            request_id,
            profile.clone(),
            SnowflakeErrorCode::MultiStatementRefused,
            "Multiple SQL statements are refused by default; submit exactly one read-only statement.",
            vec![plan_hint(profile.as_deref(), &sql_text)],
        );
    }
    if !is_select_like(&sql_text) {
        return refusal(
            format,
            "query.run",
            "fsnow.query.run.v1",
            request_id,
            profile.clone(),
            SnowflakeErrorCode::MutationRefused,
            "`query run` is the read path: it accepts a single SELECT/WITH/SHOW/DESCRIBE/EXPLAIN. To MUTATE data (INSERT/UPDATE/DELETE/MERGE/COPY INTO/PUT/DDL) use `query write`, which executes directly once the profile sets WRITE_ENABLED. (A typo'd keyword like `selcet` also lands here; if you meant to read, start with SELECT.)",
            vec![
                plan_hint(profile.as_deref(), &sql_text),
                write_hint(profile.as_deref(), &sql_text),
            ],
        );
    }

    // The two builds diverge only here: with `live` the real transport runs; the
    // default no-account build refuses cleanly. Split into cfg-gated helpers so the
    // tail stays a single unambiguous expression (no cfg-block-as-tail, no
    // needless_return under the `-D warnings` clippy gate).
    query_run_dispatch(format, request_id, profile, &sql_text)
}

/// Live build: drive the real SQL API transport. The profile presence was checked
/// by the caller, so `unwrap_or_default` only ever yields the named profile.
#[cfg(feature = "live")]
fn query_run_dispatch(
    format: OutputFormat,
    request_id: String,
    profile: Option<String>,
    sql_text: &str,
) -> Outcome {
    live::run_query_outcome(format, request_id, profile.unwrap_or_default(), sql_text)
}

/// Default (no-account) build: the transport is intentionally not linked, so
/// refuse cleanly rather than substitute fixture or empty data.
#[cfg(not(feature = "live"))]
fn query_run_dispatch(
    format: OutputFormat,
    request_id: String,
    profile: Option<String>,
    _sql_text: &str,
) -> Outcome {
    live_transport_required_with_data(
        format,
        "query.run",
        "fsnow.query.run.v1",
        request_id,
        profile,
        json_object(vec![
            ("sql_accepted_by_local_safety_check", Json::Bool(true)),
            (
                "requires",
                json_array(vec![
                    json_string("live SQL API transport"),
                    json_string("profile credential handles"),
                    json_string("statement lifecycle submit/poll/partition handler"),
                ]),
            ),
        ]),
        vec!["franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string()],
    )
}

/// Drive the write path for `query write`.
///
/// Default flow once a profile sets `WRITE_ENABLED`: a bare `query write` (no
/// `--dry-run`, no `--confirm`) goes straight to `PrepareExecution`, the ladder
/// authorizes the mutation, and the `live` transport EXECUTES it — frictionless by
/// default. `--dry-run` stays available as an optional non-executing preview that
/// returns a [`WriteIntentPlan`] (statement kind, safety class, confirmation token,
/// remaining rungs). `--confirm <token>` re-derives the same idempotency id from the
/// (profile, SQL) pair and executes a previously previewed write.
///
/// A cautious profile can re-arm the ceremony with `WRITE_REQUIRE_CONFIRM=true`:
/// then a bare `query write` refuses and tells the caller to `--dry-run` first, and
/// execution requires the exact `--confirm <token>`. Without `WRITE_ENABLED` the
/// ladder emits the typed `WriteDisabled` refusal. The connector authorizes here;
/// the SQL is submitted only by the `live` transport executor.
fn query_write_outcome(
    format: OutputFormat,
    request_id: String,
    profile: Option<String>,
    sql: Option<String>,
    dry_run: bool,
    confirm: Option<String>,
) -> Outcome {
    let Some(profile) = profile else {
        return usage_error(
            format,
            "query.write",
            "fsnow.query.write.v1",
            "Missing --profile for `query write`. Pass --profile <profile> or set FRANKEN_SNOWFLAKE_DEFAULT_PROFILE.",
            vec![write_example(None)],
            vec![],
        );
    };
    let Some(sql_text) = sql else {
        return usage_error(
            format,
            "query.write",
            "fsnow.query.write.v1",
            "Missing --sql for `query write`.",
            vec![write_example(Some(&profile))],
            vec![],
        );
    };

    if has_multiple_statements(&sql_text) {
        return refusal(
            format,
            "query.write",
            "fsnow.query.write.v1",
            request_id,
            Some(profile.clone()),
            SnowflakeErrorCode::MultiStatementRefused,
            "Multiple SQL statements are refused by default; submit exactly one mutating statement.",
            vec![write_hint(Some(&profile), &sql_text)],
        );
    }

    // The two safety flags are mutually exclusive. `--dry-run` previews; `--confirm`
    // executes a previewed write. Supplying both is ambiguous.
    if dry_run && confirm.is_some() {
        return usage_error(
            format,
            "query.write",
            "fsnow.query.write.v1",
            "Choose either --dry-run (to preview) or --confirm <token> (to execute a previewed write), not both.",
            vec![write_dry_run_example(Some(&profile))],
            vec![],
        );
    }

    // Reject read/unrecognized statements up front with a read-path pointer, before
    // any execution decision.
    let statement_kind = classify_write_statement(&sql_text);
    if statement_kind == WriteStatementKind::Unknown {
        return usage_error(
            format,
            "query.write",
            "fsnow.query.write.v1",
            "`query write` expects a mutating statement (INSERT/UPDATE/DELETE/MERGE/COPY INTO/PUT/...). For reads use `query run`.",
            vec![run_hint(Some(&profile), &sql_text)],
            vec![],
        );
    }

    // Mode selection. `--confirm` executes a previewed write; `--dry-run` previews
    // without executing. With neither flag the write is frictionless BY DEFAULT once
    // the profile is write-enabled: route straight to PrepareExecution so the ladder
    // authorizes and the transport executes. A cautious profile that opted into
    // `WRITE_REQUIRE_CONFIRM` instead refuses a bare write and asks the caller to
    // dry-run first. A profile without `WRITE_ENABLED` still falls through to
    // PrepareExecution, where the ladder emits the typed `WriteDisabled` refusal.
    let mode = if confirm.is_some() {
        WriteIntentMode::PrepareExecution
    } else if dry_run {
        WriteIntentMode::PlanDryRun
    } else if profile_env_flag(&profile, "WRITE_ENABLED")
        && profile_env_flag(&profile, "WRITE_REQUIRE_CONFIRM")
    {
        return refusal(
            format,
            "query.write",
            "fsnow.query.write.v1",
            request_id,
            Some(profile.clone()),
            SnowflakeErrorCode::WriteConfirmationRequired,
            "This profile sets WRITE_REQUIRE_CONFIRM=true: run `query write --dry-run` first to get a confirmation token, then re-run with --confirm <token>.",
            vec![write_hint(Some(&profile), &sql_text)],
        );
    } else {
        WriteIntentMode::PrepareExecution
    };

    let policy = write_policy_for_profile(&profile, statement_kind);
    let allowlist_id = cli_allowlist_id(statement_kind);

    // Deterministic idempotency id bound to (profile, compacted SQL): the dry-run
    // confirmation token only validates a re-run of the *same* statement.
    let ladder_request_id =
        stable_request_id(&format!("write\u{1f}{profile}\u{1f}{}", compact_sql(&sql_text)));

    let mut intent = WriteIntentRequest::new(mode, &sql_text);
    intent.dry_run = true;
    intent.allowlist_id = Some(allowlist_id);
    intent.request_id = Some(RequestId::new(ladder_request_id));
    if let Some(token) = &confirm {
        intent.confirmation_token = Some(ConfirmationToken::new(token.clone()));
    }

    match evaluate_write_intent(&intent, &policy) {
        WriteIntentDecision::Refused { refusal: detail } => {
            write_refusal_outcome(format, request_id, profile, &sql_text, &detail)
        }
        WriteIntentDecision::DryRunPlanned { plan } => {
            write_plan_outcome(format, request_id, profile, &plan)
        }
        WriteIntentDecision::ExecutionAuthorized { plan } => {
            query_write_execute_dispatch(format, request_id, profile, &sql_text, &plan)
        }
    }
}

/// Build the per-profile write-intent policy from env handles. By default a
/// write-enabled profile authorizes data writes DIRECTLY: the dry-run and exact
/// confirmation rungs are off (`require_dry_run`/`require_exact_confirmation` are
/// false), so a bare `query write` reaches `ExecutionAuthorized`. A profile can
/// re-arm the cautious dry-run -> confirm ceremony with `<PREFIX>_WRITE_REQUIRE_CONFIRM`.
/// The append-only-audit and hand-maintained allowlist knobs the core models stay
/// off by default. DDL stays behind an explicit `<PREFIX>_WRITE_ALLOW_DDL` opt-in.
fn write_policy_for_profile(profile: &str, statement_kind: WriteStatementKind) -> WriteIntentPolicy {
    write_policy_from_flags(
        profile_env_flag(profile, "WRITE_ENABLED"),
        profile_env_flag(profile, "WRITE_ALLOW_DDL"),
        profile_env_flag(profile, "WRITE_REQUIRE_CONFIRM"),
        statement_kind,
    )
}

/// Pure write-intent policy assembly from the resolved boolean flags (env-free, so
/// it is unit-testable). `require_confirm` drives BOTH the `require_dry_run` and
/// `require_exact_confirmation` rungs: false (the default) makes writes frictionless;
/// true restores the dry-run -> confirmation-token ceremony.
fn write_policy_from_flags(
    enabled: bool,
    allow_ddl: bool,
    require_confirm: bool,
    statement_kind: WriteStatementKind,
) -> WriteIntentPolicy {
    WriteIntentPolicy {
        enabled,
        allow_ddl,
        require_dry_run: require_confirm,
        require_exact_confirmation: require_confirm,
        require_idempotency_request_id: true,
        require_append_only_audit: false,
        statement_allowlist: vec![StatementAllowlistEntry::new(
            cli_allowlist_id(statement_kind),
            statement_kind,
        )],
    }
}

/// The auto allowlist id the CLI binds for a classified statement kind, so routine
/// writes do not require the operator to hand-maintain an allowlist.
fn cli_allowlist_id(statement_kind: WriteStatementKind) -> String {
    format!("cli_auto_{}", statement_kind.as_token())
}

/// Read a boolean profile env handle (`<PREFIX>_<KEY> == "true"`, case-insensitive).
fn profile_env_flag(profile: &str, key: &str) -> bool {
    let prefix = profile_env_prefix(profile);
    env::var(format!("{prefix}_{key}"))
        .ok()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
}

/// A non-executing dry-run write plan envelope: statement kind, safety class, the
/// exact confirmation token, the remaining ladder rungs, and the ready-to-run
/// `--confirm` command. `execution_enabled`/`will_submit` are false; nothing runs.
fn write_plan_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    plan: &WriteIntentPlan,
) -> Outcome {
    let token = plan.required_confirmation_token.as_str().to_string();
    let confirm_command = format!(
        "franken-snowflake query write --profile {profile} --sql \"{}\" --confirm {token} --json",
        compact_sql(&plan.redacted_sql_preview)
    );
    let next_stages = string_array(
        plan.next_required_stages
            .iter()
            .map(|stage| format!("{stage:?}"))
            .collect(),
    );
    success_with_profile(
        format,
        "query.write",
        "fsnow.query.write.v1",
        request_id,
        Some(profile),
        json_object(vec![
            ("mode", json_string("dry_run")),
            ("execution_enabled", Json::Bool(false)),
            ("will_submit", Json::Bool(false)),
            ("statement_kind", json_string(plan.statement_kind.as_token())),
            (
                "safety_class",
                json_string(safety_class_token(plan.safety_class)),
            ),
            (
                "redacted_sql_preview",
                json_string(plan.redacted_sql_preview.clone()),
            ),
            (
                "idempotency_request_id",
                json_string(plan.receipt.request_id.as_str().to_string()),
            ),
            ("required_confirmation_token", json_string(token)),
            ("next_required_stages", next_stages),
            ("confirm_command", json_string(confirm_command.clone())),
        ]),
        vec![],
        vec![confirm_command],
    )
}

/// A typed write-intent refusal envelope, mapping the core `WriteIntentRefusalCode`
/// to a stable `FSNOW-*` code with an actionable repair hint.
fn write_refusal_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    sql: &str,
    detail: &WriteIntentRefusal,
) -> Outcome {
    let code = write_refusal_code(detail.code);
    let mut envelope = base_envelope(
        false,
        "refusal",
        "query.write",
        "fsnow.query.write.v1",
        request_id,
        json_object(vec![
            (
                "write_intent_stage",
                json_string(format!("{:?}", detail.stage)),
            ),
            ("execution_enabled", Json::Bool(false)),
        ]),
    );
    envelope.profile_id = Some(profile.clone());
    envelope.error = Some(error_info(
        code,
        detail.message.clone(),
        vec![json_string("write-intent ladder")],
    ));
    envelope.safe_next_commands = vec![write_hint(Some(&profile), sql)];
    envelope.repair_commands = write_refusal_repair(detail.code, &profile);
    Outcome {
        status: code.exit_code(),
        body: Body::Envelope { envelope, format },
    }
}

/// Map a core write-intent refusal code to the CLI's stable error code.
fn write_refusal_code(code: WriteIntentRefusalCode) -> SnowflakeErrorCode {
    match code {
        WriteIntentRefusalCode::MutationsDisabled => SnowflakeErrorCode::WriteDisabled,
        WriteIntentRefusalCode::DdlRefused => SnowflakeErrorCode::WriteDdlRefused,
        WriteIntentRefusalCode::MissingDryRun
        | WriteIntentRefusalCode::MissingConfirmationToken
        | WriteIntentRefusalCode::ConfirmationTokenMismatch => {
            SnowflakeErrorCode::WriteConfirmationRequired
        }
        WriteIntentRefusalCode::StatementNotAllowlisted
        | WriteIntentRefusalCode::MissingIdempotencyRequestId
        | WriteIntentRefusalCode::MissingAppendOnlyAudit
        | WriteIntentRefusalCode::ExecutionUnavailable => SnowflakeErrorCode::MutationRefused,
    }
}

/// The most actionable repair command for a write-intent refusal.
fn write_refusal_repair(code: WriteIntentRefusalCode, profile: &str) -> Vec<String> {
    let prefix = profile_env_prefix(profile);
    match code {
        WriteIntentRefusalCode::MutationsDisabled => {
            vec![format!("export {prefix}_WRITE_ENABLED=true")]
        }
        WriteIntentRefusalCode::DdlRefused => {
            vec![format!("export {prefix}_WRITE_ALLOW_DDL=true")]
        }
        _ => vec![write_dry_run_example(Some(profile))],
    }
}

/// Stable lowercase token for a write safety class (matches the core serde naming).
fn safety_class_token(class: WriteSafetyClass) -> &'static str {
    match class {
        WriteSafetyClass::Dml => "dml",
        WriteSafetyClass::Ddl => "ddl",
        WriteSafetyClass::Procedure => "procedure",
        WriteSafetyClass::ExternalFile => "external_file",
        WriteSafetyClass::SessionState => "session_state",
        WriteSafetyClass::Unknown => "unknown",
    }
}

/// `query write --dry-run` form carrying the agent's actual profile + SQL.
fn write_hint(profile: Option<&str>, sql: &str) -> String {
    let profile = profile.unwrap_or("<profile>");
    format!(
        "franken-snowflake query write --profile {profile} --sql \"{}\" --dry-run --json",
        compact_sql(sql)
    )
}

/// `query write --dry-run` form with a neutral example, for preview/ceremony hints.
fn write_dry_run_example(profile: Option<&str>) -> String {
    let profile = profile.unwrap_or("<profile>");
    format!(
        "franken-snowflake query write --profile {profile} --sql \"insert into t values (1)\" --dry-run --json"
    )
}

/// Direct `query write` form (the default once WRITE_ENABLED), for usage errors.
fn write_example(profile: Option<&str>) -> String {
    let profile = profile.unwrap_or("<profile>");
    format!(
        "franken-snowflake query write --profile {profile} --sql \"insert into t values (1)\" --json"
    )
}

/// Live build: hand the authorized write to the SQL API transport executor.
#[cfg(feature = "live")]
fn query_write_execute_dispatch(
    format: OutputFormat,
    request_id: String,
    profile: String,
    sql: &str,
    plan: &WriteIntentPlan,
) -> Outcome {
    let write = live::AuthorizedWrite {
        sql,
        statement_kind: plan.statement_kind.as_token(),
        safety_class: safety_class_token(plan.safety_class),
        idempotency_request_id: plan.receipt.request_id.as_str().to_string(),
        database: None,
        schema: None,
    };
    live::run_write_outcome(format, request_id, profile, &write)
}

/// Default (no-account) build: the write was authorized by the ladder, but no live
/// transport is linked, so refuse cleanly rather than pretend it executed.
#[cfg(not(feature = "live"))]
fn query_write_execute_dispatch(
    format: OutputFormat,
    request_id: String,
    profile: String,
    _sql: &str,
    plan: &WriteIntentPlan,
) -> Outcome {
    live_transport_required_with_data(
        format,
        "query.write",
        "fsnow.query.write.v1",
        request_id,
        Some(profile),
        json_object(vec![
            ("write_intent_authorized", Json::Bool(true)),
            ("execution_enabled", Json::Bool(false)),
            ("statement_kind", json_string(plan.statement_kind.as_token())),
            (
                "idempotency_request_id",
                json_string(plan.receipt.request_id.as_str().to_string()),
            ),
            (
                "requires",
                json_array(vec![
                    json_string("live SQL API transport (build with --features live)"),
                    json_string("profile credential handles"),
                ]),
            ),
        ]),
        vec!["franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string()],
    )
}

/// Live build: run an `INFORMATION_SCHEMA.TABLES` discovery scan. `parse_catalog`
/// guarantees `database`/`schema` are present, so `unwrap_or_default` only ever
/// yields the supplied values.
#[cfg(feature = "live")]
fn catalog_scan_dispatch(
    format: OutputFormat,
    request_id: String,
    profile: String,
    database: Option<String>,
    schema: Option<String>,
) -> Outcome {
    live::run_catalog_scan_outcome(
        format,
        request_id,
        profile,
        database.unwrap_or_default(),
        schema.unwrap_or_default(),
    )
}

/// Default (no-account) build: catalog discovery needs live transport, so refuse
/// cleanly rather than substitute fixture or empty data.
#[cfg(not(feature = "live"))]
fn catalog_scan_dispatch(
    format: OutputFormat,
    request_id: String,
    profile: String,
    database: Option<String>,
    schema: Option<String>,
) -> Outcome {
    not_implemented_with_data(
        format,
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
    )
}

#[allow(clippy::too_many_arguments)]
fn refusal(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    profile_id: Option<String>,
    code: SnowflakeErrorCode,
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
    // mfw: name the agent's real profile in the repair command rather than the
    // literal `<profile>` placeholder (captured before profile_id is moved into
    // the envelope). `<sql>` stays a placeholder — the refusing SQL is the caller's
    // to correct, and the safe_next_commands already carry the compacted SQL.
    let profile_label = profile_id.as_deref().unwrap_or("<profile>").to_string();
    envelope.profile_id = profile_id;
    envelope.error = Some(error_info(
        code,
        message,
        vec![json_string("local SQL safety check")],
    ));
    envelope.safe_next_commands = safe_next_commands;
    envelope.repair_commands = vec![format!(
        "franken-snowflake query plan --profile {profile_label} --sql <sql> --json"
    )];
    Outcome {
        status: code.exit_code(),
        body: Body::Envelope { envelope, format },
    }
}

fn catalog_graph_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    database: Option<String>,
    schema: Option<String>,
    graph_output: GraphOutput,
) -> Outcome {
    catalog_graph_dispatch(format, request_id, profile, database, schema, graph_output)
}

/// Live build: render the real catalog lineage graph from a live scan.
#[cfg(feature = "live")]
fn catalog_graph_dispatch(
    format: OutputFormat,
    request_id: String,
    profile: String,
    database: Option<String>,
    schema: Option<String>,
    graph_output: GraphOutput,
) -> Outcome {
    live::run_catalog_graph_outcome(format, request_id, profile, database, schema, graph_output)
}

/// Default (no-account) build: the lineage graph is derived from a live catalog
/// scan, so without transport refuse cleanly rather than emit a placeholder an
/// agent could mistake for a real (empty) graph.
#[cfg(not(feature = "live"))]
fn catalog_graph_dispatch(
    format: OutputFormat,
    request_id: String,
    profile: String,
    database: Option<String>,
    schema: Option<String>,
    _graph_output: GraphOutput,
) -> Outcome {
    live_transport_required_with_data(
        format,
        "catalog.graph",
        "fsnow.catalog.graph.v1",
        request_id,
        Some(profile),
        json_object(vec![
            ("requested_database", option_json(database)),
            ("requested_schema", option_json(schema)),
            (
                "requires",
                json_array(vec![
                    json_string("live SQL API transport"),
                    json_string("a catalog scan over --database/--schema"),
                ]),
            ),
        ]),
        vec![
            "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                .to_string(),
        ],
    )
}

fn exit_code_json() -> Json {
    Json::Array(vec![
        exit_code_entry(0, "success, including empty-but-valid results"),
        exit_code_entry(1, "completed with non-fatal findings or warnings"),
        exit_code_entry(2, "refusal (safety block or reserved/unimplemented surface)"),
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
        SnowflakeErrorCode::ALL
            .iter()
            .copied()
            .map(|code| {
                let entry = code.entry();
                json_object(vec![
                    ("code", json_string(entry.stable_code)),
                    ("exit_code", Json::Number(i64::from(entry.exit_code.code()))),
                    ("description", json_string(entry.summary)),
                    ("retryable", Json::Bool(entry.retryable)),
                    ("policy_boundary", Json::Bool(entry.policy_boundary)),
                    (
                        "safe_next_commands",
                        string_array(
                            entry
                                .safe_next_commands
                                .iter()
                                .map(|cmd| (*cmd).to_string())
                                .collect(),
                        ),
                    ),
                    (
                        "repair_commands",
                        string_array(
                            entry
                                .repair_commands
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
    SnowflakeErrorCode::ALL
        .iter()
        .map(|code| code.stable_code().to_string())
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
        "franken-snowflake onboard --json".to_string(),
        "franken-snowflake capabilities --json".to_string(),
        "franken-snowflake agent-handbook --json".to_string(),
        "franken-snowflake robot-docs guide".to_string(),
        "franken-snowflake doctor --json".to_string(),
        "franken-snowflake selftest --json".to_string(),
        "franken-snowflake profile validate <profile> --json".to_string(),
        "franken-snowflake query plan --profile <profile> --sql \"select 1\" --json".to_string(),
        "franken-snowflake dataset describe-operator between --jsonschema".to_string(),
        "franken-snowflake catalog graph <profile> --database <db> --mermaid".to_string(),
        "franken-snowflake query cancel <statement-handle> --json".to_string(),
    ]
}

fn extract_output_format(raw_args: Vec<String>) -> (OutputFormat, bool, Vec<String>) {
    let mut output = OutputFormat::Json;
    let mut explicit_json = false;
    let mut filtered = Vec::new();
    for arg in raw_args {
        match arg.as_str() {
            "--json" => {
                explicit_json = true;
                output = OutputFormat::Json;
            }
            "--toon" => output = OutputFormat::Toon,
            "--no-color" => {}
            _ => filtered.push(arg),
        }
    }
    (output, explicit_json, filtered)
}

fn validate_known_flags(output: OutputFormat, args: &[String]) -> Result<(), Outcome> {
    let mut skip_next = false;
    for (index, arg) in args.iter().enumerate() {
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
                let Some(next) = args.get(index + 1) else {
                    return Err(missing_flag_value_outcome(output, flag_name));
                };
                if next.starts_with('-') && !flag_allows_flag_like_value(flag_name) {
                    return Err(missing_flag_value_outcome(output, flag_name));
                }
                skip_next = true;
            }
            continue;
        }

        return Err(error_outcome(
            output,
            "help",
            "fsnow.help.v1",
            CoreExitCode::Usage,
            "error",
            error_info(
                SnowflakeErrorCode::UsageError,
                format!("Unknown flag `{arg}`."),
                vec![json_string(format!("flag={arg}"))],
            ),
            vec!["franken-snowflake capabilities --json".to_string()],
            vec!["franken-snowflake --help".to_string()],
            did_you_mean(flag_name, &known_flags()),
        ));
    }

    Ok(())
}

fn missing_flag_value_outcome(output: OutputFormat, flag_name: &str) -> Outcome {
    usage_error(
        output,
        "help",
        "fsnow.help.v1",
        &format!("Missing value for `{flag_name}`."),
        vec![
            "franken-snowflake capabilities --json".to_string(),
            format!("franken-snowflake <command> {flag_name} <value> --json"),
        ],
        vec![],
    )
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
    // `--http` is intentionally excluded: it is exclusive to `mcp serve`, which
    // owns its own missing-address/conflict diagnostics in `parse_mcp` (with the
    // `mcp.serve` command id). Treating it as a generic value-flag here made the
    // global validator emit a less precise `help`-scoped "Missing value for
    // `--http`" *before* `parse_mcp` could run, shadowing the specific message.
    matches!(
        flag,
        "--as-of"
            | "--confirm"
            | "--database"
            | "--dataset"
            | "--entity"
            | "--from"
            | "--limit"
            | "--profile"
            | "--role"
            | "--schema"
            | "--sql"
            | "--to"
            | "--warehouse"
    )
}

fn flag_allows_flag_like_value(flag: &str) -> bool {
    matches!(flag, "--sql")
}

fn has_any(args: &[String], needles: &[&str]) -> bool {
    args.iter()
        .any(|arg| needles.iter().any(|needle| arg == needle))
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn flag_present(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| {
        arg == flag
            || arg
                .strip_prefix(flag)
                .is_some_and(|suffix| suffix.starts_with('='))
    })
}

fn value_after(args: &[String], flag: &str) -> Option<String> {
    value_after_inner(args, flag, false)
}

fn raw_value_after(args: &[String], flag: &str) -> Option<String> {
    value_after_inner(args, flag, true)
}

fn value_after_inner(args: &[String], flag: &str, allow_flag_like_value: bool) -> Option<String> {
    for (index, arg) in args.iter().enumerate() {
        if arg == flag {
            let value = args.get(index + 1)?;
            if !allow_flag_like_value && value.starts_with('-') {
                return None;
            }
            return Some(value.clone());
        }

        if let Some(value) = arg
            .strip_prefix(flag)
            .and_then(|suffix| suffix.strip_prefix('='))
        {
            return (!value.is_empty()).then(|| value.to_string());
        }
    }

    None
}

/// Environment variable that supplies a default profile when `--profile` (or the
/// positional profile argument) is omitted. This is intentionally distinct from
/// the internal `FRANKEN_SNOWFLAKE_PROFILE` env-prefix fallback used by credential
/// lookup (see [`profile_env_prefix`]); reusing that name would conflate the two.
const DEFAULT_PROFILE_ENV: &str = "FRANKEN_SNOWFLAKE_DEFAULT_PROFILE";

/// Read `FRANKEN_SNOWFLAKE_DEFAULT_PROFILE`, treating an unset OR empty value as
/// absent. Centralizing the env read behind one indirection keeps the resolution
/// policy unit-testable as the pure [`resolve_profile_with`] (the workspace forbids
/// `env::set_var` in tests under edition 2024, so the policy is tested directly).
fn default_profile_env() -> Option<String> {
    std::env::var(DEFAULT_PROFILE_ENV)
        .ok()
        .filter(|value| !value.is_empty())
}

/// Resolve the active profile for any command that needs one: an explicit
/// `--profile <p>` (or positional `<profile>`) wins; otherwise fall back to
/// `FRANKEN_SNOWFLAKE_DEFAULT_PROFILE`. Returns `None` only when neither source
/// provides one, which routes into the typed Missing-profile usage error.
fn resolve_profile(explicit: Option<String>) -> Option<String> {
    resolve_profile_with(explicit, default_profile_env())
}

/// Pure resolution policy behind [`resolve_profile`]: the explicit value wins,
/// else the supplied env value. Kept side-effect free so the precedence is
/// directly unit-testable without touching process environment.
fn resolve_profile_with(explicit: Option<String>, env_value: Option<String>) -> Option<String> {
    explicit.or(env_value)
}

/// The positional profile argument (`args[2]`) for the positional-profile commands
/// (`profile validate|doctor`, `catalog scan|graph`). A flag-like token (starting
/// with `-`) is treated as "no positional profile" so the slot can fall back to
/// `FRANKEN_SNOWFLAKE_DEFAULT_PROFILE` rather than being mistaken for the profile.
fn positional_profile(args: &[String]) -> Option<String> {
    args.get(2)
        .filter(|value| !value.starts_with('-'))
        .cloned()
}

fn has_multiple_statements(sql: &str) -> bool {
    // A bare `.contains(';')` over-refuses valid single statements whose text
    // legitimately holds a semicolon inside a string literal (`select ';'`), a
    // line comment (`select 1 -- a; b`), or a block comment (`/* a; b */ select`).
    // Scan with the same quote/comment state machine as `skip_balanced_sql_parens`
    // and only treat a *top-level* `;` as a separator. A single trailing separator
    // (optionally followed by whitespace/comments) is allowed; a second top-level
    // `;`, or any real content after one, means multiple statements.
    let bytes = sql.as_bytes();
    let mut cursor = 0usize;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut separator_seen = false;

    while cursor < bytes.len() {
        if in_line_comment {
            in_line_comment = bytes[cursor] != b'\n';
            cursor += 1;
            continue;
        }
        if in_block_comment {
            if bytes[cursor] == b'*' && bytes.get(cursor + 1) == Some(&b'/') {
                in_block_comment = false;
                cursor += 2;
            } else {
                cursor += 1;
            }
            continue;
        }
        if in_single_quote {
            if bytes[cursor] == b'\'' {
                if bytes.get(cursor + 1) == Some(&b'\'') {
                    cursor += 2;
                } else {
                    in_single_quote = false;
                    cursor += 1;
                }
            } else {
                cursor += 1;
            }
            continue;
        }
        if in_double_quote {
            if bytes[cursor] == b'"' {
                if bytes.get(cursor + 1) == Some(&b'"') {
                    cursor += 2;
                } else {
                    in_double_quote = false;
                    cursor += 1;
                }
            } else {
                cursor += 1;
            }
            continue;
        }
        match bytes[cursor] {
            b'\'' => {
                in_single_quote = true;
                cursor += 1;
            }
            b'"' => {
                in_double_quote = true;
                cursor += 1;
            }
            b'-' if bytes.get(cursor + 1) == Some(&b'-') => {
                in_line_comment = true;
                cursor += 2;
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'*') => {
                in_block_comment = true;
                cursor += 2;
            }
            b';' => {
                if separator_seen {
                    return true;
                }
                separator_seen = true;
                cursor += 1;
            }
            other => {
                if separator_seen && !other.is_ascii_whitespace() {
                    return true;
                }
                cursor += 1;
            }
        }
    }
    false
}

fn is_select_like(sql: &str) -> bool {
    let start = skip_sql_ws_and_comments(sql, 0);
    if consume_sql_keyword(sql, start, "with").is_some() {
        return cte_select_tail_is_read(sql, start);
    }
    ["select", "show", "describe", "desc", "explain"]
        .iter()
        .any(|keyword| consume_sql_keyword(sql, start, keyword).is_some())
}

fn cte_select_tail_is_read(sql: &str, start: usize) -> bool {
    let Some(mut index) = consume_sql_keyword(sql, start, "with") else {
        return false;
    };
    index = skip_sql_ws_and_comments(sql, index);
    if let Some(after_recursive) = consume_sql_keyword(sql, index, "recursive") {
        index = skip_sql_ws_and_comments(sql, after_recursive);
    }

    loop {
        let Some(after_name) = consume_sql_identifier(sql, index) else {
            return false;
        };
        index = skip_sql_ws_and_comments(sql, after_name);

        if sql[index..].starts_with('(') {
            let Some(after_columns) = skip_balanced_sql_parens(sql, index) else {
                return false;
            };
            index = skip_sql_ws_and_comments(sql, after_columns);
        }

        let Some(after_as) = consume_sql_keyword(sql, index, "as") else {
            return false;
        };
        index = skip_sql_ws_and_comments(sql, after_as);

        let Some(after_cte_query) = skip_balanced_sql_parens(sql, index) else {
            return false;
        };
        index = skip_sql_ws_and_comments(sql, after_cte_query);

        if sql[index..].starts_with(',') {
            index = skip_sql_ws_and_comments(sql, index + 1);
            continue;
        }

        return consume_sql_keyword(sql, index, "select").is_some();
    }
}

fn skip_sql_ws_and_comments(sql: &str, mut index: usize) -> usize {
    loop {
        while let Some(ch) = sql[index..].chars().next() {
            if !ch.is_whitespace() {
                break;
            }
            index += ch.len_utf8();
        }

        if sql[index..].starts_with("--") {
            match sql[index..].find('\n') {
                Some(line_end) => {
                    index += line_end + 1;
                    continue;
                }
                None => return sql.len(),
            }
        }

        if sql[index..].starts_with("/*") {
            match sql[index + 2..].find("*/") {
                Some(block_end) => {
                    index += block_end + 4;
                    continue;
                }
                None => return sql.len(),
            }
        }

        return index;
    }
}

fn consume_sql_keyword(sql: &str, index: usize, keyword: &str) -> Option<usize> {
    let rest = sql.get(index..)?;
    // `rest.get(..keyword.len())` yields `None` when `keyword.len()` is past the
    // end *or* lands inside a multi-byte UTF-8 char, so a non-ASCII statement
    // (e.g. `query plan --sql "€€"`) can never panic on a non-char-boundary
    // slice — the prior `rest[..keyword.len()]` did exactly that.
    let head = rest.get(..keyword.len())?;
    if !head.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let end = index + keyword.len();
    match sql[end..].chars().next() {
        Some(ch) if is_sql_identifier_continue(ch) => None,
        _ => Some(end),
    }
}

fn consume_sql_identifier(sql: &str, index: usize) -> Option<usize> {
    let rest = sql.get(index..)?;
    if rest.starts_with('"') {
        let bytes = sql.as_bytes();
        let mut cursor = index + 1;
        while cursor < bytes.len() {
            if bytes[cursor] == b'"' {
                if bytes.get(cursor + 1) == Some(&b'"') {
                    cursor += 2;
                    continue;
                }
                return Some(cursor + 1);
            }
            cursor += 1;
        }
        return None;
    }

    let mut end = index;
    let mut saw_char = false;
    for (offset, ch) in rest.char_indices() {
        if !is_sql_identifier_continue(ch) {
            break;
        }
        saw_char = true;
        end = index + offset + ch.len_utf8();
    }
    saw_char.then_some(end)
}

fn is_sql_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$')
}

fn skip_balanced_sql_parens(sql: &str, index: usize) -> Option<usize> {
    if !sql[index..].starts_with('(') {
        return None;
    }

    let bytes = sql.as_bytes();
    let mut cursor = index;
    let mut depth = 0usize;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;

    while cursor < bytes.len() {
        if in_line_comment {
            in_line_comment = bytes[cursor] != b'\n';
            cursor += 1;
            continue;
        }

        if in_block_comment {
            if bytes[cursor] == b'*' && bytes.get(cursor + 1) == Some(&b'/') {
                in_block_comment = false;
                cursor += 2;
            } else {
                cursor += 1;
            }
            continue;
        }

        if in_single_quote {
            if bytes[cursor] == b'\'' {
                if bytes.get(cursor + 1) == Some(&b'\'') {
                    cursor += 2;
                } else {
                    in_single_quote = false;
                    cursor += 1;
                }
            } else {
                cursor += 1;
            }
            continue;
        }

        if in_double_quote {
            if bytes[cursor] == b'"' {
                if bytes.get(cursor + 1) == Some(&b'"') {
                    cursor += 2;
                } else {
                    in_double_quote = false;
                    cursor += 1;
                }
            } else {
                cursor += 1;
            }
            continue;
        }

        match bytes[cursor] {
            b'\'' => {
                in_single_quote = true;
                cursor += 1;
            }
            b'"' => {
                in_double_quote = true;
                cursor += 1;
            }
            b'-' if bytes.get(cursor + 1) == Some(&b'-') => {
                in_line_comment = true;
                cursor += 2;
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'*') => {
                in_block_comment = true;
                cursor += 2;
            }
            b'(' => {
                depth += 1;
                cursor += 1;
            }
            b')' => {
                depth = depth.checked_sub(1)?;
                cursor += 1;
                if depth == 0 {
                    return Some(cursor);
                }
            }
            _ => cursor += 1,
        }
    }

    None
}

fn compact_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn top_level_commands() -> Vec<&'static str> {
    vec![
        "capabilities",
        "onboard",
        "robot-docs",
        "agent-handbook",
        "doctor",
        "selftest",
        "profile",
        "catalog",
        "dataset",
        "query",
        "write",
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

fn render_envelope(envelope: &Envelope, format: OutputFormat) -> String {
    let value = envelope_json(envelope);
    match format {
        OutputFormat::Json => render_json(&value),
        OutputFormat::Toon => render_toon_payload(&value),
    }
}

#[cfg(feature = "toon")]
fn render_toon_payload(value: &Json) -> String {
    render_toon(value)
}

#[cfg(not(feature = "toon"))]
fn render_toon_payload(value: &Json) -> String {
    render_json(value)
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

#[cfg(feature = "toon")]
fn render_toon(value: &Json) -> String {
    toon::encode(
        toon_json_value(value),
        Some(toon::EncodeOptions {
            indent: Some(1),
            delimiter: None,
            key_folding: None,
            flatten_depth: None,
            replacer: None,
        }),
    )
}

/// Rendered output from the shared CLI contract path.
///
/// MCP tools use this instead of reimplementing command behavior; the returned
/// `stdout` is exactly the deterministic envelope/body the CLI would print.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliContractOutput {
    /// Numeric process-style exit code.
    pub exit_code: i32,
    /// Rendered stdout payload, without the trailing newline the binary adds.
    pub stdout: String,
    /// Rendered diagnostic line, when the CLI would write one to stderr.
    pub stderr: Option<String>,
}

/// Execute the existing CLI command contract and render its body.
#[must_use]
pub fn execute_cli_contract(args: Vec<String>) -> CliContractOutput {
    let outcome = execute(args);
    let exit_code = outcome.status.code();
    match outcome.body {
        Body::Envelope { envelope, format } => {
            let stderr = if envelope.ok {
                None
            } else {
                Some(match &envelope.error {
                    Some(error) => format!("{}: {}", error.code.stable_code(), error.message),
                    None => format!(
                        "{}: command failed",
                        SnowflakeErrorCode::Internal.stable_code()
                    ),
                })
            };
            let stdout = render_envelope(&envelope, format);
            CliContractOutput {
                exit_code,
                stdout,
                stderr,
            }
        }
        Body::Raw { data } => CliContractOutput {
            exit_code,
            stdout: data,
            stderr: None,
        },
    }
}

#[cfg(feature = "mcp")]
mod mcp_surface;

#[cfg(feature = "mcp")]
pub use mcp_surface::run_mcp_serve_process;

#[cfg(feature = "live")]
mod live;

fn toon_output_available() -> bool {
    cfg!(feature = "toon")
}

fn mcp_surface_available() -> bool {
    cfg!(feature = "mcp")
}

// Feature flags must report what is ACTUALLY compiled into this binary, computed
// from this crate's own `cfg!`. Hardcoding them (the prior `false` literals) made
// `capabilities.feature_flags.live` lie when built `--features live`, so an agent
// reading capabilities would never attempt a live command that in fact works.
fn live_transport_available() -> bool {
    cfg!(feature = "live")
}

// Shared by `capabilities` and the `onboard` mega-command so the two surfaces
// can never drift on what this binary actually has compiled in. `live`/`mcp`/
// `toon` are real CLI-crate features (reported via `cfg!`); `testkit` and `tui`
// are NOT features of this binary — those surfaces live in sibling crates — so
// they are definitionally false for any `franken-snowflake`/`fsnow` build.
fn feature_flags_json() -> Json {
    json_object(vec![
        ("live", Json::Bool(live_transport_available())),
        ("testkit", Json::Bool(false)),
        ("mcp", Json::Bool(mcp_surface_available())),
        ("tui", Json::Bool(false)),
        ("toon", Json::Bool(toon_output_available())),
    ])
}

fn output_mode_usage() -> &'static str {
    if toon_output_available() {
        "franken-snowflake <command> [--json|--toon]"
    } else {
        "franken-snowflake <command> [--json]"
    }
}

#[cfg(feature = "toon")]
fn toon_json_value(value: &Json) -> toon::JsonValue {
    match value {
        Json::Null => toon::JsonValue::Primitive(toon::StringOrNumberOrBoolOrNull::Null),
        Json::Bool(value) => {
            toon::JsonValue::Primitive(toon::StringOrNumberOrBoolOrNull::Bool(*value))
        }
        Json::Number(value) => {
            toon::JsonValue::Primitive(toon::StringOrNumberOrBoolOrNull::Number(*value as f64))
        }
        Json::String(value) => {
            toon::JsonValue::Primitive(toon::StringOrNumberOrBoolOrNull::String(value.clone()))
        }
        Json::Array(values) => toon::JsonValue::Array(values.iter().map(toon_json_value).collect()),
        Json::Object(entries) => toon::JsonValue::Object(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_string(), toon_json_value(value)))
                .collect(),
        ),
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

    fn error_code_for(args: &[&str]) -> Option<&'static str> {
        match execute(args.iter().map(|arg| (*arg).to_string()).collect()).body {
            Body::Envelope { envelope, .. } => envelope.error.map(|error| error.code.stable_code()),
            Body::Raw { .. } => None,
        }
    }

    #[test]
    fn capabilities_lists_every_required_surface() {
        let rendered = render_json(&envelope_for(&["capabilities", "--json"]));
        assert!(rendered.contains("\"command_id\":\"capabilities\""));
        assert!(rendered.contains("\"command_id\":\"robot-docs.guide\""));
        assert!(rendered.contains("\"command_id\":\"agent-handbook\""));
        assert!(rendered.contains("\"command_id\":\"doctor\""));
        assert!(rendered.contains("\"command_id\":\"profile.validate\""));
        assert!(rendered.contains("\"command_id\":\"query.plan\""));
        assert!(rendered.contains("\"command_id\":\"query.run\""));
        assert!(rendered.contains("\"command_id\":\"query.cancel\""));
        assert!(rendered.contains("\"command_id\":\"mcp.serve\""));
        assert!(rendered.contains("franken-snowflake query [run] --profile"));
        if mcp_surface_available() {
            assert!(rendered.contains("\"mcp\":true"));
        } else {
            assert!(rendered.contains("\"mcp\":false"));
        }
        if toon_output_available() {
            assert!(rendered.contains("\"alternate_outputs\":[\"toon\"]"));
            assert!(rendered.contains("\"toon\":true"));
        } else {
            assert!(rendered.contains("\"alternate_outputs\":[]"));
            assert!(rendered.contains("\"toon\":false"));
        }
        assert!(rendered.contains("\"error_registry\""));
        assert!(rendered.contains("FSNOW-1002"));
    }

    // Regression for the `feature_flags` accuracy fix: the reported flags must
    // reflect what is actually compiled into THIS binary (via `cfg!`), never a
    // hardcoded literal. Previously `live`/`testkit`/`tui` were hardcoded
    // `false`, so a `--features live` build advertised `live:false` and an agent
    // would never attempt a live command that in fact works.
    #[test]
    fn capabilities_feature_flags_reflect_compiled_features() {
        let rendered = render_json(&envelope_for(&["capabilities", "--json"]));
        let expect = |flag: &str, on: bool| {
            assert!(
                rendered.contains(&format!("\"{flag}\":{on}")),
                "feature_flags.{flag} should be {on} for this build"
            );
        };
        expect("live", cfg!(feature = "live"));
        // testkit/tui are not features of the CLI binary — always false here.
        expect("testkit", false);
        expect("tui", false);
        expect("mcp", cfg!(feature = "mcp"));
        expect("toon", cfg!(feature = "toon"));
    }

    // Regression for the short-alias surface: capabilities advertises the
    // `fsnow` binary alias so an agent can discover the short form.
    #[test]
    fn capabilities_advertises_fsnow_alias() {
        let rendered = render_json(&envelope_for(&["capabilities", "--json"]));
        assert!(rendered.contains("\"binary_aliases\":[\"fsnow\"]"));
    }

    // Regression for the `onboard` mega-command: a single call must return every
    // orientation slice an agent would otherwise fetch across four round-trips
    // (feature flags, exit codes, first commands, command list, health), with a
    // success envelope and exit 0.
    #[test]
    fn onboard_returns_all_orientation_slices_in_one_call() {
        let outcome = execute(vec!["onboard".to_string(), "--json".to_string()]);
        assert_eq!(outcome.status.code(), 0, "onboard is read-only and must exit 0");
        let rendered = render_json(&envelope_for(&["onboard", "--json"]));
        assert!(rendered.contains("\"command_id\":\"onboard\""));
        assert!(rendered.contains("\"feature_flags\""));
        assert!(rendered.contains("\"exit_codes\""));
        assert!(rendered.contains("\"first_commands\""));
        assert!(rendered.contains("\"getting_started\""));
        assert!(rendered.contains("\"health\""));
        assert!(rendered.contains("\"binary_aliases\":[\"fsnow\"]"));
        // It is also discoverable from the registry and listed first.
        let caps = render_json(&envelope_for(&["capabilities", "--json"]));
        assert!(caps.contains("\"command_id\":\"onboard\""));
    }

    // a3y: the safety pre-check runs before any live dispatch, so these hold under
    // both builds. A typo'd SELECT is "unrecognized", NOT "multiple statements".
    #[test]
    fn query_run_distinguishes_multi_statement_from_unrecognized_sql() {
        let typo = render_json(&envelope_for(&["query", "run", "--profile", "demo", "--sql", "selcet 1"]));
        assert!(typo.contains("is the read path"));
        assert!(typo.contains("query write"));
        assert!(!typo.contains("Multiple SQL statements"));
        let multi = render_json(&envelope_for(&[
            "query", "run", "--profile", "demo", "--sql", "select 1; select 2",
        ]));
        assert!(multi.contains("Multiple SQL statements are refused"));
        assert!(!multi.contains("is the read path"));
    }

    // mfw: the refusal's next/repair command names the agent's real profile, not
    // the literal `<profile>` placeholder.
    #[test]
    fn query_refusal_interpolates_actual_profile_into_next_command() {
        let rendered = render_json(&envelope_for(&[
            "query", "run", "--profile", "demo", "--sql", "drop table t",
        ]));
        assert!(rendered.contains("--profile demo"));
        assert!(!rendered.contains("--profile <profile>"));
    }

    // ynp F6: clean local readiness is exit 0 so an agent can `doctor && proceed`.
    #[test]
    fn doctor_and_selftest_exit_zero_when_local_checks_pass() {
        assert_eq!(
            execute(vec!["doctor".to_string(), "--json".to_string()])
                .status
                .code(),
            0
        );
        assert_eq!(
            execute(vec!["selftest".to_string(), "--json".to_string()])
                .status
                .code(),
            0
        );
    }

    // ynp F4: a structurally-valid profile validates at exit 0; an invalid id is a
    // real finding at exit 1.
    #[test]
    fn profile_validate_exit_code_reflects_validity() {
        assert_eq!(
            execute(vec![
                "profile".to_string(),
                "validate".to_string(),
                "demo".to_string(),
                "--json".to_string(),
            ])
            .status
            .code(),
            0
        );
        assert_eq!(
            execute(vec![
                "profile".to_string(),
                "validate".to_string(),
                "bad!id".to_string(),
                "--json".to_string(),
            ])
            .status
            .code(),
            1
        );
    }

    // ynp F9: a reserved-but-unimplemented surface is a refusal (exit 2 / FSNOW-9002),
    // not an I/O fault (74).
    #[test]
    fn reserved_surfaces_refuse_with_exit_two_not_io() {
        let outcome = execute(vec!["export".to_string(), "plan".to_string(), "--json".to_string()]);
        assert_eq!(outcome.status.code(), 2);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("FSNOW-9002"));
    }

    // 1p1: the no-account build refuses `catalog graph` cleanly (live transport
    // required) instead of emitting the old empty-graph stub that an agent could
    // mistake for a real, empty catalog. Under `live` it renders from a real scan.
    #[cfg(not(feature = "live"))]
    #[test]
    fn catalog_graph_refuses_cleanly_without_live_transport() {
        let outcome = execute(vec![
            "catalog".to_string(),
            "graph".to_string(),
            "demo".to_string(),
            "--database".to_string(),
            "FRANKEN_TEST".to_string(),
            "--json".to_string(),
        ]);
        assert_ne!(outcome.status.code(), 0, "no-account catalog graph must refuse");
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("\"command_id\":\"catalog.graph\""));
        assert!(rendered.contains("live SQL API transport"));
        assert!(
            !rendered.contains("requires catalog scan fixtures"),
            "the misleading empty-graph stub must be gone"
        );
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
        assert!(rendered.contains("FSNOW-3002"));
    }

    fn top_level_profile_id(args: &[&str]) -> Option<String> {
        match execute(args.iter().map(|arg| (*arg).to_string()).collect()).body {
            Body::Envelope { envelope, .. } => envelope.profile_id,
            Body::Raw { .. } => None,
        }
    }

    #[test]
    fn successful_query_plan_and_catalog_graph_carry_top_level_profile_id() {
        // Regression: the envelope contract defines `profile_id` as "Profile
        // used". Previously the success paths for `query plan` and `catalog graph`
        // surfaced the profile only inside `data`, leaving the top-level field
        // null exactly when the command succeeded — while their refusal paths set
        // it — so an agent keyed on `profile_id` lost it on success.
        assert_eq!(
            top_level_profile_id(&["query", "plan", "--profile", "demo", "--sql", "select 1"]),
            Some("demo".to_string()),
            "query plan success must set top-level profile_id"
        );
        assert_eq!(
            top_level_profile_id(&["catalog", "graph", "demo", "--json"]),
            Some("demo".to_string()),
            "catalog graph success must set top-level profile_id"
        );
        // The refusal path already set it; success must agree, not diverge.
        assert_eq!(
            top_level_profile_id(&[
                "query",
                "plan",
                "--profile",
                "demo",
                "--sql",
                "delete from t"
            ]),
            Some("demo".to_string()),
            "query plan refusal still sets top-level profile_id"
        );
    }

    #[test]
    fn cte_fronted_selects_are_read_but_cte_fronted_dml_is_not() {
        assert!(is_select_like("with cte as (select 1) select * from cte"));
        assert!(is_select_like(
            "with recursive cte as (select 1) select * from cte"
        ));
        assert!(is_select_like(
            "with cte(id) as (select 1), c2 as (select id from cte) select * from c2"
        ));

        assert!(!is_select_like(
            "with cte as (select 1) delete from t using cte where t.id = cte.id"
        ));
        assert!(!is_select_like(
            "with cte as (select 1) update t set id = 2 from cte"
        ));
        assert!(!is_select_like(
            "with cte as (select 1) insert into t select * from cte"
        ));
        assert!(!is_select_like(
            "with cte as (select 1) merge into t using cte on t.id = cte.id"
        ));
    }

    #[test]
    fn sql_keyword_scan_is_panic_free_on_non_ascii_input() {
        // `consume_sql_keyword` sliced a fixed byte length; a multi-byte char
        // straddling that offset panicked (`end byte index N is not a char
        // boundary`). These must all return cleanly, never abort the process.
        for sql in [
            "€€",
            "x€€ from t",
            "naïve select",
            "  /* π */ select 1",
            "señor",
            "用户 select",
        ] {
            // The point is the absence of a panic; the boolean is incidental.
            let _ = is_select_like(sql);
            let _ = has_multiple_statements(sql);
        }
        // A leading multi-byte run is not SELECT-like, and a genuine select with
        // a non-ASCII tail still parses as read.
        assert!(!is_select_like("€€ select"));
        assert!(is_select_like("select 'café' as c"));
    }

    #[test]
    fn has_multiple_statements_ignores_semicolons_in_strings_and_comments() {
        // A semicolon inside a string literal, a `--` line comment, or a `/* */`
        // block comment is NOT a statement separator; a single read statement that
        // happens to contain one must not be refused as multi-statement.
        for sql in [
            "select 1",
            "select 1;",
            "select 1 ;  ",
            "select ';'",
            "where name = 'a;b'",
            "select 1 -- trailing; comment",
            "select /* a; b */ 1",
            "select 1; -- trailing comment only",
            "select \"weird;col\" from t",
        ] {
            assert!(
                !has_multiple_statements(sql),
                "single statement wrongly flagged as multiple: {sql:?}"
            );
        }
        // Genuine separators (real content after a top-level `;`, or an empty
        // statement) must still be detected.
        for sql in [
            "select 1; select 2",
            "select 1;;",
            "select 1; -- c\nselect 2",
            "insert into t values (1); select 1",
        ] {
            assert!(
                has_multiple_statements(sql),
                "multiple statements not detected: {sql:?}"
            );
        }
    }

    #[cfg(feature = "toon")]
    #[test]
    fn toon_renderer_uses_same_envelope_keys() {
        let envelope = envelope_for(&["agent-handbook", "--toon"]);
        let rendered = render_toon(&envelope);
        assert!(rendered.contains("ok: true"));
        assert!(rendered.contains("output_contract_id: fsnow.agent_handbook.v1"));
        assert!(rendered.contains("schema_version: fsnow.envelope.v1"));
        assert!(rendered.contains("exit_codes["));
        assert!(rendered.contains("error_registry["));
        assert!(!rendered.contains("\"ok\""));
    }

    #[cfg(feature = "toon")]
    #[test]
    fn toon_output_round_trips_to_same_logical_envelope() {
        let envelope = envelope_for(&["capabilities", "--json"]);
        let rendered = render_toon(&envelope);
        let decoded = toon::try_decode(
            &rendered,
            Some(toon::DecodeOptions {
                indent: Some(1),
                strict: Some(true),
                expand_paths: None,
            }),
        )
        .expect("toon decodes");
        assert_eq!(decoded, toon_json_value(&envelope));
    }

    #[cfg(feature = "toon")]
    #[test]
    fn toon_output_is_smaller_for_large_agent_payload() {
        let envelope = envelope_for(&["capabilities", "--json"]);
        let rendered_json = render_json(&envelope);
        let rendered_toon = render_toon(&envelope);
        assert!(
            rendered_toon.len() < rendered_json.len(),
            "TOON should be smaller than JSON for capabilities: toon={}, json={}",
            rendered_toon.len(),
            rendered_json.len()
        );
    }

    #[test]
    fn query_plan_redacts_secret_shaped_sql_preview() {
        let rendered = render_json(&envelope_for(&[
            "query",
            "plan",
            "--profile",
            "demo",
            "--sql",
            "select * from t where token = 'ghp_realSecret0123'",
        ]));
        assert!(rendered.contains("\"normalized_sql_preview\""));
        assert!(rendered.contains("[REDACTED]"));
        assert!(rendered.contains("\"redactions_applied\":[\"core.redact\"]"));
        assert!(!rendered.contains("ghp_realSecret0123"));
    }

    #[test]
    fn unknown_flag_redacts_secret_shaped_value_in_message_and_evidence() {
        let rendered = render_json(&envelope_for(&["doctor", "--tokn=ghp_realSecret0123"]));
        assert!(rendered.contains("Unknown flag `--tokn=[REDACTED]`."));
        assert!(rendered.contains("\"flag=--tokn=[REDACTED]\""));
        assert!(rendered.contains("\"redactions_applied\":[\"core.redact\"]"));
        assert!(!rendered.contains("ghp_realSecret0123"));
    }

    #[test]
    fn did_you_mean_catches_near_miss() {
        let suggestions = did_you_mean("capabilties", &["capabilities", "catalog"]);
        assert_eq!(suggestions, vec!["capabilities".to_string()]);
    }

    // Regression: the new top-level `onboard` verb must be a did_you_mean
    // candidate, so a typo suggests it like every other command.
    #[test]
    fn onboard_typo_suggests_onboard() {
        let outcome = execute(vec!["onbord".to_string(), "--json".to_string()]);
        assert_eq!(outcome.status.code(), 64);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("\"did_you_mean\":[\"onboard\"]"));
    }

    #[test]
    fn unknown_flag_teaches_json_typo() {
        let outcome = execute(vec!["capabilities".to_string(), "--jsno".to_string()]);
        assert_eq!(outcome.status.code(), 64);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("FSNOW-1002"));
        assert!(rendered.contains("--json"));
    }

    #[test]
    fn missing_global_flag_value_cannot_swallow_following_flags() {
        let outcome = execute(vec![
            "capabilities".to_string(),
            "--profile".to_string(),
            "--bogus".to_string(),
        ]);
        assert_eq!(outcome.status.code(), 64);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("Missing value for `--profile`."));
        assert!(!rendered.contains("\"command_id\":\"capabilities\""));
    }

    #[test]
    fn help_value_is_not_misparsed_as_global_help() {
        let profile_validate = render_json(&envelope_for(&["profile", "validate", "help"]));
        assert!(profile_validate.contains("\"command_id\":\"profile.validate\""));
        assert!(profile_validate.contains("\"profile_id\":\"help\""));
        assert!(!profile_validate.contains("\"command_id\":\"help\""));

        let query_plan = render_json(&envelope_for(&[
            "query",
            "plan",
            "--profile",
            "help",
            "--sql",
            "select 1",
        ]));
        assert!(query_plan.contains("\"command_id\":\"query.plan\""));
        assert!(query_plan.contains("\"profile_id\":\"help\""));
        assert!(!query_plan.contains("\"command_id\":\"help\""));
    }

    #[cfg(feature = "toon")]
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

    #[cfg(not(feature = "toon"))]
    #[test]
    fn toon_requests_return_json_feature_refusal_when_encoder_is_absent() {
        let output = execute_cli_contract(vec!["capabilities".to_string(), "--toon".to_string()]);

        assert_eq!(output.exit_code, CoreExitCode::Usage.code());
        assert!(output.stdout.starts_with("{\"ok\":false"));
        assert!(output.stdout.contains("\"command_id\":\"help\""));
        assert!(output.stdout.contains("\"feature_enabled\":false"));
        assert!(output.stdout.contains("\"context\":\"toon\""));
        assert!(output.stdout.contains("TOON output is feature-gated"));
        assert_eq!(
            output.stderr.as_deref(),
            Some(
                "FSNOW-1002: TOON output is feature-gated and not linked in this CLI build; retry with --json or rebuild with the `toon` feature."
            )
        );
    }

    #[test]
    fn catalog_graph_rejects_conflicting_output_formats() {
        let mermaid_svg = execute(vec![
            "catalog".to_string(),
            "graph".to_string(),
            "demo".to_string(),
            "--mermaid".to_string(),
            "--svg".to_string(),
        ]);
        assert_eq!(mermaid_svg.status.code(), 64);
        let rendered = match mermaid_svg.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("Conflicting catalog graph output formats"));
        assert!(
            rendered.contains("franken-snowflake catalog graph &lt;profile&gt; --toon")
                || rendered.contains("franken-snowflake catalog graph <profile> --toon")
        );

        let json_mermaid = execute(vec![
            "catalog".to_string(),
            "graph".to_string(),
            "demo".to_string(),
            "--json".to_string(),
            "--mermaid".to_string(),
        ]);
        assert_eq!(json_mermaid.status.code(), 64);
        let rendered = match json_mermaid.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("Conflicting catalog graph output formats"));
        assert!(!rendered.starts_with("graph TD"));

        let toon_mermaid = execute(vec![
            "catalog".to_string(),
            "graph".to_string(),
            "demo".to_string(),
            "--toon".to_string(),
            "--mermaid".to_string(),
        ]);
        assert_eq!(toon_mermaid.status.code(), 64);
        match toon_mermaid.body {
            Body::Envelope { format, .. } => assert_eq!(format, OutputFormat::Toon),
            Body::Raw { .. } => panic!("conflicting graph output must return an envelope"),
        }
    }

    // No-account build: `query run` reaches the local-safety-check stub. Under the
    // `live` feature this same invocation drives the real transport instead, so the
    // assertion is gated and a `live` companion below covers that lane.
    #[cfg(not(feature = "live"))]
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

    // Live build, credential-less profile: `query` shorthand still maps to the run
    // surface, but with no creds it must produce a typed refusal/error and NEVER
    // substitute fixture/empty data (`data_source:live` only appears on a real
    // success). This runs without network because credential resolution fails first.
    #[cfg(feature = "live")]
    #[test]
    fn query_shorthand_maps_to_run_surface_live() {
        let outcome = execute(vec![
            "query".to_string(),
            "--profile".to_string(),
            "no_creds_profile".to_string(),
            "--sql".to_string(),
            "select 1".to_string(),
        ]);
        assert_ne!(outcome.status.code(), 0, "credential-less run must not succeed");
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("\"command_id\":\"query.run\""));
        assert!(
            !rendered.contains("\"data_source\":\"live\""),
            "must never claim live data without credentials (no fixture substitution)"
        );
        assert!(rendered.contains("\"ok\":false"));
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
        // The recovery hint now also points at the env-var fallback.
        assert!(rendered.contains("FRANKEN_SNOWFLAKE_DEFAULT_PROFILE"));
    }

    // FRANKEN_SNOWFLAKE_DEFAULT_PROFILE resolution policy. The env read is behind
    // `default_profile_env`; the precedence itself is tested here as the pure
    // `resolve_profile_with` (edition 2024 forbids `env::set_var` in tests, so we
    // never mutate the process environment).
    #[test]
    fn resolve_profile_prefers_explicit_over_env() {
        assert_eq!(
            resolve_profile_with(Some("explicit".to_string()), Some("env".to_string())),
            Some("explicit".to_string()),
            "an explicit --profile/positional value always wins over the env default"
        );
        assert_eq!(
            resolve_profile_with(Some("explicit".to_string()), None),
            Some("explicit".to_string())
        );
        // `resolve_profile` itself returns the explicit value without consulting
        // the environment at all.
        assert_eq!(
            resolve_profile(Some("explicit".to_string())),
            Some("explicit".to_string())
        );
    }

    #[test]
    fn resolve_profile_falls_back_to_env_when_explicit_absent() {
        assert_eq!(
            resolve_profile_with(None, Some("env-default".to_string())),
            Some("env-default".to_string()),
            "FRANKEN_SNOWFLAKE_DEFAULT_PROFILE is used when --profile is omitted"
        );
    }

    #[test]
    fn resolve_profile_returns_none_when_both_absent() {
        assert_eq!(
            resolve_profile_with(None, None),
            None,
            "no explicit profile and no env default routes into the typed Missing-profile error"
        );
    }

    // No-account build: `catalog scan` reaches the stub that echoes
    // `requested_database`. Under `live` the same flags drive a real scan, so the
    // catalog-scan assertions are gated; the `live` companion checks the parser
    // (the part that is feature-independent) instead.
    #[cfg(not(feature = "live"))]
    #[test]
    fn equals_style_flags_are_read_by_command_parsers() {
        let rendered = render_json(&envelope_for(&[
            "query",
            "plan",
            "--profile=demo",
            "--sql=select 1",
        ]));
        assert!(rendered.contains("\"command_id\":\"query.plan\""));
        assert!(rendered.contains("\"ok\":true"));
        assert!(rendered.contains("\"normalized_sql_preview\":\"select 1\""));
        assert!(!rendered.contains("Missing --profile"));
        assert!(!rendered.contains("Missing --sql"));

        let outcome = execute(vec![
            "catalog".to_string(),
            "scan".to_string(),
            "demo".to_string(),
            "--database=ANALYTICS".to_string(),
            "--schema=PUBLIC".to_string(),
        ]);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("\"requested_database\":\"ANALYTICS\""));
        assert!(rendered.contains("\"requested_schema\":\"PUBLIC\""));
        assert!(!rendered.contains("Missing --database"));
        assert!(!rendered.contains("Missing --schema"));
    }

    // Live build: equals-style flag parsing is feature-independent — `query plan`
    // (offline under both builds) proves `--profile=`/`--sql=` are read, and
    // `catalog scan` with credential-less flags is parsed (no "Missing --database")
    // before refusing cleanly without fixture substitution.
    #[cfg(feature = "live")]
    #[test]
    fn equals_style_flags_are_read_by_command_parsers_live() {
        let rendered = render_json(&envelope_for(&[
            "query",
            "plan",
            "--profile=demo",
            "--sql=select 1",
        ]));
        assert!(rendered.contains("\"command_id\":\"query.plan\""));
        assert!(rendered.contains("\"ok\":true"));
        assert!(rendered.contains("\"normalized_sql_preview\":\"select 1\""));

        let outcome = execute(vec![
            "catalog".to_string(),
            "scan".to_string(),
            "no_creds_profile".to_string(),
            "--database=ANALYTICS".to_string(),
            "--schema=PUBLIC".to_string(),
        ]);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        // Parsed (not a usage error about missing flags) and never fixture-backed.
        assert!(!rendered.contains("Missing --database"));
        assert!(!rendered.contains("Missing --schema"));
        assert!(!rendered.contains("\"data_source\":\"live\""));
    }

    #[test]
    fn missing_flag_value_is_not_swallowed_from_next_flag() {
        let outcome = execute(vec![
            "query".to_string(),
            "plan".to_string(),
            "--profile".to_string(),
            "--sql".to_string(),
            "select 1".to_string(),
        ]);
        assert_eq!(outcome.status.code(), 64);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("Missing value for `--profile`."));
        assert!(!rendered.contains("\"profile_id\":\"--sql\""));
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
    fn mcp_serve_rejects_missing_http_address_and_conflicting_modes() {
        let missing_addr = execute(vec![
            "mcp".to_string(),
            "serve".to_string(),
            "--http".to_string(),
        ]);
        assert_eq!(missing_addr.status.code(), 64);
        let rendered = match missing_addr.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("Missing address for `mcp serve --http`."));
        assert!(!rendered.contains("\"context\":null"));

        let conflicting = execute(vec![
            "mcp".to_string(),
            "serve".to_string(),
            "--stdio".to_string(),
            "--http".to_string(),
            "127.0.0.1:3000".to_string(),
        ]);
        assert_eq!(conflicting.status.code(), 64);
        let rendered = match conflicting.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("Conflicting MCP serve modes"));
    }

    #[test]
    fn profile_validate_is_offline_and_secret_safe() {
        let outcome = execute(vec![
            "profile".to_string(),
            "validate".to_string(),
            "demo-prod".to_string(),
        ]);
        // ynp F4: a structurally-valid profile validates at exit 0 (the
        // "registry not linked" scope note is informational, not a finding).
        assert_eq!(outcome.status.code(), 0);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("\"command_id\":\"profile.validate\""));
        assert!(rendered.contains("\"profile_registry_linked\":false"));
        assert!(rendered.contains("\"secret_values_read\":false"));
        assert!(rendered.contains("FRANKEN_SNOWFLAKE_DEMO_PROD_PAT"));
    }

    // No-account build: `profile doctor --online` records the request but never
    // probes. Under `live` the same flag drives a real probe, so this is gated and
    // a `live` companion below covers the credential-less refusal lane.
    #[cfg(not(feature = "live"))]
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

    // Live build, credential-less profile: `profile doctor --online` must refuse
    // cleanly (typed error, no fixture, no network — credential resolution fails
    // before any I/O). Robust invariants only, so the test is stable across the
    // exact error code.
    #[cfg(feature = "live")]
    #[test]
    fn profile_doctor_online_refuses_without_credentials_live() {
        let outcome = execute(vec![
            "profile".to_string(),
            "doctor".to_string(),
            "no_creds_profile".to_string(),
            "--online".to_string(),
        ]);
        let rendered = match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        };
        assert!(rendered.contains("\"command_id\":\"profile.doctor\""));
        assert!(
            !rendered.contains("\"data_source\":\"live\""),
            "must not claim live data without credentials"
        );
    }

    #[test]
    fn profile_doctor_reports_lifetime_warnings_without_secret_values() {
        let rendered = render_json(&envelope_for(&["profile", "doctor", "demo-prod"]));
        assert!(rendered.contains("\"credential_lifetime_warnings\""));
        assert!(rendered.contains("programmatic_access_token"));
        assert!(rendered.contains("15-day lifetime"));
        assert!(rendered.contains("key_pair_jwt"));
        assert!(rendered.contains("one-hour cap"));
        assert!(rendered.contains("oauth_bearer_token"));
        assert!(rendered.contains("roughly 10-minute lifetime"));
        assert!(rendered.contains("\"secret_values_read\":false"));
        assert!(!rendered.contains("snowflake_pat_"));
        assert!(!rendered.contains("BEGIN PRIVATE KEY"));
        assert!(!rendered.contains("eyJ"));
    }

    #[test]
    fn selftest_reports_redaction_and_debug_gate_linkage() {
        let rendered = render_json(&envelope_for(&["selftest", "--json"]));
        assert!(rendered.contains("\"command_id\":\"selftest\""));
        assert!(rendered.contains("\"name\":\"secret_redaction\""));
        assert!(rendered.contains("\"name\":\"credential_debug_gate\""));
        assert!(rendered.contains("\"status\":\"pass\""));
    }

    #[test]
    fn query_cancel_surface_is_versioned_and_stable() {
        let rendered = render_json(&envelope_for(&["query", "cancel", "01bcaafe-0000"]));
        assert!(rendered.contains("\"command_id\":\"query.cancel\""));
        assert!(rendered.contains("\"output_contract_id\":\"fsnow.query.cancel.v1\""));
        assert!(rendered.contains("\"statement_handle\":\"01bcaafe-0000\""));
        assert!(rendered.contains("FSNOW-3003"));
    }

    #[test]
    fn operator_schema_uses_json_schema_type_array() {
        let rendered = render_json(&envelope_for(&["dataset", "describe-operator", "between"]));
        assert!(rendered.contains("\"type\":[\"number\",\"string\"]"));
    }

    #[test]
    fn error_registry_entries_have_default_recovery() {
        for code in SnowflakeErrorCode::ALL {
            let entry = code.entry();
            assert!(!entry.safe_next_commands.is_empty());
            assert!(!entry.repair_commands.is_empty());
            assert_eq!(
                SnowflakeErrorCode::from_stable_code(entry.stable_code),
                Some(*code)
            );
        }
    }

    #[test]
    fn cli_error_codes_resolve_against_core_registry() {
        let emitted_codes = [
            error_code_for(&["capabilties"]).expect("unknown command emits error"),
            error_code_for(&["capabilities", "--jsno"]).expect("unknown flag emits error"),
            error_code_for(&[
                "query",
                "plan",
                "--profile",
                "demo",
                "--sql",
                "select 1; select 2",
            ])
            .expect("multi-statement refusal emits error"),
            error_code_for(&["dataset", "describe-operator", "bogus"])
                .expect("unknown operator emits error"),
        ];

        for code in emitted_codes {
            assert!(
                SnowflakeErrorCode::from_stable_code(code).is_some(),
                "{code} did not resolve against core registry"
            );
        }

        for code in error_codes() {
            assert!(
                SnowflakeErrorCode::from_stable_code(&code).is_some(),
                "{code} from CLI registry did not resolve against core registry"
            );
        }
    }

    fn render_outcome(outcome: Outcome) -> String {
        match outcome.body {
            Body::Envelope { envelope, .. } => render_json(&envelope_json(&envelope)),
            Body::Raw { data } => data,
        }
    }

    fn enabled_write_policy(
        kind: WriteStatementKind,
        require_confirmation: bool,
    ) -> WriteIntentPolicy {
        WriteIntentPolicy {
            enabled: true,
            allow_ddl: false,
            require_dry_run: true,
            require_exact_confirmation: require_confirmation,
            require_idempotency_request_id: true,
            require_append_only_audit: false,
            statement_allowlist: vec![StatementAllowlistEntry::new(cli_allowlist_id(kind), kind)],
        }
    }

    fn dry_run_insert_plan() -> WriteIntentPlan {
        let policy = enabled_write_policy(WriteStatementKind::Insert, true);
        let mut req =
            WriteIntentRequest::new(WriteIntentMode::PlanDryRun, "insert into t values (1)");
        req.dry_run = true;
        req.allowlist_id = Some(cli_allowlist_id(WriteStatementKind::Insert));
        req.request_id = Some(RequestId::new("plan-req"));
        match evaluate_write_intent(&req, &policy) {
            WriteIntentDecision::DryRunPlanned { plan } => plan,
            other => panic!("expected a dry-run plan, got {other:?}"),
        }
    }

    fn authorized_insert_plan() -> WriteIntentPlan {
        let policy = enabled_write_policy(WriteStatementKind::Insert, false);
        let mut req =
            WriteIntentRequest::new(WriteIntentMode::PrepareExecution, "insert into t values (1)");
        req.dry_run = true;
        req.allowlist_id = Some(cli_allowlist_id(WriteStatementKind::Insert));
        req.request_id = Some(RequestId::new("exec-req"));
        match evaluate_write_intent(&req, &policy) {
            WriteIntentDecision::ExecutionAuthorized { plan } => plan,
            other => panic!("expected execution authorization, got {other:?}"),
        }
    }

    #[test]
    fn query_write_requires_profile_and_sql() {
        let missing_profile = execute(vec![
            "query".to_string(),
            "write".to_string(),
            "--sql".to_string(),
            "insert into t values (1)".to_string(),
            "--dry-run".to_string(),
        ]);
        assert_eq!(missing_profile.status.code(), 64);
        assert!(render_outcome(missing_profile).contains("Missing --profile for `query write`."));

        let missing_sql = execute(vec![
            "query".to_string(),
            "write".to_string(),
            "--profile".to_string(),
            "demo".to_string(),
            "--dry-run".to_string(),
        ]);
        assert_eq!(missing_sql.status.code(), 64);
        assert!(render_outcome(missing_sql).contains("Missing --sql for `query write`."));
    }

    // A bare `query write` (no --dry-run, no --confirm) is no longer a usage error:
    // it routes straight into the write-intent ladder. For a profile with no
    // WRITE_ENABLED handle (the distinctive id avoids colliding with a real env
    // var) the ladder emits the typed WriteDisabled refusal, never a fake execution.
    #[test]
    fn query_write_bare_invocation_routes_into_ladder() {
        let bare = execute(vec![
            "query".to_string(),
            "write".to_string(),
            "--profile".to_string(),
            "wmode_off_xyz".to_string(),
            "--sql".to_string(),
            "insert into t values (1)".to_string(),
        ]);
        assert_eq!(bare.status.code(), 2, "bare write routes to the ladder, not a usage error");
        let rendered = render_outcome(bare);
        assert!(rendered.contains("FSNOW-3007"), "disabled profile -> WriteDisabled");
        assert!(!rendered.contains("\"data_source\":\"live\""));
    }

    #[test]
    fn query_write_rejects_both_mode_flags() {
        let both = execute(vec![
            "query".to_string(),
            "write".to_string(),
            "--profile".to_string(),
            "demo".to_string(),
            "--sql".to_string(),
            "insert into t values (1)".to_string(),
            "--dry-run".to_string(),
            "--confirm".to_string(),
            "confirm:insert:abc".to_string(),
        ]);
        assert_eq!(both.status.code(), 64);
        assert!(render_outcome(both).contains("not both"));
    }

    #[test]
    fn query_write_points_reads_to_query_run() {
        let outcome = execute(vec![
            "query".to_string(),
            "write".to_string(),
            "--profile".to_string(),
            "demo".to_string(),
            "--sql".to_string(),
            "select 1".to_string(),
            "--dry-run".to_string(),
        ]);
        assert_eq!(outcome.status.code(), 64);
        let rendered = render_outcome(outcome);
        assert!(rendered.contains("expects a mutating statement"));
        assert!(rendered.contains("franken-snowflake query run"));
    }

    #[test]
    fn query_write_refuses_multi_statement() {
        let outcome = execute(vec![
            "query".to_string(),
            "write".to_string(),
            "--profile".to_string(),
            "demo".to_string(),
            "--sql".to_string(),
            "insert into t values (1); insert into t values (2)".to_string(),
            "--dry-run".to_string(),
        ]);
        assert_eq!(outcome.status.code(), 2);
        assert!(render_outcome(outcome).contains("FSNOW-3002"));
    }

    // A profile with no WRITE_ENABLED handle (the default) cannot even plan a
    // write: the ladder refuses with the typed WriteDisabled code. The profile id
    // is distinctive so the test never collides with a real env handle.
    #[test]
    fn query_write_refuses_when_profile_not_write_enabled() {
        let outcome = execute(vec![
            "query".to_string(),
            "write".to_string(),
            "--profile".to_string(),
            "wcap_off_xyz".to_string(),
            "--sql".to_string(),
            "insert into t values (1)".to_string(),
            "--dry-run".to_string(),
        ]);
        assert_eq!(outcome.status.code(), 2);
        let rendered = render_outcome(outcome);
        assert!(rendered.contains("FSNOW-3007"));
        assert!(rendered.contains("\"command_id\":\"query.write\""));
        assert!(rendered.contains("WRITE_ENABLED"));
        assert!(
            !rendered.contains("\"data_source\":\"live\""),
            "a disabled-write refusal must never claim live data"
        );
    }

    // The default once WRITE_ENABLED=true (no WRITE_REQUIRE_CONFIRM): a direct
    // PrepareExecution write with no dry-run and no confirmation token reaches
    // ExecutionAuthorized. This is the frictionless-by-default path.
    #[test]
    fn write_policy_default_authorizes_direct_execution() {
        let policy = write_policy_from_flags(true, false, false, WriteStatementKind::Insert);
        assert!(!policy.require_dry_run);
        assert!(!policy.require_exact_confirmation);
        let mut req =
            WriteIntentRequest::new(WriteIntentMode::PrepareExecution, "insert into t values (1)");
        req.dry_run = true;
        req.allowlist_id = Some(cli_allowlist_id(WriteStatementKind::Insert));
        req.request_id = Some(RequestId::new("direct-req"));
        // No confirmation token supplied — the default path needs none.
        let decision = evaluate_write_intent(&req, &policy);
        assert!(
            matches!(decision, WriteIntentDecision::ExecutionAuthorized { .. }),
            "write-enabled default profile must authorize a direct write, got {decision:?}"
        );
    }

    // WRITE_REQUIRE_CONFIRM=true restores the dry-run -> confirm ceremony: a direct
    // PrepareExecution write with no token is refused (MissingConfirmationToken), and
    // only the exact token authorizes execution.
    #[test]
    fn write_policy_require_confirm_restores_confirmation_requirement() {
        let policy = write_policy_from_flags(true, false, true, WriteStatementKind::Insert);
        assert!(policy.require_dry_run);
        assert!(policy.require_exact_confirmation);
        let mut req =
            WriteIntentRequest::new(WriteIntentMode::PrepareExecution, "insert into t values (1)");
        req.dry_run = true;
        req.allowlist_id = Some(cli_allowlist_id(WriteStatementKind::Insert));
        req.request_id = Some(RequestId::new("confirm-req"));

        let refused = evaluate_write_intent(&req, &policy);
        assert!(
            matches!(
                refused,
                WriteIntentDecision::Refused {
                    refusal: WriteIntentRefusal {
                        code: WriteIntentRefusalCode::MissingConfirmationToken,
                        ..
                    }
                }
            ),
            "require-confirm profile must refuse a token-less direct write, got {refused:?}"
        );

        req.confirmation_token = Some(ConfirmationToken::for_request(
            &RequestId::new("confirm-req"),
            WriteStatementKind::Insert,
        ));
        let authorized = evaluate_write_intent(&req, &policy);
        assert!(
            matches!(authorized, WriteIntentDecision::ExecutionAuthorized { .. }),
            "the exact confirmation token must authorize execution, got {authorized:?}"
        );
    }

    #[test]
    fn write_policy_from_flags_maps_handles() {
        let off = write_policy_from_flags(false, false, false, WriteStatementKind::Insert);
        assert!(!off.enabled);
        assert!(!off.allow_ddl);
        assert!(!off.require_dry_run);
        assert!(!off.require_exact_confirmation);
        assert!(!off.require_append_only_audit);

        let strict = write_policy_from_flags(true, true, true, WriteStatementKind::Create);
        assert!(strict.enabled);
        assert!(strict.allow_ddl);
        assert!(strict.require_dry_run);
        assert!(strict.require_exact_confirmation);
        assert!(!strict.require_append_only_audit);
    }

    #[test]
    fn write_plan_outcome_emits_confirmation_token_and_executes_nothing() {
        let plan = dry_run_insert_plan();
        let token = plan.required_confirmation_token.as_str().to_string();
        let outcome = write_plan_outcome(
            OutputFormat::Json,
            "req-test".to_string(),
            "demo".to_string(),
            &plan,
        );
        assert_eq!(outcome.status.code(), 0);
        let rendered = render_outcome(outcome);
        assert!(rendered.contains("\"command_id\":\"query.write\""));
        assert!(rendered.contains("\"ok\":true"));
        assert!(rendered.contains("\"execution_enabled\":false"));
        assert!(rendered.contains("\"will_submit\":false"));
        assert!(rendered.contains("\"statement_kind\":\"insert\""));
        assert!(rendered.contains("\"required_confirmation_token\""));
        assert!(rendered.contains(&token));
        assert!(rendered.contains("--confirm"));
    }

    // No-account build: an authorized write has nothing to run it, so it refuses
    // cleanly with the typed live-transport-required code instead of pretending to
    // execute or emitting fixture data.
    #[cfg(not(feature = "live"))]
    #[test]
    fn authorized_write_without_live_transport_refuses_cleanly() {
        let plan = authorized_insert_plan();
        let outcome = query_write_execute_dispatch(
            OutputFormat::Json,
            "req-test".to_string(),
            "demo".to_string(),
            "insert into t values (1)",
            &plan,
        );
        assert_ne!(outcome.status.code(), 0, "no-transport build must refuse");
        let rendered = render_outcome(outcome);
        assert!(rendered.contains("\"command_id\":\"query.write\""));
        assert!(rendered.contains("FSNOW-3003"));
        assert!(rendered.contains("live SQL API transport"));
        assert!(rendered.contains("\"write_intent_authorized\":true"));
        assert!(!rendered.contains("\"data_source\":\"live\""));
    }

    // Live build, credential-less profile: the executor IS reachable behind the
    // `live` cfg, but with no credentials it must produce a typed error and never
    // claim live data. Credential resolution fails before any network I/O.
    #[cfg(feature = "live")]
    #[test]
    fn authorized_write_without_credentials_refuses_cleanly_live() {
        let plan = authorized_insert_plan();
        let outcome = query_write_execute_dispatch(
            OutputFormat::Json,
            "req-test".to_string(),
            "no_creds_profile".to_string(),
            "insert into t values (1)",
            &plan,
        );
        assert_ne!(outcome.status.code(), 0, "credential-less write must not succeed");
        let rendered = render_outcome(outcome);
        assert!(rendered.contains("\"command_id\":\"query.write\""));
        assert!(rendered.contains("\"ok\":false"));
        assert!(
            !rendered.contains("\"data_source\":\"live\""),
            "must never claim live data without credentials"
        );
    }

    #[test]
    fn capabilities_lists_query_write_and_typed_write_codes() {
        let rendered = render_json(&envelope_for(&["capabilities", "--json"]));
        assert!(rendered.contains("\"command_id\":\"query.write\""));
        assert!(rendered.contains("FSNOW-3007"));
        assert!(rendered.contains("FSNOW-3008"));
        assert!(rendered.contains("FSNOW-3009"));
    }

    #[test]
    fn write_refusal_codes_resolve_against_core_registry() {
        for refusal_code in [
            WriteIntentRefusalCode::MutationsDisabled,
            WriteIntentRefusalCode::MissingDryRun,
            WriteIntentRefusalCode::DdlRefused,
            WriteIntentRefusalCode::StatementNotAllowlisted,
            WriteIntentRefusalCode::MissingIdempotencyRequestId,
            WriteIntentRefusalCode::MissingConfirmationToken,
            WriteIntentRefusalCode::ConfirmationTokenMismatch,
            WriteIntentRefusalCode::MissingAppendOnlyAudit,
            WriteIntentRefusalCode::ExecutionUnavailable,
        ] {
            let code = write_refusal_code(refusal_code);
            assert!(
                SnowflakeErrorCode::from_stable_code(code.stable_code()).is_some(),
                "{refusal_code:?} mapped to an unregistered code"
            );
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
