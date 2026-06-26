//! Feature-gated MCP server surface for franken_snowflake.
//!
//! `franken-snowflake mcp serve [--stdio | --http <addr>]` exposes read verbs as
//! MCP tools. This crate stays a thin adapter: callers inject the CLI contract
//! runner, and every tool returns that runner's deterministic stdout payload.

/// Marker for builds that omit the optional MCP server dependency graph.
pub const MCP_SURFACE_STATUS: &str = "feature-gated: enable the `mcp` feature";

/// Rendered output from the shared CLI contract path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliContractOutput {
    /// Numeric process-style exit code.
    pub exit_code: i32,
    /// Rendered stdout payload, without the trailing newline the binary adds.
    pub stdout: String,
    /// Rendered diagnostic line, when the CLI would write one to stderr.
    pub stderr: Option<String>,
}

/// Minimal contract this adapter needs from the CLI crate.
pub trait CliContractRunner: Send + Sync {
    /// Execute one CLI command invocation and render its contract output.
    fn run_cli_contract(&self, args: Vec<String>) -> CliContractOutput;
}

impl<F> CliContractRunner for F
where
    F: Fn(Vec<String>) -> CliContractOutput + Send + Sync,
{
    fn run_cli_contract(&self, args: Vec<String>) -> CliContractOutput {
        self(args)
    }
}

#[cfg(feature = "mcp")]
mod fastmcp_surface {
    use std::sync::Arc;

    use fastmcp_rust::{
        Content, McpContext, McpError, McpErrorCode, McpResult, Server, Tool, ToolAnnotations,
        ToolHandler,
    };
    use franken_snowflake_core::{error::SnowflakeErrorCode, redact::redact};
    use serde_json::{Map, Value, json};

    use super::{CliContractOutput, CliContractRunner};

    const SERVER_NAME: &str = "franken-snowflake";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReadVerb {
        Capabilities,
        Doctor,
        AgentHandbook,
        RobotDocsGuide,
        Selftest,
        ProfileValidate,
        ProfileDoctor,
        CatalogScan,
        CatalogGraph,
        DatasetInspect,
        DatasetProfile,
        DatasetDescribeOperator,
        QueryPlan,
        QueryRun,
        QueryCancel,
        ReceiptShow,
        ExportPlan,
    }

    const READ_VERBS: &[ReadVerb] = &[
        ReadVerb::Capabilities,
        ReadVerb::Doctor,
        ReadVerb::AgentHandbook,
        ReadVerb::RobotDocsGuide,
        ReadVerb::Selftest,
        ReadVerb::ProfileValidate,
        ReadVerb::ProfileDoctor,
        ReadVerb::CatalogScan,
        ReadVerb::CatalogGraph,
        ReadVerb::DatasetInspect,
        ReadVerb::DatasetProfile,
        ReadVerb::DatasetDescribeOperator,
        ReadVerb::QueryPlan,
        ReadVerb::QueryRun,
        ReadVerb::QueryCancel,
        ReadVerb::ReceiptShow,
        ReadVerb::ExportPlan,
    ];

    #[derive(Clone, Copy)]
    struct ParamSpec {
        name: &'static str,
        description: &'static str,
        required: bool,
        kind: ParamKind,
    }

    #[derive(Clone, Copy)]
    enum ParamKind {
        String,
        Bool,
        Enum(&'static [&'static str]),
    }

    #[derive(Clone)]
    struct ToolSpec {
        name: &'static str,
        description: &'static str,
        open_world_hint: &'static str,
        read_only: bool,
        params: Vec<ParamSpec>,
        tags: &'static [&'static str],
    }

    impl ReadVerb {
        fn spec(self) -> ToolSpec {
            match self {
                Self::Capabilities => ToolSpec {
                    name: "capabilities",
                    description: "Return the franken-snowflake read-only capability registry as the CLI JSON envelope.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: Vec::new(),
                    tags: &["discovery", "offline"],
                },
                Self::Doctor => ToolSpec {
                    name: "doctor",
                    description: "Run local, non-live readiness checks through the CLI doctor handler.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: Vec::new(),
                    tags: &["diagnostics", "offline"],
                },
                Self::AgentHandbook => ToolSpec {
                    name: "agent_handbook",
                    description: "Return the embedded agent handbook with envelope, exit-code, and recovery contract details.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: Vec::new(),
                    tags: &["discovery", "offline"],
                },
                Self::RobotDocsGuide => ToolSpec {
                    name: "robot_docs_guide",
                    description: "Return the first-contact robot guide through the CLI robot-docs handler.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: Vec::new(),
                    tags: &["discovery", "offline"],
                },
                Self::Selftest => ToolSpec {
                    name: "selftest",
                    description: "Run the offline selftest surface and return the same CLI envelope.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: Vec::new(),
                    tags: &["diagnostics", "offline"],
                },
                Self::ProfileValidate => ToolSpec {
                    name: "profile_validate",
                    description: "Validate a profile shape without reading secret values or performing live I/O.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: vec![ParamSpec::string(
                        "profile",
                        "Profile id or profile path to validate.",
                        true,
                    )],
                    tags: &["profile", "offline"],
                },
                Self::ProfileDoctor => ToolSpec {
                    name: "profile_doctor",
                    description: "Inspect profile readiness using the CLI profile doctor contract; online probes remain explicit.",
                    open_world_hint: "snowflake",
                    read_only: true,
                    params: vec![
                        ParamSpec::string(
                            "profile",
                            "Profile id or profile path to inspect.",
                            true,
                        ),
                        ParamSpec::boolean(
                            "online",
                            "Set true to request explicit online probes.",
                            false,
                        ),
                    ],
                    tags: &["profile", "diagnostics"],
                },
                Self::CatalogScan => ToolSpec {
                    name: "catalog_scan",
                    description: "Scan catalog metadata through the CLI catalog scan handler and return its envelope.",
                    open_world_hint: "snowflake",
                    read_only: true,
                    params: vec![
                        ParamSpec::string(
                            "profile",
                            "Profile id to use for catalog discovery.",
                            true,
                        ),
                        ParamSpec::string("database", "Snowflake database name.", true),
                        ParamSpec::string("schema", "Snowflake schema name.", true),
                    ],
                    tags: &["catalog", "snowflake"],
                },
                Self::CatalogGraph => ToolSpec {
                    name: "catalog_graph",
                    description: "Render the catalog graph through the CLI catalog graph handler; format may be json, mermaid, or svg.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: vec![
                        ParamSpec::string(
                            "profile",
                            "Profile id whose cached catalog graph should be rendered.",
                            true,
                        ),
                        ParamSpec::string_enum(
                            "format",
                            "Graph output format.",
                            false,
                            &["json", "mermaid", "svg"],
                        ),
                    ],
                    tags: &["catalog", "graph"],
                },
                Self::DatasetInspect => ToolSpec {
                    name: "dataset_inspect",
                    description: "Return the dataset manifest surface through the CLI dataset inspect handler.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: vec![ParamSpec::string(
                        "dataset_id",
                        "Dataset identifier to inspect.",
                        true,
                    )],
                    tags: &["dataset", "offline"],
                },
                Self::DatasetProfile => ToolSpec {
                    name: "dataset_profile",
                    description: "Plan pushed-down dataset profiling through the CLI dataset profile handler.",
                    open_world_hint: "snowflake",
                    read_only: true,
                    params: vec![ParamSpec::string(
                        "dataset_id",
                        "Dataset identifier to profile.",
                        true,
                    )],
                    tags: &["dataset", "snowflake"],
                },
                Self::DatasetDescribeOperator => ToolSpec {
                    name: "dataset_describe_operator",
                    description: "Return JSON Schema for a supported dataset predicate operator.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: vec![ParamSpec::string(
                        "operator",
                        "Dataset predicate operator to describe.",
                        true,
                    )],
                    tags: &["dataset", "schema"],
                },
                Self::QueryPlan => ToolSpec {
                    name: "query_plan",
                    description: "Validate and explain a read-only SQL plan without submitting it.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: vec![
                        ParamSpec::string("profile", "Profile id to plan against.", true),
                        ParamSpec::string("sql", "Single read-only SQL statement.", true),
                    ],
                    tags: &["query", "offline"],
                },
                Self::QueryRun => ToolSpec {
                    name: "query_run",
                    description: "Run a read-only SQL query through the CLI query run handler; write tools are not exposed here.",
                    open_world_hint: "snowflake",
                    read_only: true,
                    params: vec![
                        ParamSpec::string("profile", "Profile id to query with.", true),
                        ParamSpec::string("sql", "Single read-only SQL statement.", true),
                    ],
                    tags: &["query", "snowflake"],
                },
                Self::QueryCancel => ToolSpec {
                    name: "query_cancel",
                    description: "Cancel a Snowflake SQL API statement handle through the CLI query cancel handler.",
                    open_world_hint: "snowflake",
                    read_only: false,
                    params: vec![ParamSpec::string(
                        "statement_handle",
                        "Statement handle returned by query run.",
                        true,
                    )],
                    tags: &["query", "snowflake", "cancel"],
                },
                Self::ReceiptShow => ToolSpec {
                    name: "receipt_show",
                    description: "Look up a content-addressed query receipt through the CLI receipt show handler.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: vec![ParamSpec::string(
                        "receipt_hash",
                        "Content-addressed receipt hash to look up.",
                        true,
                    )],
                    tags: &["receipt", "offline"],
                },
                Self::ExportPlan => ToolSpec {
                    name: "export_plan",
                    description: "Draft export plans through the CLI export plan handler; execution is not exposed.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: Vec::new(),
                    tags: &["export", "offline"],
                },
            }
        }

        fn cli_args(self, arguments: &Value) -> McpResult<Vec<String>> {
            match self {
                Self::Capabilities => Ok(json_args(&["capabilities"])),
                Self::Doctor => Ok(json_args(&["doctor"])),
                Self::AgentHandbook => Ok(json_args(&["agent-handbook"])),
                Self::RobotDocsGuide => Ok(json_args(&["robot-docs", "guide"])),
                Self::Selftest => Ok(json_args(&["selftest"])),
                Self::ProfileValidate => Ok(json_args_with(
                    &["profile", "validate"],
                    vec![required_string(arguments, "profile")?],
                )),
                Self::ProfileDoctor => {
                    let mut args = json_args_with(
                        &["profile", "doctor"],
                        vec![required_string(arguments, "profile")?],
                    );
                    if optional_bool(arguments, "online")?.unwrap_or(false) {
                        args.push("--online".to_string());
                    }
                    args.push("--json".to_string());
                    Ok(args)
                }
                Self::CatalogScan => Ok(vec![
                    "catalog".to_string(),
                    "scan".to_string(),
                    required_string(arguments, "profile")?,
                    "--database".to_string(),
                    required_string(arguments, "database")?,
                    "--schema".to_string(),
                    required_string(arguments, "schema")?,
                    "--json".to_string(),
                ]),
                Self::CatalogGraph => {
                    let mut args = vec![
                        "catalog".to_string(),
                        "graph".to_string(),
                        required_string(arguments, "profile")?,
                    ];
                    match optional_string(arguments, "format")?
                        .as_deref()
                        .unwrap_or("json")
                    {
                        "json" => args.push("--json".to_string()),
                        "mermaid" => args.push("--mermaid".to_string()),
                        "svg" => args.push("--svg".to_string()),
                        other => {
                            return Err(invalid_params(
                                format!("unsupported graph format `{other}`"),
                                Some(json!({"available_formats": ["json", "mermaid", "svg"]})),
                            ));
                        }
                    }
                    Ok(args)
                }
                Self::DatasetInspect => Ok(json_args_with(
                    &["dataset", "inspect"],
                    vec![required_string(arguments, "dataset_id")?],
                )),
                Self::DatasetProfile => Ok(json_args_with(
                    &["dataset", "profile"],
                    vec![required_string(arguments, "dataset_id")?],
                )),
                Self::DatasetDescribeOperator => Ok(vec![
                    "dataset".to_string(),
                    "describe-operator".to_string(),
                    required_string(arguments, "operator")?,
                    "--jsonschema".to_string(),
                ]),
                Self::QueryPlan => Ok(vec![
                    "query".to_string(),
                    "plan".to_string(),
                    "--profile".to_string(),
                    required_string(arguments, "profile")?,
                    "--sql".to_string(),
                    required_string(arguments, "sql")?,
                    "--json".to_string(),
                ]),
                Self::QueryRun => Ok(vec![
                    "query".to_string(),
                    "run".to_string(),
                    "--profile".to_string(),
                    required_string(arguments, "profile")?,
                    "--sql".to_string(),
                    required_string(arguments, "sql")?,
                    "--json".to_string(),
                ]),
                Self::QueryCancel => Ok(vec![
                    "query".to_string(),
                    "cancel".to_string(),
                    required_string(arguments, "statement_handle")?,
                    "--json".to_string(),
                ]),
                Self::ReceiptShow => Ok(json_args_with(
                    &["receipt", "show"],
                    vec![required_string(arguments, "receipt_hash")?],
                )),
                Self::ExportPlan => Ok(json_args(&["export", "plan"])),
            }
        }
    }

    impl ParamSpec {
        const fn string(name: &'static str, description: &'static str, required: bool) -> Self {
            Self {
                name,
                description,
                required,
                kind: ParamKind::String,
            }
        }

        const fn boolean(name: &'static str, description: &'static str, required: bool) -> Self {
            Self {
                name,
                description,
                required,
                kind: ParamKind::Bool,
            }
        }

        const fn string_enum(
            name: &'static str,
            description: &'static str,
            required: bool,
            values: &'static [&'static str],
        ) -> Self {
            Self {
                name,
                description,
                required,
                kind: ParamKind::Enum(values),
            }
        }
    }

    struct ReadTool {
        verb: ReadVerb,
        runner: Arc<dyn CliContractRunner>,
    }

    impl ReadTool {
        fn new(verb: ReadVerb, runner: Arc<dyn CliContractRunner>) -> Self {
            Self { verb, runner }
        }
    }

    impl ToolHandler for ReadTool {
        fn definition(&self) -> Tool {
            let spec = self.verb.spec();
            Tool {
                name: spec.name.to_string(),
                description: Some(spec.description.to_string()),
                input_schema: input_schema(&spec.params),
                output_schema: Some(json!({
                    "type": "string",
                    "description": "The exact stdout payload produced by the matching franken-snowflake CLI read command."
                })),
                icon: None,
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                tags: spec.tags.iter().map(|tag| (*tag).to_string()).collect(),
                annotations: Some(
                    ToolAnnotations::new()
                        .read_only(spec.read_only)
                        .idempotent(true)
                        .open_world_hint(spec.open_world_hint),
                ),
            }
        }

        fn call(&self, ctx: &McpContext, arguments: Value) -> McpResult<Vec<Content>> {
            ctx.checkpoint()?;
            let args = self.verb.cli_args(&arguments)?;
            let output = self.runner.run_cli_contract(args);
            ctx.checkpoint()?;
            cli_output_to_mcp_result(output)
        }
    }

    /// Build the feature-gated FastMCP server.
    pub fn build_mcp_server<R>(runner: R) -> Server
    where
        R: CliContractRunner + 'static,
    {
        let runner: Arc<dyn CliContractRunner> = Arc::new(runner);
        let mut builder = Server::new(SERVER_NAME, env!("CARGO_PKG_VERSION"))
            .instructions(
                "Read-only Snowflake SQL API tools. Each tool delegates to the same \
                 franken-snowflake CLI handler and returns the same deterministic envelope.",
            )
            .strict_input_validation(true)
            .mask_error_details(true);

        for verb in READ_VERBS {
            builder = builder.tool(ReadTool::new(*verb, runner.clone()));
        }

        builder.build()
    }

    /// Run `franken-snowflake mcp serve` on stdio or HTTP.
    pub fn run_mcp_serve_process<R>(mode: Option<String>, runner: R) -> !
    where
        R: CliContractRunner + 'static,
    {
        match mode.as_deref() {
            None | Some("stdio") => build_mcp_server(runner).run_stdio(),
            Some(value) if value.starts_with("http:") => {
                // Strip exactly one `http:` mode tag. `trim_start_matches` would
                // peel every leading `http:`, mangling an address that itself
                // begins with it (e.g. `--http http://host:port` -> `//host:port`).
                let addr = value.strip_prefix("http:").unwrap_or(value);
                build_mcp_server(runner).run_http(addr.to_string())
            }
            Some(other) => {
                // Redact the echoed mode: a secret-shaped value mis-passed as the
                // serve mode must not leak to stderr (mirrors `invalid_params`).
                eprintln!(
                    "{}: unsupported MCP serve mode `{}`; use --stdio or --http <addr>",
                    SnowflakeErrorCode::UsageError.stable_code(),
                    franken_snowflake_core::redact::redact(other)
                );
                std::process::exit(64)
            }
        }
    }

    /// Serialize the registered FastMCP tool schemas.
    pub fn mcp_tool_schema_json<R>(runner: R) -> Result<String, serde_json::Error>
    where
        R: CliContractRunner + 'static,
    {
        serde_json::to_string(&build_mcp_server(runner).tools())
    }

    fn json_args(prefix: &[&str]) -> Vec<String> {
        let mut args = prefix
            .iter()
            .map(|part| (*part).to_string())
            .collect::<Vec<_>>();
        args.push("--json".to_string());
        args
    }

    fn json_args_with(prefix: &[&str], values: Vec<String>) -> Vec<String> {
        let mut args = prefix
            .iter()
            .map(|part| (*part).to_string())
            .collect::<Vec<_>>();
        args.extend(values);
        args.push("--json".to_string());
        args
    }

    fn input_schema(params: &[ParamSpec]) -> Value {
        let mut properties = Map::new();
        let mut required = Vec::new();

        for param in params {
            properties.insert(param.name.to_string(), param_schema(param));
            if param.required {
                required.push(Value::String(param.name.to_string()));
            }
        }

        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": Value::Object(properties),
            "required": required
        })
    }

    fn param_schema(param: &ParamSpec) -> Value {
        match param.kind {
            ParamKind::String => json!({
                "type": "string",
                "description": param.description
            }),
            ParamKind::Bool => json!({
                "type": "boolean",
                "description": param.description,
                "default": false
            }),
            ParamKind::Enum(values) => json!({
                "type": "string",
                "description": param.description,
                "enum": values
            }),
        }
    }

    fn required_string(arguments: &Value, key: &str) -> McpResult<String> {
        match arguments.get(key).and_then(Value::as_str) {
            Some(value) if !value.trim().is_empty() => Ok(value.to_string()),
            Some(_) => Err(invalid_params(
                format!("`{key}` must be a non-empty string"),
                None,
            )),
            None => Err(invalid_params(
                format!("missing required string parameter `{key}`"),
                None,
            )),
        }
    }

    fn optional_string(arguments: &Value, key: &str) -> McpResult<Option<String>> {
        match arguments.get(key) {
            Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
            Some(Value::String(_)) => Err(invalid_params(
                format!("`{key}` must be a non-empty string when provided"),
                None,
            )),
            Some(_) => Err(invalid_params(
                format!("`{key}` must be a string when provided"),
                None,
            )),
            None => Ok(None),
        }
    }

    fn optional_bool(arguments: &Value, key: &str) -> McpResult<Option<bool>> {
        match arguments.get(key) {
            Some(Value::Bool(value)) => Ok(Some(*value)),
            Some(_) => Err(invalid_params(
                format!("`{key}` must be a boolean when provided"),
                None,
            )),
            None => Ok(None),
        }
    }

    fn invalid_params(message: impl Into<String>, data: Option<Value>) -> McpError {
        let message = redact(&message.into()).into_owned();
        let mut payload = Map::new();
        payload.insert("recoverable".to_string(), Value::Bool(true));
        payload.insert(
            "fix_hint".to_string(),
            Value::String("Call the tool with arguments matching its inputSchema.".to_string()),
        );
        if let Some(Value::Object(extra)) = data {
            for (key, value) in extra {
                payload.insert(key, value);
            }
        }
        McpError::with_data(
            McpErrorCode::InvalidParams,
            message,
            Value::Object(payload),
        )
    }

    fn cli_output_to_mcp_result(output: CliContractOutput) -> McpResult<Vec<Content>> {
        if output.exit_code <= 1 && output.stderr.is_none() {
            return Ok(vec![Content::text(output.stdout)]);
        }

        let mut payload = Map::new();
        payload.insert(
            "exit_code".to_string(),
            Value::Number(serde_json::Number::from(output.exit_code)),
        );
        payload.insert("stdout".to_string(), Value::String(output.stdout.clone()));
        if let Some(stderr) = &output.stderr {
            payload.insert("stderr".to_string(), Value::String(stderr.clone()));
        }

        Err(McpError::with_data(
            McpErrorCode::ToolExecutionError,
            output.stdout,
            Value::Object(payload),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::CliContractOutput;

        fn fake_runner(args: Vec<String>) -> CliContractOutput {
            CliContractOutput {
                exit_code: 0,
                stdout: args.join(" "),
                stderr: None,
            }
        }

        #[test]
        fn tool_annotations_match_cli_contract_safety() {
            let tools = build_mcp_server(fake_runner).tools();
            assert!(tools.len() >= 10);
            for tool in &tools {
                let read_only = tool
                    .annotations
                    .as_ref()
                    .and_then(|annotations| annotations.read_only);
                if tool.name == "query_cancel" {
                    assert_eq!(read_only, Some(false));
                } else {
                    assert_eq!(
                        read_only,
                        Some(true),
                        "tool {} must be read-only",
                        tool.name
                    );
                }
            }
            assert!(tools.iter().any(|tool| tool.name == "query_run"));
            assert!(tools.iter().any(|tool| tool.name == "query_cancel"));
        }

        #[test]
        fn query_cancel_routes_to_the_cli_cancel_contract() {
            let args = ReadVerb::QueryCancel
                .cli_args(&json!({"statement_handle": "01bcaafe-0000"}))
                .expect("query_cancel cli args");
            assert_eq!(
                args,
                vec![
                    "query".to_string(),
                    "cancel".to_string(),
                    "01bcaafe-0000".to_string(),
                    "--json".to_string()
                ]
            );
        }

        #[test]
        fn tool_schema_json_is_stable_json() {
            let schemas = match mcp_tool_schema_json(fake_runner) {
                Ok(schemas) => schemas,
                Err(err) => {
                    assert!(false, "tool schemas serialize: {err}");
                    String::new()
                }
            };
            assert!(schemas.contains("\"name\":\"capabilities\""));
            assert!(schemas.contains("\"name\":\"profile_validate\""));
            assert!(schemas.contains("\"inputSchema\""));
        }

        #[test]
        fn cli_refusals_become_mcp_tool_errors_with_cli_envelope() {
            let stdout = "{\"ok\":false,\"error\":{\"code\":\"FSNOW-3001\"}}".to_string();
            let stderr = "FSNOW-3001: mutation refused".to_string();

            let err = match cli_output_to_mcp_result(CliContractOutput {
                exit_code: 2,
                stdout: stdout.clone(),
                stderr: Some(stderr.clone()),
            }) {
                Ok(_) => {
                    assert!(
                        false,
                        "CLI refusal must not be returned as successful MCP content"
                    );
                    return;
                }
                Err(err) => err,
            };

            assert_eq!(err.code, McpErrorCode::ToolExecutionError);
            assert_eq!(err.message, stdout);
            let Some(Value::Object(data)) = err.data else {
                assert!(false, "tool error should carry CLI parity data");
                return;
            };
            assert_eq!(data.get("exit_code").and_then(Value::as_i64), Some(2));
            assert_eq!(
                data.get("stdout").and_then(Value::as_str),
                Some(stdout.as_str())
            );
            assert_eq!(
                data.get("stderr").and_then(Value::as_str),
                Some(stderr.as_str())
            );
        }

        #[test]
        fn cli_findings_remain_successful_mcp_content() {
            let content = match cli_output_to_mcp_result(CliContractOutput {
                exit_code: 1,
                stdout: "{\"ok\":true,\"outcome_kind\":\"partial_success\"}".to_string(),
                stderr: None,
            }) {
                Ok(content) => content,
                Err(err) => {
                    assert!(
                        false,
                        "CLI findings are ok=true and should stay successful: {err:?}"
                    );
                    return;
                }
            };

            assert_eq!(content.len(), 1);
        }

        #[test]
        fn invalid_params_redacts_secret_shaped_argument_values() {
            let raw_secret = "sfpat_mcpBadFormat001";
            let err = match ReadVerb::CatalogGraph.cli_args(
                &json!({"profile": "demo", "format": raw_secret}),
            ) {
                Ok(_) => {
                    assert!(
                        false,
                        "secret-shaped unsupported graph format should be rejected"
                    );
                    return;
                }
                Err(err) => err,
            };

            assert_eq!(err.code, McpErrorCode::InvalidParams);
            assert!(!err.message.contains(raw_secret));
            assert!(err.message.contains("[REDACTED]"));
            let data = serde_json::to_string(&err.data).expect("MCP error data serializes");
            assert!(!data.contains(raw_secret));
        }
    }
}

#[cfg(feature = "mcp")]
pub use fastmcp_surface::{build_mcp_server, mcp_tool_schema_json, run_mcp_serve_process};
