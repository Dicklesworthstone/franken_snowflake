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

/// Asks whether the MCP request behind a running CLI invocation was
/// cancelled (a `notifications/cancelled` for it, or the client went away).
/// The CLI polls it while a statement runs and cancels the statement when it
/// turns true (reality-check bead E2).
pub type CancelProbe = std::sync::Arc<dyn Fn() -> bool + Send + Sync>;

/// Minimal contract this adapter needs from the CLI crate.
pub trait CliContractRunner: Send + Sync {
    /// Execute one CLI command invocation and render its contract output;
    /// `cancel` reports whether the MCP request was cancelled meanwhile.
    fn run_cli_contract(&self, args: Vec<String>, cancel: CancelProbe) -> CliContractOutput;
}

impl<F> CliContractRunner for F
where
    F: Fn(Vec<String>, CancelProbe) -> CliContractOutput + Send + Sync,
{
    fn run_cli_contract(&self, args: Vec<String>, cancel: CancelProbe) -> CliContractOutput {
        self(args, cancel)
    }
}

#[cfg(feature = "mcp")]
mod fastmcp_surface {
    use std::sync::Arc;

    use fastmcp_rust::{
        Content, McpContext, McpError, McpErrorCode, McpResult, Server, Tool, ToolAnnotations,
        ToolHandler,
    };
    use franken_snowflake_core::redact::redact;
    use serde_json::{Map, Value, json};

    use super::{CancelProbe, CliContractOutput, CliContractRunner};

    const SERVER_NAME: &str = "franken-snowflake";

    /// Cancellations the client sent while tool calls ran, by FastMCP's
    /// request id, from either transport, and whether stdin closed.
    #[derive(Default)]
    struct RequestCancellations {
        cancelled: std::sync::Mutex<std::collections::BTreeSet<u64>>,
        closed: std::sync::atomic::AtomicBool,
    }

    impl RequestCancellations {
        /// Note a stdin line if it is a `notifications/cancelled`.
        fn observe(&self, line: &[u8]) {
            let Ok(message) = serde_json::from_slice::<Value>(line) else {
                return;
            };
            if message.get("method").and_then(Value::as_str) == Some("notifications/cancelled") {
                self.note(message.get("params"));
            }
        }

        /// Note the request a `notifications/cancelled` names.
        fn note(&self, params: Option<&Value>) {
            let id = match params.and_then(|params| params.get("requestId")) {
                Some(Value::Number(number)) => number
                    .as_u64()
                    .or_else(|| number.as_i64().map(|signed| signed as u64)),
                Some(Value::String(text)) => Some(request_id_hash(text)),
                _ => None,
            };
            if let (Some(id), Ok(mut cancelled)) = (id, self.cancelled.lock()) {
                cancelled.insert(id);
            }
        }

        fn is_cancelled(&self, request_id: u64) -> bool {
            self.closed.load(std::sync::atomic::Ordering::SeqCst)
                || self
                    .cancelled
                    .lock()
                    .is_ok_and(|cancelled| cancelled.contains(&request_id))
        }

        /// Forget a finished call's cancellation: clients reuse ids.
        fn finish(&self, request_id: u64) {
            if let Ok(mut cancelled) = self.cancelled.lock() {
                cancelled.remove(&request_id);
            }
        }
    }

    /// Record a `notifications/cancelled` that arrived over HTTP (the HTTP
    /// front answers notifications itself instead of dispatching them).
    pub(crate) fn note_http_cancellation(params: Option<&Value>) {
        CANCELLATIONS.note(params);
    }

    /// FastMCP's request id for a string JSON-RPC id (FNV-1a, 0 remapped),
    /// so a cancellation matches the `McpContext::request_id` of its call.
    fn request_id_hash(value: &str) -> u64 {
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut hash = OFFSET;
        for byte in value.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(PRIME);
        }
        if hash == 0 { OFFSET } else { hash }
    }

    static CANCELLATIONS: std::sync::LazyLock<std::sync::Arc<RequestCancellations>> =
        std::sync::LazyLock::new(std::sync::Arc::default);

    /// Stdin as the stdio transport sees it, read by a thread that notes
    /// cancellations and EOF the moment they arrive: FastMCP's stdio loop
    /// handles one request at a time, so it would read a
    /// `notifications/cancelled` only after the call it cancels had finished.
    struct WatchedStdin {
        lines: std::sync::mpsc::Receiver<Vec<u8>>,
        pending: Vec<u8>,
        offset: usize,
    }

    impl std::io::Read for WatchedStdin {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.offset >= self.pending.len() {
                match self.lines.recv() {
                    Ok(line) => {
                        self.pending = line;
                        self.offset = 0;
                    }
                    Err(_) => return Ok(0),
                }
            }
            let available = self.pending.get(self.offset..).unwrap_or_default();
            let count = available.len().min(buf.len());
            if let (Some(target), Some(source)) = (buf.get_mut(..count), available.get(..count)) {
                target.copy_from_slice(source);
            }
            self.offset += count;
            Ok(count)
        }
    }

    fn watched_stdin(state: std::sync::Arc<RequestCancellations>) -> WatchedStdin {
        let (sender, lines) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            use std::io::BufRead as _;
            let stdin = std::io::stdin();
            let mut reader = stdin.lock();
            loop {
                let mut line = Vec::new();
                match reader.read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        state.observe(&line);
                        if sender.send(line).is_err() {
                            break;
                        }
                    }
                }
            }
            // The client is gone: a call still running is cancelled.
            state
                .closed
                .store(true, std::sync::atomic::Ordering::SeqCst);
        });
        WatchedStdin {
            lines,
            pending: Vec::new(),
            offset: 0,
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReadVerb {
        Capabilities,
        Onboard,
        Doctor,
        AgentHandbook,
        RobotDocsGuide,
        Selftest,
        ProfileValidate,
        ProfileDoctor,
        CatalogScan,
        CatalogGraph,
        CatalogDiff,
        CatalogSearch,
        CatalogRelates,
        CatalogLineage,
        CatalogCycles,
        DatasetInspect,
        DatasetProfile,
        DatasetValidateManifest,
        DatasetDescribeOperator,
        QueryPlan,
        QueryRun,
        QueryCancel,
        ReceiptShow,
        ReceiptRefetch,
        ExportPlan,
        ExportRun,
    }

    const READ_VERBS: &[ReadVerb] = &[
        ReadVerb::Capabilities,
        ReadVerb::Onboard,
        ReadVerb::Doctor,
        ReadVerb::AgentHandbook,
        ReadVerb::RobotDocsGuide,
        ReadVerb::Selftest,
        ReadVerb::ProfileValidate,
        ReadVerb::ProfileDoctor,
        ReadVerb::CatalogScan,
        ReadVerb::CatalogGraph,
        ReadVerb::CatalogDiff,
        ReadVerb::CatalogSearch,
        ReadVerb::CatalogRelates,
        ReadVerb::CatalogLineage,
        ReadVerb::CatalogCycles,
        ReadVerb::DatasetInspect,
        ReadVerb::DatasetProfile,
        ReadVerb::DatasetValidateManifest,
        ReadVerb::DatasetDescribeOperator,
        ReadVerb::QueryPlan,
        ReadVerb::QueryRun,
        ReadVerb::QueryCancel,
        ReadVerb::ReceiptShow,
        ReadVerb::ReceiptRefetch,
        ReadVerb::ExportPlan,
        ReadVerb::ExportRun,
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
                Self::Onboard => ToolSpec {
                    name: "onboard",
                    description: "Mega-command: capabilities + exit codes + first commands + local health in one call, via the CLI onboard handler.",
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
                        ParamSpec::boolean(
                            "require_live",
                            "Set true to enforce a hard refusal if live transport is unavailable.",
                            false,
                        ),
                        ParamSpec::string(
                            "max_view_refs",
                            "Views whose dependencies are read, one statement each (0-500, default 25; 0 skips).",
                            false,
                        ),
                        ParamSpec::boolean(
                            "tags",
                            "Set true to also read tag assignments from SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES (needs GOVERNANCE_VIEWER; lags up to 2 h).",
                            false,
                        ),
                    ],
                    tags: &["catalog", "snowflake"],
                },
                Self::CatalogGraph => ToolSpec {
                    name: "catalog_graph",
                    description: "Render the catalog lineage graph from the local store's latest snapshot for the database (run catalog_scan first); set refresh=true to rescan live before rendering; format may be json, mermaid, or svg.",
                    open_world_hint: "snowflake",
                    read_only: true,
                    params: vec![
                        ParamSpec::string(
                            "profile",
                            "Profile id whose snapshot (or live rescan) to render.",
                            true,
                        ),
                        ParamSpec::boolean(
                            "refresh",
                            "Set true to run a live catalog scan before rendering (needs credentials).",
                            false,
                        ),
                        ParamSpec::string(
                            "database",
                            "Snowflake database name to scope the graph (required).",
                            true,
                        ),
                        ParamSpec::string(
                            "schema",
                            "Optional Snowflake schema name to narrow the graph.",
                            false,
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
                Self::CatalogDiff => ToolSpec {
                    name: "catalog_diff",
                    description: "Compare two catalog snapshots or audit schema drift across historical scans from the local store.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: vec![
                        ParamSpec::string("profile", "Profile id to inspect.", true),
                        ParamSpec::string(
                            "database",
                            "Snowflake database name scope filter.",
                            false,
                        ),
                        ParamSpec::string("schema", "Snowflake schema name scope filter.", false),
                        ParamSpec::string(
                            "base_snapshot",
                            "Base (older) snapshot ID. Defaults to the snapshot preceding target.",
                            false,
                        ),
                        ParamSpec::string(
                            "target_snapshot",
                            "Target (newer) snapshot ID. Defaults to the latest snapshot.",
                            false,
                        ),
                    ],
                    tags: &["catalog", "diff", "drift", "offline"],
                },
                Self::CatalogRelates => ToolSpec {
                    name: "catalog_relates",
                    description: "What relates to a catalog object (node key, dataset id, or DB.SCHEMA.OBJECT[.COLUMN]) within `depth` hops, from the local snapshot.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: vec![
                        ParamSpec::string("profile", "Profile id whose snapshot to read.", true),
                        ParamSpec::string(
                            "object",
                            "Node key, dataset id, or DB.SCHEMA.OBJECT[.COLUMN].",
                            true,
                        ),
                        ParamSpec::string("depth", "Hops to follow, 1..=6 (default 2).", false),
                        ParamSpec::string("database", "Snapshot scope: database.", false),
                        ParamSpec::string("schema", "Snapshot scope: schema.", false),
                    ],
                    tags: &["catalog", "graph", "offline"],
                },
                Self::CatalogLineage => ToolSpec {
                    name: "catalog_lineage",
                    description: "Everything above (direction up) or below (down) a catalog object in the catalog graph, from the local snapshot.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: vec![
                        ParamSpec::string("profile", "Profile id whose snapshot to read.", true),
                        ParamSpec::string(
                            "object",
                            "Node key, dataset id, or DB.SCHEMA.OBJECT[.COLUMN].",
                            true,
                        ),
                        ParamSpec::string_enum(
                            "direction",
                            "up (ancestors) or down (descendants).",
                            true,
                            &["up", "down"],
                        ),
                        ParamSpec::string("database", "Snapshot scope: database.", false),
                        ParamSpec::string("schema", "Snapshot scope: schema.", false),
                    ],
                    tags: &["catalog", "graph", "lineage", "offline"],
                },
                Self::CatalogSearch => ToolSpec {
                    name: "catalog_search",
                    description: "Find datasets in the local snapshot whose names, columns, comments, or tags contain the query's words; ranked, offline.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: vec![
                        ParamSpec::string("profile", "Profile id whose snapshot to search.", true),
                        ParamSpec::string(
                            "query",
                            "Words to find (e.g. \"customer email\").",
                            true,
                        ),
                        ParamSpec::string(
                            "limit",
                            "Most hits to return, 1-100 (default 10).",
                            false,
                        ),
                        ParamSpec::string("database", "Snapshot scope: database.", false),
                        ParamSpec::string("schema", "Snapshot scope: schema.", false),
                    ],
                    tags: &["catalog", "search", "offline"],
                },
                Self::CatalogCycles => ToolSpec {
                    name: "catalog_cycles",
                    description: "Dependency cycles in the catalog graph, from the local snapshot.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: vec![
                        ParamSpec::string("profile", "Profile id whose snapshot to read.", true),
                        ParamSpec::string("database", "Snapshot scope: database.", false),
                        ParamSpec::string("schema", "Snapshot scope: schema.", false),
                    ],
                    tags: &["catalog", "graph", "offline"],
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
                    description: "Build the pushed-down APPROX_COUNT_DISTINCT / null-count / min-max profiling statement for a dataset from the local snapshot; set execute=true to run it live and return the stats.",
                    open_world_hint: "snowflake",
                    read_only: true,
                    params: vec![
                        ParamSpec::string("dataset_id", "Dataset identifier to profile.", true),
                        ParamSpec::boolean(
                            "execute",
                            "Set true to execute the profiling statement live (needs credentials).",
                            false,
                        ),
                    ],
                    tags: &["dataset", "snowflake"],
                },
                Self::DatasetValidateManifest => ToolSpec {
                    name: "dataset_validate_manifest",
                    description: "Parse the non-secret dataset manifest overlay (field roles, limits, rights class) and check each entry against the datasets in the local store.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: Vec::new(),
                    tags: &["dataset", "offline"],
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
                    description: "Validate and explain a read-only plan without submitting it: raw sql, or dataset mode (dataset_id plus entity/from/to/as_of/select/filter/limit compiled through the catalog planner with typed positional bindings).",
                    open_world_hint: "offline",
                    read_only: true,
                    params: query_params(false),
                    tags: &["query", "offline"],
                },
                Self::QueryRun => ToolSpec {
                    name: "query_run",
                    description: "Run a read-only query through the CLI query run handler (raw sql or dataset mode); every flag is honored or rejected; write tools are not exposed here.",
                    open_world_hint: "snowflake",
                    read_only: true,
                    params: query_params(true),
                    tags: &["query", "snowflake"],
                },
                Self::QueryCancel => ToolSpec {
                    name: "query_cancel",
                    description: "POST to the SQL API cancel endpoint for a statement handle with the profile's credentials.",
                    open_world_hint: "snowflake",
                    read_only: false,
                    params: vec![
                        ParamSpec::string(
                            "statement_handle",
                            "Statement handle returned by query run.",
                            true,
                        ),
                        ParamSpec::string(
                            "profile",
                            "Profile id whose credentials cancel the statement (defaults to FRANKEN_SNOWFLAKE_DEFAULT_PROFILE).",
                            false,
                        ),
                    ],
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
                Self::ReceiptRefetch => ToolSpec {
                    name: "receipt_refetch",
                    description: "Re-read a completed statement's rows from Snowflake's result cache (RESULT_SCAN on the receipt's query id, about 24 h) without running it again.",
                    open_world_hint: "snowflake",
                    read_only: true,
                    params: vec![
                        ParamSpec::string(
                            "receipt_hash",
                            "Receipt hash of a completed live statement.",
                            true,
                        ),
                        ParamSpec::string(
                            "profile",
                            "Profile whose credentials run RESULT_SCAN (defaults to the receipt's).",
                            false,
                        ),
                        ParamSpec::string("limit", "Rows to emit in the envelope.", false),
                        ParamSpec::boolean(
                            "raw_cells",
                            "Set true for the SQL API jsonv2 wire strings instead of typed.v1 cells.",
                            false,
                        ),
                    ],
                    tags: &["receipt", "snowflake"],
                },
                Self::ExportPlan => ToolSpec {
                    name: "export_plan",
                    description: "Build a content-addressed COPY INTO <stage> plan (Snowflake-side unload) and the exact `query write` command that executes it; nothing runs.",
                    open_world_hint: "offline",
                    read_only: true,
                    params: export_params(true),
                    tags: &["export", "offline"],
                },
                Self::ExportRun => ToolSpec {
                    name: "export_run",
                    description: "Run a read-only query live and write a content-addressed local CSV, JSONL, or Parquet file at `out`; records an export receipt in the local store.",
                    open_world_hint: "snowflake",
                    read_only: false,
                    params: export_params(false),
                    tags: &["export", "snowflake"],
                },
            }
        }

        fn cli_args(self, arguments: &Value) -> McpResult<Vec<String>> {
            refuse_unknown_arguments(self.spec().name, &self.spec().params, arguments)?;
            match self {
                Self::Capabilities => Ok(json_args(&["capabilities"])),
                Self::Onboard => Ok(json_args(&["onboard"])),
                Self::Doctor => Ok(json_args(&["doctor"])),
                Self::AgentHandbook => Ok(json_args(&["agent-handbook"])),
                Self::RobotDocsGuide => Ok(json_args(&["robot-docs", "guide"])),
                Self::Selftest => Ok(json_args(&["selftest"])),
                Self::ProfileValidate => Ok(json_args_with(
                    &["profile", "validate"],
                    vec![required_string(arguments, "profile")?],
                )),
                Self::ProfileDoctor => {
                    let mut args = vec![
                        "profile".to_string(),
                        "doctor".to_string(),
                        required_string(arguments, "profile")?,
                    ];
                    if optional_bool(arguments, "online")?.unwrap_or(false) {
                        args.push("--online".to_string());
                    }
                    args.push("--json".to_string());
                    Ok(args)
                }
                Self::CatalogScan => {
                    let mut args = vec![
                        "catalog".to_string(),
                        "scan".to_string(),
                        required_string(arguments, "profile")?,
                        "--database".to_string(),
                        required_string(arguments, "database")?,
                        "--schema".to_string(),
                        required_string(arguments, "schema")?,
                    ];
                    if optional_bool(arguments, "require_live")?.unwrap_or(false) {
                        args.push("--require-live".to_string());
                    }
                    if let Some(limit) = optional_string(arguments, "max_view_refs")? {
                        args.push("--max-view-refs".to_string());
                        args.push(limit);
                    }
                    if optional_bool(arguments, "tags")?.unwrap_or(false) {
                        args.push("--tags".to_string());
                    }
                    args.push("--json".to_string());
                    Ok(args)
                }
                Self::CatalogGraph => {
                    let mut args = vec![
                        "catalog".to_string(),
                        "graph".to_string(),
                        required_string(arguments, "profile")?,
                        "--database".to_string(),
                        required_string(arguments, "database")?,
                    ];
                    if let Some(schema) = optional_string(arguments, "schema")? {
                        args.push("--schema".to_string());
                        args.push(schema);
                    }
                    if optional_bool(arguments, "refresh")?.unwrap_or(false) {
                        args.push("--refresh".to_string());
                    }
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
                Self::CatalogDiff => {
                    let mut args = vec![
                        "catalog".to_string(),
                        "diff".to_string(),
                        required_string(arguments, "profile")?,
                    ];
                    if let Some(database) = optional_string(arguments, "database")? {
                        args.push("--database".to_string());
                        args.push(database);
                    }
                    if let Some(schema) = optional_string(arguments, "schema")? {
                        args.push("--schema".to_string());
                        args.push(schema);
                    }
                    if let Some(base) = optional_string(arguments, "base_snapshot")? {
                        args.push("--base".to_string());
                        args.push(base);
                    }
                    if let Some(target) = optional_string(arguments, "target_snapshot")? {
                        args.push("--target".to_string());
                        args.push(target);
                    }
                    args.push("--json".to_string());
                    Ok(args)
                }
                Self::CatalogSearch => {
                    let mut args = vec![
                        "catalog".to_string(),
                        "search".to_string(),
                        required_string(arguments, "profile")?,
                        required_string(arguments, "query")?,
                    ];
                    for (key, flag) in [
                        ("limit", "--limit"),
                        ("database", "--database"),
                        ("schema", "--schema"),
                    ] {
                        if let Some(value) = optional_string(arguments, key)? {
                            args.push(flag.to_string());
                            args.push(value);
                        }
                    }
                    args.push("--json".to_string());
                    Ok(args)
                }
                Self::CatalogRelates | Self::CatalogLineage | Self::CatalogCycles => {
                    let verb = match self {
                        Self::CatalogRelates => "relates",
                        Self::CatalogLineage => "lineage",
                        _ => "cycles",
                    };
                    let mut args = vec![
                        "catalog".to_string(),
                        verb.to_string(),
                        required_string(arguments, "profile")?,
                    ];
                    if !matches!(self, Self::CatalogCycles) {
                        args.push(required_string(arguments, "object")?);
                    }
                    if matches!(self, Self::CatalogLineage) {
                        let direction = required_string(arguments, "direction")?;
                        args.push(if direction == "up" { "--up" } else { "--down" }.to_string());
                    }
                    for (key, flag) in [
                        ("depth", "--depth"),
                        ("database", "--database"),
                        ("schema", "--schema"),
                    ] {
                        if let Some(value) = optional_string(arguments, key)? {
                            args.push(flag.to_string());
                            args.push(value);
                        }
                    }
                    args.push("--json".to_string());
                    Ok(args)
                }
                Self::DatasetInspect => Ok(json_args_with(
                    &["dataset", "inspect"],
                    vec![required_string(arguments, "dataset_id")?],
                )),
                Self::DatasetProfile => {
                    let mut args = vec![
                        "dataset".to_string(),
                        "profile".to_string(),
                        required_string(arguments, "dataset_id")?,
                    ];
                    if optional_bool(arguments, "execute")?.unwrap_or(false) {
                        args.push("--execute".to_string());
                    }
                    args.push("--json".to_string());
                    Ok(args)
                }
                Self::DatasetValidateManifest => Ok(json_args(&["dataset", "validate-manifest"])),
                Self::DatasetDescribeOperator => Ok(vec![
                    "dataset".to_string(),
                    "describe-operator".to_string(),
                    required_string(arguments, "operator")?,
                    "--jsonschema".to_string(),
                ]),
                Self::QueryPlan => query_args("plan", arguments),
                Self::QueryRun => query_args("run", arguments),
                Self::QueryCancel => {
                    let mut args = vec![
                        "query".to_string(),
                        "cancel".to_string(),
                        required_string(arguments, "statement_handle")?,
                    ];
                    if let Some(profile) = optional_string(arguments, "profile")? {
                        args.push("--profile".to_string());
                        args.push(profile);
                    }
                    args.push("--json".to_string());
                    Ok(args)
                }
                Self::ReceiptShow => Ok(json_args_with(
                    &["receipt", "show"],
                    vec![required_string(arguments, "receipt_hash")?],
                )),
                Self::ReceiptRefetch => {
                    let mut args = vec![
                        "receipt".to_string(),
                        "refetch".to_string(),
                        required_string(arguments, "receipt_hash")?,
                    ];
                    for (key, flag) in [("profile", "--profile"), ("limit", "--limit")] {
                        if let Some(value) = optional_string(arguments, key)? {
                            args.push(flag.to_string());
                            args.push(value);
                        }
                    }
                    if optional_bool(arguments, "raw_cells")?.unwrap_or(false) {
                        args.push("--raw-cells".to_string());
                    }
                    args.push("--json".to_string());
                    Ok(args)
                }
                Self::ExportPlan => export_args("plan", arguments),
                Self::ExportRun => export_args("run", arguments),
            }
        }
    }

    /// Parameters shared by `query_plan` and `query_run`: raw `sql` or dataset
    /// mode (`dataset_id` plus axis flags); `run` adds the session flags.
    fn query_params(run: bool) -> Vec<ParamSpec> {
        let mut params = vec![
            ParamSpec::string(
                "profile",
                "Profile id (defaults to FRANKEN_SNOWFLAKE_DEFAULT_PROFILE; in dataset mode defaults to the profile the dataset was scanned under).",
                false,
            ),
            ParamSpec::string(
                "sql",
                "Single read-only SQL statement (raw mode). Mutually exclusive with dataset_id.",
                false,
            ),
            ParamSpec::string(
                "dataset_id",
                "Dataset id from catalog_scan / dataset_inspect (dataset mode). Mutually exclusive with sql.",
                false,
            ),
            ParamSpec::string(
                "entity",
                "Dataset mode: entity-key value to filter on (bound, never interpolated).",
                false,
            ),
            ParamSpec::string(
                "from",
                "Dataset mode: inclusive lower bound on the time index (ISO date/timestamp).",
                false,
            ),
            ParamSpec::string(
                "to",
                "Dataset mode: exclusive upper bound on the time index.",
                false,
            ),
            ParamSpec::string(
                "as_of",
                "Dataset mode: Time Travel AT(TIMESTAMP => ...) point.",
                false,
            ),
            ParamSpec::string(
                "select",
                "Dataset mode: comma-separated column list to project.",
                false,
            ),
            ParamSpec::string(
                "filter",
                "Dataset mode: predicate AST as JSON ({\"column\":..,\"op\":..,\"value\":..} or {\"and\":[..]}).",
                false,
            ),
            ParamSpec::string(
                "limit",
                "Row limit: dataset mode pushes it down; raw mode caps the rows emitted and fetched (default 1000, max 100000).",
                false,
            ),
        ];
        if run {
            params.extend([
                ParamSpec::string("role", "Session role override.", false),
                ParamSpec::string("warehouse", "Session warehouse override.", false),
                ParamSpec::string(
                    "statement_timeout",
                    "SQL API statement timeout in seconds.",
                    false,
                ),
                ParamSpec::string(
                    "query_tag",
                    "QUERY_TAG session parameter for this run.",
                    false,
                ),
                ParamSpec::string(
                    "bindings_env",
                    "Env var name holding positional typed bindings as JSON (raw mode).",
                    false,
                ),
                ParamSpec::boolean(
                    "require_live",
                    "Set true to enforce a hard refusal if live transport is unavailable.",
                    false,
                ),
                ParamSpec::boolean(
                    "raw_cells",
                    "Set true for the SQL API jsonv2 wire strings instead of typed.v1 cells.",
                    false,
                ),
            ]);
        }
        params
    }

    fn query_args(verb: &str, arguments: &Value) -> McpResult<Vec<String>> {
        let mut args = vec!["query".to_string(), verb.to_string()];
        if let Some(profile) = optional_string(arguments, "profile")? {
            args.push("--profile".to_string());
            args.push(profile);
        }
        match (
            optional_string(arguments, "sql")?,
            optional_string(arguments, "dataset_id")?,
        ) {
            (Some(sql), None) => {
                args.push("--sql".to_string());
                args.push(sql);
            }
            (None, Some(dataset_id)) => {
                args.push("--dataset".to_string());
                args.push(dataset_id);
            }
            (Some(_), Some(_)) => {
                return Err(invalid_params(
                    "pass either `sql` (raw mode) or `dataset_id` (dataset mode), not both",
                    None,
                ));
            }
            (None, None) => {
                return Err(invalid_params(
                    "one of `sql` (raw mode) or `dataset_id` (dataset mode) is required",
                    None,
                ));
            }
        }
        for (key, flag) in [
            ("entity", "--entity"),
            ("from", "--from"),
            ("to", "--to"),
            ("as_of", "--as-of"),
            ("select", "--select"),
            ("filter", "--filter"),
            ("limit", "--limit"),
        ] {
            if let Some(value) = optional_string(arguments, key)? {
                args.push(flag.to_string());
                args.push(value);
            }
        }
        if verb == "run" {
            for (key, flag) in [
                ("role", "--role"),
                ("warehouse", "--warehouse"),
                ("statement_timeout", "--statement-timeout"),
                ("query_tag", "--query-tag"),
                ("bindings_env", "--bindings-env"),
            ] {
                if let Some(value) = optional_string(arguments, key)? {
                    args.push(flag.to_string());
                    args.push(value);
                }
            }
            if optional_bool(arguments, "require_live")?.unwrap_or(false) {
                args.push("--require-live".to_string());
            }
            if optional_bool(arguments, "raw_cells")?.unwrap_or(false) {
                args.push("--raw-cells".to_string());
            }
        }
        args.push("--json".to_string());
        Ok(args)
    }

    /// Parameters for `export_plan` (stage unload plan) and `export_run` (local file).
    fn export_params(plan: bool) -> Vec<ParamSpec> {
        let mut params = vec![
            ParamSpec::string("profile", "Profile id the export belongs to.", true),
            ParamSpec::string(
                "sql",
                "Read-only SELECT to export. Mutually exclusive with query_id.",
                false,
            ),
            ParamSpec::string(
                "query_id",
                "Snowflake query id to export via RESULT_SCAN. Mutually exclusive with sql.",
                false,
            ),
            if plan {
                ParamSpec::string_enum(
                    "format",
                    "Output format.",
                    false,
                    &["csv", "jsonl", "parquet"],
                )
            } else {
                ParamSpec::string_enum(
                    "format",
                    "Output format (csv, jsonl, parquet, or frame).",
                    false,
                    &["csv", "jsonl", "parquet", "frame"],
                )
            },
        ];
        if plan {
            params.extend([
                ParamSpec::string(
                    "location",
                    "Stage location for COPY INTO, e.g. @my_stage/exports/run_001.",
                    true,
                ),
                ParamSpec::string("compression", "Stage file compression (e.g. gzip).", false),
                ParamSpec::string("header", "Emit a header row: true or false.", false),
                ParamSpec::boolean(
                    "overwrite",
                    "Allow overwriting existing stage files.",
                    false,
                ),
                ParamSpec::boolean("single", "Write a single file.", false),
                ParamSpec::string("max_file_size", "Maximum stage file size in bytes.", false),
            ]);
        } else {
            params.extend([
                ParamSpec::string(
                    "out",
                    "File path relative to the server's export directory (<data_dir>/exports); absolute paths, `..` and symlinks are refused.",
                    true,
                ),
                ParamSpec::boolean(
                    "overwrite",
                    "Replace an existing regular file at `out` (never a symlink).",
                    false,
                ),
                ParamSpec::string_enum(
                    "compression",
                    "Compression for parquet export: snappy (default), gzip, or none.",
                    false,
                    &["snappy", "gzip", "none"],
                ),
                ParamSpec::string(
                    "max_rows",
                    "Refuse a result with more rows than this (default 1000000).",
                    false,
                ),
            ]);
        }
        params
    }

    fn export_args(verb: &str, arguments: &Value) -> McpResult<Vec<String>> {
        let mut args = vec![
            "export".to_string(),
            verb.to_string(),
            "--profile".to_string(),
            required_string(arguments, "profile")?,
        ];
        match (
            optional_string(arguments, "sql")?,
            optional_string(arguments, "query_id")?,
        ) {
            (Some(sql), None) => {
                args.push("--sql".to_string());
                args.push(sql);
            }
            (None, Some(query_id)) => {
                args.push("--query-id".to_string());
                args.push(query_id);
            }
            (Some(_), Some(_)) => {
                return Err(invalid_params(
                    "pass either `sql` or `query_id`, not both",
                    None,
                ));
            }
            (None, None) => {
                return Err(invalid_params(
                    "one of `sql` or `query_id` is required",
                    None,
                ));
            }
        }
        if let Some(format) = optional_string(arguments, "format")? {
            args.push("--format".to_string());
            args.push(format);
        }
        if verb == "plan" {
            args.push("--location".to_string());
            args.push(required_string(arguments, "location")?);
            for (key, flag) in [
                ("compression", "--compression"),
                ("header", "--header"),
                ("max_file_size", "--max-file-size"),
            ] {
                if let Some(value) = optional_string(arguments, key)? {
                    args.push(flag.to_string());
                    args.push(value);
                }
            }
            if optional_bool(arguments, "overwrite")?.unwrap_or(false) {
                args.push("--overwrite".to_string());
            }
            if optional_bool(arguments, "single")?.unwrap_or(false) {
                args.push("--single".to_string());
            }
        } else {
            if let Some(compression) = optional_string(arguments, "compression")? {
                args.push("--compression".to_string());
                args.push(compression);
            }
            if let Some(max_rows) = optional_string(arguments, "max_rows")? {
                args.push("--max-rows".to_string());
                args.push(max_rows);
            }
            args.push("--out".to_string());
            args.push(required_string(arguments, "out")?);
            if optional_bool(arguments, "overwrite")?.unwrap_or(false) {
                args.push("--overwrite".to_string());
            }
            // An MCP caller never chooses an arbitrary filesystem path: the
            // export is always confined under <data_dir>/exports.
            args.push("--sandbox-out".to_string());
        }
        args.push("--json".to_string());
        Ok(args)
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
                // Truthful hints: only the side-effecting tools (`export_run`
                // writes a local file, `query_cancel` cancels a remote statement)
                // are destructive and non-idempotent.
                annotations: Some(
                    ToolAnnotations::new()
                        .read_only(spec.read_only)
                        .idempotent(spec.read_only)
                        .destructive(!spec.read_only)
                        .open_world_hint(spec.open_world_hint),
                ),
            }
        }

        fn call(&self, ctx: &McpContext, arguments: Value) -> McpResult<Vec<Content>> {
            ctx.checkpoint()?;
            let args = self.verb.cli_args(&arguments)?;
            // A cancellation arrives on the watched stdin or, over HTTP, on
            // another connection; both land in CANCELLATIONS. A cancelled
            // request Cx counts too.
            let request_cx = ctx.cx().clone();
            let request_id = ctx.request_id();
            let cancellations = std::sync::Arc::clone(&CANCELLATIONS);
            let cancel: CancelProbe = std::sync::Arc::new(move || {
                request_cx.is_cancel_requested() || cancellations.is_cancelled(request_id)
            });
            let output = self.runner.run_cli_contract(args, cancel);
            CANCELLATIONS.finish(request_id);
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
                "Snowflake SQL API tools. Each tool delegates to the same franken-snowflake \
                 CLI handler and returns the same deterministic envelope. `export_run` writes \
                 a local file and `query_cancel` cancels a remote statement; every other tool \
                 only reads.",
            )
            .strict_input_validation(true)
            .mask_error_details(true);

        for verb in READ_VERBS {
            builder = builder.tool(ReadTool::new(*verb, runner.clone()));
        }

        builder.build()
    }

    /// How `mcp serve` listens.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum McpServeMode {
        /// JSON-RPC over stdin/stdout (the agent-spawn path).
        Stdio,
        /// The secured HTTP transport (see [`crate::http_front`]).
        Http(crate::http_front::HttpServeOptions),
    }

    /// Names of the tools that only read; the HTTP transport exposes these by
    /// default and the rest only via `--allow-tool`.
    #[must_use]
    pub fn read_only_tool_names() -> Vec<&'static str> {
        READ_VERBS
            .iter()
            .map(|verb| verb.spec())
            .filter(|spec| spec.read_only)
            .map(|spec| spec.name)
            .collect()
    }

    /// Run `franken-snowflake mcp serve` on stdio or HTTP.
    pub fn run_mcp_serve_process<R>(mode: McpServeMode, runner: R) -> !
    where
        R: CliContractRunner + 'static,
    {
        match mode {
            McpServeMode::Stdio => {
                let transport = fastmcp_rust::StdioTransport::new(
                    watched_stdin(std::sync::Arc::clone(&CANCELLATIONS)),
                    std::io::stdout(),
                );
                build_mcp_server(runner).run_transport(transport)
            }
            McpServeMode::Http(options) => crate::http_front::run_secure_http(
                build_mcp_server(runner),
                &options,
                &read_only_tool_names(),
            ),
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

    /// An argument the tool's inputSchema does not declare is refused, never
    /// silently dropped (the schema says `additionalProperties: false`).
    fn refuse_unknown_arguments(
        tool: &str,
        params: &[ParamSpec],
        arguments: &Value,
    ) -> McpResult<()> {
        let Some(object) = arguments.as_object() else {
            return Ok(());
        };
        let unknown: Vec<&str> = object
            .keys()
            .map(String::as_str)
            .filter(|key| !params.iter().any(|param| param.name == *key))
            .collect();
        if unknown.is_empty() {
            return Ok(());
        }
        let accepted: Vec<&str> = params.iter().map(|param| param.name).collect();
        Err(invalid_params(
            format!(
                "`{tool}` does not take {}; it accepts {}",
                unknown
                    .iter()
                    .map(|key| format!("`{key}`"))
                    .collect::<Vec<_>>()
                    .join(", "),
                if accepted.is_empty() {
                    "no arguments".to_string()
                } else {
                    accepted.join(", ")
                }
            ),
            Some(json!({ "unknown_arguments": unknown, "accepted_arguments": accepted })),
        ))
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
        McpError::with_data(McpErrorCode::InvalidParams, message, Value::Object(payload))
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

        fn fake_runner(args: Vec<String>, _cancel: CancelProbe) -> CliContractOutput {
            CliContractOutput {
                exit_code: 0,
                stdout: args.join(" "),
                stderr: None,
            }
        }

        #[test]
        fn a_cancel_notification_marks_its_request_and_nothing_else() {
            let stdio = RequestCancellations::default();
            stdio.observe(br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}"#);
            assert!(!stdio.is_cancelled(3), "a request is not a cancellation");
            stdio.observe(
                br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"user"}}"#,
            );
            assert!(stdio.is_cancelled(7));
            assert!(!stdio.is_cancelled(8));
            stdio.observe(
                br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"call-a"}}"#,
            );
            assert!(stdio.is_cancelled(request_id_hash("call-a")));
            stdio.observe(b"not json");
            // A finished call's id is forgotten: the next call reusing it runs.
            stdio.finish(7);
            assert!(!stdio.is_cancelled(7));
            stdio
                .closed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(
                stdio.is_cancelled(8),
                "stdin closed: every call is cancelled"
            );
        }

        #[test]
        fn watched_stdin_hands_bytes_through_unchanged() {
            use std::io::Read as _;
            let (sender, lines) = std::sync::mpsc::channel::<Vec<u8>>();
            sender.send(b"{\"a\":1}\n".to_vec()).expect("send");
            sender.send(b"{\"b\":2}\n".to_vec()).expect("send");
            drop(sender);
            let mut reader = WatchedStdin {
                lines,
                pending: Vec::new(),
                offset: 0,
            };
            let mut text = String::new();
            reader.read_to_string(&mut text).expect("read");
            assert_eq!(text, "{\"a\":1}\n{\"b\":2}\n");
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
                if tool.name == "query_cancel" || tool.name == "export_run" {
                    assert_eq!(read_only, Some(false), "{} has side effects", tool.name);
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
        fn query_cancel_routes_to_the_cli_cancel_contract() -> Result<(), String> {
            let args = ReadVerb::QueryCancel
                .cli_args(&json!({"statement_handle": "01bcaafe-0000"}))
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(
                args,
                vec![
                    "query".to_string(),
                    "cancel".to_string(),
                    "01bcaafe-0000".to_string(),
                    "--json".to_string()
                ]
            );
            Ok(())
        }

        #[test]
        fn query_tools_map_dataset_mode_and_session_flags_to_the_cli_contract() -> Result<(), String>
        {
            let args = ReadVerb::QueryRun
                .cli_args(&json!({
                    "dataset_id": "analytics_public_events_b3_abc",
                    "entity": "ENTITY123",
                    "from": "2024-01-01",
                    "to": "2024-12-31",
                    "select": "EVENT_DATE,VALUE",
                    "limit": "10",
                    "role": "ANALYST",
                    "statement_timeout": "120"
                }))
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(
                args,
                vec![
                    "query",
                    "run",
                    "--dataset",
                    "analytics_public_events_b3_abc",
                    "--entity",
                    "ENTITY123",
                    "--from",
                    "2024-01-01",
                    "--to",
                    "2024-12-31",
                    "--select",
                    "EVENT_DATE,VALUE",
                    "--limit",
                    "10",
                    "--role",
                    "ANALYST",
                    "--statement-timeout",
                    "120",
                    "--json",
                ]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
            );
            // `role` is a query_run argument; query_plan refuses it instead of
            // dropping it.
            let refused = ReadVerb::QueryPlan
                .cli_args(&json!({"profile": "demo", "sql": "select 1", "role": "ANALYST"}));
            match refused {
                Err(error) => assert!(
                    error.message.contains("`query_plan` does not take `role`"),
                    "{error:?}"
                ),
                Ok(args) => return Err(format!("role on query_plan was accepted: {args:?}")),
            }
            let plan = ReadVerb::QueryPlan
                .cli_args(&json!({"profile": "demo", "sql": "select 1"}))
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(
                plan,
                vec![
                    "query",
                    "plan",
                    "--profile",
                    "demo",
                    "--sql",
                    "select 1",
                    "--json"
                ]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
            );
            let both =
                match ReadVerb::QueryRun.cli_args(&json!({"sql": "select 1", "dataset_id": "x"})) {
                    Err(err) => err,
                    Ok(_) => {
                        return Err("sql and dataset_id together must be refused".to_owned());
                    }
                };
            assert_eq!(both.code, McpErrorCode::InvalidParams);
            let neither = match ReadVerb::QueryPlan.cli_args(&json!({"profile": "demo"})) {
                Err(err) => err,
                Ok(_) => {
                    return Err("neither sql nor dataset_id must be refused".to_owned());
                }
            };
            assert_eq!(neither.code, McpErrorCode::InvalidParams);
            Ok(())
        }

        #[test]
        fn export_tools_map_to_the_cli_contract() -> Result<(), String> {
            let plan = ReadVerb::ExportPlan
                .cli_args(&json!({
                    "profile": "demo",
                    "sql": "select * from events",
                    "location": "@my_stage/exports/run_001",
                    "format": "jsonl",
                    "compression": "gzip",
                    "header": "false",
                    "overwrite": true,
                    "single": true,
                    "max_file_size": "1000000"
                }))
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(
                plan,
                vec![
                    "export",
                    "plan",
                    "--profile",
                    "demo",
                    "--sql",
                    "select * from events",
                    "--format",
                    "jsonl",
                    "--location",
                    "@my_stage/exports/run_001",
                    "--compression",
                    "gzip",
                    "--header",
                    "false",
                    "--max-file-size",
                    "1000000",
                    "--overwrite",
                    "--single",
                    "--json",
                ]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
            );
            let run = ReadVerb::ExportRun
                .cli_args(&json!({"profile": "demo", "query_id": "01b2-qid", "out": "events.csv"}))
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(
                run,
                vec![
                    "export",
                    "run",
                    "--profile",
                    "demo",
                    "--query-id",
                    "01b2-qid",
                    "--out",
                    "events.csv",
                    "--sandbox-out",
                    "--json",
                ]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
            );
            let run_frame = ReadVerb::ExportRun
                .cli_args(&json!({"profile": "demo", "sql": "select 1", "format": "frame", "out": "events.json"}))
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(
                run_frame,
                vec![
                    "export",
                    "run",
                    "--profile",
                    "demo",
                    "--sql",
                    "select 1",
                    "--format",
                    "frame",
                    "--out",
                    "events.json",
                    "--sandbox-out",
                    "--json",
                ]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
            );
            let run_parquet = ReadVerb::ExportRun
                .cli_args(&json!({
                    "profile": "demo",
                    "sql": "select 1",
                    "format": "parquet",
                    "compression": "gzip",
                    "out": "events.parquet"
                }))
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(
                run_parquet,
                vec![
                    "export",
                    "run",
                    "--profile",
                    "demo",
                    "--sql",
                    "select 1",
                    "--format",
                    "parquet",
                    "--compression",
                    "gzip",
                    "--out",
                    "events.parquet",
                    "--sandbox-out",
                    "--json",
                ]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
            );
            let missing_location = match ReadVerb::ExportPlan
                .cli_args(&json!({"profile": "demo", "sql": "select 1"}))
            {
                Err(err) => err,
                Ok(_) => {
                    return Err("export plan needs a stage location".to_owned());
                }
            };
            assert_eq!(missing_location.code, McpErrorCode::InvalidParams);
            Ok(())
        }

        #[test]
        fn graph_profile_and_cancel_tools_forward_their_new_flags() -> Result<(), String> {
            let graph = ReadVerb::CatalogGraph
                .cli_args(&json!({"profile": "demo", "database": "DB", "refresh": true, "format": "mermaid"}))
                .map_err(|e| format!("{e:?}"))?;
            assert!(graph.contains(&"--refresh".to_string()));
            assert!(graph.contains(&"--mermaid".to_string()));
            let profile = ReadVerb::DatasetProfile
                .cli_args(&json!({"dataset_id": "ds", "execute": true}))
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(
                profile,
                vec!["dataset", "profile", "ds", "--execute", "--json"]
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            );
            let cancel = ReadVerb::QueryCancel
                .cli_args(&json!({"statement_handle": "01bc", "profile": "demo"}))
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(
                cancel,
                vec!["query", "cancel", "01bc", "--profile", "demo", "--json"]
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            );

            let profile_doc = ReadVerb::ProfileDoctor
                .cli_args(&json!({"profile": "demo", "online": true}))
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(
                profile_doc,
                vec!["profile", "doctor", "demo", "--online", "--json"]
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            );

            let cat_scan = ReadVerb::CatalogScan
                .cli_args(&json!({"profile": "demo", "database": "DB", "schema": "SCH", "require_live": true}))
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(
                cat_scan,
                vec![
                    "catalog",
                    "scan",
                    "demo",
                    "--database",
                    "DB",
                    "--schema",
                    "SCH",
                    "--require-live",
                    "--json"
                ]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
            );

            let cat_diff = ReadVerb::CatalogDiff
                .cli_args(&json!({"profile": "demo", "database": "DB", "schema": "SCH", "base_snapshot": "snap1", "target_snapshot": "snap2"}))
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(
                cat_diff,
                vec![
                    "catalog",
                    "diff",
                    "demo",
                    "--database",
                    "DB",
                    "--schema",
                    "SCH",
                    "--base",
                    "snap1",
                    "--target",
                    "snap2",
                    "--json"
                ]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
            );

            let query_live = ReadVerb::QueryRun
                .cli_args(&json!({"profile": "demo", "sql": "select 1", "require_live": true}))
                .map_err(|e| format!("{e:?}"))?;
            assert!(query_live.contains(&"--require-live".to_string()));
            assert_eq!(query_live.iter().filter(|a| *a == "--json").count(), 1);
            Ok(())
        }

        #[test]
        fn tool_schema_json_is_stable_json() -> Result<(), String> {
            let schemas = mcp_tool_schema_json(fake_runner)
                .map_err(|err| format!("tool schemas serialize: {err}"))?;
            assert!(schemas.contains("\"name\":\"capabilities\""));
            assert!(schemas.contains("\"name\":\"profile_validate\""));
            assert!(schemas.contains("\"name\":\"catalog_diff\""));
            assert!(schemas.contains("\"inputSchema\""));
            Ok(())
        }

        #[test]
        fn cli_refusals_become_mcp_tool_errors_with_cli_envelope() -> Result<(), String> {
            let stdout = "{\"ok\":false,\"error\":{\"code\":\"FSNOW-3001\"}}".to_string();
            let stderr = "FSNOW-3001: mutation refused".to_string();

            let err = match cli_output_to_mcp_result(CliContractOutput {
                exit_code: 2,
                stdout: stdout.clone(),
                stderr: Some(stderr.clone()),
            }) {
                Err(err) => err,
                Ok(_) => {
                    return Err(
                        "CLI refusal must not be returned as successful MCP content".to_owned()
                    );
                }
            };

            assert_eq!(err.code, McpErrorCode::ToolExecutionError);
            assert_eq!(err.message, stdout);
            let Some(Value::Object(data)) = err.data else {
                return Err("tool error should carry CLI parity data".to_owned());
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
            Ok(())
        }

        #[test]
        fn cli_findings_remain_successful_mcp_content() -> Result<(), String> {
            let content = cli_output_to_mcp_result(CliContractOutput {
                exit_code: 1,
                stdout: "{\"ok\":true,\"outcome_kind\":\"partial_success\"}".to_string(),
                stderr: None,
            })
            .map_err(|err| {
                format!("CLI findings are ok=true and should stay successful: {err:?}")
            })?;

            assert_eq!(content.len(), 1);
            Ok(())
        }

        #[test]
        fn invalid_params_redacts_secret_shaped_argument_values() -> Result<(), String> {
            let raw_secret = "sfpat_mcpBadFormat001";
            // `database` is now required for catalog_graph and is validated before
            // `format`; supply it so the unsupported-format (secret-shaped) value is
            // the failure under test.
            let err = match ReadVerb::CatalogGraph
                .cli_args(&json!({"profile": "demo", "database": "DB", "format": raw_secret}))
            {
                Err(err) => err,
                Ok(_) => {
                    return Err(
                        "secret-shaped unsupported graph format should be rejected".to_owned()
                    );
                }
            };

            assert_eq!(err.code, McpErrorCode::InvalidParams);
            assert!(!err.message.contains(raw_secret));
            assert!(err.message.contains("[REDACTED]"));
            let data = serde_json::to_string(&err.data).map_err(|e| e.to_string())?;
            assert!(!data.contains(raw_secret));
            Ok(())
        }
    }
}

#[cfg(feature = "mcp")]
pub mod http_front;

#[cfg(feature = "mcp")]
pub use fastmcp_surface::{
    McpServeMode, build_mcp_server, mcp_tool_schema_json, read_only_tool_names,
    run_mcp_serve_process,
};
#[cfg(feature = "mcp")]
pub use http_front::{HttpServeOptions, MCP_TOKEN_ENV};
