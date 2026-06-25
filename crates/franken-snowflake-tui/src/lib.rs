//! Optional FrankenTUI surface for `franken-snowflake`.
//!
//! The crate keeps terminal rendering behind the default-off `tui` feature, but
//! the model/update layer remains testable without a real terminal. Catalog
//! browsing is derived from `franken-snowflake-catalog` snapshots, query planning
//! delegates to the existing raw SQL dry-run planner, and progress telemetry is
//! driven by the connector's Asupersync budget type via `franken-snowflake-core`.

use std::collections::BTreeMap;

use franken_snowflake_catalog::prelude::{
    CatalogSnapshot, PlanRefusal, QueryPlan, RawSqlPlanRequest, plan_raw_sql_dry_run,
};
use franken_snowflake_core::prelude::Budget;
use serde::{Deserialize, Serialize};

/// Marker for builds that omit the optional terminal dependency graph.
pub const TUI_SURFACE_STATUS: &str = "feature-gated: enable the `tui` feature";

const DEFAULT_QUERY_LIMIT: u64 = 1_000;
const DEFAULT_COMMAND_ID: &str = "tui.query.plan";
const DEFAULT_TRACE_ID: &str = "fsnow-tui-trace";

/// Browser tree derived from catalog discovery output.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogTree {
    /// Databases in deterministic display order.
    pub databases: Vec<DatabaseNode>,
}

impl CatalogTree {
    /// Convert a flat catalog snapshot into a database -> schema -> table ->
    /// column tree for terminal navigation.
    #[must_use]
    pub fn from_snapshot(snapshot: &CatalogSnapshot) -> Self {
        let mut databases: BTreeMap<String, BTreeMap<String, BTreeMap<String, Vec<ColumnNode>>>> =
            BTreeMap::new();

        for dataset in &snapshot.datasets {
            databases
                .entry(dataset.database.clone())
                .or_default()
                .entry(dataset.schema.clone())
                .or_default()
                .entry(dataset.object.clone())
                .or_default();
        }

        for column in &snapshot.columns {
            databases
                .entry(column.database.clone())
                .or_default()
                .entry(column.schema.clone())
                .or_default()
                .entry(column.object.clone())
                .or_default()
                .push(ColumnNode {
                    name: column.column.clone(),
                    ordinal: column.ordinal,
                    snowflake_type: column.snowflake_type.clone(),
                    nullable: column.nullable,
                });
        }

        Self {
            databases: databases
                .into_iter()
                .map(|(name, schemas)| DatabaseNode {
                    name,
                    schemas: schemas
                        .into_iter()
                        .map(|(name, tables)| SchemaNode {
                            name,
                            tables: tables
                                .into_iter()
                                .map(|(name, mut columns)| {
                                    columns.sort_by_key(|column| column.ordinal);
                                    TableNode { name, columns }
                                })
                                .collect(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    /// True when the catalog tree has no databases.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.databases.is_empty()
    }
}

/// Database node in the browser tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseNode {
    /// Exact Snowflake database identifier.
    pub name: String,
    /// Schemas under the database.
    pub schemas: Vec<SchemaNode>,
}

/// Schema node in the browser tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaNode {
    /// Exact Snowflake schema identifier.
    pub name: String,
    /// Tables/views under the schema.
    pub tables: Vec<TableNode>,
}

/// Table or view node in the browser tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableNode {
    /// Exact Snowflake object identifier.
    pub name: String,
    /// Columns under the object.
    pub columns: Vec<ColumnNode>,
}

/// Column node in the browser tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnNode {
    /// Exact Snowflake column identifier.
    pub name: String,
    /// 1-based ordinal position.
    pub ordinal: u32,
    /// Snowflake logical type.
    pub snowflake_type: String,
    /// SQL nullability.
    pub nullable: bool,
}

/// Focusable TUI pane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FocusPane {
    /// Catalog browser.
    #[default]
    Catalog,
    /// Raw SQL query runner.
    Query,
    /// Statement/partition progress.
    Progress,
    /// Structured activity log.
    Log,
}

impl FocusPane {
    fn next(self) -> Self {
        match self {
            Self::Catalog => Self::Query,
            Self::Query => Self::Progress,
            Self::Progress => Self::Log,
            Self::Log => Self::Catalog,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Catalog => Self::Log,
            Self::Query => Self::Catalog,
            Self::Progress => Self::Query,
            Self::Log => Self::Progress,
        }
    }
}

/// Current depth and row selection in the catalog browser.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserSelection {
    /// Selected database row.
    pub database: usize,
    /// Selected schema row.
    pub schema: usize,
    /// Selected table row.
    pub table: usize,
    /// Selected column row.
    pub column: usize,
    /// Browser depth, clamped to the current tree shape.
    pub depth: BrowserDepth,
}

impl BrowserSelection {
    fn move_down(&mut self, tree: &CatalogTree) {
        let len = self.visible_len(tree);
        if len > 0 {
            let active = self.active_index();
            self.set_active_index((active + 1).min(len - 1));
        }
    }

    fn move_up(&mut self) {
        let active = self.active_index();
        self.set_active_index(active.saturating_sub(1));
    }

    fn enter(&mut self, tree: &CatalogTree) {
        if self.visible_len(tree) == 0 {
            return;
        }
        self.depth = match self.depth {
            BrowserDepth::Databases => BrowserDepth::Schemas,
            BrowserDepth::Schemas => BrowserDepth::Tables,
            BrowserDepth::Tables => BrowserDepth::Columns,
            BrowserDepth::Columns => BrowserDepth::Columns,
        };
        self.clamp_to(tree);
    }

    fn back(&mut self, tree: &CatalogTree) {
        self.depth = match self.depth {
            BrowserDepth::Databases => BrowserDepth::Databases,
            BrowserDepth::Schemas => BrowserDepth::Databases,
            BrowserDepth::Tables => BrowserDepth::Schemas,
            BrowserDepth::Columns => BrowserDepth::Tables,
        };
        self.clamp_to(tree);
    }

    fn clamp_to(&mut self, tree: &CatalogTree) {
        self.database = clamp_index(self.database, tree.databases.len());
        self.schema = clamp_index(self.schema, self.schemas(tree).map_or(0, Vec::len));
        self.table = clamp_index(self.table, self.tables(tree).map_or(0, Vec::len));
        self.column = clamp_index(self.column, self.columns(tree).map_or(0, Vec::len));
    }

    fn active_index(&self) -> usize {
        match self.depth {
            BrowserDepth::Databases => self.database,
            BrowserDepth::Schemas => self.schema,
            BrowserDepth::Tables => self.table,
            BrowserDepth::Columns => self.column,
        }
    }

    fn set_active_index(&mut self, index: usize) {
        match self.depth {
            BrowserDepth::Databases => {
                self.database = index;
                self.schema = 0;
                self.table = 0;
                self.column = 0;
            }
            BrowserDepth::Schemas => {
                self.schema = index;
                self.table = 0;
                self.column = 0;
            }
            BrowserDepth::Tables => {
                self.table = index;
                self.column = 0;
            }
            BrowserDepth::Columns => {
                self.column = index;
            }
        }
    }

    fn visible_len(&self, tree: &CatalogTree) -> usize {
        match self.depth {
            BrowserDepth::Databases => tree.databases.len(),
            BrowserDepth::Schemas => self.schemas(tree).map_or(0, Vec::len),
            BrowserDepth::Tables => self.tables(tree).map_or(0, Vec::len),
            BrowserDepth::Columns => self.columns(tree).map_or(0, Vec::len),
        }
    }

    fn schemas<'a>(&self, tree: &'a CatalogTree) -> Option<&'a Vec<SchemaNode>> {
        tree.databases
            .get(self.database)
            .map(|database| &database.schemas)
    }

    fn tables<'a>(&self, tree: &'a CatalogTree) -> Option<&'a Vec<TableNode>> {
        self.schemas(tree)
            .and_then(|schemas| schemas.get(self.schema))
            .map(|schema| &schema.tables)
    }

    fn columns<'a>(&self, tree: &'a CatalogTree) -> Option<&'a Vec<ColumnNode>> {
        self.tables(tree)
            .and_then(|tables| tables.get(self.table))
            .map(|table| &table.columns)
    }
}

/// Catalog browser depth.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserDepth {
    /// Showing databases.
    #[default]
    Databases,
    /// Showing schemas for the selected database.
    Schemas,
    /// Showing objects for the selected schema.
    Tables,
    /// Showing columns for the selected object.
    Columns,
}

/// Raw SQL editor state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryDraft {
    /// Optional non-secret profile identifier.
    pub profile_id: Option<String>,
    /// Secret-free profile fingerprint used by the planner.
    pub profile_fingerprint: String,
    /// SQL text in the runner.
    pub sql: String,
    /// Optional row limit pushed down by the planner.
    pub limit: Option<u64>,
    /// Optional warehouse chosen by profile resolution.
    pub warehouse: Option<String>,
}

impl Default for QueryDraft {
    fn default() -> Self {
        Self {
            profile_id: None,
            profile_fingerprint: "profile:unset".to_owned(),
            sql: "SELECT 1".to_owned(),
            limit: Some(DEFAULT_QUERY_LIMIT),
            warehouse: None,
        }
    }
}

impl QueryDraft {
    fn to_raw_request(&self) -> RawSqlPlanRequest {
        RawSqlPlanRequest {
            sql: self.sql.clone(),
            limit: self.limit,
            export_mode: false,
            confirmation_token: None,
            warehouse: self.warehouse.clone(),
            profile_fingerprint: self.profile_fingerprint.clone(),
            command_id: DEFAULT_COMMAND_ID.to_owned(),
            trace_id: DEFAULT_TRACE_ID.to_owned(),
        }
    }
}

/// Statement lifecycle phase shown in the progress pane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementPhase {
    /// No submitted statement yet.
    #[default]
    Idle,
    /// Plan accepted and ready for submission.
    Planned,
    /// Statement submitted.
    Submitted,
    /// Polling the statement handle.
    Polling,
    /// Fetching result partitions.
    FetchingPartitions,
    /// Statement completed successfully.
    Complete,
    /// Statement cancelled locally or remotely.
    Cancelled,
    /// Planner or lifecycle refusal.
    Refused,
}

/// Redaction-safe live progress model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementProgress {
    /// Stable statement handle when one exists.
    pub statement_handle: Option<String>,
    /// Current lifecycle phase.
    pub phase: StatementPhase,
    /// Number of result partitions fetched.
    pub partitions_fetched: u32,
    /// Total partition count, when known.
    pub partitions_total: Option<u32>,
    /// Rows streamed into the client.
    pub rows_streamed: u64,
    /// Budget telemetry from the same Asupersync budget path as execution.
    pub budget: ProgressBudget,
}

impl Default for StatementProgress {
    fn default() -> Self {
        Self {
            statement_handle: None,
            phase: StatementPhase::Idle,
            partitions_fetched: 0,
            partitions_total: None,
            rows_streamed: 0,
            budget: ProgressBudget::from_budget(&Budget::new()),
        }
    }
}

impl StatementProgress {
    /// Apply a live tick emitted by a statement lifecycle or partition fetcher.
    pub fn apply_tick(&mut self, tick: ProgressTick) {
        if let Some(handle) = tick.statement_handle {
            self.statement_handle = Some(handle);
        }
        if let Some(total) = tick.partitions_total {
            self.partitions_total = Some(total);
        }
        self.partitions_fetched = self
            .partitions_fetched
            .saturating_add(tick.partitions_fetched_delta);
        if let Some(total) = self.partitions_total {
            self.partitions_fetched = self.partitions_fetched.min(total);
        }
        self.rows_streamed = self.rows_streamed.saturating_add(tick.rows_delta);
        self.budget = tick.budget;
        if self.phase == StatementPhase::Idle || self.phase == StatementPhase::Planned {
            self.phase = StatementPhase::Polling;
        }
        if self
            .partitions_total
            .is_some_and(|total| total == self.partitions_fetched)
            && self.phase != StatementPhase::Cancelled
        {
            self.phase = StatementPhase::Complete;
        }
    }
}

/// Budget details safe to render and log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressBudget {
    /// Poll quota copied from the execution budget.
    pub poll_quota: u32,
    /// Cost quota copied from the execution budget.
    pub cost_quota: Option<u64>,
    /// Scheduling priority copied from the execution budget.
    pub priority: u8,
    /// Whether an absolute deadline was configured.
    pub has_deadline: bool,
}

impl ProgressBudget {
    /// Capture stable fields from the connector's Asupersync budget type.
    #[must_use]
    pub fn from_budget(budget: &Budget) -> Self {
        Self {
            poll_quota: budget.poll_quota,
            cost_quota: budget.cost_quota,
            priority: budget.priority,
            has_deadline: budget.deadline.is_some(),
        }
    }
}

/// Progress update emitted by lifecycle workers or tests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressTick {
    /// Optional statement handle update.
    pub statement_handle: Option<String>,
    /// Optional known partition total update.
    pub partitions_total: Option<u32>,
    /// Fetched partition delta.
    pub partitions_fetched_delta: u32,
    /// Streamed row delta.
    pub rows_delta: u64,
    /// Current budget telemetry.
    pub budget: ProgressBudget,
}

/// Structured, secret-free TUI log line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TuiLogLine {
    /// Event name.
    pub event: String,
    /// `ok`, `refusal`, or `progress`.
    pub outcome: String,
    /// Redaction-safe message.
    pub message: String,
    /// Optional stable code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Terminal-independent app model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnowflakeTuiApp {
    /// Catalog browser data.
    pub catalog: CatalogTree,
    /// Browser selection.
    pub selection: BrowserSelection,
    /// Focused pane.
    pub focus: FocusPane,
    /// Query runner draft.
    pub query: QueryDraft,
    /// Last accepted query plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_plan: Option<QueryPlan>,
    /// Last planner refusals.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub last_refusals: Vec<PlanRefusal>,
    /// Live progress panel state.
    pub progress: StatementProgress,
    /// Structured UI activity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logs: Vec<TuiLogLine>,
}

impl Default for SnowflakeTuiApp {
    fn default() -> Self {
        Self {
            catalog: CatalogTree::default(),
            selection: BrowserSelection::default(),
            focus: FocusPane::Catalog,
            query: QueryDraft::default(),
            last_plan: None,
            last_refusals: Vec::new(),
            progress: StatementProgress::default(),
            logs: Vec::new(),
        }
    }
}

impl SnowflakeTuiApp {
    /// Construct an app model from catalog discovery output.
    #[must_use]
    pub fn from_catalog_snapshot(snapshot: &CatalogSnapshot) -> Self {
        Self {
            catalog: CatalogTree::from_snapshot(snapshot),
            ..Self::default()
        }
    }

    /// Apply one terminal-independent event.
    #[must_use]
    pub fn apply_event(&mut self, event: TuiEvent) -> TuiAction {
        match event {
            TuiEvent::NextPane => {
                self.focus = self.focus.next();
                TuiAction::None
            }
            TuiEvent::PreviousPane => {
                self.focus = self.focus.previous();
                TuiAction::None
            }
            TuiEvent::CatalogDown => {
                self.selection.move_down(&self.catalog);
                TuiAction::None
            }
            TuiEvent::CatalogUp => {
                self.selection.move_up();
                TuiAction::None
            }
            TuiEvent::CatalogEnter => {
                self.selection.enter(&self.catalog);
                TuiAction::None
            }
            TuiEvent::CatalogBack => {
                self.selection.back(&self.catalog);
                TuiAction::None
            }
            TuiEvent::QueryInput(ch) => {
                self.query.sql.push(ch);
                TuiAction::None
            }
            TuiEvent::QueryBackspace => {
                self.query.sql.pop();
                TuiAction::None
            }
            TuiEvent::QuerySubmit => self.plan_query(),
            TuiEvent::Progress(tick) => {
                self.progress.apply_tick(tick);
                self.logs.push(TuiLogLine {
                    event: "statement_progress".to_owned(),
                    outcome: "progress".to_owned(),
                    message: format!(
                        "{} partitions, {} rows",
                        self.progress.partitions_fetched, self.progress.rows_streamed
                    ),
                    code: None,
                });
                TuiAction::None
            }
            TuiEvent::Quit => TuiAction::Quit,
        }
    }

    /// Return deterministic text rows used by the FrankenTUI renderer and tests.
    #[must_use]
    pub fn render_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!("franken-snowflake tui | focus={:?}", self.focus));
        lines.push(format!(
            "catalog | {} databases | depth={:?}",
            self.catalog.databases.len(),
            self.selection.depth
        ));
        for row in self.browser_rows().into_iter().take(8) {
            lines.push(row);
        }
        lines.push(format!("query | {}", self.query.sql));
        if let Some(plan) = &self.last_plan {
            lines.push(format!("plan | {} | {}", plan.plan_id, plan.sql));
        }
        for refusal in &self.last_refusals {
            lines.push(format!("refusal | {} | {}", refusal.code, refusal.message));
        }
        lines.push(format!(
            "progress | {:?} | {}/{} partitions | {} rows | polls={} priority={}",
            self.progress.phase,
            self.progress.partitions_fetched,
            self.progress
                .partitions_total
                .map_or_else(|| "?".to_owned(), |total| total.to_string()),
            self.progress.rows_streamed,
            self.progress.budget.poll_quota,
            self.progress.budget.priority
        ));
        for log in self.logs.iter().rev().take(4).rev() {
            lines.push(format!(
                "log | {} | {} | {}",
                log.outcome, log.event, log.message
            ));
        }
        lines
    }

    fn plan_query(&mut self) -> TuiAction {
        let request = self.query.to_raw_request();
        match plan_raw_sql_dry_run(&request) {
            Ok(plan) => {
                self.progress.phase = StatementPhase::Planned;
                self.last_refusals.clear();
                self.last_plan = Some(plan.clone());
                self.logs.push(TuiLogLine {
                    event: "query_plan".to_owned(),
                    outcome: "ok".to_owned(),
                    message: "query plan accepted".to_owned(),
                    code: None,
                });
                TuiAction::PlanQuery(plan)
            }
            Err(refusals) => {
                self.progress.phase = StatementPhase::Refused;
                self.last_plan = None;
                self.last_refusals = refusals.clone();
                for refusal in &refusals {
                    self.logs.push(TuiLogLine {
                        event: "query_plan".to_owned(),
                        outcome: "refusal".to_owned(),
                        message: refusal.message.clone(),
                        code: Some(refusal.code.clone()),
                    });
                }
                TuiAction::Refused(refusals)
            }
        }
    }

    fn browser_rows(&self) -> Vec<String> {
        match self.selection.depth {
            BrowserDepth::Databases => self
                .catalog
                .databases
                .iter()
                .enumerate()
                .map(|(index, database)| {
                    format_browser_row(index == self.selection.database, &database.name)
                })
                .collect(),
            BrowserDepth::Schemas => self
                .selection
                .schemas(&self.catalog)
                .into_iter()
                .flatten()
                .enumerate()
                .map(|(index, schema)| {
                    format_browser_row(index == self.selection.schema, &schema.name)
                })
                .collect(),
            BrowserDepth::Tables => self
                .selection
                .tables(&self.catalog)
                .into_iter()
                .flatten()
                .enumerate()
                .map(|(index, table)| {
                    format_browser_row(index == self.selection.table, &table.name)
                })
                .collect(),
            BrowserDepth::Columns => self
                .selection
                .columns(&self.catalog)
                .into_iter()
                .flatten()
                .enumerate()
                .map(|(index, column)| {
                    format_browser_row(
                        index == self.selection.column,
                        &format!(
                            "{} {} nullable={}",
                            column.name, column.snowflake_type, column.nullable
                        ),
                    )
                })
                .collect(),
        }
    }
}

/// Terminal-independent app event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TuiEvent {
    /// Focus the next pane.
    NextPane,
    /// Focus the previous pane.
    PreviousPane,
    /// Move down in the catalog browser.
    CatalogDown,
    /// Move up in the catalog browser.
    CatalogUp,
    /// Descend one catalog level.
    CatalogEnter,
    /// Ascend one catalog level.
    CatalogBack,
    /// Append a query character.
    QueryInput(char),
    /// Remove one query character.
    QueryBackspace,
    /// Dry-run plan the query.
    QuerySubmit,
    /// Apply a progress tick.
    Progress(ProgressTick),
    /// Quit the program.
    Quit,
}

/// Action requested by a model update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TuiAction {
    /// No side effect needed.
    None,
    /// Query was accepted by the shared planner.
    PlanQuery(QueryPlan),
    /// Query was refused by the shared planner.
    Refused(Vec<PlanRefusal>),
    /// Exit the UI.
    Quit,
}

fn clamp_index(index: usize, len: usize) -> usize {
    if len == 0 { 0 } else { index.min(len - 1) }
}

fn format_browser_row(selected: bool, label: &str) -> String {
    if selected {
        format!("> {label}")
    } else {
        format!("  {label}")
    }
}

#[cfg(feature = "tui")]
mod ftui_surface {
    use ftui::render::drawing::Draw;
    use ftui::{Cell, Cmd, Event, Frame, KeyCode, KeyEvent, KeyEventKind, Model, PackedRgba};

    use super::{FocusPane, SnowflakeTuiApp, TuiEvent};

    /// FrankenTUI message wrapper for the app model.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum TuiMessage {
        /// Raw key event interpreted against the current focused pane.
        Key(KeyEvent),
        /// Terminal-independent app event.
        App(TuiEvent),
        /// Ignore key-release and unsupported terminal events.
        Ignore,
    }

    impl From<Event> for TuiMessage {
        fn from(event: Event) -> Self {
            match event {
                Event::Tick => Self::Ignore,
                Event::Key(key) if key.kind == KeyEventKind::Release => Self::Ignore,
                Event::Key(key) => Self::Key(key),
                _ => Self::Ignore,
            }
        }
    }

    impl Model for SnowflakeTuiApp {
        type Message = TuiMessage;

        fn update(&mut self, msg: Self::Message) -> Cmd<Self::Message> {
            match msg {
                TuiMessage::App(TuiEvent::Quit) => Cmd::quit(),
                TuiMessage::Key(key) => match event_for_key(self.focus, key) {
                    Some(TuiEvent::Quit) => Cmd::quit(),
                    Some(event) => {
                        let _ = self.apply_event(event);
                        Cmd::none()
                    }
                    None => Cmd::none(),
                },
                TuiMessage::App(event) => {
                    let _ = self.apply_event(event);
                    Cmd::none()
                }
                TuiMessage::Ignore => Cmd::none(),
            }
        }

        fn view(&self, frame: &mut Frame) {
            frame.clear();
            frame.set_cursor_visible(false);
            let width = frame.width();
            let height = frame.height();
            if width == 0 || height == 0 {
                return;
            }

            let base = Cell::from_char(' ')
                .with_fg(PackedRgba::rgb(220, 225, 232))
                .with_bg(PackedRgba::rgb(20, 24, 28));
            let heading = Cell::from_char(' ')
                .with_fg(PackedRgba::rgb(255, 255, 255))
                .with_bg(PackedRgba::rgb(41, 77, 97));
            let accent = Cell::from_char(' ')
                .with_fg(PackedRgba::rgb(126, 210, 164))
                .with_bg(PackedRgba::rgb(20, 24, 28));

            for y in 0..height {
                for x in 0..width {
                    frame.buffer.set_fast(x, y, base);
                }
            }

            for (row, line) in self.render_lines().iter().enumerate() {
                let y = row as u16;
                if y >= height {
                    break;
                }
                let cell = if row == 0 {
                    heading
                } else if line.starts_with("> ") || line.starts_with("plan |") {
                    accent
                } else {
                    base
                };
                frame.buffer.print_text_clipped(0, y, line, cell, width);
            }
        }
    }

    fn event_for_key(focus: FocusPane, key: KeyEvent) -> Option<TuiEvent> {
        if key.ctrl() && matches!(key.code, KeyCode::Char('c')) {
            return Some(TuiEvent::Quit);
        }

        match key.code {
            KeyCode::Tab => Some(TuiEvent::NextPane),
            KeyCode::BackTab => Some(TuiEvent::PreviousPane),
            KeyCode::Char('q') if focus != FocusPane::Query && !key.ctrl() => Some(TuiEvent::Quit),
            KeyCode::Down if focus == FocusPane::Catalog => Some(TuiEvent::CatalogDown),
            KeyCode::Up if focus == FocusPane::Catalog => Some(TuiEvent::CatalogUp),
            KeyCode::Right | KeyCode::Enter if focus == FocusPane::Catalog => {
                Some(TuiEvent::CatalogEnter)
            }
            KeyCode::Left | KeyCode::Escape if focus == FocusPane::Catalog => {
                Some(TuiEvent::CatalogBack)
            }
            KeyCode::Enter if focus == FocusPane::Query => Some(TuiEvent::QuerySubmit),
            KeyCode::Backspace if focus == FocusPane::Query => Some(TuiEvent::QueryBackspace),
            KeyCode::Char(ch) if focus == FocusPane::Query && !key.ctrl() => {
                Some(TuiEvent::QueryInput(ch))
            }
            _ => None,
        }
    }

    /// Public alias for the model type when the terminal feature is enabled.
    pub type FrankenSnowflakeTuiModel = SnowflakeTuiApp;
}

#[cfg(feature = "tui")]
pub use ftui_surface::{FrankenSnowflakeTuiModel, TuiMessage};

#[cfg(test)]
mod tests {
    use franken_snowflake_catalog::prelude::{
        CatalogSnapshot, ColumnCatalogEntry, DataSourceClass, DatasetKind, DatasetManifest,
        DtypeClass, Provenance, ProvenanceSource, RightsClass,
    };
    use franken_snowflake_core::budget::query_budget;

    use super::*;

    #[test]
    fn catalog_browser_reflects_snapshot_hierarchy() {
        let snapshot = fixture_snapshot();
        let mut app = SnowflakeTuiApp::from_catalog_snapshot(&snapshot);

        assert_eq!(app.catalog.databases[0].name, "DB1");
        assert_eq!(app.apply_event(TuiEvent::CatalogEnter), TuiAction::None);
        assert_eq!(app.selection.depth, BrowserDepth::Schemas);
        assert_eq!(app.apply_event(TuiEvent::CatalogEnter), TuiAction::None);
        assert_eq!(app.selection.depth, BrowserDepth::Tables);
        assert_eq!(app.apply_event(TuiEvent::CatalogEnter), TuiAction::None);
        assert_eq!(app.selection.depth, BrowserDepth::Columns);

        let rows = app.render_lines().join("\n");
        assert!(rows.contains("ID NUMBER nullable=false"));
        assert!(rows.contains("NAME TEXT nullable=true"));
    }

    #[test]
    fn query_runner_uses_shared_raw_sql_planner() {
        let mut app = SnowflakeTuiApp {
            query: QueryDraft {
                sql: "SELECT ID FROM DB1.PUBLIC.POSITIONS".to_owned(),
                ..QueryDraft::default()
            },
            ..SnowflakeTuiApp::default()
        };

        let action = app.apply_event(TuiEvent::QuerySubmit);

        let TuiAction::PlanQuery(plan) = action else {
            assert!(false, "expected accepted raw SQL plan");
            return;
        };
        assert!(plan.sql.contains("SELECT ID FROM DB1.PUBLIC.POSITIONS"));
        assert!(plan.sql.contains("LIMIT ?"));
        assert_eq!(
            plan.bindings.get("1").map(|binding| binding.value.as_str()),
            Some("1000")
        );
        assert_eq!(app.progress.phase, StatementPhase::Planned);
        assert!(app.last_refusals.is_empty());
    }

    #[test]
    fn query_runner_refuses_mutation() {
        let mut app = SnowflakeTuiApp {
            query: QueryDraft {
                sql: "DROP TABLE DB1.PUBLIC.POSITIONS".to_owned(),
                ..QueryDraft::default()
            },
            ..SnowflakeTuiApp::default()
        };

        let action = app.apply_event(TuiEvent::QuerySubmit);

        let TuiAction::Refused(refusals) = action else {
            assert!(false, "expected raw SQL refusal");
            return;
        };
        assert_eq!(refusals[0].code, "FSNOW_RAW_SQL_UNSAFE");
        assert_eq!(app.progress.phase, StatementPhase::Refused);
        assert!(app.last_plan.is_none());
    }

    #[test]
    fn progress_tick_uses_budget_and_clamps_partitions() {
        let mut app = SnowflakeTuiApp::default();
        let budget = query_budget(None, 7, Some(55), 200);
        let tick = ProgressTick {
            statement_handle: Some("01abc".to_owned()),
            partitions_total: Some(2),
            partitions_fetched_delta: 5,
            rows_delta: 42,
            budget: ProgressBudget::from_budget(&budget),
        };

        assert_eq!(app.apply_event(TuiEvent::Progress(tick)), TuiAction::None);

        assert_eq!(app.progress.statement_handle.as_deref(), Some("01abc"));
        assert_eq!(app.progress.partitions_fetched, 2);
        assert_eq!(app.progress.rows_streamed, 42);
        assert_eq!(app.progress.phase, StatementPhase::Complete);
        assert_eq!(app.progress.budget.poll_quota, 7);
        assert_eq!(app.progress.budget.cost_quota, Some(55));
        assert_eq!(app.progress.budget.priority, 200);
    }

    #[test]
    fn focus_cycles_across_expected_panes() {
        let mut app = SnowflakeTuiApp::default();

        assert_eq!(app.focus, FocusPane::Catalog);
        assert_eq!(app.apply_event(TuiEvent::NextPane), TuiAction::None);
        assert_eq!(app.focus, FocusPane::Query);
        assert_eq!(app.apply_event(TuiEvent::NextPane), TuiAction::None);
        assert_eq!(app.focus, FocusPane::Progress);
        assert_eq!(app.apply_event(TuiEvent::PreviousPane), TuiAction::None);
        assert_eq!(app.focus, FocusPane::Query);
    }

    #[cfg(feature = "tui")]
    #[test]
    fn terminal_enter_submits_query_when_query_pane_is_focused() {
        use ftui::{Event, KeyCode, KeyEvent, Model};

        let mut app = SnowflakeTuiApp {
            focus: FocusPane::Query,
            query: QueryDraft {
                sql: "SELECT ID FROM DB1.PUBLIC.POSITIONS".to_owned(),
                ..QueryDraft::default()
            },
            ..SnowflakeTuiApp::default()
        };

        let _ = app.update(TuiMessage::from(Event::Key(KeyEvent::new(KeyCode::Enter))));

        assert!(app.last_plan.is_some());
        assert_eq!(app.progress.phase, StatementPhase::Planned);
    }

    #[cfg(feature = "tui")]
    #[test]
    fn terminal_character_input_is_scoped_to_query_focus() {
        use ftui::{Event, KeyCode, KeyEvent, Model};

        let mut app = SnowflakeTuiApp::default();
        let original = app.query.sql.clone();
        let _ = app.update(TuiMessage::from(Event::Key(KeyEvent::new(KeyCode::Char(
            'X',
        )))));
        assert_eq!(app.query.sql, original);

        app.focus = FocusPane::Query;
        app.query.sql.clear();
        let _ = app.update(TuiMessage::from(Event::Key(KeyEvent::new(KeyCode::Char(
            'q',
        )))));
        assert_eq!(app.query.sql, "q");
        assert!(app.last_plan.is_none());
    }

    fn fixture_snapshot() -> CatalogSnapshot {
        let provenance = Provenance {
            source: ProvenanceSource::Fixture,
            data_source: DataSourceClass::Fixture,
            snapshot_id: "snapshot-fixture".to_owned(),
            discovered_at: "1970-01-01T00:00:00Z".to_owned(),
            profile_fingerprint: "profile:fixture".to_owned(),
            object_fingerprint: "snowflake-scope:DB1.PUBLIC.POSITIONS".to_owned(),
            command_id: "catalog.scan".to_owned(),
            trace_id: "trace-fixture".to_owned(),
            redactions_applied: Vec::new(),
        };
        CatalogSnapshot {
            schema_version: "franken_snowflake.dataset_manifest.v1".to_owned(),
            provenance: provenance.clone(),
            datasets: vec![DatasetManifest {
                id: "DB1.PUBLIC.POSITIONS".to_owned(),
                profile: "fixture".to_owned(),
                database: "DB1".to_owned(),
                schema: "PUBLIC".to_owned(),
                object: "POSITIONS".to_owned(),
                kind: DatasetKind::Table,
                rights_class: RightsClass::Restricted,
                default_limit: 100,
                max_rows_without_export: 1_000,
                description: None,
                provenance: provenance.clone(),
                fields: Vec::new(),
            }],
            columns: vec![
                ColumnCatalogEntry {
                    dataset_id: "DB1.PUBLIC.POSITIONS".to_owned(),
                    database: "DB1".to_owned(),
                    schema: "PUBLIC".to_owned(),
                    object: "POSITIONS".to_owned(),
                    column: "NAME".to_owned(),
                    ordinal: 2,
                    snowflake_type: "TEXT".to_owned(),
                    dtype_class: DtypeClass::String,
                    nullable: true,
                    precision: None,
                    scale: None,
                    length: Some(255),
                    aliases: Vec::new(),
                    comment: None,
                    tags: Vec::new(),
                    provenance: Some(provenance.clone()),
                },
                ColumnCatalogEntry {
                    dataset_id: "DB1.PUBLIC.POSITIONS".to_owned(),
                    database: "DB1".to_owned(),
                    schema: "PUBLIC".to_owned(),
                    object: "POSITIONS".to_owned(),
                    column: "ID".to_owned(),
                    ordinal: 1,
                    snowflake_type: "NUMBER".to_owned(),
                    dtype_class: DtypeClass::Number,
                    nullable: false,
                    precision: Some(38),
                    scale: Some(0),
                    length: None,
                    aliases: Vec::new(),
                    comment: None,
                    tags: Vec::new(),
                    provenance: Some(provenance.clone()),
                },
            ],
            operators: Vec::new(),
        }
    }
}
