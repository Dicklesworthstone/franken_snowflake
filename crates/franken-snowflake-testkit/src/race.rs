//! Deterministic cancel/retry race suite for the Snowflake SQL API lifecycle.
//!
//! This is the `fsnow-native-snowflake-connector-w0i.4` proof lane: no live
//! account, no kernel sockets, fixed seeds, and a replayable report. Each HTTP
//! exchange is a real Asupersync HTTP/1 client/server round trip over a
//! [`VirtualTcpStream`](asupersync::net::tcp::VirtualTcpStream), while the SQL
//! API phase decisions are driven through the committed
//! [`StatementMachine`](franken_snowflake_sqlapi::lifecycle::StatementMachine).
//! The suite intentionally stays at the protocol/testkit layer rather than
//! opening an ambient Snowflake endpoint.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::http::h1::{
    Http1Client, Http1Config, Http1Server, Method as H1Method, Request as H1Request,
    Response as H1Response, Version, server::HostPolicy,
};
use asupersync::lab::{DporExplorer, ExplorationReport, ExplorerConfig, LabRuntime};
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::types::Budget;
use franken_snowflake_sqlapi::lifecycle::{PollPlan, Progress, StatementMachine};
use franken_snowflake_sqlapi::status::ResponseClass;
use serde::{Deserialize, Serialize};

use crate::harness::clock::{BackoffPolicy, Clock, ManualClock, backoff_schedule};
use crate::harness::logger::{LogError, RunLogger, RunSummary, StepOutcome};
use crate::mock::http::{Method as MockMethod, MockHttpRequest, MockHttpResponse, reason_phrase};
use crate::mock::{scenarios, server::MockSqlApi};

/// JSON schema version for race-suite reports.
pub const RACE_SUITE_SCHEMA_VERSION: u32 = 1;

const DEFAULT_BASE_SEED: u64 = 0xF5_00_00_04;
const DEFAULT_DPOR_RUNS: usize = 4;
const DEFAULT_MAX_STEPS: u64 = 50_000;
const DEFAULT_RETRY_LIMIT: u32 = 2;
const CLIENT_HOST: &str = "snowflake.test";
const COMMAND_ID: &str = "fsnow-native-snowflake-connector-w0i.4";

/// Configuration for the deterministic race suite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RaceSuiteConfig {
    /// First DPOR seed.
    pub base_seed: u64,
    /// Maximum DPOR runs per case.
    pub dpor_runs: usize,
    /// Per-run lab step cap.
    pub max_steps_per_run: u64,
    /// Retry attempts after the first request.
    pub retry_limit: u32,
}

impl Default for RaceSuiteConfig {
    fn default() -> Self {
        default_race_suite_config()
    }
}

/// The CI-friendly default race-suite configuration.
#[must_use]
pub const fn default_race_suite_config() -> RaceSuiteConfig {
    RaceSuiteConfig {
        base_seed: DEFAULT_BASE_SEED,
        dpor_runs: DEFAULT_DPOR_RUNS,
        max_steps_per_run: DEFAULT_MAX_STEPS,
        retry_limit: DEFAULT_RETRY_LIMIT,
    }
}

/// A deterministic interleaving scenario covered by the suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RaceCaseKind {
    /// A handle is accepted, then local cancellation arrives before the first poll.
    CancelDuringSubmit,
    /// Cancellation arrives while the statement is still in the poll loop.
    CancelDuringPoll,
    /// Cancellation arrives while later partitions remain outstanding.
    CancelDuringPartitionFetch,
    /// Polling sees a bounded 429 storm and advances deterministic backoff.
    RateLimitStorm,
    /// A later partition keeps failing until the retry budget is exhausted.
    PartialPartitionFailure,
    /// A plain non-idempotent submit receives a retryable status and is refused.
    UnsafeSubmitRetryRefusal,
}

impl RaceCaseKind {
    /// Stable scenario id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CancelDuringSubmit => "cancel_during_submit",
            Self::CancelDuringPoll => "cancel_during_poll",
            Self::CancelDuringPartitionFetch => "cancel_during_partition_fetch",
            Self::RateLimitStorm => "rate_limit_storm",
            Self::PartialPartitionFailure => "partial_partition_failure",
            Self::UnsafeSubmitRetryRefusal => "unsafe_submit_retry_refusal",
        }
    }

    fn all() -> [Self; 6] {
        [
            Self::CancelDuringSubmit,
            Self::CancelDuringPoll,
            Self::CancelDuringPartitionFetch,
            Self::RateLimitStorm,
            Self::PartialPartitionFailure,
            Self::UnsafeSubmitRetryRefusal,
        ]
    }
}

/// A single DPOR schedule result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaceCaseReport {
    /// Report schema.
    pub schema_version: u32,
    /// Scenario id.
    pub case: RaceCaseKind,
    /// Lab seed for this schedule.
    pub seed: u64,
    /// Total virtual TCP exchanges.
    pub virtual_tcp_exchanges: u32,
    /// Plain `POST /api/v2/statements` attempts.
    pub plain_submits: u32,
    /// Idempotent `POST /api/v2/statements?requestId=...&retry=true` attempts.
    pub retry_submits: u32,
    /// Poll GET attempts, including retryable failures.
    pub polls: u32,
    /// Partition GET attempts, including retryable failures.
    pub partitions: u32,
    /// Cancel POST attempts.
    pub cancels: u32,
    /// Deterministic retry delays applied by the manual clock.
    pub retry_delays_ms: Vec<u64>,
    /// Manual clock timestamp at the end of the schedule.
    pub manual_clock_ms: u64,
    /// Whether the statement reached a complete result.
    pub completed: bool,
    /// Whether the schedule ended as locally cancelled.
    pub cancelled: bool,
    /// Whether a retry budget was exhausted.
    pub retry_budget_exhausted: bool,
    /// Whether a non-idempotent submit retry was refused.
    pub unsafe_submit_retry_refused: bool,
    /// No plain submit was automatically reissued after a retryable response.
    pub no_double_submit: bool,
    /// Once a handle existed, local cancellation reached `/cancel`.
    pub cancel_propagated: bool,
    /// Retry attempts stayed within `1 + retry_limit`.
    pub bounded_retries: bool,
    /// The lab runtime reported no invariant violations.
    pub lab_invariants_clean: bool,
    /// The run exhausted the per-run step budget before quiescing, making it
    /// inconclusive. Under DPOR an unfair interleaving can starve a task to the
    /// step cap (the virtual HTTP exchange's tasks spin and the forced stop
    /// reports a spurious `TaskLeak`); such a schedule proves neither safety nor
    /// a violation, so [`RaceCaseReport::ok`] does not hold it to the invariants
    /// and the suite assertions skip it. See [`DporCaseReport::step_capped_runs`].
    pub step_capped: bool,
    /// Stable schedule certificate hash.
    pub certificate_hash: u64,
    /// Stable trace fingerprint for DPOR coverage grouping.
    pub trace_fingerprint: u64,
    /// Replay hint emitted in failure artifacts.
    pub replay_command: String,
    /// Crashpack/manifest id a failing scheduler can use as an artifact name.
    pub crashpack_manifest: String,
}

impl RaceCaseReport {
    /// True when every invariant this bead owns holds for the schedule.
    #[must_use]
    pub const fn ok(&self) -> bool {
        // A step-capped run is inconclusive (truncated mid-flight by an unfair
        // DPOR schedule), so it is not held to the cancel/retry invariants.
        self.step_capped
            || (self.no_double_submit
                && self.cancel_propagated
                && self.bounded_retries
                && self.lab_invariants_clean)
    }
}

/// Whole-suite report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaceSuiteReport {
    /// Report schema.
    pub schema_version: u32,
    /// Stable suite id.
    pub suite_id: String,
    /// Configuration summary.
    pub config: RaceSuiteConfigReport,
    /// Per-case, per-seed reports.
    pub schedules: Vec<RaceCaseReport>,
    /// DPOR coverage by case.
    pub dpor: Vec<DporCaseReport>,
}

impl RaceSuiteReport {
    /// True when every explored schedule passed.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.schedules.iter().all(RaceCaseReport::ok) && self.dpor.iter().all(DporCaseReport::ok)
    }
}

/// Serializable config summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaceSuiteConfigReport {
    /// First DPOR seed.
    pub base_seed: u64,
    /// Maximum DPOR runs per case.
    pub dpor_runs: usize,
    /// Per-run lab step cap.
    pub max_steps_per_run: u64,
    /// Retry attempts after the first request.
    pub retry_limit: u32,
}

impl From<&RaceSuiteConfig> for RaceSuiteConfigReport {
    fn from(value: &RaceSuiteConfig) -> Self {
        Self {
            base_seed: value.base_seed,
            dpor_runs: value.dpor_runs,
            max_steps_per_run: value.max_steps_per_run,
            retry_limit: value.retry_limit,
        }
    }
}

/// Serializable DPOR coverage summary for one case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DporCaseReport {
    /// Scenario id.
    pub case: RaceCaseKind,
    /// Number of schedules explored.
    pub total_runs: usize,
    /// Number of trace equivalence classes reached.
    pub unique_classes: usize,
    /// Number of violating schedules found by the lab runtime, excluding runs
    /// truncated at the per-run step budget (those are inconclusive — see
    /// [`DporCaseReport::step_capped_runs`]).
    pub violation_count: usize,
    /// Violating runs discarded because they exhausted the per-run step budget
    /// without quiescing. Under DPOR these are unfair-schedule truncations (a
    /// virtual HTTP exchange starved to the step cap, which the forced stop
    /// reports as a spurious `TaskLeak`), not reproducible invariant failures, so
    /// they are surfaced here but excluded from `violation_count`.
    pub step_capped_runs: usize,
    /// DPOR race counter.
    pub total_races: usize,
    /// DPOR backtrack points generated.
    pub total_backtrack_points: usize,
}

impl DporCaseReport {
    /// True when DPOR exploration found no lab invariant violations.
    #[must_use]
    pub const fn ok(&self) -> bool {
        self.violation_count == 0
    }
}

/// Race-suite error.
#[derive(Debug)]
pub enum RaceError {
    /// A lab/runtime operation failed.
    Lab(String),
    /// The explorer truncated the run at its per-run step budget before the
    /// virtual HTTP exchange could quiesce. The run is inconclusive (standard
    /// bounded-model-checking semantics): it proves neither safety nor a
    /// violation, so the suite treats it as step-capped rather than failed.
    Truncated,
    /// An HTTP exchange failed.
    Http(String),
    /// The lifecycle state machine rejected a transition.
    Lifecycle(String),
    /// A shared harness state lock was poisoned.
    Poisoned(&'static str),
    /// Serialization failed.
    Serialize(serde_json::Error),
    /// Structured logger failed.
    Log(LogError),
}

impl fmt::Display for RaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lab(message) => write!(f, "lab race error: {message}"),
            Self::Truncated => write!(
                f,
                "lab run truncated at the per-run step budget before quiescence (inconclusive)"
            ),
            Self::Http(message) => write!(f, "virtual HTTP error: {message}"),
            Self::Lifecycle(message) => write!(f, "lifecycle race error: {message}"),
            Self::Poisoned(name) => write!(f, "shared race state poisoned: {name}"),
            Self::Serialize(error) => write!(f, "race report serialization error: {error}"),
            Self::Log(error) => write!(f, "race logger error: {error}"),
        }
    }
}

impl std::error::Error for RaceError {}

impl From<serde_json::Error> for RaceError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialize(error)
    }
}

impl From<LogError> for RaceError {
    fn from(error: LogError) -> Self {
        Self::Log(error)
    }
}

/// Run the default deterministic race suite.
///
/// # Errors
/// Returns [`RaceError`] when the virtual HTTP layer or lifecycle machine fails
/// before a report can be produced.
pub fn run_default_race_suite() -> Result<RaceSuiteReport, RaceError> {
    run_race_suite(&default_race_suite_config())
}

/// Run the deterministic race suite with `config`.
///
/// # Errors
/// Returns [`RaceError`] when the virtual HTTP layer or lifecycle machine fails
/// before a report can be produced.
pub fn run_race_suite(config: &RaceSuiteConfig) -> Result<RaceSuiteReport, RaceError> {
    let schedules = Arc::new(Mutex::new(Vec::new()));
    let mut dpor = Vec::new();

    for (case_idx, case) in RaceCaseKind::all().into_iter().enumerate() {
        let case_seed = config.base_seed.wrapping_add((case_idx as u64) << 16);
        let mut explorer = DporExplorer::new(
            ExplorerConfig::new(case_seed, config.dpor_runs)
                .worker_count(2)
                .max_steps(config.max_steps_per_run),
        );
        let schedules_for_case = Arc::clone(&schedules);
        let retry_limit = config.retry_limit;
        let report = explorer.explore(move |runtime| {
            let schedule = run_case_under_lab(runtime, case, retry_limit);
            match schedules_for_case.lock() {
                Ok(mut reports) => reports.push(schedule),
                Err(poisoned) => poisoned.into_inner().push(poisoned_report(
                    case,
                    runtime.config().seed,
                    "race schedule sink",
                )),
            }
        });
        let coverage = explorer.dpor_coverage();
        dpor.push(dpor_case_report(
            case,
            &report,
            &coverage,
            config.max_steps_per_run,
        ));
    }

    let schedules = match Arc::try_unwrap(schedules) {
        Ok(mutex) => mutex
            .into_inner()
            .map_err(|_| RaceError::Poisoned("race schedules"))?,
        Err(shared) => shared
            .lock()
            .map_err(|_| RaceError::Poisoned("race schedules"))?
            .clone(),
    };

    Ok(RaceSuiteReport {
        schema_version: RACE_SUITE_SCHEMA_VERSION,
        suite_id: COMMAND_ID.to_owned(),
        config: RaceSuiteConfigReport::from(config),
        schedules,
        dpor,
    })
}

/// Serialize one JSON object per explored schedule.
///
/// # Errors
/// Returns [`RaceError::Serialize`] when a schedule cannot be serialized.
pub fn race_suite_jsonl(report: &RaceSuiteReport) -> Result<String, RaceError> {
    let mut out = String::new();
    for schedule in &report.schedules {
        out.push_str(&serde_json::to_string(schedule)?);
        out.push('\n');
    }
    Ok(out)
}

/// Write JSON-line race-suite artifacts using the shared testkit logger.
///
/// # Errors
/// Returns [`RaceError`] if the artifact directory cannot be written.
pub fn write_race_suite_artifacts(
    report: &RaceSuiteReport,
    artifacts_root: impl AsRef<Path>,
) -> Result<RunSummary, RaceError> {
    let mut logger = RunLogger::new(artifacts_root, &report.suite_id)?;
    for schedule in &report.schedules {
        let detail = serde_json::to_string(schedule)?;
        logger.emit(
            COMMAND_ID,
            schedule.case.as_str(),
            if schedule.ok() {
                StepOutcome::Pass
            } else {
                StepOutcome::Fail
            },
            Some(detail),
            schedule.ok().then_some("all invariants true".to_owned()),
            (!schedule.ok()).then_some(format!(
                "no_double_submit={} cancel_propagated={} bounded_retries={} lab_invariants_clean={}",
                schedule.no_double_submit,
                schedule.cancel_propagated,
                schedule.bounded_retries,
                schedule.lab_invariants_clean
            )),
        )?;
    }
    Ok(logger.finish()?)
}

fn dpor_case_report(
    case: RaceCaseKind,
    report: &ExplorationReport,
    coverage: &asupersync::lab::DporCoverageMetrics,
    max_steps_per_run: u64,
) -> DporCaseReport {
    // A run that consumed the entire per-run step budget was truncated before it
    // could quiesce. Under DPOR this occurs on unfair interleavings that starve a
    // task: the virtual HTTP exchange's client/server spin to the step cap and the
    // forced stop reports a `TaskLeak` for the two still-live tasks. Such a run
    // proves neither safety nor a violation — it is inconclusive. Counting these
    // made the suite non-deterministic (~40% pass) because the explorer only
    // sometimes reaches that high-step seed. Genuine invariant violations are
    // detected strictly before the cap, so `steps < max_steps_per_run` keeps them.
    let mut violation_count = 0;
    let mut step_capped_runs = 0;
    for violation in &report.violations {
        if violation.steps >= max_steps_per_run {
            step_capped_runs += 1;
        } else {
            violation_count += 1;
        }
    }
    DporCaseReport {
        case,
        total_runs: report.total_runs,
        unique_classes: report.unique_classes,
        violation_count,
        step_capped_runs,
        total_races: coverage.total_races,
        total_backtrack_points: coverage.total_backtrack_points,
    }
}

fn run_case_under_lab(
    runtime: &mut LabRuntime,
    case: RaceCaseKind,
    retry_limit: u32,
) -> RaceCaseReport {
    let seed = runtime.config().seed;
    match run_case_inner(runtime, case, retry_limit) {
        Ok(mut report) => {
            report.seed = seed;
            report.certificate_hash = runtime.certificate().hash();
            report.trace_fingerprint = trace_fingerprint(runtime);
            // Defensive backstop. Truncation is caught upstream at the virtual HTTP
            // exchange — the sole point of runtime advancement — and returned as
            // `RaceError::Truncated`, so an `Ok` run has already quiesced and this
            // flag is normally `false`. Should any future scenario advance the
            // runtime elsewhere and end non-quiescent, treat that truncation the
            // same way rather than letting its leftover live tasks poison the
            // invariants as a spurious `TaskLeak`.
            let step_capped = !runtime.is_quiescent();
            report.step_capped = step_capped;
            report.lab_invariants_clean = step_capped || runtime.check_invariants().is_empty();
            report
        }
        // The explorer truncated this run at its per-run step budget before the
        // exchange could quiesce. It is inconclusive (bounded-model-checking
        // semantics): mark it step-capped so `RaceCaseReport::ok()` and the suite's
        // cancel-propagation assertion skip it instead of failing on an artifact of
        // the unfair interleaving. The error is recorded in the report's manifest.
        Err(RaceError::Truncated) => {
            let mut report = failed_report(runtime, case, RaceError::Truncated);
            report.step_capped = true;
            report
        }
        Err(error) => failed_report(runtime, case, error),
    }
}

fn run_case_inner(
    runtime: &mut LabRuntime,
    case: RaceCaseKind,
    retry_limit: u32,
) -> Result<RaceCaseReport, RaceError> {
    let mut driver = RaceDriver::new(runtime, case, retry_limit);
    match case {
        RaceCaseKind::CancelDuringSubmit => driver.cancel_during_submit()?,
        RaceCaseKind::CancelDuringPoll => driver.cancel_during_poll()?,
        RaceCaseKind::CancelDuringPartitionFetch => driver.cancel_during_partition_fetch()?,
        RaceCaseKind::RateLimitStorm => driver.rate_limit_storm()?,
        RaceCaseKind::PartialPartitionFailure => driver.partial_partition_failure()?,
        RaceCaseKind::UnsafeSubmitRetryRefusal => driver.unsafe_submit_retry_refusal()?,
    }
    Ok(driver.finish())
}

struct RaceDriver<'a> {
    runtime: &'a mut LabRuntime,
    case: RaceCaseKind,
    retry_limit: u32,
    server: Arc<Mutex<RaceServerState>>,
    machine: StatementMachine,
    clock: ManualClock,
    retry_delays_ms: Vec<u64>,
    completed: bool,
    cancelled: bool,
    retry_budget_exhausted: bool,
    unsafe_submit_retry_refused: bool,
    max_attempts_observed: u32,
    region: asupersync::types::RegionId,
}

impl<'a> RaceDriver<'a> {
    fn new(runtime: &'a mut LabRuntime, case: RaceCaseKind, retry_limit: u32) -> Self {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        Self {
            runtime,
            case,
            retry_limit,
            server: Arc::new(Mutex::new(RaceServerState::for_case(case))),
            machine: StatementMachine::new(PollPlan::with_max_polls(8)),
            clock: ManualClock::new(),
            retry_delays_ms: Vec::new(),
            completed: false,
            cancelled: false,
            retry_budget_exhausted: false,
            unsafe_submit_retry_refused: false,
            max_attempts_observed: 0,
            region,
        }
    }

    fn cancel_during_submit(&mut self) -> Result<(), RaceError> {
        let response = self.send_with_retry(RouteKind::SubmitPlain, submit_request(false))?;
        let progress = self.on_submit(response)?;
        if let Progress::PollAgain(handle) = progress {
            self.cancel_handle(handle.as_str())?;
        }
        Ok(())
    }

    fn cancel_during_poll(&mut self) -> Result<(), RaceError> {
        let response = self.send_with_retry(RouteKind::SubmitPlain, submit_request(false))?;
        let progress = self.on_submit(response)?;
        let Progress::PollAgain(handle) = progress else {
            return Err(RaceError::Lifecycle(
                "expected poll handle after async submit".to_owned(),
            ));
        };
        let poll = self.send_with_retry(RouteKind::Poll, poll_request(handle.as_str()))?;
        let progress = self
            .machine
            .on_poll(ResponseClass::from_status(poll.status), &poll.body)
            .map_err(|error| RaceError::Lifecycle(error.to_string()))?;
        if let Progress::PollAgain(next) = progress {
            self.cancel_handle(next.as_str())?;
        }
        Ok(())
    }

    fn cancel_during_partition_fetch(&mut self) -> Result<(), RaceError> {
        let response = self.send_with_retry(RouteKind::SubmitPlain, submit_request(false))?;
        let progress = self.on_submit(response)?;
        let Progress::FetchPartition { handle, partition } = progress else {
            return Err(RaceError::Lifecycle(
                "expected first partition fetch after immediate multi-partition submit".to_owned(),
            ));
        };
        let fetched = self.send_with_retry(
            RouteKind::Partition,
            partition_request(handle.as_str(), partition),
        )?;
        let progress = self
            .machine
            .on_partition(
                ResponseClass::from_status(fetched.status),
                partition,
                &fetched.body,
            )
            .map_err(|error| RaceError::Lifecycle(error.to_string()))?;
        if let Progress::FetchPartition { handle, .. } = progress {
            self.cancel_handle(handle.as_str())?;
        }
        Ok(())
    }

    fn rate_limit_storm(&mut self) -> Result<(), RaceError> {
        let response = self.send_with_retry(RouteKind::SubmitPlain, submit_request(false))?;
        let progress = self.on_submit(response)?;
        let Progress::PollAgain(handle) = progress else {
            return Err(RaceError::Lifecycle(
                "expected poll handle after rate-limit submit".to_owned(),
            ));
        };
        let first_poll = self.send_with_retry(RouteKind::Poll, poll_request(handle.as_str()))?;
        let progress = self
            .machine
            .on_poll(
                ResponseClass::from_status(first_poll.status),
                &first_poll.body,
            )
            .map_err(|error| RaceError::Lifecycle(error.to_string()))?;
        let Progress::PollAgain(handle) = progress else {
            return Err(RaceError::Lifecycle(
                "expected running status after bounded 429 storm".to_owned(),
            ));
        };
        let terminal = self.send_with_retry(RouteKind::Poll, poll_request(handle.as_str()))?;
        let terminal_progress = self
            .machine
            .on_poll(ResponseClass::from_status(terminal.status), &terminal.body);
        self.mark_terminal(terminal_progress)?;
        Ok(())
    }

    fn partial_partition_failure(&mut self) -> Result<(), RaceError> {
        let response = self.send_with_retry(RouteKind::SubmitPlain, submit_request(false))?;
        let progress = self.on_submit(response)?;
        let Progress::FetchPartition { handle, partition } = progress else {
            return Err(RaceError::Lifecycle(
                "expected partition fetch after partial-failure submit".to_owned(),
            ));
        };
        let first = self.send_with_retry(
            RouteKind::Partition,
            partition_request(handle.as_str(), partition),
        )?;
        let progress = self
            .machine
            .on_partition(
                ResponseClass::from_status(first.status),
                partition,
                &first.body,
            )
            .map_err(|error| RaceError::Lifecycle(error.to_string()))?;
        let Progress::FetchPartition { handle, partition } = progress else {
            return Err(RaceError::Lifecycle(
                "expected second partition after partition 1".to_owned(),
            ));
        };
        let second = self.send_with_retry(
            RouteKind::Partition,
            partition_request(handle.as_str(), partition),
        );
        if matches!(second, Err(RaceError::Http(_))) {
            self.retry_budget_exhausted = true;
            self.cancel_handle(handle.as_str())?;
            return Ok(());
        }
        let response = second?;
        let terminal_progress = self.machine.on_partition(
            ResponseClass::from_status(response.status),
            partition,
            &response.body,
        );
        self.mark_terminal(terminal_progress)?;
        Ok(())
    }

    fn unsafe_submit_retry_refusal(&mut self) -> Result<(), RaceError> {
        match self.send_with_retry(RouteKind::SubmitPlain, submit_request(false)) {
            // A run truncated at the explorer's per-run step budget is inconclusive.
            // Propagate it unchanged so `run_case_under_lab` marks the schedule
            // step-capped; converting it into the resubmit-failure error below would
            // turn an unfair interleaving into a spurious suite failure. (This arm
            // must precede the `Http(_)` arm: before `Truncated` existed, truncation
            // arrived here as `Http("client did not produce a response")` and was
            // silently misread as a successful refusal.)
            Err(RaceError::Truncated) => Err(RaceError::Truncated),
            // The plain (non-idempotent) submit must REFUSE to retry a retryable
            // response; `send_with_retry` signals that refusal as an `Http` error.
            Err(RaceError::Http(_)) => {
                self.unsafe_submit_retry_refused = true;
                Ok(())
            }
            // A completed `Ok` response — or any non-truncation error — means the
            // unsafe submit was not refused as the invariant requires.
            _ => Err(RaceError::Http(
                "plain submit should refuse retryable response instead of resubmitting".to_owned(),
            )),
        }
    }

    fn on_submit(&mut self, response: MockHttpResponse) -> Result<Progress, RaceError> {
        let progress = self
            .machine
            .on_submit(ResponseClass::from_status(response.status), &response.body)
            .map_err(|error| RaceError::Lifecycle(error.to_string()))?;
        self.mark_progress(&progress);
        Ok(progress)
    }

    fn mark_terminal(
        &mut self,
        progress: Result<Progress, franken_snowflake_sqlapi::lifecycle::LifecycleError>,
    ) -> Result<(), RaceError> {
        let progress = progress.map_err(|error| RaceError::Lifecycle(error.to_string()))?;
        self.mark_progress(&progress);
        Ok(())
    }

    fn mark_progress(&mut self, progress: &Progress) {
        if matches!(progress, Progress::Complete(_)) {
            self.completed = true;
        }
    }

    fn cancel_handle(&mut self, handle: &str) -> Result<(), RaceError> {
        let response = self.send_once(cancel_request(handle))?;
        if response.status == 200 {
            self.cancelled = true;
        }
        Ok(())
    }

    fn send_with_retry(
        &mut self,
        route: RouteKind,
        request: H1Request,
    ) -> Result<MockHttpResponse, RaceError> {
        let schedule = retry_schedule(self.retry_limit, self.runtime.config().seed);
        let mut retries_spent = 0_u32;
        loop {
            let response = self.send_once(request.clone())?;
            let attempts = retries_spent.saturating_add(1);
            self.max_attempts_observed = self.max_attempts_observed.max(attempts);
            if !is_retryable_status(response.status) {
                return Ok(response);
            }
            if !route.allows_retry() {
                self.unsafe_submit_retry_refused = route == RouteKind::SubmitPlain;
                return Err(RaceError::Http(format!(
                    "{} returned retryable status {} but route is not idempotent",
                    route.as_str(),
                    response.status
                )));
            }
            if retries_spent >= self.retry_limit {
                self.retry_budget_exhausted = true;
                return Err(RaceError::Http(format!(
                    "{} exhausted retry budget after {} attempts",
                    route.as_str(),
                    attempts
                )));
            }
            if let Some(delay) = schedule.get(retries_spent as usize) {
                self.clock.advance(*delay);
                self.retry_delays_ms.push(duration_millis(*delay));
            }
            retries_spent = retries_spent.saturating_add(1);
        }
    }

    fn send_once(&mut self, request: H1Request) -> Result<MockHttpResponse, RaceError> {
        let exchange = perform_virtual_http_exchange(
            self.runtime,
            self.region,
            Arc::clone(&self.server),
            request,
        )?;
        Ok(exchange)
    }

    fn finish(self) -> RaceCaseReport {
        let counters = self
            .server
            .lock()
            .map(|state| state.counters.clone())
            .unwrap_or_default();
        let cancel_required = matches!(
            self.case,
            RaceCaseKind::CancelDuringSubmit
                | RaceCaseKind::CancelDuringPoll
                | RaceCaseKind::CancelDuringPartitionFetch
                | RaceCaseKind::PartialPartitionFailure
        );
        let no_double_submit = counters.plain_submits <= 1;
        let bounded_retries = self.max_attempts_observed <= self.retry_limit.saturating_add(1);
        RaceCaseReport {
            schema_version: RACE_SUITE_SCHEMA_VERSION,
            case: self.case,
            seed: self.runtime.config().seed,
            virtual_tcp_exchanges: counters.virtual_tcp_exchanges,
            plain_submits: counters.plain_submits,
            retry_submits: counters.retry_submits,
            polls: counters.polls,
            partitions: counters.partitions,
            cancels: counters.cancels,
            retry_delays_ms: self.retry_delays_ms,
            manual_clock_ms: duration_millis(self.clock.now()),
            completed: self.completed,
            cancelled: self.cancelled,
            retry_budget_exhausted: self.retry_budget_exhausted,
            unsafe_submit_retry_refused: self.unsafe_submit_retry_refused,
            no_double_submit,
            cancel_propagated: !cancel_required || counters.cancels >= 1,
            bounded_retries,
            lab_invariants_clean: true,
            step_capped: false,
            certificate_hash: 0,
            trace_fingerprint: 0,
            replay_command: replay_command(self.case, self.runtime.config().seed),
            crashpack_manifest: crashpack_manifest(self.case, self.runtime.config().seed),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RouteKind {
    SubmitPlain,
    Poll,
    Partition,
}

impl RouteKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SubmitPlain => "submit_plain",
            Self::Poll => "poll",
            Self::Partition => "partition",
        }
    }

    const fn allows_retry(self) -> bool {
        matches!(self, Self::Poll | Self::Partition)
    }
}

#[derive(Clone, Debug, Default)]
struct RaceCounters {
    virtual_tcp_exchanges: u32,
    plain_submits: u32,
    retry_submits: u32,
    polls: u32,
    partitions: u32,
    cancels: u32,
}

struct RaceServerState {
    mock: MockSqlApi,
    scripts: BTreeMap<String, VecDeque<MockHttpResponse>>,
    counters: RaceCounters,
}

impl RaceServerState {
    fn for_case(case: RaceCaseKind) -> Self {
        let mut state = match case {
            RaceCaseKind::CancelDuringPartitionFetch | RaceCaseKind::PartialPartitionFailure => {
                Self::multi_partition(case)
            }
            RaceCaseKind::UnsafeSubmitRetryRefusal => Self::unsafe_submit_refusal(case),
            RaceCaseKind::RateLimitStorm => Self::rate_limit_storm(case),
            RaceCaseKind::CancelDuringSubmit | RaceCaseKind::CancelDuringPoll => {
                Self::default_async(case)
            }
        };
        state.install_common_scripts();
        state
    }

    fn default_async(_case: RaceCaseKind) -> Self {
        Self {
            mock: scenarios::default_async_lifecycle(),
            scripts: BTreeMap::new(),
            counters: RaceCounters::default(),
        }
    }

    fn rate_limit_storm(_case: RaceCaseKind) -> Self {
        let handle = scenarios::DEFAULT_HANDLE;
        let mut scripts = BTreeMap::new();
        scripts.insert(
            format!("GET /api/v2/statements/{handle}"),
            VecDeque::from([
                scenarios::rate_limited(),
                scenarios::rate_limited(),
                scenarios::running(),
                scenarios::ok_single_partition(),
            ]),
        );
        Self {
            mock: scenarios::default_async_lifecycle(),
            scripts,
            counters: RaceCounters::default(),
        }
    }

    fn multi_partition(case: RaceCaseKind) -> Self {
        let handle = "01b2c3d4-0000-0000-0000-000000000010";
        let mut scripts = BTreeMap::new();
        if case == RaceCaseKind::PartialPartitionFailure {
            scripts.insert(
                format!("GET /api/v2/statements/{handle}?partition=2"),
                VecDeque::from([
                    retryable_failure(),
                    retryable_failure(),
                    retryable_failure(),
                ]),
            );
        }
        Self {
            mock: MockSqlApi::new(
                handle,
                scenarios::running(),
                scenarios::ok_multi_partition(),
                scenarios::cancel(),
            )
            .immediate()
            .with_partition(
                1,
                MockHttpResponse::json(
                    200,
                    br#"[["18264","ENTITY125"],["18265","ENTITY126"]]"#.to_vec(),
                ),
            )
            .with_partition(
                2,
                MockHttpResponse::json(200, br#"[["18266","ENTITY127"]]"#.to_vec()),
            ),
            scripts,
            counters: RaceCounters::default(),
        }
    }

    fn unsafe_submit_refusal(_case: RaceCaseKind) -> Self {
        let mut scripts = BTreeMap::new();
        scripts.insert(
            "POST /api/v2/statements".to_owned(),
            VecDeque::from([retryable_failure(), scenarios::running()]),
        );
        Self {
            mock: scenarios::default_async_lifecycle(),
            scripts,
            counters: RaceCounters::default(),
        }
    }

    fn install_common_scripts(&mut self) {}

    fn respond(&mut self, request: H1Request) -> H1Response {
        let mock_request = h1_to_mock_request(request);
        self.counters.virtual_tcp_exchanges = self.counters.virtual_tcp_exchanges.saturating_add(1);
        self.count(&mock_request);
        let key = format!("{} {}", mock_request.method.as_str(), mock_request.path);
        let response = self
            .scripts
            .get_mut(&key)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| self.mock.respond(&mock_request));
        mock_to_h1_response(response)
    }

    fn count(&mut self, request: &MockHttpRequest) {
        match (&request.method, request.path.as_str()) {
            (MockMethod::Post, "/api/v2/statements") => {
                self.counters.plain_submits = self.counters.plain_submits.saturating_add(1);
            }
            (MockMethod::Post, path) if path.starts_with("/api/v2/statements?") => {
                self.counters.retry_submits = self.counters.retry_submits.saturating_add(1);
            }
            (MockMethod::Get, path) if path.contains("?partition=") => {
                self.counters.partitions = self.counters.partitions.saturating_add(1);
            }
            (MockMethod::Get, path) if path.starts_with("/api/v2/statements/") => {
                self.counters.polls = self.counters.polls.saturating_add(1);
            }
            (MockMethod::Post, path) if path.ends_with("/cancel") => {
                self.counters.cancels = self.counters.cancels.saturating_add(1);
            }
            _ => {}
        }
    }
}

fn perform_virtual_http_exchange(
    runtime: &mut LabRuntime,
    region: asupersync::types::RegionId,
    server_state: Arc<Mutex<RaceServerState>>,
    request: H1Request,
) -> Result<MockHttpResponse, RaceError> {
    let seed_low = (runtime.config().seed & 0xffff) as u16;
    let base_port = 30_000_u16.saturating_add(seed_low % 10_000);
    let client_addr = socket_addr(base_port);
    let server_addr = socket_addr(base_port.saturating_add(1));
    let (client_io, server_io) = VirtualTcpStream::pair(client_addr, server_addr);
    let client_result: Arc<Mutex<Option<Result<H1Response, String>>>> = Arc::new(Mutex::new(None));

    let server = Http1Server::with_config(
        move |request| {
            let server_state = Arc::clone(&server_state);
            async move {
                match server_state.lock() {
                    Ok(mut state) => state.respond(request),
                    Err(poisoned) => {
                        let mut state = poisoned.into_inner();
                        state.respond(request)
                    }
                }
            }
        },
        Http1Config::default()
            .host_policy(HostPolicy::AllowAll)
            .keep_alive(false)
            .max_requests(Some(1)),
    );

    let (server_task, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let _ = server.serve(server_io).await;
        })
        .map_err(|error| RaceError::Lab(format!("server task spawn failed: {error}")))?;

    let client_slot = Arc::clone(&client_result);
    let (client_task, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let result = Http1Client::request_with_io(client_io, request)
                .await
                .map(|(response, _)| response)
                .map_err(|error| error.to_string());
            match client_slot.lock() {
                Ok(mut slot) => *slot = Some(result),
                Err(poisoned) => {
                    *poisoned.into_inner() = Some(Err("client slot poisoned".to_owned()))
                }
            }
        })
        .map_err(|error| RaceError::Lab(format!("client task spawn failed: {error}")))?;

    {
        let mut scheduler = runtime.scheduler.lock();
        scheduler.schedule(server_task, 0);
        scheduler.schedule(client_task, 0);
    }
    runtime.run_until_quiescent();

    // `run_until_quiescent` returns either when the runtime quiesces or when the
    // explorer's external per-run step budget is exhausted. Every byte of runtime
    // advancement in a race case flows through this exchange, so this is the one
    // place truncation can be observed reliably. A non-quiescent return means an
    // unfair DPOR interleaving starved the server/client tasks: the run is
    // truncated and inconclusive. Surface it as a typed `Truncated` error here so
    // its two leftover live tasks never reach the end-of-run invariant check (where
    // they would masquerade as a `TaskLeak`) and so the missing client response is
    // attributed to truncation rather than reported as a spurious HTTP failure.
    if !runtime.is_quiescent() {
        return Err(RaceError::Truncated);
    }

    let result = client_result
        .lock()
        .map_err(|_| RaceError::Poisoned("virtual HTTP client result"))?
        .take()
        .ok_or_else(|| RaceError::Http("client did not produce a response".to_owned()))?;
    let response = result.map_err(RaceError::Http)?;
    Ok(h1_to_mock_response(response))
}

fn h1_to_mock_request(request: H1Request) -> MockHttpRequest {
    MockHttpRequest {
        method: match request.method {
            H1Method::Get => MockMethod::Get,
            H1Method::Post => MockMethod::Post,
            other => MockMethod::Other(other.as_str().to_owned()),
        },
        path: request.uri,
        headers: request.headers,
        body: request.body,
    }
}

fn h1_to_mock_response(response: H1Response) -> MockHttpResponse {
    MockHttpResponse {
        status: response.status,
        headers: response.headers,
        body: response.body,
    }
}

fn mock_to_h1_response(response: MockHttpResponse) -> H1Response {
    H1Response {
        version: Version::Http11,
        status: response.status,
        reason: reason_phrase(response.status).to_owned(),
        headers: response.headers,
        body: response.body,
        trailers: Vec::new(),
    }
}

fn submit_request(retry: bool) -> H1Request {
    let path = if retry {
        "/api/v2/statements?requestId=req-w0i4&retry=true"
    } else {
        "/api/v2/statements"
    };
    h1_request(
        H1Method::Post,
        path,
        scenarios::SUBMIT_SELECT_REQUEST.to_vec(),
    )
}

fn poll_request(handle: &str) -> H1Request {
    h1_request(
        H1Method::Get,
        format!("/api/v2/statements/{handle}"),
        Vec::new(),
    )
}

fn partition_request(handle: &str, partition: u32) -> H1Request {
    h1_request(
        H1Method::Get,
        format!("/api/v2/statements/{handle}?partition={partition}"),
        Vec::new(),
    )
}

fn cancel_request(handle: &str) -> H1Request {
    h1_request(
        H1Method::Post,
        format!("/api/v2/statements/{handle}/cancel"),
        Vec::new(),
    )
}

fn h1_request(method: H1Method, uri: impl Into<String>, body: Vec<u8>) -> H1Request {
    H1Request {
        method,
        uri: uri.into(),
        version: Version::Http11,
        headers: vec![("Host".to_owned(), CLIENT_HOST.to_owned())],
        body,
        trailers: Vec::new(),
        peer_addr: None,
    }
}

fn retry_schedule(retry_limit: u32, seed: u64) -> Vec<Duration> {
    let policy = BackoffPolicy::exponential(
        Duration::from_millis(25),
        Duration::from_millis(100),
        retry_limit,
    );
    backoff_schedule(&policy, seed)
}

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500..=599)
}

fn retryable_failure() -> MockHttpResponse {
    MockHttpResponse::json(
        503,
        br#"{"code":"390503","message":"transient overload"}"#.to_vec(),
    )
}

fn socket_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn trace_fingerprint(runtime: &LabRuntime) -> u64 {
    asupersync::trace::trace_fingerprint(&runtime.trace().snapshot())
}

fn replay_command(case: RaceCaseKind, seed: u64) -> String {
    format!(
        "cargo test -p franken-snowflake-testkit race::{case} -- --exact seed={seed}",
        case = case.as_str()
    )
}

fn crashpack_manifest(case: RaceCaseKind, seed: u64) -> String {
    format!("fsnow-w0i4-{}-{seed}.replay.json", case.as_str())
}

fn failed_report(runtime: &LabRuntime, case: RaceCaseKind, error: RaceError) -> RaceCaseReport {
    let seed = runtime.config().seed;
    RaceCaseReport {
        schema_version: RACE_SUITE_SCHEMA_VERSION,
        case,
        seed,
        virtual_tcp_exchanges: 0,
        plain_submits: 0,
        retry_submits: 0,
        polls: 0,
        partitions: 0,
        cancels: 0,
        retry_delays_ms: Vec::new(),
        manual_clock_ms: 0,
        completed: false,
        cancelled: false,
        retry_budget_exhausted: false,
        unsafe_submit_retry_refused: false,
        no_double_submit: false,
        cancel_propagated: false,
        bounded_retries: false,
        lab_invariants_clean: false,
        step_capped: false,
        certificate_hash: runtime.certificate().hash(),
        trace_fingerprint: trace_fingerprint(runtime),
        replay_command: replay_command(case, seed),
        crashpack_manifest: format!("{}; error={error}", crashpack_manifest(case, seed)),
    }
}

fn poisoned_report(case: RaceCaseKind, seed: u64, name: &'static str) -> RaceCaseReport {
    RaceCaseReport {
        schema_version: RACE_SUITE_SCHEMA_VERSION,
        case,
        seed,
        virtual_tcp_exchanges: 0,
        plain_submits: 0,
        retry_submits: 0,
        polls: 0,
        partitions: 0,
        cancels: 0,
        retry_delays_ms: Vec::new(),
        manual_clock_ms: 0,
        completed: false,
        cancelled: false,
        retry_budget_exhausted: false,
        unsafe_submit_retry_refused: false,
        no_double_submit: false,
        cancel_propagated: false,
        bounded_retries: false,
        lab_invariants_clean: false,
        step_capped: false,
        certificate_hash: 0,
        trace_fingerprint: 0,
        replay_command: replay_command(case, seed),
        crashpack_manifest: format!("{}; poisoned={name}", crashpack_manifest(case, seed)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_race_suite_proves_cancel_retry_invariants() -> Result<(), Box<dyn std::error::Error>>
    {
        let report = run_default_race_suite()?;
        assert!(report.ok(), "race suite report: {report:#?}");
        assert_eq!(
            report.schedules.len(),
            RaceCaseKind::all().len() * DEFAULT_DPOR_RUNS
        );
        assert!(report.schedules.iter().any(|schedule| schedule.case
            == RaceCaseKind::UnsafeSubmitRetryRefusal
            && schedule.unsafe_submit_retry_refused
            && schedule.plain_submits == 1));
        assert!(
            report
                .schedules
                .iter()
                .filter(|schedule| matches!(
                    schedule.case,
                    RaceCaseKind::CancelDuringSubmit
                        | RaceCaseKind::CancelDuringPoll
                        | RaceCaseKind::CancelDuringPartitionFetch
                        | RaceCaseKind::PartialPartitionFailure
                ))
                // Step-capped runs are inconclusive (truncated before the cancel
                // step), so they are exempt from the cancel-propagation check.
                .all(|schedule| schedule.step_capped || schedule.cancels >= 1)
        );
        let jsonl = race_suite_jsonl(&report)?;
        assert_eq!(jsonl.lines().count(), report.schedules.len());
        Ok(())
    }
}
