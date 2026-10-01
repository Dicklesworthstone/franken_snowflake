//! Public downstream adapter contract.
//!
//! Downstream integrations should consume connector artifacts through this
//! narrow trait instead of depending on Snowflake SQL API request/response
//! structs. Every method returns the same deterministic [`Envelope`] metadata
//! used by the CLI and MCP surfaces, so adapters can preserve output contract
//! ids, error codes, data-source provenance, and safety classes.

use serde::{Deserialize, Serialize};

use crate::envelope::Envelope;
use crate::error::{SnowflakeError, SnowflakeErrorCode};
use crate::guardrails::RightsClass;
use crate::ids::{DatasetId, ProfileName, QueryId, ReceiptHash, RequestId, StatementHandle};
use crate::outcome::{DataSource, OutcomeKind};

/// Adapter provider manifest payload contract id.
pub const ADAPTER_PROVIDER_MANIFEST_CONTRACT_ID: &str = "fsnow.adapter.provider_manifest.v1";
/// Profile diagnostics payload contract id.
pub const ADAPTER_PROFILE_DIAGNOSTICS_CONTRACT_ID: &str = "fsnow.adapter.profile_diagnostics.v1";
/// Catalog discovery payload contract id.
pub const ADAPTER_CATALOG_DISCOVERY_CONTRACT_ID: &str = "fsnow.adapter.catalog_discovery.v1";
/// Dataset manifest payload contract id.
pub const ADAPTER_DATASET_MANIFEST_CONTRACT_ID: &str = "fsnow.adapter.dataset_manifest.v1";
/// Query receipt payload contract id.
pub const ADAPTER_QUERY_RECEIPT_CONTRACT_ID: &str = "fsnow.adapter.query_receipt.v1";
/// Content export payload contract id.
pub const ADAPTER_CONTENT_EXPORT_CONTRACT_ID: &str = "fsnow.adapter.content_export.v1";
/// Frame ingest payload contract id.
pub const ADAPTER_FRAME_INGEST_CONTRACT_ID: &str = "fsnow.adapter.frame_ingest.v1";
/// Structured JSON-line log contract id for adapter fixtures.
pub const ADAPTER_FIXTURE_LOG_CONTRACT_ID: &str = "fsnow.adapter.fixture_log.v1";

/// Public adapter result type. Errors use the same stable registry as CLI/MCP.
pub type AdapterResult<T> = Result<Envelope<T>, SnowflakeError>;

/// Narrow downstream contract for authenticated private data-lake integrations.
///
/// Implementors expose connector artifacts and diagnostics. They do not expose
/// Snowflake SQL API protocol structs, raw credentials, or downstream-specific
/// policy decisions.
pub trait SnowflakeDataLakeAdapter {
    /// Provider and contract manifest.
    fn provider_manifest(&self) -> AdapterResult<ProviderManifest>;

    /// Secret-free profile diagnostics for one profile.
    fn profile_diagnostics(&self, profile: &ProfileName) -> AdapterResult<ProfileDiagnostics>;

    /// Catalog discovery summary for one profile.
    fn catalog_discovery(&self, profile: &ProfileName) -> AdapterResult<CatalogDiscoveryContract>;

    /// Dataset manifest view for a downstream dataset id.
    fn dataset_manifest(&self, dataset: &DatasetId) -> AdapterResult<DatasetManifestContract>;

    /// Content-addressed query receipt lookup.
    fn query_receipt(&self, receipt: &ReceiptHash) -> AdapterResult<QueryReceiptContract>;

    /// Content-addressed export lookup.
    fn content_export(&self, export_id: &str) -> AdapterResult<ContentExportContract>;

    /// Frame-ingest schema/provenance lookup for materialized result frames.
    fn frame_ingest(&self, frame_id: &str) -> AdapterResult<FrameIngestContract>;
}

/// One output contract exposed by an adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterOutputContract {
    /// Stable command or tool identifier.
    pub command_id: String,
    /// Stable payload contract id.
    pub output_contract_id: String,
    /// Safety facets compatible with CLI/MCP capability rows.
    pub safety: AdapterSafetyFacet,
    /// Stable connector error codes this operation may surface.
    pub possible_error_codes: Vec<SnowflakeErrorCode>,
    /// Safe follow-up commands copied from the public CLI contract.
    pub safe_next_commands: Vec<String>,
}

/// Safety facets that downstream adapters can map into their own policy model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterSafetyFacet {
    /// Operation is read-only from the adapter's point of view.
    pub read_only: bool,
    /// Operation may require a live Snowflake/provider network call upstream.
    pub provider_network: bool,
    /// Operation mutates local connector state.
    pub mutates_local_state: bool,
    /// Payload may reveal private business data or sensitive metadata.
    pub sensitive_output: bool,
    /// Maximum rights class this operation can return.
    pub max_rights_class: RightsClass,
}

impl AdapterSafetyFacet {
    /// Read-only private-data safety facet.
    #[must_use]
    pub const fn read_private(provider_network: bool) -> Self {
        Self {
            read_only: true,
            provider_network,
            mutates_local_state: false,
            sensitive_output: true,
            max_rights_class: RightsClass::Private,
        }
    }
}

/// Provider manifest that lets downstreams discover the integration surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderManifest {
    /// Contract schema id for the manifest itself.
    pub schema: String,
    /// Public provider id.
    pub provider_id: String,
    /// Human-readable provider name.
    pub display_name: String,
    /// Explicit statement of the integration boundary.
    pub data_lake_kind: DataLakeKind,
    /// Whether the provider requires authenticated profile context.
    pub authenticated_private_source: bool,
    /// Supported artifact contracts.
    pub contracts: Vec<AdapterOutputContract>,
    /// Stable non-goals for downstream adapter authors.
    pub non_goals: Vec<String>,
}

/// Source class represented by the adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataLakeKind {
    /// Authenticated Snowflake SQL API data lake.
    SnowflakeSqlApi,
}

/// Secret-free profile diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileDiagnostics {
    /// Profile checked.
    pub profile_id: ProfileName,
    /// Diagnostic status.
    pub status: ProfileDiagnosticStatus,
    /// Authentication lane selected by profile metadata.
    pub auth_lane: AuthLaneContract,
    /// Credential reference; never a raw credential value.
    pub credential_ref: CredentialRefContract,
    /// Redacted account locator or host fingerprint.
    pub account_ref_redacted: String,
    /// Rights class required to use the profile.
    pub required_rights_class: RightsClass,
    /// Stable warnings.
    pub warnings: Vec<String>,
    /// Stable error codes reported by this diagnostic.
    pub error_codes: Vec<SnowflakeErrorCode>,
}

/// Diagnostic status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileDiagnosticStatus {
    /// Profile is structurally valid.
    Valid,
    /// Profile exists but credentials are absent.
    CredentialMissing,
    /// Profile is invalid.
    Invalid,
}

/// Supported auth lane labels for downstream contract metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthLaneContract {
    /// Programmatic access token.
    ProgrammaticAccessToken,
    /// Key-pair JWT.
    KeyPairJwt,
    /// OAuth bearer.
    OAuthBearer,
    /// Workload Identity Federation.
    WorkloadIdentityFederation,
}

/// Credential reference kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRefKind {
    /// Environment variable name.
    Env,
    /// External secret-provider handle.
    Provider,
}

/// Secret-free credential reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRefContract {
    /// Reference kind.
    pub kind: CredentialRefKind,
    /// Non-secret env var name or provider handle.
    pub handle: String,
}

/// Catalog discovery summary for downstream ingestion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogDiscoveryContract {
    /// Profile that produced the catalog.
    pub profile_id: ProfileName,
    /// Stable catalog snapshot id.
    pub snapshot_id: String,
    /// Snapshot payload address.
    pub content_address: ContentAddressRef,
    /// Number of dataset manifests in the snapshot.
    pub dataset_count: u32,
    /// Number of column catalog rows in the snapshot.
    pub column_count: u32,
    /// Number of operator catalog rows in the snapshot.
    pub operator_count: u32,
    /// Discovery provenance.
    pub provenance: AdapterProvenance,
}

/// Dataset manifest contract consumed by downstream adapters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetManifestContract {
    /// Dataset identifier.
    pub dataset_id: DatasetId,
    /// Owning profile.
    pub profile_id: ProfileName,
    /// Redacted object reference for display/logging.
    pub object_ref_redacted: String,
    /// Stable object fingerprint for joins and audit.
    pub object_fingerprint: String,
    /// Rights class attached to the dataset.
    pub rights_class: RightsClass,
    /// Default row limit.
    pub default_limit: u64,
    /// Maximum rows before export is required.
    pub max_rows_without_export: u64,
    /// Dataset fields.
    pub fields: Vec<DatasetFieldContract>,
    /// Manifest payload address.
    pub content_address: ContentAddressRef,
    /// Manifest provenance.
    pub provenance: AdapterProvenance,
}

/// Dataset field role assignment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetFieldContract {
    /// Column name as exposed by the manifest.
    pub column: String,
    /// Planner-facing role label.
    pub role: FieldRoleContract,
    /// Dtype class label.
    pub dtype: DtypeClassContract,
    /// Whether the downstream contract expects this field.
    pub required: bool,
}

/// Dataset field role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldRoleContract {
    /// Entity key.
    EntityKey,
    /// Time index.
    TimeIndex,
    /// Point-in-time known-at axis.
    KnownAt,
    /// Feature/value column.
    Feature,
    /// Label column.
    Label,
    /// Metadata column.
    Metadata,
}

/// Downstream dtype class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DtypeClassContract {
    /// Text/string.
    String,
    /// Numeric.
    Number,
    /// Boolean.
    Boolean,
    /// Date.
    Date,
    /// Timestamp.
    Timestamp,
    /// Semi-structured.
    Variant,
}

/// Query receipt contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryReceiptContract {
    /// Receipt content address.
    pub receipt_hash: ReceiptHash,
    /// Plan id used to produce the receipt.
    pub plan_id: String,
    /// Profile used by the query.
    pub profile_id: ProfileName,
    /// Optional dataset id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<DatasetId>,
    /// Request id / SQL API idempotency key.
    pub request_id: RequestId,
    /// Snowflake query id where available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_id: Option<QueryId>,
    /// Statement handle where available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_handle: Option<StatementHandle>,
    /// Outcome class.
    pub outcome_kind: OutcomeKind,
    /// Rights class propagated from profile/dataset policy.
    pub rights_class: RightsClass,
    /// Row count where known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<u64>,
    /// Receipt payload address.
    pub content_address: ContentAddressRef,
    /// Redactions applied before publishing the receipt.
    pub redactions_applied: Vec<String>,
}

/// Content export contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentExportContract {
    /// Stable export id.
    pub export_id: String,
    /// Source receipt.
    pub receipt_hash: ReceiptHash,
    /// Export format.
    pub format: ExportFormatContract,
    /// Redacted target URI.
    pub target_uri_redacted: String,
    /// Artifact address.
    pub content_address: ContentAddressRef,
    /// Row count where known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<u64>,
}

/// Supported export format labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormatContract {
    /// Snowflake-side COPY INTO.
    CopyInto,
    /// Local CSV.
    Csv,
    /// Local JSONL.
    Jsonl,
    /// Local Parquet.
    Parquet,
}

/// Frame ingest contract for downstream materializers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameIngestContract {
    /// Stable frame id.
    pub frame_id: String,
    /// Source receipt.
    pub receipt_hash: ReceiptHash,
    /// Frame column schema.
    pub columns: Vec<FrameColumnContract>,
    /// Row count where known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<u64>,
    /// Frame payload/schema address.
    pub content_address: ContentAddressRef,
    /// Rights class propagated from source receipt.
    pub rights_class: RightsClass,
}

/// Frame column schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameColumnContract {
    /// Column name.
    pub name: String,
    /// Dtype class.
    pub dtype: DtypeClassContract,
    /// Whether the column may contain null values.
    pub nullable: bool,
}

/// Portable content address reference shared by receipts, exports, and frames.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentAddressRef {
    /// Hash algorithm label.
    pub algorithm: String,
    /// Lowercase hex digest.
    pub digest_hex: String,
    /// Canonical byte length.
    pub byte_len: u64,
}

/// Secret-free provenance for adapter artifacts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterProvenance {
    /// Data source class.
    pub data_source: DataSource,
    /// Producer command id.
    pub command_id: String,
    /// Trace id.
    pub trace_id: String,
    /// Profile/object fingerprint.
    pub fingerprint: String,
}

/// Structured JSON-line log emitted by adapter contract fixtures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterContractLogLine {
    /// Log schema version.
    pub schema_version: u16,
    /// Fixture surface.
    pub surface: String,
    /// Outcome class.
    pub outcome_kind: OutcomeKind,
    /// Output contract checked.
    pub output_contract_id: String,
    /// Secret-free detail.
    pub detail: String,
}

impl AdapterContractLogLine {
    /// Create a fixture log line.
    #[must_use]
    pub fn checked(surface: impl Into<String>, output_contract_id: impl Into<String>) -> Self {
        Self {
            schema_version: 1,
            surface: surface.into(),
            outcome_kind: OutcomeKind::Success,
            output_contract_id: output_contract_id.into(),
            detail: "adapter contract fixture passed".to_owned(),
        }
    }

    /// Serialize to one JSON line.
    ///
    /// # Errors
    /// Returns the underlying serializer error if the line cannot be rendered.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self).map(|line| format!("{line}\n"))
    }
}

/// The seven adapter operations with their contract ids, read-only
/// private-data safety facets, and the error codes each may surface. Every
/// adapter's provider manifest lists exactly these.
#[must_use]
pub fn standard_output_contracts() -> Vec<AdapterOutputContract> {
    vec![
        output_contract(
            "adapter.provider_manifest",
            ADAPTER_PROVIDER_MANIFEST_CONTRACT_ID,
            false,
            vec![SnowflakeErrorCode::Internal],
        ),
        output_contract(
            "adapter.profile_diagnostics",
            ADAPTER_PROFILE_DIAGNOSTICS_CONTRACT_ID,
            false,
            vec![
                SnowflakeErrorCode::ProfileNotFound,
                SnowflakeErrorCode::ProfileInvalid,
                SnowflakeErrorCode::CredentialMissing,
            ],
        ),
        output_contract(
            "adapter.catalog_discovery",
            ADAPTER_CATALOG_DISCOVERY_CONTRACT_ID,
            true,
            vec![
                SnowflakeErrorCode::ProfileNotFound,
                SnowflakeErrorCode::UpstreamError,
                SnowflakeErrorCode::MetadataError,
            ],
        ),
        output_contract(
            "adapter.dataset_manifest",
            ADAPTER_DATASET_MANIFEST_CONTRACT_ID,
            false,
            vec![SnowflakeErrorCode::MetadataError],
        ),
        output_contract(
            "adapter.query_receipt",
            ADAPTER_QUERY_RECEIPT_CONTRACT_ID,
            false,
            vec![
                SnowflakeErrorCode::MetadataError,
                SnowflakeErrorCode::CacheError,
            ],
        ),
        output_contract(
            "adapter.content_export",
            ADAPTER_CONTENT_EXPORT_CONTRACT_ID,
            false,
            vec![
                SnowflakeErrorCode::MetadataError,
                SnowflakeErrorCode::CacheError,
            ],
        ),
        output_contract(
            "adapter.frame_ingest",
            ADAPTER_FRAME_INGEST_CONTRACT_ID,
            false,
            vec![SnowflakeErrorCode::MetadataError],
        ),
    ]
}

fn output_contract(
    command_id: &str,
    output_contract_id: &str,
    provider_network: bool,
    possible_error_codes: Vec<SnowflakeErrorCode>,
) -> AdapterOutputContract {
    AdapterOutputContract {
        command_id: command_id.to_owned(),
        output_contract_id: output_contract_id.to_owned(),
        safety: AdapterSafetyFacet::read_private(provider_network),
        possible_error_codes,
        safe_next_commands: vec!["franken-snowflake capabilities --json".to_owned()],
    }
}

pub mod conformance {
    //! The trait conformance suite every [`SnowflakeDataLakeAdapter`] must
    //! pass (reality-check bead oj0.39): contract ids and outcome on every
    //! envelope, provenance that agrees with the envelope's data source (an
    //! adapter may not relabel fixture artifacts as live), typed errors for
    //! unknown ids instead of empty successes, well-formed content addresses,
    //! and no secret-shaped text anywhere in an answer.

    use super::{
        ADAPTER_CATALOG_DISCOVERY_CONTRACT_ID, ADAPTER_CONTENT_EXPORT_CONTRACT_ID,
        ADAPTER_DATASET_MANIFEST_CONTRACT_ID, ADAPTER_FRAME_INGEST_CONTRACT_ID,
        ADAPTER_PROFILE_DIAGNOSTICS_CONTRACT_ID, ADAPTER_PROVIDER_MANIFEST_CONTRACT_ID,
        ADAPTER_QUERY_RECEIPT_CONTRACT_ID, AdapterProvenance, AdapterResult, ContentAddressRef,
        SnowflakeDataLakeAdapter,
    };
    use crate::envelope::{Envelope, EnvelopeMeta};
    use crate::error::SnowflakeErrorCode;
    use crate::guardrails::RightsClass;
    use crate::ids::{DatasetId, ProfileName, ReceiptHash};
    use crate::outcome::{DataSource, OutcomeKind};

    /// The artifacts to look up, and where they came from.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ConformanceProbe {
        /// A profile the adapter knows.
        pub profile: ProfileName,
        /// A dataset the adapter knows.
        pub dataset: DatasetId,
        /// A query receipt the adapter knows.
        pub receipt: ReceiptHash,
        /// An export the adapter knows, when it has one.
        pub export_id: Option<String>,
        /// A frame the adapter knows, when it has one.
        pub frame_id: Option<String>,
        /// The data source the artifacts truly come from (`Live` for a store
        /// fed by live runs, `Fixture` for fixtures).
        pub expected_data_source: DataSource,
    }

    const UNKNOWN: &str = "fsnow-conformance-unknown-id";

    /// Every way `adapter` breaks the contract for `probe`; empty when it
    /// conforms.
    #[must_use]
    pub fn check_adapter_conformance<A: SnowflakeDataLakeAdapter + ?Sized>(
        adapter: &A,
        probe: &ConformanceProbe,
    ) -> Vec<String> {
        let mut violations = Vec::new();
        let expected = probe.expected_data_source;

        match adapter.provider_manifest() {
            Ok(manifest) => {
                check_meta(
                    &mut violations,
                    &manifest.meta,
                    "adapter.provider_manifest",
                    ADAPTER_PROVIDER_MANIFEST_CONTRACT_ID,
                    expected,
                    false,
                );
                if !manifest.data.authenticated_private_source {
                    violations
                        .push("provider_manifest: not an authenticated private source".into());
                }
                if manifest.data.contracts.len() != 7 {
                    violations.push(format!(
                        "provider_manifest: {} contracts, expected the 7 adapter operations",
                        manifest.data.contracts.len()
                    ));
                }
                for contract in &manifest.data.contracts {
                    if !contract.safety.read_only
                        || contract.safety.mutates_local_state
                        || contract.safety.max_rights_class != RightsClass::Private
                        || !contract.output_contract_id.starts_with("fsnow.adapter.")
                        || contract.possible_error_codes.is_empty()
                    {
                        violations.push(format!(
                            "provider_manifest: contract {} is not a read-only private-data operation with error codes",
                            contract.command_id
                        ));
                    }
                }
                check_secret_free(&mut violations, "provider_manifest", &manifest);
            }
            Err(error) => violations.push(format!("provider_manifest failed: {}", error.message)),
        }

        match adapter.profile_diagnostics(&probe.profile) {
            Ok(diagnostics) => {
                check_meta(
                    &mut violations,
                    &diagnostics.meta,
                    "adapter.profile_diagnostics",
                    ADAPTER_PROFILE_DIAGNOSTICS_CONTRACT_ID,
                    expected,
                    false,
                );
                if diagnostics.data.profile_id != probe.profile {
                    violations.push("profile_diagnostics: answered for another profile".into());
                }
                check_secret_free(&mut violations, "profile_diagnostics", &diagnostics);
            }
            Err(error) => violations.push(format!("profile_diagnostics failed: {}", error.message)),
        }

        match adapter.catalog_discovery(&probe.profile) {
            Ok(catalog) => {
                check_meta(
                    &mut violations,
                    &catalog.meta,
                    "adapter.catalog_discovery",
                    ADAPTER_CATALOG_DISCOVERY_CONTRACT_ID,
                    expected,
                    true,
                );
                check_provenance(
                    &mut violations,
                    "catalog_discovery",
                    &catalog.meta,
                    &catalog.data.provenance,
                );
                check_address(
                    &mut violations,
                    "catalog_discovery",
                    &catalog.data.content_address,
                );
                if catalog.data.profile_id != probe.profile {
                    violations.push("catalog_discovery: answered for another profile".into());
                }
                check_secret_free(&mut violations, "catalog_discovery", &catalog);
            }
            Err(error) => violations.push(format!("catalog_discovery failed: {}", error.message)),
        }

        match adapter.dataset_manifest(&probe.dataset) {
            Ok(dataset) => {
                check_meta(
                    &mut violations,
                    &dataset.meta,
                    "adapter.dataset_manifest",
                    ADAPTER_DATASET_MANIFEST_CONTRACT_ID,
                    expected,
                    true,
                );
                check_provenance(
                    &mut violations,
                    "dataset_manifest",
                    &dataset.meta,
                    &dataset.data.provenance,
                );
                check_address(
                    &mut violations,
                    "dataset_manifest",
                    &dataset.data.content_address,
                );
                if dataset.data.dataset_id != probe.dataset {
                    violations.push("dataset_manifest: answered for another dataset".into());
                }
                if dataset.data.fields.is_empty() {
                    violations.push("dataset_manifest: no fields".into());
                }
                check_secret_free(&mut violations, "dataset_manifest", &dataset);
            }
            Err(error) => violations.push(format!("dataset_manifest failed: {}", error.message)),
        }

        match adapter.query_receipt(&probe.receipt) {
            Ok(receipt) => {
                check_meta(
                    &mut violations,
                    &receipt.meta,
                    "adapter.query_receipt",
                    ADAPTER_QUERY_RECEIPT_CONTRACT_ID,
                    expected,
                    true,
                );
                check_address(
                    &mut violations,
                    "query_receipt",
                    &receipt.data.content_address,
                );
                if receipt.data.receipt_hash != probe.receipt
                    || receipt.meta.receipt_hash.as_ref() != Some(&probe.receipt)
                {
                    violations.push("query_receipt: the receipt hash does not round-trip".into());
                }
                check_secret_free(&mut violations, "query_receipt", &receipt);
            }
            Err(error) => violations.push(format!("query_receipt failed: {}", error.message)),
        }

        if let Some(export_id) = &probe.export_id {
            match adapter.content_export(export_id) {
                Ok(export) => {
                    check_meta(
                        &mut violations,
                        &export.meta,
                        "adapter.content_export",
                        ADAPTER_CONTENT_EXPORT_CONTRACT_ID,
                        expected,
                        true,
                    );
                    check_address(
                        &mut violations,
                        "content_export",
                        &export.data.content_address,
                    );
                    if &export.data.export_id != export_id
                        || export.meta.receipt_hash.as_ref() != Some(&export.data.receipt_hash)
                    {
                        violations.push("content_export: ids do not round-trip".into());
                    }
                    check_secret_free(&mut violations, "content_export", &export);
                }
                Err(error) => violations.push(format!("content_export failed: {}", error.message)),
            }
        }

        if let Some(frame_id) = &probe.frame_id {
            match adapter.frame_ingest(frame_id) {
                Ok(frame) => {
                    check_meta(
                        &mut violations,
                        &frame.meta,
                        "adapter.frame_ingest",
                        ADAPTER_FRAME_INGEST_CONTRACT_ID,
                        expected,
                        true,
                    );
                    check_address(&mut violations, "frame_ingest", &frame.data.content_address);
                    if &frame.data.frame_id != frame_id || frame.data.columns.is_empty() {
                        violations.push("frame_ingest: wrong frame or no columns".into());
                    }
                    check_secret_free(&mut violations, "frame_ingest", &frame);
                }
                Err(error) => violations.push(format!("frame_ingest failed: {}", error.message)),
            }
        }

        // Unknown ids are typed errors, never empty successes.
        let unknown_profile = ProfileName::new(UNKNOWN);
        check_unknown(
            &mut violations,
            "profile_diagnostics",
            adapter.profile_diagnostics(&unknown_profile),
        );
        check_unknown(
            &mut violations,
            "catalog_discovery",
            adapter.catalog_discovery(&unknown_profile),
        );
        check_unknown(
            &mut violations,
            "dataset_manifest",
            adapter.dataset_manifest(&DatasetId::new(UNKNOWN)),
        );
        check_unknown(
            &mut violations,
            "query_receipt",
            adapter.query_receipt(&ReceiptHash::new(UNKNOWN)),
        );
        check_unknown(
            &mut violations,
            "content_export",
            adapter.content_export(UNKNOWN),
        );
        check_unknown(
            &mut violations,
            "frame_ingest",
            adapter.frame_ingest(UNKNOWN),
        );
        violations
    }

    /// `artifact` envelopes must carry the artifacts' true data source; the
    /// others may leave it unspecified but may not claim another one.
    fn check_meta(
        violations: &mut Vec<String>,
        meta: &EnvelopeMeta,
        command_id: &str,
        output_contract_id: &str,
        expected: DataSource,
        artifact: bool,
    ) {
        if !meta.ok || meta.outcome_kind != OutcomeKind::Success {
            violations.push(format!("{command_id}: not a successful envelope"));
        }
        if meta.command_id != command_id || meta.output_contract_id != output_contract_id {
            violations.push(format!(
                "{command_id}: envelope names {} / {}",
                meta.command_id, meta.output_contract_id
            ));
        }
        let allowed = meta.data_source == expected
            || (!artifact && meta.data_source == DataSource::Unspecified);
        if !allowed {
            violations.push(format!(
                "{command_id}: data_source {:?}, the artifacts are {expected:?}",
                meta.data_source
            ));
        }
    }

    fn check_provenance(
        violations: &mut Vec<String>,
        what: &str,
        meta: &EnvelopeMeta,
        provenance: &AdapterProvenance,
    ) {
        if provenance.data_source != meta.data_source {
            violations.push(format!(
                "{what}: envelope says {:?} but the artifact's provenance is {:?}",
                meta.data_source, provenance.data_source
            ));
        }
    }

    fn check_address(violations: &mut Vec<String>, what: &str, address: &ContentAddressRef) {
        if address.algorithm != "blake3" || address.digest_hex.is_empty() || address.byte_len == 0 {
            violations.push(format!("{what}: malformed content address {address:?}"));
        }
    }

    fn check_secret_free<T: serde::Serialize>(
        violations: &mut Vec<String>,
        what: &str,
        envelope: &Envelope<T>,
    ) {
        match serde_json::to_string(envelope) {
            Ok(text) if crate::redact::contains_secret(&text) => {
                violations.push(format!("{what}: the answer carries secret-shaped text"));
            }
            Ok(_) => {}
            Err(error) => violations.push(format!("{what}: does not serialize: {error}")),
        }
    }

    fn check_unknown<T>(violations: &mut Vec<String>, what: &str, result: AdapterResult<T>) {
        match result {
            Ok(_) => violations.push(format!("{what}: an unknown id answered success")),
            Err(error)
                if matches!(
                    error.code,
                    SnowflakeErrorCode::ProfileNotFound | SnowflakeErrorCode::MetadataError
                ) => {}
            Err(error) => violations.push(format!(
                "{what}: an unknown id answered {:?}, not ProfileNotFound/MetadataError",
                error.code
            )),
        }
    }
}

#[cfg(feature = "adapter-fixtures")]
pub mod fixtures {
    //! Public adapter contract fixtures.

    use super::*;
    use crate::envelope::EnvelopeMeta;

    /// Result of running the adapter contract fixture.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AdapterFixtureReport {
        /// Fixture schema id.
        pub schema: String,
        /// Provider id checked.
        pub provider_id: String,
        /// Output contract ids checked.
        pub checked_contracts: Vec<String>,
        /// Structured JSON-line logs.
        pub log_lines: Vec<String>,
    }

    /// No-account fixture adapter for downstream contract tests.
    #[derive(Clone, Debug, Default)]
    pub struct FixtureSnowflakeAdapter;

    impl SnowflakeDataLakeAdapter for FixtureSnowflakeAdapter {
        fn provider_manifest(&self) -> AdapterResult<ProviderManifest> {
            Ok(envelope(
                "adapter.provider_manifest",
                ADAPTER_PROVIDER_MANIFEST_CONTRACT_ID,
                ProviderManifest {
                    schema: ADAPTER_PROVIDER_MANIFEST_CONTRACT_ID.to_owned(),
                    provider_id: "snowflake_sql_api".to_owned(),
                    display_name: "Snowflake SQL API".to_owned(),
                    data_lake_kind: DataLakeKind::SnowflakeSqlApi,
                    authenticated_private_source: true,
                    contracts: standard_output_contracts(),
                    non_goals: vec![
                        "downstream adapters must not handle raw credentials".to_owned(),
                        "downstream adapters must not embed Snowflake protocol code".to_owned(),
                        "downstream adapters own their user-facing policy semantics".to_owned(),
                    ],
                },
            ))
        }

        fn profile_diagnostics(&self, profile: &ProfileName) -> AdapterResult<ProfileDiagnostics> {
            if profile.as_str() != fixture_profile().as_str() {
                return Err(SnowflakeError::new(
                    SnowflakeErrorCode::ProfileNotFound,
                    "fixture profile not found",
                ));
            }
            Ok(envelope_with_profile(
                "adapter.profile_diagnostics",
                ADAPTER_PROFILE_DIAGNOSTICS_CONTRACT_ID,
                profile.clone(),
                ProfileDiagnostics {
                    profile_id: profile.clone(),
                    status: ProfileDiagnosticStatus::Valid,
                    auth_lane: AuthLaneContract::ProgrammaticAccessToken,
                    credential_ref: CredentialRefContract {
                        kind: CredentialRefKind::Env,
                        handle: "FRANKEN_SNOWFLAKE_FIXTURE_PAT".to_owned(),
                    },
                    account_ref_redacted: "[redacted-account]".to_owned(),
                    required_rights_class: RightsClass::Private,
                    warnings: Vec::new(),
                    error_codes: vec![
                        SnowflakeErrorCode::ProfileNotFound,
                        SnowflakeErrorCode::CredentialMissing,
                    ],
                },
            ))
        }

        fn catalog_discovery(
            &self,
            profile: &ProfileName,
        ) -> AdapterResult<CatalogDiscoveryContract> {
            if profile.as_str() != fixture_profile().as_str() {
                return Err(SnowflakeError::new(
                    SnowflakeErrorCode::ProfileNotFound,
                    "fixture profile not found",
                ));
            }
            Ok(envelope_with_profile(
                "adapter.catalog_discovery",
                ADAPTER_CATALOG_DISCOVERY_CONTRACT_ID,
                profile.clone(),
                CatalogDiscoveryContract {
                    profile_id: profile.clone(),
                    snapshot_id: "catalog-fixture-0001".to_owned(),
                    content_address: fixture_address("catalog snapshot"),
                    dataset_count: 1,
                    column_count: 4,
                    operator_count: 3,
                    provenance: fixture_provenance("catalog.scan"),
                },
            ))
        }

        fn dataset_manifest(&self, dataset: &DatasetId) -> AdapterResult<DatasetManifestContract> {
            if dataset.as_str() != fixture_dataset().as_str() {
                return Err(SnowflakeError::new(
                    SnowflakeErrorCode::MetadataError,
                    "fixture dataset not found",
                ));
            }
            Ok(envelope_with_profile(
                "adapter.dataset_manifest",
                ADAPTER_DATASET_MANIFEST_CONTRACT_ID,
                fixture_profile(),
                DatasetManifestContract {
                    dataset_id: dataset.clone(),
                    profile_id: fixture_profile(),
                    object_ref_redacted: "[redacted-db].[redacted-schema].[redacted-object]"
                        .to_owned(),
                    object_fingerprint: "obj_blake3_6f6a_fixture".to_owned(),
                    rights_class: RightsClass::Private,
                    default_limit: 1_000,
                    max_rows_without_export: 10_000,
                    fields: vec![
                        DatasetFieldContract {
                            column: "ENTITY_ID".to_owned(),
                            role: FieldRoleContract::EntityKey,
                            dtype: DtypeClassContract::String,
                            required: true,
                        },
                        DatasetFieldContract {
                            column: "OBSERVED_AT".to_owned(),
                            role: FieldRoleContract::TimeIndex,
                            dtype: DtypeClassContract::Timestamp,
                            required: true,
                        },
                        DatasetFieldContract {
                            column: "KNOWN_AT".to_owned(),
                            role: FieldRoleContract::KnownAt,
                            dtype: DtypeClassContract::Timestamp,
                            required: false,
                        },
                        DatasetFieldContract {
                            column: "VALUE".to_owned(),
                            role: FieldRoleContract::Feature,
                            dtype: DtypeClassContract::Number,
                            required: true,
                        },
                    ],
                    content_address: fixture_address("dataset manifest"),
                    provenance: fixture_provenance("catalog.scan"),
                },
            ))
        }

        fn query_receipt(&self, receipt: &ReceiptHash) -> AdapterResult<QueryReceiptContract> {
            if receipt.as_str() != fixture_receipt().as_str() {
                return Err(SnowflakeError::new(
                    SnowflakeErrorCode::MetadataError,
                    "fixture receipt not found",
                ));
            }
            let mut envelope = envelope_with_profile(
                "adapter.query_receipt",
                ADAPTER_QUERY_RECEIPT_CONTRACT_ID,
                fixture_profile(),
                QueryReceiptContract {
                    receipt_hash: receipt.clone(),
                    plan_id: "plan-fixture-0001".to_owned(),
                    profile_id: fixture_profile(),
                    dataset_id: Some(fixture_dataset()),
                    request_id: RequestId::new("00000000-0000-4000-8000-000000000201"),
                    query_id: Some(QueryId::new("01b70844-0000-0000-0000-fixture")),
                    statement_handle: Some(StatementHandle::new("stmt-fixture-0001")),
                    outcome_kind: OutcomeKind::Success,
                    rights_class: RightsClass::Private,
                    row_count: Some(3),
                    content_address: fixture_address("query receipt"),
                    redactions_applied: vec!["account".to_owned()],
                },
            );
            envelope.meta.receipt_hash = Some(receipt.clone());
            Ok(envelope)
        }

        fn content_export(&self, export_id: &str) -> AdapterResult<ContentExportContract> {
            if export_id != "export-fixture-0001" {
                return Err(SnowflakeError::new(
                    SnowflakeErrorCode::MetadataError,
                    "fixture export not found",
                ));
            }
            let mut envelope = envelope_with_profile(
                "adapter.content_export",
                ADAPTER_CONTENT_EXPORT_CONTRACT_ID,
                fixture_profile(),
                ContentExportContract {
                    export_id: export_id.to_owned(),
                    receipt_hash: fixture_receipt(),
                    format: ExportFormatContract::Jsonl,
                    target_uri_redacted: "file://[redacted-path]/fixture.jsonl".to_owned(),
                    content_address: fixture_address("content export"),
                    row_count: Some(3),
                },
            );
            envelope.meta.receipt_hash = Some(fixture_receipt());
            Ok(envelope)
        }

        fn frame_ingest(&self, frame_id: &str) -> AdapterResult<FrameIngestContract> {
            if frame_id != "frame-fixture-0001" {
                return Err(SnowflakeError::new(
                    SnowflakeErrorCode::MetadataError,
                    "fixture frame not found",
                ));
            }
            let mut envelope = envelope_with_profile(
                "adapter.frame_ingest",
                ADAPTER_FRAME_INGEST_CONTRACT_ID,
                fixture_profile(),
                FrameIngestContract {
                    frame_id: frame_id.to_owned(),
                    receipt_hash: fixture_receipt(),
                    columns: vec![
                        FrameColumnContract {
                            name: "ENTITY_ID".to_owned(),
                            dtype: DtypeClassContract::String,
                            nullable: false,
                        },
                        FrameColumnContract {
                            name: "OBSERVED_AT".to_owned(),
                            dtype: DtypeClassContract::Timestamp,
                            nullable: false,
                        },
                        FrameColumnContract {
                            name: "VALUE".to_owned(),
                            dtype: DtypeClassContract::Number,
                            nullable: true,
                        },
                    ],
                    row_count: Some(3),
                    content_address: fixture_address("frame ingest"),
                    rights_class: RightsClass::Private,
                },
            );
            envelope.meta.receipt_hash = Some(fixture_receipt());
            Ok(envelope)
        }
    }

    /// Run the public adapter contract fixture against an implementation.
    ///
    /// # Errors
    /// Returns the adapter's stable [`SnowflakeError`] when an implementation
    /// fails to provide a required fixture contract.
    pub fn assert_adapter_contract<A: SnowflakeDataLakeAdapter>(
        adapter: &A,
    ) -> Result<AdapterFixtureReport, SnowflakeError> {
        let provider = adapter.provider_manifest()?;
        assert_contract(
            &provider.meta,
            "adapter.provider_manifest",
            ADAPTER_PROVIDER_MANIFEST_CONTRACT_ID,
        );
        assert!(provider.data.authenticated_private_source);
        assert_contract_list(&provider.data.contracts);

        let profile = fixture_profile();
        let diagnostics = adapter.profile_diagnostics(&profile)?;
        assert_contract(
            &diagnostics.meta,
            "adapter.profile_diagnostics",
            ADAPTER_PROFILE_DIAGNOSTICS_CONTRACT_ID,
        );
        assert_eq!(diagnostics.data.profile_id, profile);
        assert_eq!(diagnostics.data.required_rights_class, RightsClass::Private);

        let catalog = adapter.catalog_discovery(&fixture_profile())?;
        assert_contract(
            &catalog.meta,
            "adapter.catalog_discovery",
            ADAPTER_CATALOG_DISCOVERY_CONTRACT_ID,
        );
        assert_eq!(catalog.data.dataset_count, 1);
        assert_eq!(catalog.data.provenance.data_source, DataSource::Fixture);

        let dataset = adapter.dataset_manifest(&fixture_dataset())?;
        assert_contract(
            &dataset.meta,
            "adapter.dataset_manifest",
            ADAPTER_DATASET_MANIFEST_CONTRACT_ID,
        );
        assert_eq!(dataset.data.rights_class, RightsClass::Private);
        assert!(
            dataset
                .data
                .fields
                .iter()
                .any(|field| field.role == FieldRoleContract::EntityKey)
        );

        let receipt = adapter.query_receipt(&fixture_receipt())?;
        assert_contract(
            &receipt.meta,
            "adapter.query_receipt",
            ADAPTER_QUERY_RECEIPT_CONTRACT_ID,
        );
        assert_eq!(receipt.data.outcome_kind, OutcomeKind::Success);
        assert_eq!(receipt.data.content_address.algorithm, "blake3");

        let export = adapter.content_export("export-fixture-0001")?;
        assert_contract(
            &export.meta,
            "adapter.content_export",
            ADAPTER_CONTENT_EXPORT_CONTRACT_ID,
        );
        assert_eq!(export.data.receipt_hash, fixture_receipt());
        assert_eq!(export.data.content_address.algorithm, "blake3");

        let frame = adapter.frame_ingest("frame-fixture-0001")?;
        assert_contract(
            &frame.meta,
            "adapter.frame_ingest",
            ADAPTER_FRAME_INGEST_CONTRACT_ID,
        );
        assert_eq!(frame.data.rights_class, RightsClass::Private);
        assert_eq!(frame.data.columns.len(), 3);

        let checked_contracts = vec![
            ADAPTER_PROVIDER_MANIFEST_CONTRACT_ID.to_owned(),
            ADAPTER_PROFILE_DIAGNOSTICS_CONTRACT_ID.to_owned(),
            ADAPTER_CATALOG_DISCOVERY_CONTRACT_ID.to_owned(),
            ADAPTER_DATASET_MANIFEST_CONTRACT_ID.to_owned(),
            ADAPTER_QUERY_RECEIPT_CONTRACT_ID.to_owned(),
            ADAPTER_CONTENT_EXPORT_CONTRACT_ID.to_owned(),
            ADAPTER_FRAME_INGEST_CONTRACT_ID.to_owned(),
        ];
        let mut log_lines = Vec::new();
        for contract in &checked_contracts {
            let line = AdapterContractLogLine::checked("adapter-fixtures", contract)
                .to_json_line()
                .map_err(|error| {
                    SnowflakeError::new(SnowflakeErrorCode::Internal, error.to_string())
                })?;
            log_lines.push(line);
        }

        Ok(AdapterFixtureReport {
            schema: ADAPTER_FIXTURE_LOG_CONTRACT_ID.to_owned(),
            provider_id: provider.data.provider_id,
            checked_contracts,
            log_lines,
        })
    }

    fn envelope<T: serde::Serialize>(
        command_id: &str,
        output_contract_id: &str,
        data: T,
    ) -> Envelope<T> {
        Envelope::new(
            fixture_meta(command_id, output_contract_id).with_data_source(DataSource::Fixture),
            data,
        )
    }

    fn envelope_with_profile<T: serde::Serialize>(
        command_id: &str,
        output_contract_id: &str,
        profile: ProfileName,
        data: T,
    ) -> Envelope<T> {
        Envelope::new(
            fixture_meta(command_id, output_contract_id)
                .with_data_source(DataSource::Fixture)
                .with_profile(profile),
            data,
        )
    }

    fn fixture_meta(command_id: &str, output_contract_id: &str) -> EnvelopeMeta {
        EnvelopeMeta::success(command_id, output_contract_id).with_timing(
            "2026-06-25T00:00:00Z",
            "2026-06-25T00:00:00Z",
            0,
        )
    }

    fn fixture_profile() -> ProfileName {
        ProfileName::new("fixture-private-lake")
    }

    fn fixture_dataset() -> DatasetId {
        DatasetId::new("fixture.events_daily")
    }

    fn fixture_receipt() -> ReceiptHash {
        ReceiptHash::new("blake3:fixture-query-receipt-0001")
    }

    fn fixture_provenance(command_id: &str) -> AdapterProvenance {
        AdapterProvenance {
            data_source: DataSource::Fixture,
            command_id: command_id.to_owned(),
            trace_id: "trace-fixture-0001".to_owned(),
            fingerprint: "profile_obj_fingerprint_fixture".to_owned(),
        }
    }

    fn fixture_address(label: &str) -> ContentAddressRef {
        ContentAddressRef {
            algorithm: "blake3".to_owned(),
            digest_hex: format!("fixture_{}", label.replace(' ', "_")),
            byte_len: label.len() as u64,
        }
    }

    fn assert_contract(meta: &EnvelopeMeta, command_id: &str, output_contract_id: &str) {
        assert!(meta.ok);
        assert_eq!(meta.outcome_kind, OutcomeKind::Success);
        assert_eq!(meta.command_id, command_id);
        assert_eq!(meta.output_contract_id, output_contract_id);
        assert_eq!(meta.data_source, DataSource::Fixture);
    }

    fn assert_contract_list(contracts: &[AdapterOutputContract]) {
        assert_eq!(contracts.len(), 7);
        for contract in contracts {
            assert!(contract.safety.read_only);
            assert!(!contract.safety.mutates_local_state);
            assert!(contract.safety.sensitive_output);
            assert_eq!(contract.safety.max_rights_class, RightsClass::Private);
            assert!(contract.output_contract_id.starts_with("fsnow.adapter."));
            assert!(!contract.possible_error_codes.is_empty());
        }
    }
}

#[cfg(all(test, feature = "adapter-fixtures"))]
mod tests {
    use super::conformance::{ConformanceProbe, check_adapter_conformance};
    use super::fixtures::{FixtureSnowflakeAdapter, assert_adapter_contract};
    use super::*;

    fn fixture_probe(expected: DataSource) -> ConformanceProbe {
        ConformanceProbe {
            profile: ProfileName::new("fixture-private-lake"),
            dataset: DatasetId::new("fixture.events_daily"),
            receipt: ReceiptHash::new("blake3:fixture-query-receipt-0001"),
            export_id: Some("export-fixture-0001".to_owned()),
            frame_id: Some("frame-fixture-0001".to_owned()),
            expected_data_source: expected,
        }
    }

    /// Fixture data relabeled as live: what the suite must refuse.
    struct RelabeledAsLive(FixtureSnowflakeAdapter);

    fn live<T>(result: AdapterResult<T>) -> AdapterResult<T> {
        result.map(|mut envelope| {
            envelope.meta.data_source = DataSource::Live;
            envelope
        })
    }

    impl SnowflakeDataLakeAdapter for RelabeledAsLive {
        fn provider_manifest(&self) -> AdapterResult<ProviderManifest> {
            live(self.0.provider_manifest())
        }
        fn profile_diagnostics(&self, profile: &ProfileName) -> AdapterResult<ProfileDiagnostics> {
            live(self.0.profile_diagnostics(profile))
        }
        fn catalog_discovery(
            &self,
            profile: &ProfileName,
        ) -> AdapterResult<CatalogDiscoveryContract> {
            live(self.0.catalog_discovery(profile))
        }
        fn dataset_manifest(&self, dataset: &DatasetId) -> AdapterResult<DatasetManifestContract> {
            live(self.0.dataset_manifest(dataset))
        }
        fn query_receipt(&self, receipt: &ReceiptHash) -> AdapterResult<QueryReceiptContract> {
            live(self.0.query_receipt(receipt))
        }
        fn content_export(&self, export_id: &str) -> AdapterResult<ContentExportContract> {
            live(self.0.content_export(export_id))
        }
        fn frame_ingest(&self, frame_id: &str) -> AdapterResult<FrameIngestContract> {
            live(self.0.frame_ingest(frame_id))
        }
    }

    #[test]
    fn the_fixture_adapter_passes_the_conformance_suite() {
        let violations = check_adapter_conformance(
            &FixtureSnowflakeAdapter,
            &fixture_probe(DataSource::Fixture),
        );
        assert_eq!(violations, Vec::<String>::new());
    }

    #[test]
    fn fixture_data_labeled_live_fails_the_conformance_suite() {
        // Probed as live: the provenance still says fixture.
        let violations = check_adapter_conformance(
            &RelabeledAsLive(FixtureSnowflakeAdapter),
            &fixture_probe(DataSource::Live),
        );
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("provenance is Fixture")),
            "{violations:?}"
        );
        // Probed as the fixture it is: every envelope claims live.
        let violations = check_adapter_conformance(
            &RelabeledAsLive(FixtureSnowflakeAdapter),
            &fixture_probe(DataSource::Fixture),
        );
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("data_source Live")),
            "{violations:?}"
        );
    }

    #[test]
    fn fixture_adapter_satisfies_public_downstream_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let adapter = FixtureSnowflakeAdapter;
        let report = assert_adapter_contract(&adapter)?;
        assert_eq!(report.provider_id, "snowflake_sql_api");
        assert_eq!(report.checked_contracts.len(), 7);
        for line in &report.log_lines {
            assert!(line.ends_with('\n'));
            assert!(line.contains("fsnow.adapter."));
        }
        let rendered = serde_json::to_string(&report)?;
        assert!(rendered.contains("fsnow.adapter.fixture_log.v1"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("token"));
        assert!(!rendered.contains("private key"));
        Ok(())
    }
}
