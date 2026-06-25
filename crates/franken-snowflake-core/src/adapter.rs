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
                    contracts: output_contracts(),
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

    fn output_contracts() -> Vec<AdapterOutputContract> {
        vec![
            contract(
                "adapter.provider_manifest",
                ADAPTER_PROVIDER_MANIFEST_CONTRACT_ID,
                false,
                vec![SnowflakeErrorCode::Internal],
            ),
            contract(
                "adapter.profile_diagnostics",
                ADAPTER_PROFILE_DIAGNOSTICS_CONTRACT_ID,
                false,
                vec![
                    SnowflakeErrorCode::ProfileNotFound,
                    SnowflakeErrorCode::ProfileInvalid,
                    SnowflakeErrorCode::CredentialMissing,
                ],
            ),
            contract(
                "adapter.catalog_discovery",
                ADAPTER_CATALOG_DISCOVERY_CONTRACT_ID,
                true,
                vec![
                    SnowflakeErrorCode::ProfileNotFound,
                    SnowflakeErrorCode::UpstreamError,
                    SnowflakeErrorCode::MetadataError,
                ],
            ),
            contract(
                "adapter.dataset_manifest",
                ADAPTER_DATASET_MANIFEST_CONTRACT_ID,
                false,
                vec![SnowflakeErrorCode::MetadataError],
            ),
            contract(
                "adapter.query_receipt",
                ADAPTER_QUERY_RECEIPT_CONTRACT_ID,
                false,
                vec![
                    SnowflakeErrorCode::MetadataError,
                    SnowflakeErrorCode::CacheError,
                ],
            ),
            contract(
                "adapter.content_export",
                ADAPTER_CONTENT_EXPORT_CONTRACT_ID,
                false,
                vec![
                    SnowflakeErrorCode::MetadataError,
                    SnowflakeErrorCode::CacheError,
                ],
            ),
            contract(
                "adapter.frame_ingest",
                ADAPTER_FRAME_INGEST_CONTRACT_ID,
                false,
                vec![SnowflakeErrorCode::MetadataError],
            ),
        ]
    }

    fn contract(
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
    use super::fixtures::{FixtureSnowflakeAdapter, assert_adapter_contract};

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
