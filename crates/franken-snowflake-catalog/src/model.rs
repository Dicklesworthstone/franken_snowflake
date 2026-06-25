//! Dataset manifest and catalog artifact models.

use serde::{Deserialize, Deserializer, Serialize};

/// Version string carried by persisted TOML and deterministic JSON outputs.
pub const SCHEMA_VERSION: &str = "franken_snowflake.dataset_manifest.v1";

/// A full catalog snapshot envelope payload: datasets, columns, and operators.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSnapshot {
    /// Artifact contract version.
    pub schema_version: String,
    /// Snapshot-wide provenance.
    pub provenance: Provenance,
    /// User-facing dataset manifests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub datasets: Vec<DatasetManifest>,
    /// Independently queryable column catalog entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<ColumnCatalogEntry>,
    /// Independently queryable operator catalog entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operators: Vec<crate::operator::OperatorCatalogEntry>,
}

impl CatalogSnapshot {
    /// Construct an empty snapshot using the current schema version.
    #[must_use]
    pub fn empty(provenance: Provenance) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            provenance,
            datasets: Vec::new(),
            columns: Vec::new(),
            operators: Vec::new(),
        }
    }

    /// Find a dataset by ID.
    #[must_use]
    pub fn dataset(&self, dataset_id: &str) -> Option<&DatasetManifest> {
        self.datasets
            .iter()
            .find(|dataset| dataset.id == dataset_id)
    }

    /// Return the columns associated with one dataset in ordinal order.
    #[must_use]
    pub fn columns_for_dataset(&self, dataset_id: &str) -> Vec<&ColumnCatalogEntry> {
        let mut columns = self
            .columns
            .iter()
            .filter(|column| column.dataset_id == dataset_id)
            .collect::<Vec<_>>();
        columns.sort_by_key(|column| column.ordinal);
        columns
    }
}

/// Secret-free provenance attached to snapshots and artifacts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Where the artifact came from.
    pub source: ProvenanceSource,
    /// Envelope-compatible data source class.
    pub data_source: DataSourceClass,
    /// Stable snapshot or fixture bundle ID.
    pub snapshot_id: String,
    /// Deterministic test clock or wall-clock instant.
    pub discovered_at: String,
    /// Secret-free profile fingerprint.
    pub profile_fingerprint: String,
    /// Stable object identity or redacted object fingerprint.
    pub object_fingerprint: String,
    /// CLI/MCP command identifier.
    pub command_id: String,
    /// End-to-end trace identifier.
    pub trace_id: String,
    /// Redaction markers applied while producing the artifact.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redactions_applied: Vec<String>,
}

/// Provenance source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceSource {
    /// Snowflake `INFORMATION_SCHEMA` rows.
    InformationSchema,
    /// Adapter/user overlay.
    AdapterOverlay,
    /// No-account fixture.
    Fixture,
    /// Local offline cache.
    OfflineCache,
    /// Snowflake `ACCOUNT_USAGE` views, added later.
    AccountUsage,
}

/// Envelope-compatible payload provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSourceClass {
    /// Produced from live Snowflake metadata.
    Live,
    /// Produced from deterministic fixtures.
    Fixture,
    /// Valid empty output.
    Empty,
}

/// Dataset manifest: object location, rights class, limits, and field roles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetManifest {
    /// Stable dataset identifier used by `query run --dataset`.
    pub id: String,
    /// Non-secret profile identifier.
    pub profile: String,
    /// Exact Snowflake database identifier.
    pub database: String,
    /// Exact Snowflake schema identifier.
    pub schema: String,
    /// Exact Snowflake object identifier.
    pub object: String,
    /// Snowflake object kind.
    pub kind: DatasetKind,
    /// Fail-closed rights class.
    pub rights_class: RightsClass,
    /// Default row limit.
    pub default_limit: u64,
    /// Ceiling before export or explicit override.
    pub max_rows_without_export: u64,
    /// Optional description from comments, tags, or overlays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Secret-free discovery evidence.
    pub provenance: Provenance,
    /// Per-column role assignments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<DatasetField>,
}

impl DatasetManifest {
    /// Find the first field with the requested role.
    #[must_use]
    pub fn field_by_role(&self, role: FieldRole) -> Option<&DatasetField> {
        self.fields.iter().find(|field| field.role == role)
    }

    /// True when this manifest names a column.
    #[must_use]
    pub fn has_field(&self, column: &str) -> bool {
        self.fields
            .iter()
            .any(|field| same_identifier(&field.column, column))
    }
}

/// A per-column role assignment within a dataset manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetField {
    /// Exact Snowflake column identifier.
    pub column: String,
    /// Planner-facing role.
    pub role: FieldRole,
    /// Planner-facing dtype class.
    pub dtype: DtypeClass,
    /// Whether the dataset contract expects this column.
    pub required: bool,
    /// Whether the role came from confirmed config, inference, or overlay.
    pub role_confidence: RoleConfidence,
}

/// Dataset object kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetKind {
    /// Snowflake table.
    Table,
    /// Snowflake view.
    View,
    /// Snowflake materialized view.
    MaterializedView,
    /// Snowflake external table.
    ExternalTable,
}

/// Rights class. Unknown serialized labels deserialize to the most restrictive
/// class so policy fails closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RightsClass {
    /// Public/non-sensitive.
    Public,
    /// Internal non-public data.
    Internal,
    /// Private data.
    Private,
    /// Most restrictive fallback.
    Restricted,
}

impl Default for RightsClass {
    fn default() -> Self {
        Self::Restricted
    }
}

impl<'de> Deserialize<'de> for RightsClass {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let normalized = raw.to_ascii_lowercase();
        Ok(match normalized.as_str() {
            "public" => Self::Public,
            "internal" => Self::Internal,
            "private" => Self::Private,
            "restricted" => Self::Restricted,
            _ => Self::Restricted,
        })
    }
}

/// Field role used by the planner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldRole {
    /// Entity key filtered by `--entity`.
    EntityKey,
    /// Primary time axis for `--from` / `--to`.
    TimeIndex,
    /// Point-in-time/as-of axis.
    KnownAt,
    /// Feature/value column.
    Feature,
    /// Target/label column.
    Label,
    /// Non-analytic metadata.
    Metadata,
}

/// Confidence attached to inferred field roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleConfidence {
    /// Confirmed by config or fixture contract.
    Confirmed,
    /// Inferred from names/types.
    Inferred,
    /// Supplied by adapter/user overlay.
    Overlay,
}

/// Planner-facing dtype class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DtypeClass {
    /// Text/string.
    String,
    /// Numeric value.
    Number,
    /// Boolean.
    Boolean,
    /// Date.
    Date,
    /// Time.
    Time,
    /// Timestamp.
    Timestamp,
    /// Binary payload.
    Binary,
    /// Semi-structured value.
    Variant,
    /// Unknown Snowflake type.
    Unknown,
}

impl DtypeClass {
    /// Whether this is a known scalar class usable by equality/list operators.
    #[must_use]
    pub const fn is_known_scalar(self) -> bool {
        !matches!(self, Self::Unknown | Self::Variant)
    }

    /// Snowflake SQL API binding type used by the planner.
    #[must_use]
    pub const fn default_binding_type(self) -> &'static str {
        match self {
            Self::String => "TEXT",
            Self::Number => "FIXED",
            Self::Boolean => "BOOLEAN",
            Self::Date => "DATE",
            Self::Time => "TIME",
            Self::Timestamp => "TIMESTAMP_NTZ",
            Self::Binary => "BINARY",
            Self::Variant => "VARIANT",
            Self::Unknown => "TEXT",
        }
    }
}

/// Column catalog row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnCatalogEntry {
    /// Owning dataset ID.
    pub dataset_id: String,
    /// Exact Snowflake database identifier.
    pub database: String,
    /// Exact Snowflake schema identifier.
    pub schema: String,
    /// Exact Snowflake object identifier.
    pub object: String,
    /// Exact Snowflake column identifier.
    pub column: String,
    /// 1-based ordinal position.
    pub ordinal: u32,
    /// Snowflake logical type.
    pub snowflake_type: String,
    /// Planner-facing dtype class.
    pub dtype_class: DtypeClass,
    /// SQL nullability.
    pub nullable: bool,
    /// Numeric precision where known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precision: Option<u32>,
    /// Numeric scale where known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale: Option<u32>,
    /// Length where known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    /// Alias candidates for `did_you_mean`; never emitted as SQL identifiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// Optional column comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Visible tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Column-row provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
}

impl ColumnCatalogEntry {
    /// Whether this entry names a column by exact or normalized identifier.
    #[must_use]
    pub fn matches_column(&self, column: &str) -> bool {
        same_identifier(&self.column, column)
    }

    /// Whether an alias matches by normalized comparison.
    #[must_use]
    pub fn has_alias(&self, alias: &str) -> bool {
        self.aliases
            .iter()
            .any(|candidate| normalize_identifier(candidate) == normalize_identifier(alias))
    }
}

/// Normalize for comparisons and suggestions only. SQL generation always uses
/// the original identifier stored in the manifest/catalog.
#[must_use]
pub fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|character| *character != '_' && *character != '-' && !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Case/underscore-insensitive identifier comparison for catalog lookup.
#[must_use]
pub fn same_identifier(left: &str, right: &str) -> bool {
    normalize_identifier(left) == normalize_identifier(right)
}
