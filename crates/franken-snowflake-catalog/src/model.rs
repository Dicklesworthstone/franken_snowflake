//! Dataset manifest and catalog artifact models.

use serde::{Deserialize, Deserializer, Serialize};

/// Version string carried by persisted TOML and deterministic JSON outputs.
/// v2 added the relation pass (keys, view dependencies, stages, file formats,
/// tags) and the gaps it could not fill.
pub const SCHEMA_VERSION: &str = "franken_snowflake.dataset_manifest.v2";

/// A full catalog snapshot envelope payload: datasets, columns, operators, and
/// the relations discovered between catalog objects.
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
    /// Whether the relation pass ran. Without it the snapshot says nothing
    /// about keys, dependencies, stages, file formats or tags: their absence
    /// means "not looked for", not "none".
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub relations_discovered: bool,
    /// Typed relations between catalog objects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relations: Vec<CatalogRelation>,
    /// Primary keys, columns in key order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub primary_keys: Vec<PrimaryKey>,
    /// Named stages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<StageEntry>,
    /// Named file formats.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_formats: Vec<FileFormatEntry>,
    /// Tags set directly on objects or their columns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<TagAssignment>,
    /// What discovery could not see, and why.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<DiscoveryGap>,
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
            relations_discovered: false,
            relations: Vec::new(),
            primary_keys: Vec::new(),
            stages: Vec::new(),
            file_formats: Vec::new(),
            tags: Vec::new(),
            gaps: Vec::new(),
        }
    }

    /// The primary key of `object`, if one was discovered.
    #[must_use]
    pub fn primary_key(&self, object: &ObjectRef) -> Option<&PrimaryKey> {
        self.primary_keys.iter().find(|key| &key.object == object)
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

    /// Diff this snapshot against an older base snapshot to detect drift and breaking changes.
    #[must_use]
    pub fn diff_from(&self, base: &Self) -> crate::diff::CatalogDiff {
        crate::diff::diff_snapshots(base, self)
    }
}

/// Exact three-part identity of a catalog object (table, view, stage, file
/// format, or tag), identifiers exactly as Snowflake reports them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectRef {
    /// Database identifier.
    pub database: String,
    /// Schema identifier.
    pub schema: String,
    /// Object identifier.
    pub name: String,
}

impl ObjectRef {
    /// Build a reference from its three parts.
    #[must_use]
    pub fn new(
        database: impl Into<String>,
        schema: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            database: database.into(),
            schema: schema.into(),
            name: name.into(),
        }
    }

    /// `DATABASE.SCHEMA.NAME` for display and lookup; quote each part before
    /// using it in SQL.
    #[must_use]
    pub fn qualified(&self) -> String {
        format!("{}.{}.{}", self.database, self.schema, self.name)
    }
}

/// A typed relation between catalog objects, discovered from Snowflake metadata.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CatalogRelation {
    /// `view` reads `source`, directly or through other views: Snowflake's
    /// `GET_OBJECT_REFERENCES` reports a view's whole dependency closure.
    ViewDependsOn {
        /// The dependent view.
        view: ObjectRef,
        /// A table or view it reads.
        source: ObjectRef,
        /// `TABLE` or `VIEW`, as Snowflake reports it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_type: Option<String>,
    },
    /// A foreign key of `from` referencing the primary or unique key of `to`.
    /// Table level: Snowflake's documented metadata views do not map key
    /// columns.
    ForeignKey {
        /// The table declaring the foreign key.
        from: ObjectRef,
        /// The table owning the referenced key.
        to: ObjectRef,
        /// The foreign key constraint name.
        constraint: String,
    },
    /// An external table reads its files from `stage`.
    UsesStage {
        /// The external table.
        object: ObjectRef,
        /// The stage its location names.
        stage: ObjectRef,
    },
    /// An external table parses its files with the named `file_format`.
    UsesFileFormat {
        /// The external table.
        object: ObjectRef,
        /// The named file format.
        file_format: ObjectRef,
    },
}

/// A table's primary key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PrimaryKey {
    /// The keyed table.
    pub object: ObjectRef,
    /// Key columns in key order.
    pub columns: Vec<String>,
    /// Constraint name, when reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint: Option<String>,
}

/// A named stage.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StageEntry {
    /// Stage identity.
    pub stage: ObjectRef,
    /// `Internal Named` or `External Named`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_type: Option<String>,
    /// An external stage's location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// An external stage's cloud region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Stage comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// A named file format.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FileFormatEntry {
    /// File format identity.
    pub file_format: ObjectRef,
    /// `CSV`, `JSON`, `PARQUET`, ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_type: Option<String>,
    /// File format comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// A tag set directly on an object or one of its columns.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TagAssignment {
    /// Tag identity.
    pub tag: ObjectRef,
    /// Tag value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// The tagged object (a column's table for a column tag).
    pub object: ObjectRef,
    /// The tagged column, for a column tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
}

impl TagAssignment {
    /// `DB.SCHEMA.TAG=value` (or `DB.SCHEMA.TAG` without a value), the form
    /// carried in [`ColumnCatalogEntry::tags`].
    #[must_use]
    pub fn label(&self) -> String {
        match &self.value {
            Some(value) => format!("{}={value}", self.tag.qualified()),
            None => self.tag.qualified(),
        }
    }
}

/// What a discovery pass could not see, and why: never a silent empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryGap {
    /// The metadata source (`primary_keys`, `object_references`, ...).
    pub source: String,
    /// Why the source is incomplete.
    pub kind: DiscoveryGapKind,
    /// The upstream message or the limit that applied.
    pub detail: String,
}

/// Why a discovery source is incomplete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryGapKind {
    /// The source's statement failed (privilege, edition, unsupported object).
    Failed,
    /// The source was not attempted (opt-in, or a limit of zero).
    Skipped,
    /// Only part of the source was read (a bounded per-object pass).
    Truncated,
    /// Rows came back but could not be resolved unambiguously.
    Unresolved,
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
    /// Approximate row count reported by `INFORMATION_SCHEMA.TABLES.ROW_COUNT`
    /// at discovery time (cost awareness for agents; not a live count).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approx_row_count: Option<u64>,
    /// Storage bytes reported by `INFORMATION_SCHEMA.TABLES.BYTES` at discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RightsClass {
    /// Public/non-sensitive.
    Public,
    /// Internal non-public data.
    Internal,
    /// Private data.
    Private,
    /// Most restrictive fallback.
    #[default]
    Restricted,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_provenance() -> Provenance {
        Provenance {
            source: ProvenanceSource::Fixture,
            data_source: DataSourceClass::Fixture,
            snapshot_id: "snap-1".to_string(),
            discovered_at: "2026-09-17T00:00:00Z".to_string(),
            profile_fingerprint: "prof-fp".to_string(),
            object_fingerprint: "obj-fp".to_string(),
            command_id: "cmd-1".to_string(),
            trace_id: "trace-1".to_string(),
            redactions_applied: vec![],
        }
    }

    #[test]
    fn rights_class_fails_closed_on_unknown_input() -> Result<(), serde_json::Error> {
        assert_eq!(
            serde_json::from_str::<RightsClass>(r#""public""#)?,
            RightsClass::Public
        );
        assert_eq!(
            serde_json::from_str::<RightsClass>(r#""INTERNAL""#)?,
            RightsClass::Internal
        );
        assert_eq!(
            serde_json::from_str::<RightsClass>(r#""Private""#)?,
            RightsClass::Private
        );
        assert_eq!(
            serde_json::from_str::<RightsClass>(r#""restricted""#)?,
            RightsClass::Restricted
        );
        // Fail-closed fallback: unknown or misspelled values MUST default to Restricted
        assert_eq!(
            serde_json::from_str::<RightsClass>(r#""confidential""#)?,
            RightsClass::Restricted
        );
        assert_eq!(
            serde_json::from_str::<RightsClass>(r#""unknown_secret_level""#)?,
            RightsClass::Restricted
        );
        assert_eq!(
            serde_json::from_str::<RightsClass>(r#""""#)?,
            RightsClass::Restricted
        );
        Ok(())
    }

    #[test]
    fn identifier_normalization_and_comparison() {
        assert_eq!(normalize_identifier("USER_ID"), "userid");
        assert_eq!(normalize_identifier("user-id"), "userid");
        assert_eq!(normalize_identifier("  User_Id  "), "userid");
        assert_eq!(normalize_identifier("CREATED_AT_UTC"), "createdatutc");

        assert!(same_identifier("EVENT_DATE", "event_date"));
        assert!(same_identifier("event-date", "EVENT_DATE"));
        assert!(same_identifier("EventDate", "event_date"));
        assert!(!same_identifier("event_date", "created_date"));
    }

    #[test]
    fn dtype_class_scalar_and_default_bindings() {
        assert!(DtypeClass::String.is_known_scalar());
        assert!(DtypeClass::Number.is_known_scalar());
        assert!(DtypeClass::Boolean.is_known_scalar());
        assert!(DtypeClass::Date.is_known_scalar());
        assert!(DtypeClass::Time.is_known_scalar());
        assert!(DtypeClass::Timestamp.is_known_scalar());
        assert!(DtypeClass::Binary.is_known_scalar());
        assert!(!DtypeClass::Variant.is_known_scalar());
        assert!(!DtypeClass::Unknown.is_known_scalar());

        assert_eq!(DtypeClass::String.default_binding_type(), "TEXT");
        assert_eq!(DtypeClass::Number.default_binding_type(), "FIXED");
        assert_eq!(DtypeClass::Boolean.default_binding_type(), "BOOLEAN");
        assert_eq!(DtypeClass::Date.default_binding_type(), "DATE");
        assert_eq!(DtypeClass::Time.default_binding_type(), "TIME");
        assert_eq!(
            DtypeClass::Timestamp.default_binding_type(),
            "TIMESTAMP_NTZ"
        );
        assert_eq!(DtypeClass::Binary.default_binding_type(), "BINARY");
        assert_eq!(DtypeClass::Variant.default_binding_type(), "VARIANT");
        assert_eq!(DtypeClass::Unknown.default_binding_type(), "TEXT");
    }

    #[test]
    fn dataset_manifest_field_lookups() {
        let manifest = DatasetManifest {
            id: "analytics.users".to_string(),
            profile: "default".to_string(),
            database: "ANALYTICS".to_string(),
            schema: "PUBLIC".to_string(),
            object: "USERS".to_string(),
            kind: DatasetKind::Table,
            rights_class: RightsClass::Internal,
            default_limit: 100,
            max_rows_without_export: 10_000,
            approx_row_count: Some(500),
            bytes: Some(10240),
            description: Some("Users table".to_string()),
            provenance: sample_provenance(),
            fields: vec![
                DatasetField {
                    column: "USER_ID".to_string(),
                    role: FieldRole::EntityKey,
                    dtype: DtypeClass::String,
                    required: true,
                    role_confidence: RoleConfidence::Confirmed,
                },
                DatasetField {
                    column: "CREATED_AT".to_string(),
                    role: FieldRole::TimeIndex,
                    dtype: DtypeClass::Timestamp,
                    required: true,
                    role_confidence: RoleConfidence::Confirmed,
                },
            ],
        };

        assert!(manifest.has_field("user_id"));
        assert!(manifest.has_field("USER-ID"));
        assert!(manifest.has_field("created_at"));
        assert!(!manifest.has_field("deleted_at"));

        let entity_field = manifest.field_by_role(FieldRole::EntityKey);
        assert!(entity_field.is_some());
        assert_eq!(entity_field.map(|f| f.column.as_str()), Some("USER_ID"));

        let time_field = manifest.field_by_role(FieldRole::TimeIndex);
        assert!(time_field.is_some());
        assert_eq!(time_field.map(|f| f.column.as_str()), Some("CREATED_AT"));

        assert!(manifest.field_by_role(FieldRole::Feature).is_none());
    }

    #[test]
    fn catalog_snapshot_columns_for_dataset_sorted_by_ordinal() {
        let mut snapshot = CatalogSnapshot::empty(sample_provenance());
        assert_eq!(snapshot.schema_version, SCHEMA_VERSION);
        assert!(snapshot.dataset("any").is_none());

        snapshot.columns = vec![
            ColumnCatalogEntry {
                dataset_id: "ds1".to_string(),
                database: "DB".to_string(),
                schema: "SCHEMA".to_string(),
                object: "OBJ".to_string(),
                column: "COL_B".to_string(),
                ordinal: 2,
                snowflake_type: "TEXT".to_string(),
                dtype_class: DtypeClass::String,
                nullable: true,
                precision: None,
                scale: None,
                length: Some(100),
                aliases: vec!["col-b".to_string()],
                comment: None,
                tags: vec![],
                provenance: None,
            },
            ColumnCatalogEntry {
                dataset_id: "ds2".to_string(),
                database: "DB".to_string(),
                schema: "SCHEMA".to_string(),
                object: "OBJ2".to_string(),
                column: "OTHER_COL".to_string(),
                ordinal: 1,
                snowflake_type: "TEXT".to_string(),
                dtype_class: DtypeClass::String,
                nullable: true,
                precision: None,
                scale: None,
                length: None,
                aliases: vec![],
                comment: None,
                tags: vec![],
                provenance: None,
            },
            ColumnCatalogEntry {
                dataset_id: "ds1".to_string(),
                database: "DB".to_string(),
                schema: "SCHEMA".to_string(),
                object: "OBJ".to_string(),
                column: "COL_A".to_string(),
                ordinal: 1,
                snowflake_type: "FIXED".to_string(),
                dtype_class: DtypeClass::Number,
                nullable: false,
                precision: Some(38),
                scale: Some(0),
                length: None,
                aliases: vec!["col-a".to_string()],
                comment: None,
                tags: vec![],
                provenance: None,
            },
        ];

        let ds1_cols = snapshot.columns_for_dataset("ds1");
        assert_eq!(ds1_cols.len(), 2);
        assert_eq!(ds1_cols[0].column, "COL_A");
        assert_eq!(ds1_cols[0].ordinal, 1);
        assert_eq!(ds1_cols[1].column, "COL_B");
        assert_eq!(ds1_cols[1].ordinal, 2);

        assert!(ds1_cols[0].matches_column("col_a"));
        assert!(ds1_cols[0].has_alias("col-a"));
        assert!(!ds1_cols[0].has_alias("nonexistent"));

        let ds2_cols = snapshot.columns_for_dataset("ds2");
        assert_eq!(ds2_cols.len(), 1);
        assert_eq!(ds2_cols[0].column, "OTHER_COL");

        let ds3_cols = snapshot.columns_for_dataset("ds3");
        assert!(ds3_cols.is_empty());
    }
}
