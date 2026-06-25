//! Information Schema catalog discovery and cache persistence.
//!
//! This module keeps the live boundary narrow. It builds SQL API
//! [`SubmitStatementRequest`] values for `INFORMATION_SCHEMA` scans, consumes
//! completed statement results returned by the SQL API lifecycle driver, and
//! emits deterministic catalog artifacts. No network transport or credential
//! lookup happens here.

use std::collections::{BTreeMap, BTreeSet};

use franken_snowflake_cache::{
    CacheBackend, CacheResult, CatalogSnapshotRecord, ContentAddress, DatasetManifestRecord,
    VerifiedPayload,
};
use franken_snowflake_sqlapi::lifecycle::CompletedStatement;
use franken_snowflake_sqlapi::request::{Binding, SubmitStatementRequest};
use franken_snowflake_sqlapi::response::ColumnType;
use serde::{Deserialize, Serialize};

use crate::model::{
    normalize_identifier, CatalogSnapshot, ColumnCatalogEntry, DataSourceClass, DatasetField,
    DatasetKind, DtypeClass, FieldRole, Provenance, ProvenanceSource, RightsClass, RoleConfidence,
};
use crate::operator::built_in_operator_catalog;

const DEFAULT_LIMIT: u64 = 1_000;
const DEFAULT_MAX_ROWS_WITHOUT_EXPORT: u64 = 50_000;

/// Discovery input shared by SQL construction, manifest generation, and cache
/// records. All fields are secret-free.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogDiscoveryInput {
    /// Non-secret profile ID.
    pub profile_id: String,
    /// Secret-free profile fingerprint.
    pub profile_fingerprint: String,
    /// Optional database scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// Optional schema scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// Optional object scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Stable snapshot ID.
    pub snapshot_id: String,
    /// Deterministic test clock or wall clock timestamp.
    pub discovered_at: String,
    /// Envelope-compatible data source class.
    pub data_source: DataSourceClass,
    /// CLI/MCP command identifier.
    pub command_id: String,
    /// End-to-end trace identifier.
    pub trace_id: String,
    /// Redaction markers applied before the artifact is emitted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redactions_applied: Vec<String>,
}

impl CatalogDiscoveryInput {
    /// Snapshot-wide provenance.
    #[must_use]
    pub fn provenance(&self) -> Provenance {
        Provenance {
            source: ProvenanceSource::InformationSchema,
            data_source: self.data_source,
            snapshot_id: self.snapshot_id.clone(),
            discovered_at: self.discovered_at.clone(),
            profile_fingerprint: self.profile_fingerprint.clone(),
            object_fingerprint: self.object_fingerprint(),
            command_id: self.command_id.clone(),
            trace_id: self.trace_id.clone(),
            redactions_applied: self.redactions_applied.clone(),
        }
    }

    fn object_fingerprint(&self) -> String {
        let database = self.database.as_deref().unwrap_or("*");
        let schema = self.schema.as_deref().unwrap_or("*");
        let object = self.object.as_deref().unwrap_or("*");
        format!("snowflake-scope:{database}.{schema}.{object}")
    }
}

/// SQL statements required for the first Information Schema catalog pass.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogDiscoverySql {
    /// Statement kind.
    pub kind: DiscoveryStatementKind,
    /// SQL API submit request.
    pub request: SubmitStatementRequest,
}

/// The supported discovery statement kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryStatementKind {
    /// `INFORMATION_SCHEMA.DATABASES`.
    Databases,
    /// `INFORMATION_SCHEMA.SCHEMATA`.
    Schemas,
    /// `INFORMATION_SCHEMA.TABLES`.
    Tables,
    /// `INFORMATION_SCHEMA.COLUMNS`.
    Columns,
}

/// Completed result set group for snapshot generation.
#[derive(Clone, Debug, PartialEq)]
pub struct CatalogDiscoveryTables {
    /// Database rows.
    pub databases: CompletedStatement,
    /// Schema rows.
    pub schemas: CompletedStatement,
    /// Table/view rows.
    pub tables: CompletedStatement,
    /// Column rows.
    pub columns: CompletedStatement,
}

/// A normalized Information Schema row retained in output-neutral form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InformationSchemaRow {
    /// Stable row fields in normalized uppercase keys.
    pub fields: BTreeMap<String, Option<String>>,
}

impl InformationSchemaRow {
    /// Get a field by normalized key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .get(&normalize_key(key))
            .and_then(Option::as_deref)
    }
}

/// Build deterministic SQL API submit requests for the discovery scan.
#[must_use]
pub fn build_information_schema_requests(
    input: &CatalogDiscoveryInput,
) -> Vec<CatalogDiscoverySql> {
    vec![
        discovery_sql(
            DiscoveryStatementKind::Databases,
            databases_sql(input),
            input,
        ),
        discovery_sql(DiscoveryStatementKind::Schemas, schemas_sql(input), input),
        discovery_sql(DiscoveryStatementKind::Tables, tables_sql(input), input),
        discovery_sql(DiscoveryStatementKind::Columns, columns_sql(input), input),
    ]
}

fn discovery_sql(
    kind: DiscoveryStatementKind,
    built: BuiltStatement,
    input: &CatalogDiscoveryInput,
) -> CatalogDiscoverySql {
    let mut request = SubmitStatementRequest::new(built.sql);
    request.timeout = Some(60);
    request.database = input
        .database
        .as_ref()
        .map(|database| database.as_str().into());
    request.schema = input.schema.as_ref().map(|schema| schema.as_str().into());
    // Filter values are bound as positional typed parameters, never interpolated
    // into the SQL text (quote-doubling alone is not a sound defense: Snowflake
    // string literals also honor backslash escapes, so a value such as `x\'` can
    // break out of a doubled-quote literal). Mirrors the planner's `push_binding`.
    if !built.binding_values.is_empty() {
        let mut bindings = BTreeMap::new();
        for (index, value) in built.binding_values.into_iter().enumerate() {
            bindings.insert((index + 1).to_string(), Binding::new("TEXT", value));
        }
        request.bindings = Some(bindings);
    }
    CatalogDiscoverySql { kind, request }
}

/// Build a deterministic snapshot from completed Information Schema statements.
#[must_use]
pub fn build_snapshot_from_information_schema(
    input: &CatalogDiscoveryInput,
    tables: &CatalogDiscoveryTables,
) -> CatalogSnapshot {
    let mut table_rows = rows_from_completed(&tables.tables);
    let mut column_rows = rows_from_completed(&tables.columns);
    table_rows.sort_by_key(table_sort_key);
    column_rows.sort_by_key(column_sort_key);

    let provenance = input.provenance();
    let mut snapshot = CatalogSnapshot::empty(provenance.clone());
    snapshot.operators = built_in_operator_catalog();

    for table in table_rows {
        let Some(database) = table.get("TABLE_CATALOG") else {
            continue;
        };
        let Some(schema) = table.get("TABLE_SCHEMA") else {
            continue;
        };
        let Some(object) = table.get("TABLE_NAME") else {
            continue;
        };
        if !in_scope(input, database, schema, object) {
            continue;
        }

        let dataset_id = dataset_id(database, schema, object);
        let kind = dataset_kind(table.get("TABLE_TYPE"));
        let description = table
            .get("COMMENT")
            .filter(|comment| !comment.is_empty())
            .map(ToOwned::to_owned);
        let object_columns = column_rows
            .iter()
            .filter(|column| {
                column.get("TABLE_CATALOG") == Some(database)
                    && column.get("TABLE_SCHEMA") == Some(schema)
                    && column.get("TABLE_NAME") == Some(object)
            })
            .collect::<Vec<_>>();

        let fields = object_columns
            .iter()
            .map(|column| dataset_field(column))
            .collect::<Vec<_>>();

        snapshot.datasets.push(crate::model::DatasetManifest {
            id: dataset_id.clone(),
            profile: input.profile_id.clone(),
            database: database.to_owned(),
            schema: schema.to_owned(),
            object: object.to_owned(),
            kind,
            rights_class: RightsClass::Restricted,
            default_limit: DEFAULT_LIMIT,
            max_rows_without_export: DEFAULT_MAX_ROWS_WITHOUT_EXPORT,
            description,
            provenance: provenance_for_object(input, database, schema, object),
            fields,
        });

        for column in object_columns {
            snapshot.columns.push(column_entry(
                input,
                &dataset_id,
                database,
                schema,
                object,
                column,
            ));
        }
    }

    snapshot
        .datasets
        .sort_by_key(|dataset| dataset.id.to_ascii_lowercase());
    snapshot.columns.sort_by_key(|column| {
        (
            column.dataset_id.to_ascii_lowercase(),
            column.ordinal,
            column.column.to_ascii_lowercase(),
        )
    });
    snapshot
        .operators
        .sort_by_key(|operator| operator.id.clone());
    snapshot
}

/// Persist a snapshot and every dataset manifest through the local cache
/// repository contract.
pub fn persist_snapshot<B: CacheBackend>(
    cache: &B,
    input: &CatalogDiscoveryInput,
    snapshot: &CatalogSnapshot,
    captured_at_ms: u64,
) -> CacheResult<()> {
    let snapshot_json = canonical_json(snapshot);
    cache.insert_catalog_snapshot(CatalogSnapshotRecord {
        snapshot_id: input.snapshot_id.clone(),
        profile_id: input.profile_id.clone(),
        source_kind: "information_schema".to_owned(),
        database_name: input.database.clone(),
        schema_name: input.schema.clone(),
        captured_at_ms,
        payload: verified_payload(snapshot_json),
    })?;

    for manifest in &snapshot.datasets {
        let manifest_json = canonical_json(manifest);
        cache.upsert_dataset_manifest(DatasetManifestRecord {
            dataset_id: manifest.id.clone(),
            profile_id: manifest.profile.clone(),
            snapshot_id: Some(input.snapshot_id.clone()),
            database_name: manifest.database.clone(),
            schema_name: manifest.schema.clone(),
            object_name: manifest.object.clone(),
            rights_class: rights_class_label(manifest.rights_class).to_owned(),
            default_limit: manifest.default_limit,
            max_rows_without_export: manifest.max_rows_without_export,
            manifest: verified_payload(manifest_json),
            created_at_ms: captured_at_ms,
        })?;
    }

    Ok(())
}

fn verified_payload(canonical: String) -> VerifiedPayload {
    let address = ContentAddress::blake3(canonical.as_bytes());
    VerifiedPayload { canonical, address }
}

fn canonical_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned())
}

fn rows_from_completed(completed: &CompletedStatement) -> Vec<InformationSchemaRow> {
    completed
        .rows
        .iter()
        .map(|row| row_from_values(&completed.result_set.result_set_meta_data.row_type, row))
        .collect()
}

fn row_from_values(columns: &[ColumnType], values: &[Option<String>]) -> InformationSchemaRow {
    let fields = columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            (
                normalize_key(&column.name),
                values.get(index).cloned().unwrap_or(None),
            )
        })
        .collect();
    InformationSchemaRow { fields }
}

/// A discovery statement plus its ordered positional binding values. The `?`
/// placeholders in `sql` are bound 1-based in `binding_values` order.
struct BuiltStatement {
    sql: String,
    binding_values: Vec<String>,
}

fn databases_sql(input: &CatalogDiscoveryInput) -> BuiltStatement {
    build_statement(
        "SELECT DATABASE_NAME, COMMENT FROM INFORMATION_SCHEMA.DATABASES",
        &[("DATABASE_NAME", input.database.as_deref())],
        "DATABASE_NAME",
    )
}

fn schemas_sql(input: &CatalogDiscoveryInput) -> BuiltStatement {
    build_statement(
        "SELECT CATALOG_NAME, SCHEMA_NAME, COMMENT FROM INFORMATION_SCHEMA.SCHEMATA",
        &[
            ("CATALOG_NAME", input.database.as_deref()),
            ("SCHEMA_NAME", input.schema.as_deref()),
        ],
        "CATALOG_NAME, SCHEMA_NAME",
    )
}

fn tables_sql(input: &CatalogDiscoveryInput) -> BuiltStatement {
    build_statement(
        "SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, COMMENT FROM INFORMATION_SCHEMA.TABLES",
        &[
            ("TABLE_CATALOG", input.database.as_deref()),
            ("TABLE_SCHEMA", input.schema.as_deref()),
            ("TABLE_NAME", input.object.as_deref()),
        ],
        "TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME",
    )
}

fn columns_sql(input: &CatalogDiscoveryInput) -> BuiltStatement {
    build_statement(
        "SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION, DATA_TYPE, NUMERIC_PRECISION, NUMERIC_SCALE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE, COMMENT FROM INFORMATION_SCHEMA.COLUMNS",
        &[
            ("TABLE_CATALOG", input.database.as_deref()),
            ("TABLE_SCHEMA", input.schema.as_deref()),
            ("TABLE_NAME", input.object.as_deref()),
        ],
        "TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION",
    )
}

/// Build a deterministic `SELECT ... [WHERE col = ? AND ...] ORDER BY ...`
/// statement using positional `?` placeholders for every present filter value,
/// never string interpolation. `filters` preserves placeholder order.
fn build_statement(
    select_from: &str,
    filters: &[(&str, Option<&str>)],
    order_by: &str,
) -> BuiltStatement {
    let mut sql = select_from.to_owned();
    let mut clauses = Vec::new();
    let mut binding_values = Vec::new();
    for (column, value) in filters {
        if let Some(value) = value {
            clauses.push(format!("{column} = ?"));
            binding_values.push((*value).to_owned());
        }
    }
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY ");
    sql.push_str(order_by);
    BuiltStatement {
        sql,
        binding_values,
    }
}

fn in_scope(input: &CatalogDiscoveryInput, database: &str, schema: &str, object: &str) -> bool {
    input
        .database
        .as_deref()
        .is_none_or(|scope| scope == database)
        && input.schema.as_deref().is_none_or(|scope| scope == schema)
        && input.object.as_deref().is_none_or(|scope| scope == object)
}

fn dataset_id(database: &str, schema: &str, object: &str) -> String {
    format!(
        "{}_{}_{}",
        slug_part(database),
        slug_part(schema),
        slug_part(object)
    )
}

fn slug_part(value: &str) -> String {
    let mut slug = String::new();
    let mut pending_underscore = false;
    for character in value.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            if pending_underscore && !slug.is_empty() {
                slug.push('_');
            }
            pending_underscore = false;
            slug.push(character);
        } else {
            pending_underscore = true;
        }
    }
    if slug.is_empty() {
        "dataset".to_owned()
    } else {
        slug
    }
}

fn dataset_kind(table_type: Option<&str>) -> DatasetKind {
    match table_type.unwrap_or_default().to_ascii_uppercase().as_str() {
        "VIEW" => DatasetKind::View,
        "MATERIALIZED VIEW" => DatasetKind::MaterializedView,
        "EXTERNAL TABLE" => DatasetKind::ExternalTable,
        _ => DatasetKind::Table,
    }
}

fn dataset_field(column: &InformationSchemaRow) -> DatasetField {
    let column_name = column.get("COLUMN_NAME").unwrap_or_default().to_owned();
    let dtype = dtype_class(column.get("DATA_TYPE").unwrap_or_default());
    let role = infer_field_role(&column_name, dtype);
    DatasetField {
        column: column_name,
        role,
        dtype,
        required: matches!(role, FieldRole::EntityKey | FieldRole::TimeIndex),
        role_confidence: RoleConfidence::Inferred,
    }
}

fn column_entry(
    input: &CatalogDiscoveryInput,
    dataset_id: &str,
    database: &str,
    schema: &str,
    object: &str,
    row: &InformationSchemaRow,
) -> ColumnCatalogEntry {
    let column = row.get("COLUMN_NAME").unwrap_or_default().to_owned();
    let snowflake_type = row.get("DATA_TYPE").unwrap_or("UNKNOWN").to_owned();
    ColumnCatalogEntry {
        dataset_id: dataset_id.to_owned(),
        database: database.to_owned(),
        schema: schema.to_owned(),
        object: object.to_owned(),
        column: column.clone(),
        ordinal: parse_u32(row.get("ORDINAL_POSITION")).unwrap_or(0),
        snowflake_type: snowflake_type.clone(),
        dtype_class: dtype_class(&snowflake_type),
        nullable: row
            .get("IS_NULLABLE")
            .is_none_or(|value| value.eq_ignore_ascii_case("YES")),
        precision: parse_u32(row.get("NUMERIC_PRECISION")),
        scale: parse_u32(row.get("NUMERIC_SCALE")),
        length: parse_u64(row.get("CHARACTER_MAXIMUM_LENGTH")),
        aliases: aliases_for_column(&column),
        comment: row
            .get("COMMENT")
            .filter(|comment| !comment.is_empty())
            .map(ToOwned::to_owned),
        tags: Vec::new(),
        provenance: Some(provenance_for_object(input, database, schema, object)),
    }
}

fn dtype_class(snowflake_type: &str) -> DtypeClass {
    let normalized = snowflake_type.to_ascii_uppercase();
    match normalized.as_str() {
        "TEXT" | "VARCHAR" | "CHAR" | "CHARACTER" | "STRING" => DtypeClass::String,
        "FIXED" | "NUMBER" | "NUMERIC" | "DECIMAL" | "REAL" | "FLOAT" | "DOUBLE" | "DECFLOAT" => {
            DtypeClass::Number
        }
        "BOOLEAN" => DtypeClass::Boolean,
        "DATE" => DtypeClass::Date,
        "TIME" => DtypeClass::Time,
        "TIMESTAMP" | "TIMESTAMP_NTZ" | "TIMESTAMP_LTZ" | "TIMESTAMP_TZ" => DtypeClass::Timestamp,
        "BINARY" => DtypeClass::Binary,
        "VARIANT" | "OBJECT" | "ARRAY" => DtypeClass::Variant,
        _ => DtypeClass::Unknown,
    }
}

fn infer_field_role(column: &str, dtype: DtypeClass) -> FieldRole {
    let normalized = normalize_identifier(column);
    if normalized == "entityid"
        || normalized == "entitykey"
        || normalized.ends_with("entityid")
        || normalized.ends_with("securityid")
        || normalized.ends_with("accountid")
        || normalized.ends_with("customerid")
    {
        FieldRole::EntityKey
    } else if normalized == "knownat"
        || normalized.ends_with("knownat")
        || normalized.ends_with("asof")
        || normalized.ends_with("asofdate")
    {
        FieldRole::KnownAt
    } else if matches!(
        dtype,
        DtypeClass::Date | DtypeClass::Time | DtypeClass::Timestamp
    ) && (normalized.contains("date")
        || normalized.contains("time")
        || normalized.ends_with("at")
        || normalized.ends_with("ts"))
    {
        FieldRole::TimeIndex
    } else if normalized.contains("label") || normalized.contains("target") {
        FieldRole::Label
    } else if matches!(dtype, DtypeClass::Variant | DtypeClass::Unknown) {
        FieldRole::Metadata
    } else {
        FieldRole::Feature
    }
}

fn aliases_for_column(column: &str) -> Vec<String> {
    let mut aliases = BTreeSet::new();
    aliases.insert(column.to_ascii_lowercase());
    aliases.insert(normalize_identifier(column));
    if column.eq_ignore_ascii_case("event_date") {
        aliases.insert("date".to_owned());
        aliases.insert("dt".to_owned());
    }
    if column.eq_ignore_ascii_case("entity_id") {
        aliases.insert("entity".to_owned());
    }
    aliases
        .into_iter()
        .filter(|alias| !alias.is_empty() && alias != column)
        .collect()
}

fn provenance_for_object(
    input: &CatalogDiscoveryInput,
    database: &str,
    schema: &str,
    object: &str,
) -> Provenance {
    Provenance {
        source: ProvenanceSource::InformationSchema,
        data_source: input.data_source,
        snapshot_id: input.snapshot_id.clone(),
        discovered_at: input.discovered_at.clone(),
        profile_fingerprint: input.profile_fingerprint.clone(),
        object_fingerprint: format!("snowflake-object:{database}.{schema}.{object}"),
        command_id: input.command_id.clone(),
        trace_id: input.trace_id.clone(),
        redactions_applied: input.redactions_applied.clone(),
    }
}

fn table_sort_key(row: &InformationSchemaRow) -> (String, String, String) {
    (
        row.get("TABLE_CATALOG")
            .unwrap_or_default()
            .to_ascii_lowercase(),
        row.get("TABLE_SCHEMA")
            .unwrap_or_default()
            .to_ascii_lowercase(),
        row.get("TABLE_NAME")
            .unwrap_or_default()
            .to_ascii_lowercase(),
    )
}

fn column_sort_key(row: &InformationSchemaRow) -> (String, String, String, u32) {
    (
        row.get("TABLE_CATALOG")
            .unwrap_or_default()
            .to_ascii_lowercase(),
        row.get("TABLE_SCHEMA")
            .unwrap_or_default()
            .to_ascii_lowercase(),
        row.get("TABLE_NAME")
            .unwrap_or_default()
            .to_ascii_lowercase(),
        parse_u32(row.get("ORDINAL_POSITION")).unwrap_or(0),
    )
}

fn normalize_key(key: &str) -> String {
    key.to_ascii_uppercase()
}

fn parse_u32(value: Option<&str>) -> Option<u32> {
    value.and_then(|value| value.parse::<u32>().ok())
}

fn parse_u64(value: Option<&str>) -> Option<u64> {
    value.and_then(|value| value.parse::<u64>().ok())
}

fn rights_class_label(rights: RightsClass) -> &'static str {
    match rights {
        RightsClass::Public => "public",
        RightsClass::Internal => "internal",
        RightsClass::Private => "private",
        RightsClass::Restricted => "restricted",
    }
}

#[cfg(test)]
mod tests {
    use franken_snowflake_cache::{CacheBackend, InMemoryCache};
    use franken_snowflake_core::ids::StatementHandle;
    use franken_snowflake_sqlapi::response::{
        ColumnType, PartitionInfo, ResultSet, ResultSetMetaData,
    };

    use super::*;
    use crate::model::{DatasetKind, FieldRole};

    #[test]
    fn discovery_requests_are_scoped_and_stable() {
        let mut input = fixture_input();
        input.object = Some("EVENTS\\' OR 1=1 --".to_owned());

        let requests = build_information_schema_requests(&input);

        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0].kind, DiscoveryStatementKind::Databases);
        assert_eq!(requests[1].kind, DiscoveryStatementKind::Schemas);
        assert_eq!(requests[2].kind, DiscoveryStatementKind::Tables);
        assert_eq!(requests[3].kind, DiscoveryStatementKind::Columns);
        assert_eq!(requests[0].request.timeout, Some(60));
        assert_eq!(
            requests[0]
                .request
                .database
                .as_ref()
                .map(|value| value.as_str()),
            Some("DB")
        );
        assert_eq!(
            requests[0]
                .request
                .schema
                .as_ref()
                .map(|value| value.as_str()),
            Some("PUBLIC")
        );
        // The filter value is a positional binding, never interpolated into SQL.
        let columns = &requests[3].request;
        assert!(columns.statement.contains("TABLE_NAME = ?"));
        assert!(!columns.statement.contains("EVENTS"));
        assert!(!columns.statement.contains("OR 1=1"));
        assert!(!columns.statement.contains('\''));
        let bindings = columns
            .bindings
            .as_ref()
            .expect("columns scan has bound filters");
        // database, schema, object bind 1-based in placeholder order.
        assert_eq!(bindings.get("1").map(|b| b.value.as_str()), Some("DB"));
        assert_eq!(bindings.get("2").map(|b| b.value.as_str()), Some("PUBLIC"));
        assert_eq!(
            bindings.get("3").map(|b| b.value.as_str()),
            Some("EVENTS\\' OR 1=1 --")
        );
        assert_eq!(
            bindings.get("3").map(|b| b.value_type.as_str()),
            Some("TEXT")
        );
        assert!(columns
            .statement
            .ends_with("ORDER BY TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION"));
    }

    #[test]
    fn completed_information_schema_rows_build_dataset_manifests() {
        let input = fixture_input();
        let discovery_tables = fixture_tables();

        let snapshot = build_snapshot_from_information_schema(&input, &discovery_tables);

        assert_eq!(snapshot.datasets.len(), 2);
        assert_eq!(snapshot.datasets[0].id, "db_public_events");
        assert_eq!(snapshot.datasets[0].kind, DatasetKind::Table);
        assert_eq!(snapshot.datasets[1].id, "db_public_v_events");
        assert_eq!(snapshot.datasets[1].kind, DatasetKind::View);
        assert_eq!(snapshot.columns.len(), 3);

        let events = snapshot.dataset("db_public_events");
        assert!(events.is_some());
        if let Some(events) = events {
            assert_eq!(events.profile, "profile-fixture");
            assert_eq!(events.provenance.snapshot_id, "snap-001");
            assert_eq!(
                events
                    .field_by_role(FieldRole::EntityKey)
                    .map(|field| field.column.as_str()),
                Some("ENTITY_ID")
            );
            assert_eq!(
                events
                    .field_by_role(FieldRole::TimeIndex)
                    .map(|field| field.column.as_str()),
                Some("EVENT_DATE")
            );
        }
    }

    #[test]
    fn snapshot_persistence_writes_verified_cache_records() {
        let input = fixture_input();
        let snapshot = build_snapshot_from_information_schema(&input, &fixture_tables());
        let cache = InMemoryCache::new();

        assert!(persist_snapshot(&cache, &input, &snapshot, 1_700_000_000).is_ok());

        let snapshot_record = cache.catalog_snapshot("snap-001");
        assert!(matches!(snapshot_record, Ok(Some(_))));

        let manifest_record = cache.dataset_manifest("db_public_events");
        assert!(matches!(manifest_record, Ok(Some(_))));
        if let Ok(Some(record)) = manifest_record {
            assert_eq!(record.profile_id, "profile-fixture");
            assert_eq!(record.snapshot_id.as_deref(), Some("snap-001"));
            assert_eq!(record.rights_class, "restricted");
            assert!(record.manifest.verify("dataset_manifest").is_ok());
            assert!(record.manifest.canonical.contains("\"object\":\"EVENTS\""));
        }
    }

    fn fixture_input() -> CatalogDiscoveryInput {
        CatalogDiscoveryInput {
            profile_id: "profile-fixture".to_owned(),
            profile_fingerprint: "profile:abc123".to_owned(),
            database: Some("DB".to_owned()),
            schema: Some("PUBLIC".to_owned()),
            object: None,
            snapshot_id: "snap-001".to_owned(),
            discovered_at: "2026-06-24T12:00:00Z".to_owned(),
            data_source: DataSourceClass::Fixture,
            command_id: "catalog.scan.fixture".to_owned(),
            trace_id: "trace-001".to_owned(),
            redactions_applied: vec!["account_locator".to_owned()],
        }
    }

    fn fixture_tables() -> CatalogDiscoveryTables {
        CatalogDiscoveryTables {
            databases: completed_statement(
                "h-db",
                &["DATABASE_NAME", "COMMENT"],
                vec![vec![Some("DB"), Some("fixture database")]],
            ),
            schemas: completed_statement(
                "h-schema",
                &["CATALOG_NAME", "SCHEMA_NAME", "COMMENT"],
                vec![vec![Some("DB"), Some("PUBLIC"), Some("fixture schema")]],
            ),
            tables: completed_statement(
                "h-table",
                &[
                    "TABLE_CATALOG",
                    "TABLE_SCHEMA",
                    "TABLE_NAME",
                    "TABLE_TYPE",
                    "COMMENT",
                ],
                vec![
                    vec![
                        Some("DB"),
                        Some("PUBLIC"),
                        Some("V_EVENTS"),
                        Some("VIEW"),
                        Some("view manifest"),
                    ],
                    vec![
                        Some("DB"),
                        Some("PUBLIC"),
                        Some("EVENTS"),
                        Some("BASE TABLE"),
                        Some("event facts"),
                    ],
                ],
            ),
            columns: completed_statement(
                "h-column",
                &[
                    "TABLE_CATALOG",
                    "TABLE_SCHEMA",
                    "TABLE_NAME",
                    "COLUMN_NAME",
                    "ORDINAL_POSITION",
                    "DATA_TYPE",
                    "NUMERIC_PRECISION",
                    "NUMERIC_SCALE",
                    "CHARACTER_MAXIMUM_LENGTH",
                    "IS_NULLABLE",
                    "COMMENT",
                ],
                vec![
                    vec![
                        Some("DB"),
                        Some("PUBLIC"),
                        Some("EVENTS"),
                        Some("EVENT_DATE"),
                        Some("2"),
                        Some("DATE"),
                        None,
                        None,
                        None,
                        Some("YES"),
                        Some("event date"),
                    ],
                    vec![
                        Some("DB"),
                        Some("PUBLIC"),
                        Some("EVENTS"),
                        Some("ENTITY_ID"),
                        Some("1"),
                        Some("NUMBER"),
                        Some("38"),
                        Some("0"),
                        None,
                        Some("NO"),
                        Some("entity key"),
                    ],
                    vec![
                        Some("DB"),
                        Some("PUBLIC"),
                        Some("V_EVENTS"),
                        Some("EVENT_DATE"),
                        Some("1"),
                        Some("DATE"),
                        None,
                        None,
                        None,
                        Some("YES"),
                        Some("view date"),
                    ],
                ],
            ),
        }
    }

    fn completed_statement(
        handle: &str,
        column_names: &[&str],
        rows: Vec<Vec<Option<&str>>>,
    ) -> CompletedStatement {
        let statement_handle = StatementHandle::new(handle);
        let owned_rows = rows
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|value| value.map(ToOwned::to_owned))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let row_type = column_names
            .iter()
            .map(|name| column_type(name))
            .collect::<Vec<_>>();
        let result_set = ResultSet {
            result_set_meta_data: ResultSetMetaData {
                num_rows: owned_rows.len() as i64,
                format: "jsonv2".to_owned(),
                row_type,
                partition_info: vec![PartitionInfo {
                    row_count: owned_rows.len() as i64,
                    compressed_size: 0,
                    uncompressed_size: 0,
                }],
            },
            data: owned_rows.clone(),
            code: "090001".to_owned(),
            statement_handle: statement_handle.clone(),
            statement_status_url: None,
            statement_handles: None,
            sql_state: None,
            message: None,
            request_id: None,
            created_on: None,
            stats: None,
        };
        CompletedStatement {
            statement_handle,
            result_set,
            rows: owned_rows,
        }
    }

    fn column_type(name: &str) -> ColumnType {
        ColumnType {
            name: name.to_owned(),
            column_type: "TEXT".to_owned(),
            scale: None,
            precision: None,
            nullable: true,
            length: None,
            byte_length: None,
            database: None,
            schema: None,
            table: None,
            collation: None,
        }
    }
}
