//! The relation pass: primary and foreign keys, view dependencies, stages,
//! file formats, external-table sources and (opt-in) tags, layered onto a
//! TABLES/COLUMNS snapshot (reality-check bead G1).
//!
//! Like [`crate::discovery`], this module never touches the network: it plans
//! SQL API requests from a base snapshot and folds completed (or failed)
//! statements back into it. A source that fails becomes a typed
//! [`DiscoveryGap`], never a silent empty.
//!
//! Sources, per docs.snowflake.com (consulted 2026-09-24):
//!
//! - `SHOW PRIMARY KEYS IN SCHEMA <db>.<schema>` (sql-reference/sql/show-primary-keys):
//!   `database_name`, `schema_name`, `table_name`, `column_name`,
//!   `key_sequence`, `constraint_name`. SHOW takes no bind variables, so the
//!   scope is quoted identifiers.
//! - `INFORMATION_SCHEMA.TABLE_CONSTRAINTS` and `REFERENTIAL_CONSTRAINTS`
//!   (sql-reference/info-schema/table_constraints, .../referential_constraints):
//!   a foreign key's table and the table owning the key it references. Neither
//!   view maps key columns, so foreign keys are table level, and constraint
//!   names are not unique (the documented example shows one system-generated
//!   name on two tables), so an ambiguous name is reported, not guessed.
//! - `INFORMATION_SCHEMA.STAGES`, `FILE_FORMATS` and `EXTERNAL_TABLES`
//!   (sql-reference/info-schema/...): an external table's `LOCATION` and
//!   `FILE_FORMAT_NAME` name its stage and format.
//! - `GET_OBJECT_REFERENCES(DATABASE_NAME => .., SCHEMA_NAME => .., OBJECT_NAME => ..)`
//!   (sql-reference/functions/get_object_references): one call per view,
//!   returning the view's whole dependency closure; names are double-quoted
//!   inside the string arguments. The third output column is documented both
//!   as `OBJECT_NAME` and `VIEW_NAME`, so only the `REFERENCED_*` columns are
//!   read.
//! - `SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES` (sql-reference/account-usage/tag_references):
//!   opt-in; needs the GOVERNANCE_VIEWER database role (or equivalent) and
//!   lags up to two hours.

use std::collections::{BTreeMap, BTreeSet};

use franken_snowflake_sqlapi::lifecycle::CompletedStatement;
use franken_snowflake_sqlapi::request::SubmitStatementRequest;
use serde::{Deserialize, Serialize};

use crate::discovery::{
    BuiltStatement, CatalogDiscoveryInput, InformationSchemaRow, build_statement,
    rows_from_completed, statement_request,
};
use crate::model::{
    CatalogRelation, CatalogSnapshot, DatasetKind, DiscoveryGap, DiscoveryGapKind, FileFormatEntry,
    ObjectRef, PrimaryKey, StageEntry, TagAssignment,
};
use crate::planner::quote_identifier;

/// Views whose dependencies one scan reads by default (one statement each).
pub const DEFAULT_VIEW_REFERENCE_LIMIT: usize = 25;

/// The most views one scan may read dependencies for.
pub const MAX_VIEW_REFERENCE_LIMIT: usize = 500;

/// One metadata source of the relation pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationSource {
    /// `SHOW PRIMARY KEYS`.
    PrimaryKeys,
    /// `INFORMATION_SCHEMA.TABLE_CONSTRAINTS`.
    TableConstraints,
    /// `INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS`.
    ReferentialConstraints,
    /// `INFORMATION_SCHEMA.STAGES`.
    Stages,
    /// `INFORMATION_SCHEMA.FILE_FORMATS`.
    FileFormats,
    /// `INFORMATION_SCHEMA.EXTERNAL_TABLES`.
    ExternalTables,
    /// `GET_OBJECT_REFERENCES`, one statement per view.
    ObjectReferences,
    /// `SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES`.
    TagReferences,
}

impl RelationSource {
    /// Stable label used in gaps and envelopes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrimaryKeys => "primary_keys",
            Self::TableConstraints => "table_constraints",
            Self::ReferentialConstraints => "referential_constraints",
            Self::Stages => "stages",
            Self::FileFormats => "file_formats",
            Self::ExternalTables => "external_tables",
            Self::ObjectReferences => "object_references",
            Self::TagReferences => "tag_references",
        }
    }

    /// Where the source's shape is documented.
    #[must_use]
    pub const fn documentation(self) -> &'static str {
        match self {
            Self::PrimaryKeys => {
                "https://docs.snowflake.com/en/sql-reference/sql/show-primary-keys"
            }
            Self::TableConstraints => {
                "https://docs.snowflake.com/en/sql-reference/info-schema/table_constraints"
            }
            Self::ReferentialConstraints => {
                "https://docs.snowflake.com/en/sql-reference/info-schema/referential_constraints"
            }
            Self::Stages => "https://docs.snowflake.com/en/sql-reference/info-schema/stages",
            Self::FileFormats => {
                "https://docs.snowflake.com/en/sql-reference/info-schema/file_formats"
            }
            Self::ExternalTables => {
                "https://docs.snowflake.com/en/sql-reference/info-schema/external_tables"
            }
            Self::ObjectReferences => {
                "https://docs.snowflake.com/en/sql-reference/functions/get_object_references"
            }
            Self::TagReferences => {
                "https://docs.snowflake.com/en/sql-reference/account-usage/tag_references"
            }
        }
    }
}

/// What the relation pass reads beyond its defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelationOptions {
    /// Views to read dependencies for, one statement each (0 skips them).
    pub view_reference_limit: usize,
    /// Read tag assignments from `SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES`.
    pub tags: bool,
}

impl Default for RelationOptions {
    fn default() -> Self {
        Self {
            view_reference_limit: DEFAULT_VIEW_REFERENCE_LIMIT,
            tags: false,
        }
    }
}

/// One planned relation statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationStatement {
    /// The metadata source it reads.
    pub source: RelationSource,
    /// The view an [`RelationSource::ObjectReferences`] statement reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<ObjectRef>,
    /// The SQL API submit request.
    pub request: SubmitStatementRequest,
}

/// The planned statements, in execution order, and the gaps known before
/// any of them runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationPlan {
    /// Statements to run.
    pub statements: Vec<RelationStatement>,
    /// Sources skipped or truncated by the options.
    pub gaps: Vec<DiscoveryGap>,
}

/// A planned statement's result: its rows, or the failure Snowflake reported
/// for it (a SQL error such as insufficient privileges). Transport, auth and
/// cancellation errors are not outcomes: they end the scan.
// One value per statement, built once and consumed by `apply_relation_results`;
// boxing the completed statement would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum RelationOutcome {
    /// The statement completed.
    Completed(CompletedStatement),
    /// Snowflake rejected the statement with this message.
    Failed(String),
}

/// Plan the relation pass for the database/schema a base snapshot covers.
/// Views come from the snapshot (one dependency statement each, bounded by
/// the options); external tables are only listed when the snapshot has one.
#[must_use]
pub fn plan_relation_discovery(
    input: &CatalogDiscoveryInput,
    snapshot: &CatalogSnapshot,
    options: RelationOptions,
) -> RelationPlan {
    let mut plan = RelationPlan {
        statements: Vec::new(),
        gaps: Vec::new(),
    };
    let Some(database) = input.database.as_deref() else {
        plan.gaps.push(DiscoveryGap {
            source: "relations".to_owned(),
            kind: DiscoveryGapKind::Skipped,
            detail: "the relation pass needs a database scope".to_owned(),
        });
        return plan;
    };
    let schema = input.schema.as_deref();
    let push = |plan: &mut RelationPlan, source, built| {
        plan.statements.push(RelationStatement {
            source,
            view: None,
            request: statement_request(input, built),
        });
    };

    let scope = match schema {
        Some(schema) => format!(
            "SCHEMA {}.{}",
            quote_identifier(database),
            quote_identifier(schema)
        ),
        None => format!("DATABASE {}", quote_identifier(database)),
    };
    push(
        &mut plan,
        RelationSource::PrimaryKeys,
        BuiltStatement {
            sql: format!("SHOW PRIMARY KEYS IN {scope}"),
            binding_values: Vec::new(),
        },
    );
    // The referenced key may live in another schema of the database, so the
    // constraint listing spans the database; the foreign keys themselves are
    // the scanned schema's.
    push(
        &mut plan,
        RelationSource::TableConstraints,
        build_statement(
            "SELECT CONSTRAINT_CATALOG, CONSTRAINT_SCHEMA, CONSTRAINT_NAME, TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, CONSTRAINT_TYPE FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS",
            &[("TABLE_CATALOG", Some(database))],
            "TABLE_SCHEMA, TABLE_NAME, CONSTRAINT_NAME",
        ),
    );
    push(
        &mut plan,
        RelationSource::ReferentialConstraints,
        build_statement(
            "SELECT CONSTRAINT_CATALOG, CONSTRAINT_SCHEMA, CONSTRAINT_NAME, UNIQUE_CONSTRAINT_CATALOG, UNIQUE_CONSTRAINT_SCHEMA, UNIQUE_CONSTRAINT_NAME FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS",
            &[
                ("CONSTRAINT_CATALOG", Some(database)),
                ("CONSTRAINT_SCHEMA", schema),
            ],
            "CONSTRAINT_SCHEMA, CONSTRAINT_NAME",
        ),
    );
    push(
        &mut plan,
        RelationSource::Stages,
        build_statement(
            "SELECT STAGE_CATALOG, STAGE_SCHEMA, STAGE_NAME, STAGE_URL, STAGE_REGION, STAGE_TYPE, COMMENT FROM INFORMATION_SCHEMA.STAGES",
            &[("STAGE_CATALOG", Some(database)), ("STAGE_SCHEMA", schema)],
            "STAGE_SCHEMA, STAGE_NAME",
        ),
    );
    push(
        &mut plan,
        RelationSource::FileFormats,
        build_statement(
            "SELECT FILE_FORMAT_CATALOG, FILE_FORMAT_SCHEMA, FILE_FORMAT_NAME, FILE_FORMAT_TYPE, COMMENT FROM INFORMATION_SCHEMA.FILE_FORMATS",
            &[
                ("FILE_FORMAT_CATALOG", Some(database)),
                ("FILE_FORMAT_SCHEMA", schema),
            ],
            "FILE_FORMAT_SCHEMA, FILE_FORMAT_NAME",
        ),
    );
    if snapshot
        .datasets
        .iter()
        .any(|dataset| dataset.kind == DatasetKind::ExternalTable)
    {
        push(
            &mut plan,
            RelationSource::ExternalTables,
            build_statement(
                "SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, LOCATION, FILE_FORMAT_NAME, FILE_FORMAT_TYPE FROM INFORMATION_SCHEMA.EXTERNAL_TABLES",
                &[("TABLE_CATALOG", Some(database)), ("TABLE_SCHEMA", schema)],
                "TABLE_SCHEMA, TABLE_NAME",
            ),
        );
    }

    let views: Vec<ObjectRef> = snapshot
        .datasets
        .iter()
        .filter(|dataset| dataset.kind == DatasetKind::View)
        .map(|dataset| ObjectRef::new(&dataset.database, &dataset.schema, &dataset.object))
        .collect();
    let read = views.len().min(options.view_reference_limit);
    for view in views.iter().take(read) {
        plan.statements.push(RelationStatement {
            source: RelationSource::ObjectReferences,
            view: Some(view.clone()),
            request: statement_request(
                input,
                BuiltStatement {
                    sql: "SELECT * FROM TABLE(GET_OBJECT_REFERENCES(DATABASE_NAME => ?, SCHEMA_NAME => ?, OBJECT_NAME => ?))".to_owned(),
                    binding_values: vec![
                        quote_identifier(&view.database),
                        quote_identifier(&view.schema),
                        quote_identifier(&view.name),
                    ],
                },
            ),
        });
    }
    if read < views.len() {
        plan.gaps.push(DiscoveryGap {
            source: RelationSource::ObjectReferences.as_str().to_owned(),
            kind: if read == 0 {
                DiscoveryGapKind::Skipped
            } else {
                DiscoveryGapKind::Truncated
            },
            detail: format!(
                "view dependencies read for {read} of {} views (one statement per view); raise --max-view-refs (at most {MAX_VIEW_REFERENCE_LIMIT}) to read more",
                views.len()
            ),
        });
    }

    if options.tags {
        let mut sql = "SELECT TAG_DATABASE, TAG_SCHEMA, TAG_NAME, TAG_VALUE, OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, DOMAIN, COLUMN_NAME FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES WHERE OBJECT_DELETED IS NULL AND OBJECT_DATABASE = ?".to_owned();
        let mut binding_values = vec![database.to_owned()];
        if let Some(schema) = schema {
            sql.push_str(" AND OBJECT_SCHEMA = ?");
            binding_values.push(schema.to_owned());
        }
        sql.push_str(
            " ORDER BY OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME, TAG_DATABASE, TAG_SCHEMA, TAG_NAME",
        );
        push(
            &mut plan,
            RelationSource::TagReferences,
            BuiltStatement {
                sql,
                binding_values,
            },
        );
    } else {
        plan.gaps.push(DiscoveryGap {
            source: RelationSource::TagReferences.as_str().to_owned(),
            kind: DiscoveryGapKind::Skipped,
            detail: "tags are opt-in (--tags): they come from SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES, which needs the GOVERNANCE_VIEWER database role and lags up to two hours".to_owned(),
        });
    }
    plan
}

/// Fold the relation statements' outcomes into `snapshot`. `plan_gaps` are
/// the plan's own gaps; every failed statement adds a
/// [`DiscoveryGapKind::Failed`] gap naming its source, and foreign keys whose
/// constraint names do not resolve to exactly one table add an
/// [`DiscoveryGapKind::Unresolved`] gap instead of a guessed edge.
pub fn apply_relation_results(
    snapshot: &mut CatalogSnapshot,
    plan_gaps: Vec<DiscoveryGap>,
    results: Vec<(RelationStatement, RelationOutcome)>,
) {
    let mut gaps = plan_gaps;
    let mut rows: BTreeMap<RelationSource, Vec<InformationSchemaRow>> = BTreeMap::new();
    let mut failed = BTreeSet::new();
    let mut view_references = Vec::new();
    for (statement, outcome) in results {
        match outcome {
            RelationOutcome::Completed(completed) => {
                let completed_rows = rows_from_completed(&completed);
                match statement.view {
                    Some(view) if statement.source == RelationSource::ObjectReferences => {
                        view_references.push((view, completed_rows));
                    }
                    _ => rows
                        .entry(statement.source)
                        .or_default()
                        .extend(completed_rows),
                }
            }
            RelationOutcome::Failed(message) => {
                failed.insert(statement.source);
                let detail = match &statement.view {
                    Some(view) => format!("{}: {message}", view.qualified()),
                    None => message,
                };
                gaps.push(DiscoveryGap {
                    source: statement.source.as_str().to_owned(),
                    kind: DiscoveryGapKind::Failed,
                    detail,
                });
            }
        }
    }
    let source_rows = |source| rows.get(&source).map(Vec::as_slice).unwrap_or_default();

    snapshot.primary_keys = primary_keys(source_rows(RelationSource::PrimaryKeys));
    snapshot.stages = source_rows(RelationSource::Stages)
        .iter()
        .filter_map(stage_entry)
        .collect();
    snapshot.file_formats = source_rows(RelationSource::FileFormats)
        .iter()
        .filter_map(file_format_entry)
        .collect();

    let mut relations = BTreeSet::new();
    if !failed.contains(&RelationSource::TableConstraints)
        && !failed.contains(&RelationSource::ReferentialConstraints)
    {
        let (foreign_keys, unresolved) = foreign_keys(
            source_rows(RelationSource::TableConstraints),
            source_rows(RelationSource::ReferentialConstraints),
        );
        relations.extend(foreign_keys);
        if let Some(first) = unresolved.first() {
            gaps.push(DiscoveryGap {
                source: "foreign_keys".to_owned(),
                kind: DiscoveryGapKind::Unresolved,
                detail: format!(
                    "{} foreign key(s) whose constraint name does not identify exactly one table on each side (e.g. {first}); constraint names are not unique in Snowflake",
                    unresolved.len()
                ),
            });
        }
    }
    for row in source_rows(RelationSource::ExternalTables) {
        relations.extend(external_table_relations(row, &snapshot.stages));
    }
    for (view, references) in &view_references {
        for row in references {
            let (Some(database), Some(schema), Some(name)) = (
                row.get("REFERENCED_DATABASE_NAME"),
                row.get("REFERENCED_SCHEMA_NAME"),
                row.get("REFERENCED_OBJECT_NAME"),
            ) else {
                continue;
            };
            let source = ObjectRef::new(database, schema, name);
            if &source == view {
                continue;
            }
            relations.insert(CatalogRelation::ViewDependsOn {
                view: view.clone(),
                source,
                source_type: row.get("REFERENCED_OBJECT_TYPE").map(str::to_owned),
            });
        }
    }
    snapshot.relations = relations.into_iter().collect();

    let mut tags: Vec<TagAssignment> = source_rows(RelationSource::TagReferences)
        .iter()
        .filter_map(tag_assignment)
        .collect();
    tags.sort();
    tags.dedup();
    for column in &mut snapshot.columns {
        for tag in &tags {
            if tag.column.as_deref() == Some(column.column.as_str())
                && tag.object.database == column.database
                && tag.object.schema == column.schema
                && tag.object.name == column.object
            {
                column.tags.push(tag.label());
            }
        }
        column.tags.sort();
        column.tags.dedup();
    }
    snapshot.tags = tags;
    snapshot.gaps = gaps;
    snapshot.relations_discovered = true;
}

fn object_at(
    row: &InformationSchemaRow,
    database: &str,
    schema: &str,
    name: &str,
) -> Option<ObjectRef> {
    Some(ObjectRef::new(
        non_empty(row.get(database))?,
        non_empty(row.get(schema))?,
        non_empty(row.get(name))?,
    ))
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

/// A primary key while its SHOW rows are gathered: the constraint name and
/// `(key_sequence, column)` pairs.
#[derive(Default)]
struct KeyRows {
    constraint: Option<String>,
    columns: Vec<(u32, String)>,
}

fn primary_keys(rows: &[InformationSchemaRow]) -> Vec<PrimaryKey> {
    let mut keys: BTreeMap<ObjectRef, KeyRows> = BTreeMap::new();
    for row in rows {
        let (Some(object), Some(column)) = (
            object_at(row, "DATABASE_NAME", "SCHEMA_NAME", "TABLE_NAME"),
            non_empty(row.get("COLUMN_NAME")),
        ) else {
            continue;
        };
        let sequence = row
            .get("KEY_SEQUENCE")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(u32::MAX);
        let entry = keys.entry(object).or_default();
        if entry.constraint.is_none() {
            entry.constraint = non_empty(row.get("CONSTRAINT_NAME")).map(str::to_owned);
        }
        entry.columns.push((sequence, column.to_owned()));
    }
    keys.into_iter()
        .map(|(object, mut key)| {
            key.columns.sort();
            PrimaryKey {
                object,
                columns: key.columns.into_iter().map(|(_, column)| column).collect(),
                constraint: key.constraint,
            }
        })
        .collect()
}

fn stage_entry(row: &InformationSchemaRow) -> Option<StageEntry> {
    Some(StageEntry {
        stage: object_at(row, "STAGE_CATALOG", "STAGE_SCHEMA", "STAGE_NAME")?,
        stage_type: non_empty(row.get("STAGE_TYPE")).map(str::to_owned),
        url: non_empty(row.get("STAGE_URL")).map(str::to_owned),
        region: non_empty(row.get("STAGE_REGION")).map(str::to_owned),
        comment: non_empty(row.get("COMMENT")).map(str::to_owned),
    })
}

fn file_format_entry(row: &InformationSchemaRow) -> Option<FileFormatEntry> {
    Some(FileFormatEntry {
        file_format: object_at(
            row,
            "FILE_FORMAT_CATALOG",
            "FILE_FORMAT_SCHEMA",
            "FILE_FORMAT_NAME",
        )?,
        format_type: non_empty(row.get("FILE_FORMAT_TYPE")).map(str::to_owned),
        comment: non_empty(row.get("COMMENT")).map(str::to_owned),
    })
}

/// Join REFERENTIAL_CONSTRAINTS to TABLE_CONSTRAINTS on both constraint
/// identities. Returns the resolved foreign keys and the constraints that did
/// not resolve to exactly one table on each side.
fn foreign_keys(
    table_constraints: &[InformationSchemaRow],
    referential: &[InformationSchemaRow],
) -> (Vec<CatalogRelation>, Vec<String>) {
    type ConstraintId = (String, String, String);
    let mut foreign: BTreeMap<ConstraintId, BTreeSet<ObjectRef>> = BTreeMap::new();
    let mut unique: BTreeMap<ConstraintId, BTreeSet<ObjectRef>> = BTreeMap::new();
    for row in table_constraints {
        let (Some(id), Some(table)) = (
            constraint_id(
                row,
                "CONSTRAINT_CATALOG",
                "CONSTRAINT_SCHEMA",
                "CONSTRAINT_NAME",
            ),
            object_at(row, "TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME"),
        ) else {
            continue;
        };
        match row
            .get("CONSTRAINT_TYPE")
            .unwrap_or_default()
            .to_ascii_uppercase()
            .as_str()
        {
            "FOREIGN KEY" => {
                foreign.entry(id).or_default().insert(table);
            }
            "PRIMARY KEY" | "UNIQUE" => {
                unique.entry(id).or_default().insert(table);
            }
            _ => {}
        }
    }
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();
    for row in referential {
        let (Some(id), Some(referenced)) = (
            constraint_id(
                row,
                "CONSTRAINT_CATALOG",
                "CONSTRAINT_SCHEMA",
                "CONSTRAINT_NAME",
            ),
            constraint_id(
                row,
                "UNIQUE_CONSTRAINT_CATALOG",
                "UNIQUE_CONSTRAINT_SCHEMA",
                "UNIQUE_CONSTRAINT_NAME",
            ),
        ) else {
            continue;
        };
        let single = |tables: Option<&BTreeSet<ObjectRef>>| match tables {
            Some(tables) if tables.len() == 1 => tables.iter().next().cloned(),
            _ => None,
        };
        match (single(foreign.get(&id)), single(unique.get(&referenced))) {
            (Some(from), Some(to)) => resolved.push(CatalogRelation::ForeignKey {
                from,
                to,
                constraint: id.2,
            }),
            _ => unresolved.push(format!("{}.{}.{}", id.0, id.1, id.2)),
        }
    }
    (resolved, unresolved)
}

fn constraint_id(
    row: &InformationSchemaRow,
    catalog: &str,
    schema: &str,
    name: &str,
) -> Option<(String, String, String)> {
    Some((
        non_empty(row.get(catalog))?.to_owned(),
        non_empty(row.get(schema))?.to_owned(),
        non_empty(row.get(name))?.to_owned(),
    ))
}

fn external_table_relations(
    row: &InformationSchemaRow,
    stages: &[StageEntry],
) -> Vec<CatalogRelation> {
    let Some(object) = object_at(row, "TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME") else {
        return Vec::new();
    };
    let mut relations = Vec::new();
    if let Some(stage) = non_empty(row.get("LOCATION"))
        .and_then(|location| stage_for_location(location, &object, stages))
    {
        relations.push(CatalogRelation::UsesStage {
            object: object.clone(),
            stage,
        });
    }
    if let Some(file_format) = non_empty(row.get("FILE_FORMAT_NAME"))
        .and_then(|name| parse_object_path(name, &object.database, &object.schema))
    {
        relations.push(CatalogRelation::UsesFileFormat {
            object,
            file_format,
        });
    }
    relations
}

/// The stage an external table's `LOCATION` names: an `@[db.][schema.]stage[/path]`
/// reference (resolved against the table's database and schema), or else
/// the discovered external stage whose URL the location falls under. User and
/// table stages (`@~`, `@%t`) are not named stages.
fn stage_for_location(
    location: &str,
    object: &ObjectRef,
    stages: &[StageEntry],
) -> Option<ObjectRef> {
    let location = location.trim();
    if let Some(reference) = location.strip_prefix('@') {
        let path = reference.split('/').next().unwrap_or(reference);
        if path.starts_with('~') || path.starts_with('%') {
            return None;
        }
        return parse_object_path(path, &object.database, &object.schema);
    }
    stages
        .iter()
        .filter_map(|stage| {
            let url = stage.url.as_deref()?.trim_end_matches('/');
            let under = !url.is_empty()
                && (location == url
                    || location
                        .strip_prefix(url)
                        .is_some_and(|rest| rest.starts_with('/')));
            under.then_some((url.len(), &stage.stage))
        })
        .max_by_key(|(length, _)| *length)
        .map(|(_, stage)| stage.clone())
}

/// Resolve `[db.][schema.]name` against a default database and schema.
fn parse_object_path(path: &str, database: &str, schema: &str) -> Option<ObjectRef> {
    let parts = split_identifier_path(path)?;
    match parts.as_slice() {
        [name] => Some(ObjectRef::new(database, schema, name.clone())),
        [in_schema, name] => Some(ObjectRef::new(database, in_schema.clone(), name.clone())),
        [in_database, in_schema, name] => Some(ObjectRef::new(
            in_database.clone(),
            in_schema.clone(),
            name.clone(),
        )),
        _ => None,
    }
}

/// Split `a."b.c".d` into identifiers the way Snowflake resolves them: a
/// double-quoted part keeps its exact text (`""` is one quote), an unquoted
/// part is upper-cased. `None` for an empty part or stray quote.
fn split_identifier_path(path: &str) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut chars = path.trim().chars().peekable();
    loop {
        let mut part = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            loop {
                match chars.next()? {
                    '"' if chars.peek() == Some(&'"') => {
                        chars.next();
                        part.push('"');
                    }
                    '"' => break,
                    other => part.push(other),
                }
            }
        } else {
            while let Some(&character) = chars.peek() {
                if character == '.' {
                    break;
                }
                if character == '"' {
                    return None;
                }
                part.push(character.to_ascii_uppercase());
                chars.next();
            }
        }
        if part.is_empty() {
            return None;
        }
        parts.push(part);
        match chars.next() {
            None => return Some(parts),
            Some('.') => {}
            Some(_) => return None,
        }
    }
}

fn tag_assignment(row: &InformationSchemaRow) -> Option<TagAssignment> {
    let column = if row
        .get("DOMAIN")
        .is_some_and(|domain| domain.eq_ignore_ascii_case("COLUMN"))
    {
        Some(non_empty(row.get("COLUMN_NAME"))?.to_owned())
    } else {
        None
    };
    Some(TagAssignment {
        tag: object_at(row, "TAG_DATABASE", "TAG_SCHEMA", "TAG_NAME")?,
        value: row.get("TAG_VALUE").map(str::to_owned),
        object: object_at(row, "OBJECT_DATABASE", "OBJECT_SCHEMA", "OBJECT_NAME")?,
        column,
    })
}

#[cfg(test)]
mod tests {
    use franken_snowflake_core::ids::StatementHandle;
    use franken_snowflake_sqlapi::response::{
        ColumnType, PartitionInfo, ResultSet, ResultSetMetaData,
    };

    use super::*;
    use crate::discovery::{CatalogDiscoveryTables, build_snapshot_from_information_schema};
    use crate::model::DataSourceClass;

    fn input(database: &str, schema: &str) -> CatalogDiscoveryInput {
        CatalogDiscoveryInput {
            profile_id: "profile-fixture".to_owned(),
            profile_fingerprint: "profile:fixture".to_owned(),
            database: Some(database.to_owned()),
            schema: Some(schema.to_owned()),
            object: None,
            snapshot_id: "snap-rel".to_owned(),
            discovered_at: "2026-09-24T00:00:00Z".to_owned(),
            data_source: DataSourceClass::Fixture,
            command_id: "catalog.scan".to_owned(),
            trace_id: "trace-rel".to_owned(),
            redactions_applied: Vec::new(),
        }
    }

    fn completed(columns: &[&str], rows: Vec<Vec<Option<&str>>>) -> CompletedStatement {
        let handle = StatementHandle::new("01b2c3d4-0000-0000-0000-00000000d001");
        let rows: Vec<Vec<Option<String>>> = rows
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|value| value.map(str::to_owned))
                    .collect()
            })
            .collect();
        let row_type = columns
            .iter()
            .map(|name| ColumnType {
                name: (*name).to_owned(),
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
            })
            .collect();
        CompletedStatement {
            statement_handle: handle.clone(),
            result_set: ResultSet {
                result_set_meta_data: ResultSetMetaData {
                    num_rows: rows.len() as i64,
                    format: "jsonv2".to_owned(),
                    row_type,
                    partition_info: vec![PartitionInfo {
                        row_count: rows.len() as i64,
                        compressed_size: None,
                        uncompressed_size: Some(1),
                    }],
                },
                data: rows.clone(),
                code: "090001".to_owned(),
                statement_handle: handle,
                statement_status_url: None,
                statement_handles: None,
                sql_state: None,
                message: None,
                request_id: None,
                created_on: None,
                stats: None,
            },
            rows,
            fetched_partitions: 1,
            total_partitions: 1,
        }
    }

    /// DB.PUBLIC: tables ORDERS (FK -> CUSTOMERS), CUSTOMERS, EVENTS_EXT
    /// (external), views V_ORDERS and V_TOP (V_TOP reads V_ORDERS).
    fn base_snapshot(input: &CatalogDiscoveryInput) -> CatalogSnapshot {
        let table = |name, kind| vec![Some("DB"), Some("PUBLIC"), Some(name), Some(kind), None];
        let column = |object, name, ordinal| {
            vec![
                Some("DB"),
                Some("PUBLIC"),
                Some(object),
                Some(name),
                Some(ordinal),
                Some("TEXT"),
                None,
                None,
                None,
                Some("YES"),
                None,
            ]
        };
        let tables = CatalogDiscoveryTables {
            databases: None,
            schemas: None,
            tables: completed(
                &[
                    "TABLE_CATALOG",
                    "TABLE_SCHEMA",
                    "TABLE_NAME",
                    "TABLE_TYPE",
                    "COMMENT",
                ],
                vec![
                    table("ORDERS", "BASE TABLE"),
                    table("CUSTOMERS", "BASE TABLE"),
                    table("EVENTS_EXT", "EXTERNAL TABLE"),
                    table("V_ORDERS", "VIEW"),
                    table("V_TOP", "VIEW"),
                ],
            ),
            columns: completed(
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
                    column("ORDERS", "ORDER_ID", "1"),
                    column("ORDERS", "CUSTOMER_ID", "2"),
                    column("CUSTOMERS", "CUSTOMER_ID", "1"),
                    column("CUSTOMERS", "EMAIL", "2"),
                ],
            ),
        };
        build_snapshot_from_information_schema(input, &tables)
    }

    fn statement(
        plan: &RelationPlan,
        source: RelationSource,
        view: Option<&str>,
    ) -> RelationStatement {
        plan.statements
            .iter()
            .find(|statement| {
                statement.source == source
                    && statement.view.as_ref().map(|view| view.name.as_str()) == view
            })
            .cloned()
            .unwrap_or_else(|| panic!("planned {source:?} {view:?}"))
    }

    /// Document-derived rows for every source (column names per the docs
    /// cited in the module header; SHOW output columns are lower-case).
    fn results(plan: &RelationPlan) -> Vec<(RelationStatement, RelationOutcome)> {
        let pk_columns = [
            "created_on",
            "database_name",
            "schema_name",
            "table_name",
            "column_name",
            "key_sequence",
            "comment",
            "constraint_name",
        ];
        let pk = |table, column, sequence, name| {
            vec![
                Some("2026-09-01"),
                Some("DB"),
                Some("PUBLIC"),
                Some(table),
                Some(column),
                Some(sequence),
                None,
                Some(name),
            ]
        };
        let tc = |name, table, kind| {
            vec![
                Some("DB"),
                Some("PUBLIC"),
                Some(name),
                Some("DB"),
                Some("PUBLIC"),
                Some(table),
                Some(kind),
            ]
        };
        let references = |rows: Vec<[&'static str; 4]>| {
            completed(
                &[
                    "DATABASE_NAME",
                    "SCHEMA_NAME",
                    "VIEW_NAME",
                    "REFERENCED_DATABASE_NAME",
                    "REFERENCED_SCHEMA_NAME",
                    "REFERENCED_OBJECT_NAME",
                    "REFERENCED_OBJECT_TYPE",
                ],
                rows.into_iter()
                    .map(|[view, schema, name, kind]| {
                        vec![
                            Some("DB"),
                            Some("PUBLIC"),
                            Some(view),
                            Some("DB"),
                            Some(schema),
                            Some(name),
                            Some(kind),
                        ]
                    })
                    .collect(),
            )
        };
        vec![
            (
                statement(plan, RelationSource::PrimaryKeys, None),
                RelationOutcome::Completed(completed(
                    &pk_columns,
                    vec![
                        pk("ORDERS", "ORDER_ID", "1", "PK_ORDERS"),
                        pk("CUSTOMERS", "EMAIL", "2", "PK_CUSTOMERS"),
                        pk("CUSTOMERS", "CUSTOMER_ID", "1", "PK_CUSTOMERS"),
                    ],
                )),
            ),
            (
                statement(plan, RelationSource::TableConstraints, None),
                RelationOutcome::Completed(completed(
                    &[
                        "CONSTRAINT_CATALOG",
                        "CONSTRAINT_SCHEMA",
                        "CONSTRAINT_NAME",
                        "TABLE_CATALOG",
                        "TABLE_SCHEMA",
                        "TABLE_NAME",
                        "CONSTRAINT_TYPE",
                    ],
                    vec![
                        tc("PK_ORDERS", "ORDERS", "PRIMARY KEY"),
                        tc("PK_CUSTOMERS", "CUSTOMERS", "PRIMARY KEY"),
                        tc("FK_ORDERS_CUSTOMER", "ORDERS", "FOREIGN KEY"),
                        // One system-generated name on two tables (as in the
                        // TABLE_CONSTRAINTS docs example): ambiguous.
                        tc("SYS_CONSTRAINT_1", "ORDERS", "FOREIGN KEY"),
                        tc("SYS_CONSTRAINT_1", "CUSTOMERS", "FOREIGN KEY"),
                    ],
                )),
            ),
            (
                statement(plan, RelationSource::ReferentialConstraints, None),
                RelationOutcome::Completed(completed(
                    &[
                        "CONSTRAINT_CATALOG",
                        "CONSTRAINT_SCHEMA",
                        "CONSTRAINT_NAME",
                        "UNIQUE_CONSTRAINT_CATALOG",
                        "UNIQUE_CONSTRAINT_SCHEMA",
                        "UNIQUE_CONSTRAINT_NAME",
                    ],
                    vec![
                        vec![
                            Some("DB"),
                            Some("PUBLIC"),
                            Some("FK_ORDERS_CUSTOMER"),
                            Some("DB"),
                            Some("PUBLIC"),
                            Some("PK_CUSTOMERS"),
                        ],
                        vec![
                            Some("DB"),
                            Some("PUBLIC"),
                            Some("SYS_CONSTRAINT_1"),
                            Some("DB"),
                            Some("PUBLIC"),
                            Some("PK_ORDERS"),
                        ],
                    ],
                )),
            ),
            (
                statement(plan, RelationSource::Stages, None),
                RelationOutcome::Completed(completed(
                    &[
                        "STAGE_CATALOG",
                        "STAGE_SCHEMA",
                        "STAGE_NAME",
                        "STAGE_URL",
                        "STAGE_REGION",
                        "STAGE_TYPE",
                        "COMMENT",
                    ],
                    vec![
                        vec![
                            Some("DB"),
                            Some("PUBLIC"),
                            Some("RAW"),
                            Some("s3://bucket/raw/"),
                            Some("us-east-1"),
                            Some("External Named"),
                            None,
                        ],
                        vec![
                            Some("DB"),
                            Some("PUBLIC"),
                            Some("RAW_ARCHIVE"),
                            Some("s3://bucket/raw_archive"),
                            None,
                            Some("External Named"),
                            None,
                        ],
                    ],
                )),
            ),
            (
                statement(plan, RelationSource::FileFormats, None),
                RelationOutcome::Completed(completed(
                    &[
                        "FILE_FORMAT_CATALOG",
                        "FILE_FORMAT_SCHEMA",
                        "FILE_FORMAT_NAME",
                        "FILE_FORMAT_TYPE",
                        "COMMENT",
                    ],
                    vec![vec![
                        Some("DB"),
                        Some("PUBLIC"),
                        Some("PARQUET_FMT"),
                        Some("PARQUET"),
                        None,
                    ]],
                )),
            ),
            (
                statement(plan, RelationSource::ExternalTables, None),
                RelationOutcome::Completed(completed(
                    &[
                        "TABLE_CATALOG",
                        "TABLE_SCHEMA",
                        "TABLE_NAME",
                        "LOCATION",
                        "FILE_FORMAT_NAME",
                        "FILE_FORMAT_TYPE",
                    ],
                    vec![vec![
                        Some("DB"),
                        Some("PUBLIC"),
                        Some("EVENTS_EXT"),
                        // A URL under RAW's location, not RAW_ARCHIVE's.
                        Some("s3://bucket/raw/events/"),
                        Some("parquet_fmt"),
                        Some("PARQUET"),
                    ]],
                )),
            ),
            (
                statement(plan, RelationSource::ObjectReferences, Some("V_ORDERS")),
                RelationOutcome::Completed(references(vec![
                    ["V_ORDERS", "PUBLIC", "ORDERS", "TABLE"],
                    ["V_ORDERS", "PUBLIC", "CUSTOMERS", "TABLE"],
                ])),
            ),
            (
                statement(plan, RelationSource::ObjectReferences, Some("V_TOP")),
                // The closure: V_ORDERS and, through it, its tables.
                RelationOutcome::Completed(references(vec![
                    ["V_TOP", "PUBLIC", "V_ORDERS", "VIEW"],
                    ["V_TOP", "PUBLIC", "ORDERS", "TABLE"],
                    ["V_TOP", "PUBLIC", "CUSTOMERS", "TABLE"],
                ])),
            ),
        ]
    }

    #[test]
    fn the_plan_quotes_show_scopes_binds_filters_and_bounds_views() {
        let input = input("DB\"X", "PUBLIC");
        let snapshot = base_snapshot(&self::input("DB", "PUBLIC"));
        let plan = plan_relation_discovery(&input, &snapshot, RelationOptions::default());
        let sources: Vec<RelationSource> = plan.statements.iter().map(|s| s.source).collect();
        assert_eq!(
            sources,
            vec![
                RelationSource::PrimaryKeys,
                RelationSource::TableConstraints,
                RelationSource::ReferentialConstraints,
                RelationSource::Stages,
                RelationSource::FileFormats,
                RelationSource::ExternalTables,
                RelationSource::ObjectReferences,
                RelationSource::ObjectReferences,
            ]
        );
        // SHOW takes no binds: the scope is quoted, embedded quotes doubled.
        assert_eq!(
            plan.statements[0].request.statement,
            r#"SHOW PRIMARY KEYS IN SCHEMA "DB""X"."PUBLIC""#
        );
        assert!(plan.statements[0].request.bindings.is_none());
        // Everything else binds its filters.
        let referential = &plan.statements[2].request;
        assert!(!referential.statement.contains("DB\"X"));
        let bindings = referential.bindings.as_ref().expect("bound filters");
        assert_eq!(bindings.get("1").map(|b| b.value.as_str()), Some("DB\"X"));
        assert_eq!(bindings.get("2").map(|b| b.value.as_str()), Some("PUBLIC"));
        // GET_OBJECT_REFERENCES names are double-quoted inside the bound string.
        let view = &plan.statements[6];
        assert_eq!(
            view.view.as_ref().map(ObjectRef::qualified).as_deref(),
            Some("DB.PUBLIC.V_ORDERS")
        );
        let bindings = view.request.bindings.as_ref().expect("bound names");
        assert_eq!(
            bindings.get("3").map(|b| b.value.as_str()),
            Some("\"V_ORDERS\"")
        );
        // Tags are opt-in: skipped, and said so.
        assert!(
            plan.gaps
                .iter()
                .any(|gap| gap.source == "tag_references" && gap.kind == DiscoveryGapKind::Skipped)
        );

        let bounded = plan_relation_discovery(
            &input,
            &snapshot,
            RelationOptions {
                view_reference_limit: 1,
                tags: true,
            },
        );
        let views = bounded
            .statements
            .iter()
            .filter(|s| s.source == RelationSource::ObjectReferences)
            .count();
        assert_eq!(views, 1);
        assert!(
            bounded
                .gaps
                .iter()
                .any(|gap| gap.kind == DiscoveryGapKind::Truncated
                    && gap.detail.contains("1 of 2 views"))
        );
        let tags = bounded.statements.last().expect("tags planned");
        assert_eq!(tags.source, RelationSource::TagReferences);
        assert!(tags.request.statement.contains("OBJECT_DELETED IS NULL"));
        assert!(
            !bounded
                .gaps
                .iter()
                .any(|gap| gap.source == "tag_references")
        );

        // No external table, no EXTERNAL_TABLES statement.
        let mut plain = snapshot.clone();
        plain
            .datasets
            .retain(|d| d.kind != DatasetKind::ExternalTable);
        let plan = plan_relation_discovery(&input, &plain, RelationOptions::default());
        assert!(
            !plan
                .statements
                .iter()
                .any(|s| s.source == RelationSource::ExternalTables)
        );
    }

    #[test]
    fn documented_rows_become_keys_dependencies_stages_and_formats() {
        let input = input("DB", "PUBLIC");
        let mut snapshot = base_snapshot(&input);
        let plan = plan_relation_discovery(&input, &snapshot, RelationOptions::default());
        let gaps = plan.gaps.clone();
        let results = results(&plan);
        apply_relation_results(&mut snapshot, gaps, results);

        assert!(snapshot.relations_discovered);
        let customers = ObjectRef::new("DB", "PUBLIC", "CUSTOMERS");
        let orders = ObjectRef::new("DB", "PUBLIC", "ORDERS");
        let v_orders = ObjectRef::new("DB", "PUBLIC", "V_ORDERS");
        let v_top = ObjectRef::new("DB", "PUBLIC", "V_TOP");
        let external = ObjectRef::new("DB", "PUBLIC", "EVENTS_EXT");
        // Key columns come back in key order, not row order.
        assert_eq!(
            snapshot
                .primary_key(&customers)
                .map(|key| key.columns.clone()),
            Some(vec!["CUSTOMER_ID".to_owned(), "EMAIL".to_owned()])
        );
        let expected = vec![
            CatalogRelation::ViewDependsOn {
                view: v_orders.clone(),
                source: customers.clone(),
                source_type: Some("TABLE".to_owned()),
            },
            CatalogRelation::ViewDependsOn {
                view: v_orders.clone(),
                source: orders.clone(),
                source_type: Some("TABLE".to_owned()),
            },
            CatalogRelation::ViewDependsOn {
                view: v_top.clone(),
                source: customers.clone(),
                source_type: Some("TABLE".to_owned()),
            },
            CatalogRelation::ViewDependsOn {
                view: v_top.clone(),
                source: orders.clone(),
                source_type: Some("TABLE".to_owned()),
            },
            CatalogRelation::ViewDependsOn {
                view: v_top,
                source: v_orders,
                source_type: Some("VIEW".to_owned()),
            },
            CatalogRelation::ForeignKey {
                from: orders,
                to: customers,
                constraint: "FK_ORDERS_CUSTOMER".to_owned(),
            },
            CatalogRelation::UsesStage {
                object: external.clone(),
                stage: ObjectRef::new("DB", "PUBLIC", "RAW"),
            },
            CatalogRelation::UsesFileFormat {
                object: external,
                file_format: ObjectRef::new("DB", "PUBLIC", "PARQUET_FMT"),
            },
        ];
        assert_eq!(snapshot.relations, expected);
        assert_eq!(snapshot.stages.len(), 2);
        assert_eq!(snapshot.file_formats.len(), 1);
        // The ambiguous constraint is reported, never guessed into an edge.
        let unresolved: Vec<&DiscoveryGap> = snapshot
            .gaps
            .iter()
            .filter(|gap| gap.kind == DiscoveryGapKind::Unresolved)
            .collect();
        assert_eq!(unresolved.len(), 1, "{:?}", snapshot.gaps);
        assert!(unresolved[0].detail.contains("SYS_CONSTRAINT_1"));
        assert!(!snapshot.relations.iter().any(|relation| matches!(
            relation,
            CatalogRelation::ForeignKey { constraint, .. } if constraint == "SYS_CONSTRAINT_1"
        )));
    }

    #[test]
    fn a_failed_source_is_a_named_gap_and_the_rest_still_lands() {
        let input = input("DB", "PUBLIC");
        let mut snapshot = base_snapshot(&input);
        let plan = plan_relation_discovery(
            &input,
            &snapshot,
            RelationOptions {
                view_reference_limit: DEFAULT_VIEW_REFERENCE_LIMIT,
                tags: true,
            },
        );
        let mut results = results(&plan);
        // The role cannot read the constraints, one view's references fail
        // (a documented limitation: a referenced UDF), and tags are denied.
        for (statement, outcome) in &mut results {
            if statement.source == RelationSource::ReferentialConstraints
                || statement
                    .view
                    .as_ref()
                    .is_some_and(|view| view.name == "V_TOP")
            {
                *outcome = RelationOutcome::Failed("Insufficient privileges".to_owned());
            }
        }
        results.push((
            statement(&plan, RelationSource::TagReferences, None),
            RelationOutcome::Failed(
                "Object 'SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES' does not exist or not authorized."
                    .to_owned(),
            ),
        ));
        apply_relation_results(&mut snapshot, plan.gaps.clone(), results);

        let failed: Vec<(&str, &str)> = snapshot
            .gaps
            .iter()
            .filter(|gap| gap.kind == DiscoveryGapKind::Failed)
            .map(|gap| (gap.source.as_str(), gap.detail.as_str()))
            .collect();
        assert_eq!(failed.len(), 3, "{failed:?}");
        assert!(failed.contains(&("referential_constraints", "Insufficient privileges")));
        assert!(failed.contains(&(
            "object_references",
            "DB.PUBLIC.V_TOP: Insufficient privileges"
        )));
        assert!(failed.iter().any(|(source, _)| *source == "tag_references"));
        // No foreign keys without both constraint views, and no guess either.
        assert!(
            !snapshot
                .relations
                .iter()
                .any(|relation| matches!(relation, CatalogRelation::ForeignKey { .. }))
        );
        // The sources that answered still landed.
        assert!(snapshot.relations.iter().any(|relation| matches!(
            relation,
            CatalogRelation::ViewDependsOn { view, .. } if view.name == "V_ORDERS"
        )));
        assert!(!snapshot.primary_keys.is_empty());
        assert!(snapshot.tags.is_empty());
    }

    #[test]
    fn column_tags_attach_to_their_columns() {
        let input = input("DB", "PUBLIC");
        let mut snapshot = base_snapshot(&input);
        let plan = plan_relation_discovery(
            &input,
            &snapshot,
            RelationOptions {
                view_reference_limit: 0,
                tags: true,
            },
        );
        let tag_columns = [
            "TAG_DATABASE",
            "TAG_SCHEMA",
            "TAG_NAME",
            "TAG_VALUE",
            "OBJECT_DATABASE",
            "OBJECT_SCHEMA",
            "OBJECT_NAME",
            "DOMAIN",
            "COLUMN_NAME",
        ];
        let results = vec![(
            statement(&plan, RelationSource::TagReferences, None),
            RelationOutcome::Completed(completed(
                &tag_columns,
                vec![
                    vec![
                        Some("GOV"),
                        Some("TAGS"),
                        Some("PII"),
                        Some("email"),
                        Some("DB"),
                        Some("PUBLIC"),
                        Some("CUSTOMERS"),
                        Some("COLUMN"),
                        Some("EMAIL"),
                    ],
                    vec![
                        Some("GOV"),
                        Some("TAGS"),
                        Some("TIER"),
                        Some("gold"),
                        Some("DB"),
                        Some("PUBLIC"),
                        Some("CUSTOMERS"),
                        Some("TABLE"),
                        None,
                    ],
                ],
            )),
        )];
        apply_relation_results(&mut snapshot, plan.gaps.clone(), results);
        let email = snapshot
            .columns
            .iter()
            .find(|column| column.object == "CUSTOMERS" && column.column == "EMAIL")
            .expect("email column");
        assert_eq!(email.tags, vec!["GOV.TAGS.PII=email".to_owned()]);
        assert_eq!(snapshot.tags.len(), 2);
        assert!(
            snapshot
                .tags
                .iter()
                .any(|tag| tag.column.is_none() && tag.tag.name == "TIER")
        );
        // The view pass was switched off, and said so.
        assert!(
            snapshot
                .gaps
                .iter()
                .any(|gap| gap.source == "object_references"
                    && gap.kind == DiscoveryGapKind::Skipped)
        );
    }

    #[test]
    fn identifier_paths_resolve_like_snowflake() {
        assert_eq!(
            split_identifier_path(r#"db."My ""Odd"" Stage""#),
            Some(vec!["DB".to_owned(), "My \"Odd\" Stage".to_owned()])
        );
        assert_eq!(split_identifier_path("a..b"), None);
        assert_eq!(split_identifier_path("a\"b"), None);
        assert_eq!(split_identifier_path(r#""open"#), None);
        let table = ObjectRef::new("DB", "PUBLIC", "T");
        assert_eq!(
            stage_for_location("@other.stage_x/path/", &table, &[]),
            Some(ObjectRef::new("DB", "OTHER", "STAGE_X"))
        );
        assert_eq!(stage_for_location("@~/staged", &table, &[]), None);
        assert_eq!(stage_for_location("@%T", &table, &[]), None);
        assert_eq!(stage_for_location("s3://elsewhere/x", &table, &[]), None);
    }
}
