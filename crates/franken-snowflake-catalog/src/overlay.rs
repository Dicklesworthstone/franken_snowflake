//! Non-secret dataset manifest overlays (reality-check bead oj0.35): a
//! hand-edited TOML file that confirms or corrects what discovery inferred —
//! field roles, limits, rights class, description — and applies at read time,
//! without a rescan.
//!
//! ```toml
//! [[datasets]]
//! database = "ANALYTICS"      # or: id = "<dataset id>"
//! schema = "PUBLIC"
//! object = "EVENTS"
//! rights_class = "internal"   # an unknown label fails closed to restricted
//! default_limit = 500
//!
//! [[datasets.fields]]
//! column = "ACCOUNT_REF"
//! role = "entity_key"         # entity_key | time_index | known_at | feature | label | metadata
//! ```
//!
//! An overlay never carries a credential: a key that looks like one is
//! refused before anything else is read, and parse errors report a position,
//! never the offending text.

use serde::Deserialize;

use crate::model::{DatasetManifest, FieldRole, RightsClass, RoleConfidence, normalize_identifier};

/// The overlay document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestOverlay {
    /// Informational; any manifest schema version is accepted.
    #[serde(default)]
    pub schema_version: Option<String>,
    /// Per-dataset corrections.
    #[serde(default)]
    pub datasets: Vec<DatasetOverlay>,
}

/// Corrections for one dataset, matched by `id` or by
/// `database` + `schema` + `object`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetOverlay {
    /// Dataset id, as `catalog scan` lists it.
    #[serde(default)]
    pub id: Option<String>,
    /// Database identifier (matched ASCII case-insensitively, as unquoted
    /// identifiers resolve).
    #[serde(default)]
    pub database: Option<String>,
    /// Schema identifier.
    #[serde(default)]
    pub schema: Option<String>,
    /// Object identifier.
    #[serde(default)]
    pub object: Option<String>,
    /// Rights class; an unknown label is the most restrictive class.
    #[serde(default)]
    pub rights_class: Option<RightsClass>,
    /// Default row limit.
    #[serde(default)]
    pub default_limit: Option<u64>,
    /// Ceiling before export.
    #[serde(default)]
    pub max_rows_without_export: Option<u64>,
    /// Description.
    #[serde(default)]
    pub description: Option<String>,
    /// Field role assignments.
    #[serde(default)]
    pub fields: Vec<FieldOverlay>,
}

/// One field's role.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldOverlay {
    /// The column, as the dataset names it (ASCII case-insensitive).
    pub column: String,
    /// Its role.
    pub role: FieldRole,
    /// Whether the dataset contract expects it (default: entity keys and
    /// time indexes are required).
    #[serde(default)]
    pub required: Option<bool>,
}

/// Why an overlay was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OverlayError {
    /// Not TOML, or not the overlay schema (an unknown key, an unknown role,
    /// a wrong type). `line` is 1-based when known.
    Invalid {
        /// The parser's message (never the offending text).
        message: String,
        /// 1-based line.
        line: Option<usize>,
    },
    /// A key that looks like a credential; overlays are non-secret.
    SecretLikeKey {
        /// Dotted key path (e.g. `datasets.api_token`).
        key: String,
    },
    /// An entry that names neither an `id` nor all of `database`, `schema`
    /// and `object`.
    NoTarget {
        /// 0-based entry index.
        entry: usize,
    },
    /// A field names a column the dataset does not have.
    UnknownColumn {
        /// The dataset.
        dataset_id: String,
        /// The column as written.
        column: String,
        /// Close column names.
        did_you_mean: Vec<String>,
    },
}

impl OverlayError {
    /// One-line description for envelopes.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Invalid {
                message,
                line: Some(line),
            } => format!("line {line}: {message}"),
            Self::Invalid {
                message,
                line: None,
            } => message.clone(),
            Self::SecretLikeKey { key } => format!(
                "key `{key}` looks like a credential; dataset overlays are non-secret (credentials belong in profile env handles)"
            ),
            Self::NoTarget { entry } => format!(
                "datasets[{entry}] names neither `id` nor all of `database`, `schema` and `object`"
            ),
            Self::UnknownColumn {
                dataset_id, column, ..
            } => format!("dataset `{dataset_id}` has no column `{column}`"),
        }
    }

    /// Close names for an unknown column.
    #[must_use]
    pub fn did_you_mean(&self) -> Vec<String> {
        match self {
            Self::UnknownColumn { did_you_mean, .. } => did_you_mean.clone(),
            _ => Vec::new(),
        }
    }
}

/// Parse and structurally validate an overlay document.
///
/// # Errors
/// [`OverlayError::SecretLikeKey`] before anything else, then
/// [`OverlayError::Invalid`] or [`OverlayError::NoTarget`].
pub fn parse_overlay(text: &str) -> Result<ManifestOverlay, OverlayError> {
    let table: toml::Table = toml::from_str(text).map_err(|error| invalid(text, &error))?;
    if let Some(key) = secret_like_key(&table, "") {
        return Err(OverlayError::SecretLikeKey { key });
    }
    let overlay: ManifestOverlay = toml::from_str(text).map_err(|error| invalid(text, &error))?;
    for (entry, dataset) in overlay.datasets.iter().enumerate() {
        let located =
            dataset.database.is_some() && dataset.schema.is_some() && dataset.object.is_some();
        if dataset.id.is_none() && !located {
            return Err(OverlayError::NoTarget { entry });
        }
    }
    Ok(overlay)
}

fn invalid(text: &str, error: &toml::de::Error) -> OverlayError {
    let line = error.span().map(|span| {
        text.get(..span.start)
            .map_or(1, |before| before.matches('\n').count() + 1)
    });
    OverlayError::Invalid {
        message: error.message().to_owned(),
        line,
    }
}

/// The first key (depth-first, dotted path) that names a credential.
fn secret_like_key(table: &toml::Table, prefix: &str) -> Option<String> {
    for (key, value) in table {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        let lowered = key.to_ascii_lowercase();
        if [
            "password",
            "passwd",
            "passphrase",
            "secret",
            "token",
            "private",
            "credential",
        ]
        .iter()
        .any(|marker| lowered.contains(marker))
            || lowered == "key"
            || lowered.ends_with("_key")
        {
            return Some(path);
        }
        let nested = match value {
            toml::Value::Table(inner) => secret_like_key(inner, &path),
            toml::Value::Array(items) => items.iter().find_map(|item| match item {
                toml::Value::Table(inner) => secret_like_key(inner, &path),
                _ => None,
            }),
            _ => None,
        };
        if nested.is_some() {
            return nested;
        }
    }
    None
}

/// The overlay entry for `manifest`: by id first, then by
/// database/schema/object (ASCII case-insensitive).
#[must_use]
pub fn overlay_for<'o>(
    overlay: &'o ManifestOverlay,
    manifest: &DatasetManifest,
) -> Option<&'o DatasetOverlay> {
    overlay
        .datasets
        .iter()
        .find(|entry| entry.id.as_deref() == Some(manifest.id.as_str()))
        .or_else(|| {
            overlay.datasets.iter().find(|entry| {
                entry.id.is_none()
                    && same_part(entry.database.as_deref(), &manifest.database)
                    && same_part(entry.schema.as_deref(), &manifest.schema)
                    && same_part(entry.object.as_deref(), &manifest.object)
            })
        })
}

fn same_part(wanted: Option<&str>, actual: &str) -> bool {
    wanted.is_some_and(|wanted| wanted.eq_ignore_ascii_case(actual))
}

/// Apply one overlay entry. Assigned fields report
/// [`RoleConfidence::Overlay`]; an inferred field that held a single-valued
/// role the overlay now gives another column (entity key, time index,
/// known-at) becomes a feature, so the overlay's choice is the one planning
/// uses.
///
/// # Errors
/// [`OverlayError::UnknownColumn`] when a field names a column the dataset
/// does not have; the manifest is left unchanged.
pub fn apply_dataset_overlay(
    manifest: &mut DatasetManifest,
    entry: &DatasetOverlay,
) -> Result<(), OverlayError> {
    let mut assignments = Vec::with_capacity(entry.fields.len());
    for field in &entry.fields {
        let index = manifest
            .fields
            .iter()
            .position(|existing| existing.column == field.column)
            .or_else(|| {
                manifest
                    .fields
                    .iter()
                    .position(|existing| existing.column.eq_ignore_ascii_case(&field.column))
            });
        let Some(index) = index else {
            let wanted = normalize_identifier(&field.column);
            let mut did_you_mean: Vec<String> = manifest
                .fields
                .iter()
                .filter(|existing| {
                    let candidate = normalize_identifier(&existing.column);
                    candidate.contains(&wanted) || wanted.contains(&candidate)
                })
                .map(|existing| existing.column.clone())
                .collect();
            did_you_mean.truncate(3);
            return Err(OverlayError::UnknownColumn {
                dataset_id: manifest.id.clone(),
                column: field.column.clone(),
                did_you_mean,
            });
        };
        assignments.push((index, field));
    }
    for (index, field) in assignments {
        if matches!(
            field.role,
            FieldRole::EntityKey | FieldRole::TimeIndex | FieldRole::KnownAt
        ) {
            for (other, existing) in manifest.fields.iter_mut().enumerate() {
                if other != index
                    && existing.role == field.role
                    && existing.role_confidence == RoleConfidence::Inferred
                {
                    existing.role = FieldRole::Feature;
                    existing.required = false;
                }
            }
        }
        if let Some(target) = manifest.fields.get_mut(index) {
            target.role = field.role;
            target.required = field.required.unwrap_or(matches!(
                field.role,
                FieldRole::EntityKey | FieldRole::TimeIndex
            ));
            target.role_confidence = RoleConfidence::Overlay;
        }
    }
    if let Some(rights_class) = entry.rights_class {
        manifest.rights_class = rights_class;
    }
    if let Some(limit) = entry.default_limit {
        manifest.default_limit = limit;
    }
    if let Some(ceiling) = entry.max_rows_without_export {
        manifest.max_rows_without_export = ceiling;
    }
    if let Some(description) = &entry.description {
        manifest.description = Some(description.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        DataSourceClass, DatasetField, DatasetKind, DtypeClass, Provenance, ProvenanceSource,
    };

    fn manifest() -> DatasetManifest {
        let field = |column: &str, role, dtype| DatasetField {
            column: column.to_owned(),
            role,
            dtype,
            required: matches!(role, FieldRole::EntityKey | FieldRole::TimeIndex),
            role_confidence: RoleConfidence::Inferred,
        };
        DatasetManifest {
            id: "analytics_public_events_b3_00".to_owned(),
            profile: "demo".to_owned(),
            database: "ANALYTICS".to_owned(),
            schema: "PUBLIC".to_owned(),
            object: "EVENTS".to_owned(),
            kind: DatasetKind::Table,
            rights_class: RightsClass::Restricted,
            default_limit: 1_000,
            max_rows_without_export: 50_000,
            approx_row_count: None,
            bytes: None,
            description: None,
            provenance: Provenance {
                source: ProvenanceSource::Fixture,
                data_source: DataSourceClass::Fixture,
                snapshot_id: "snap".to_owned(),
                discovered_at: "2026-09-24T00:00:00Z".to_owned(),
                profile_fingerprint: "profile:demo".to_owned(),
                object_fingerprint: "snowflake-object:ANALYTICS.PUBLIC.EVENTS".to_owned(),
                command_id: "catalog.scan".to_owned(),
                trace_id: "trace".to_owned(),
                redactions_applied: Vec::new(),
            },
            fields: vec![
                field("EVENT_DATE", FieldRole::TimeIndex, DtypeClass::Date),
                field("ENTITY_ID", FieldRole::EntityKey, DtypeClass::String),
                field("ACCOUNT_REF", FieldRole::Feature, DtypeClass::String),
                field("VALID_FROM", FieldRole::Feature, DtypeClass::Timestamp),
            ],
        }
    }

    const OVERLAY: &str = r#"
schema_version = "franken_snowflake.dataset_manifest.v2"

[[datasets]]
database = "analytics"
schema = "public"
object = "events"
rights_class = "internal"
default_limit = 250
description = "Events, one row per entity per day."

[[datasets.fields]]
column = "account_ref"
role = "entity_key"

[[datasets.fields]]
column = "VALID_FROM"
role = "known_at"
"#;

    #[test]
    fn an_overlay_reassigns_roles_and_limits_over_discovery() {
        let overlay = parse_overlay(OVERLAY).expect("valid overlay");
        let mut manifest = manifest();
        let entry = overlay_for(&overlay, &manifest).expect("matched by location");
        apply_dataset_overlay(&mut manifest, entry).expect("applies");
        let entity = manifest
            .field_by_role(FieldRole::EntityKey)
            .expect("an entity key");
        assert_eq!(entity.column, "ACCOUNT_REF");
        assert_eq!(entity.role_confidence, RoleConfidence::Overlay);
        assert!(entity.required);
        assert_eq!(
            manifest
                .field_by_role(FieldRole::KnownAt)
                .map(|field| field.column.as_str()),
            Some("VALID_FROM")
        );
        // The inferred entity key gave way; the untouched time index stays.
        let demoted = manifest
            .fields
            .iter()
            .find(|field| field.column == "ENTITY_ID")
            .expect("still a field");
        assert_eq!(demoted.role, FieldRole::Feature);
        assert_eq!(
            manifest
                .field_by_role(FieldRole::TimeIndex)
                .map(|field| field.role_confidence),
            Some(RoleConfidence::Inferred)
        );
        assert_eq!(manifest.rights_class, RightsClass::Internal);
        assert_eq!(manifest.default_limit, 250);
        assert_eq!(manifest.max_rows_without_export, 50_000);
    }

    #[test]
    fn an_unknown_column_is_refused_with_suggestions_and_changes_nothing() {
        let overlay = parse_overlay(
            "[[datasets]]\nid = \"analytics_public_events_b3_00\"\n\n[[datasets.fields]]\ncolumn = \"ACCOUNT\"\nrole = \"entity_key\"\n",
        )
        .expect("valid overlay");
        let mut manifest = manifest();
        let before = manifest.clone();
        let entry = overlay_for(&overlay, &manifest).expect("matched by id");
        let error = apply_dataset_overlay(&mut manifest, entry).expect_err("unknown column");
        assert!(
            matches!(error, OverlayError::UnknownColumn { .. }),
            "{error:?}"
        );
        assert_eq!(error.did_you_mean(), vec!["ACCOUNT_REF".to_owned()]);
        assert_eq!(manifest, before);
    }

    #[test]
    fn rights_fail_closed_and_secrets_and_strays_are_refused() {
        let overlay =
            parse_overlay("[[datasets]]\nid = \"x\"\nrights_class = \"top-secret-ish\"\n")
                .expect("an unknown rights label still parses");
        assert_eq!(
            overlay.datasets[0].rights_class,
            Some(RightsClass::Restricted)
        );

        // A credential-looking key is refused before its value is read, and
        // the error never echoes the value.
        let error = parse_overlay("[[datasets]]\nid = \"x\"\napi_token = \"hunter2\"\n")
            .expect_err("secret-like key");
        assert_eq!(
            error,
            OverlayError::SecretLikeKey {
                key: "datasets.api_token".to_owned()
            }
        );
        assert!(!error.message().contains("hunter2"));

        let error = parse_overlay(
            "[[datasets]]\nid = \"x\"\n\n[[datasets.fields]]\ncolumn = \"A\"\nrole = \"primary\"\n",
        )
        .expect_err("unknown role");
        assert!(matches!(error, OverlayError::Invalid { .. }), "{error:?}");
        assert!(error.message().contains("primary"), "{}", error.message());

        let error = parse_overlay("[[datasets]]\nid = \"x\"\nlimit = 5\n").expect_err("stray key");
        assert!(error.message().contains("limit"), "{}", error.message());

        assert_eq!(
            parse_overlay("[[datasets]]\ndatabase = \"A\"\nschema = \"B\"\n"),
            Err(OverlayError::NoTarget { entry: 0 })
        );
        assert_eq!(
            parse_overlay("").map(|overlay| overlay.datasets.len()),
            Ok(0)
        );
    }

    #[test]
    fn matching_prefers_the_id_and_ignores_other_datasets() {
        let overlay = parse_overlay(
            "[[datasets]]\ndatabase = \"ANALYTICS\"\nschema = \"PUBLIC\"\nobject = \"EVENTS\"\ndefault_limit = 1\n\n[[datasets]]\nid = \"analytics_public_events_b3_00\"\ndefault_limit = 2\n\n[[datasets]]\nid = \"other\"\ndefault_limit = 3\n",
        )
        .expect("valid overlay");
        let manifest = manifest();
        assert_eq!(
            overlay_for(&overlay, &manifest).and_then(|entry| entry.default_limit),
            Some(2)
        );
        let mut elsewhere = manifest;
        elsewhere.id = "elsewhere".to_owned();
        elsewhere.object = "OTHER".to_owned();
        assert!(overlay_for(&overlay, &elsewhere).is_none());
    }
}
