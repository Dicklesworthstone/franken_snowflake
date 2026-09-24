//! Schema diff and drift detection between catalog snapshots.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::{
    CatalogSnapshot, ColumnCatalogEntry, DatasetManifest, DtypeClass, RightsClass, same_identifier,
};

/// Contract version for catalog diff JSON outputs.
pub const DIFF_SCHEMA_VERSION: &str = "franken_snowflake.catalog_diff.v1";

/// The result of diffing two catalog snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogDiff {
    /// Schema version for the diff envelope.
    pub schema_version: String,
    /// Base/previous snapshot ID (None if initial scan or unversioned).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_snapshot_id: Option<String>,
    /// Target/new snapshot ID.
    pub target_snapshot_id: String,
    /// High-level summary of changes.
    pub summary: CatalogDiffSummary,
    /// Datasets added in target.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub datasets_added: Vec<DatasetManifest>,
    /// Datasets removed from base.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub datasets_removed: Vec<DatasetManifest>,
    /// Datasets modified between base and target.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub datasets_modified: Vec<DatasetDiff>,
}

/// Summary counts of drift between two snapshots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogDiffSummary {
    pub datasets_added: usize,
    pub datasets_removed: usize,
    pub datasets_modified: usize,
    pub columns_added: usize,
    pub columns_removed: usize,
    pub columns_modified: usize,
    /// True if any change is potentially breaking (e.g. dropped dataset, dropped column,
    /// column made non-nullable, or incompatible dtype change).
    pub has_breaking_changes: bool,
    /// True if base and target represent identical catalog contents.
    pub is_identical: bool,
}

/// Changes detected within a single dataset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetDiff {
    pub dataset_id: String,
    pub database: String,
    pub schema: String,
    pub object: String,
    /// True if this dataset change contains breaking schema changes.
    pub is_breaking: bool,
    /// Approximate row count change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approx_row_count: Option<MetricChange<u64>>,
    /// Byte size change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<MetricChange<u64>>,
    /// Description change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<ValueChange<Option<String>>>,
    /// Rights class change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rights_class: Option<ValueChange<RightsClass>>,
    /// Columns added to this dataset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns_added: Vec<ColumnCatalogEntry>,
    /// Columns removed from this dataset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns_removed: Vec<ColumnCatalogEntry>,
    /// Columns modified in this dataset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns_modified: Vec<ColumnDiff>,
}

/// Generic change in a scalar value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueChange<T> {
    pub old: T,
    pub new: T,
}

/// Metric change with old and new values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricChange<T> {
    pub old: Option<T>,
    pub new: Option<T>,
}

/// Changes detected on a specific column.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnDiff {
    pub column: String,
    pub is_breaking: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtype_class: Option<ValueChange<DtypeClass>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snowflake_type: Option<ValueChange<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullable: Option<ValueChange<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precision: Option<ValueChange<Option<u32>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale: Option<ValueChange<Option<u32>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<ValueChange<Option<String>>>,
}

impl CatalogDiff {
    /// Create a diff representing an initial scan where no prior snapshot exists.
    #[must_use]
    pub fn initial_scan(target: &CatalogSnapshot) -> Self {
        let datasets_count = target.datasets.len();
        let columns_count = target.columns.len();
        Self {
            schema_version: DIFF_SCHEMA_VERSION.to_owned(),
            base_snapshot_id: None,
            target_snapshot_id: target.provenance.snapshot_id.clone(),
            summary: CatalogDiffSummary {
                datasets_added: datasets_count,
                datasets_removed: 0,
                datasets_modified: 0,
                columns_added: columns_count,
                columns_removed: 0,
                columns_modified: 0,
                has_breaking_changes: false,
                is_identical: false,
            },
            datasets_added: target.datasets.clone(),
            datasets_removed: Vec::new(),
            datasets_modified: Vec::new(),
        }
    }

    /// True if there are any schema or metric differences.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        !self.summary.is_identical
    }

    /// True if any changes could break existing consumers.
    #[must_use]
    pub fn is_breaking(&self) -> bool {
        self.summary.has_breaking_changes
    }

    /// Render a concise, agent-friendly summary line.
    #[must_use]
    pub fn summary_text(&self) -> String {
        if self.summary.is_identical {
            return "No changes detected (identical catalog)".to_string();
        }
        let breaking_tag = if self.summary.has_breaking_changes {
            " [BREAKING]"
        } else {
            ""
        };
        format!(
            "Datasets: +{} -{} ~{} | Columns: +{} -{} ~{}{}",
            self.summary.datasets_added,
            self.summary.datasets_removed,
            self.summary.datasets_modified,
            self.summary.columns_added,
            self.summary.columns_removed,
            self.summary.columns_modified,
            breaking_tag
        )
    }
}

/// Diff two catalog snapshots and produce a structured drift report.
#[must_use]
pub fn diff_snapshots(base: &CatalogSnapshot, target: &CatalogSnapshot) -> CatalogDiff {
    let base_datasets: BTreeMap<&str, &DatasetManifest> =
        base.datasets.iter().map(|d| (d.id.as_str(), d)).collect();
    let target_datasets: BTreeMap<&str, &DatasetManifest> =
        target.datasets.iter().map(|d| (d.id.as_str(), d)).collect();

    let mut datasets_added = Vec::new();
    let mut datasets_removed = Vec::new();
    let mut datasets_modified = Vec::new();

    // Added datasets
    for (id, manifest) in &target_datasets {
        if !base_datasets.contains_key(*id) {
            datasets_added.push((*manifest).clone());
        }
    }

    // Removed datasets (always breaking)
    for (id, manifest) in &base_datasets {
        if !target_datasets.contains_key(*id) {
            datasets_removed.push((*manifest).clone());
        }
    }

    let mut total_columns_added = 0;
    let mut total_columns_removed = 0;
    let mut total_columns_modified = 0;

    // Common datasets
    for (id, base_manifest) in &base_datasets {
        if let Some(target_manifest) = target_datasets.get(*id) {
            let base_cols = base.columns_for_dataset(id);
            let target_cols = target.columns_for_dataset(id);

            let mut cols_added = Vec::new();
            let mut cols_removed = Vec::new();
            let mut cols_modified = Vec::new();

            // Find added columns
            for t_col in &target_cols {
                if !base_cols
                    .iter()
                    .any(|b_col| same_identifier(&b_col.column, &t_col.column))
                {
                    cols_added.push((*t_col).clone());
                }
            }

            // Find removed columns
            for b_col in &base_cols {
                if !target_cols
                    .iter()
                    .any(|t_col| same_identifier(&t_col.column, &b_col.column))
                {
                    cols_removed.push((*b_col).clone());
                }
            }

            // Find modified columns
            for b_col in &base_cols {
                if let Some(t_col) = target_cols
                    .iter()
                    .find(|t| same_identifier(&t.column, &b_col.column))
                {
                    let mut is_breaking = false;
                    let dtype_class = if b_col.dtype_class != t_col.dtype_class {
                        is_breaking = true;
                        Some(ValueChange {
                            old: b_col.dtype_class,
                            new: t_col.dtype_class,
                        })
                    } else {
                        None
                    };

                    let snowflake_type = if b_col.snowflake_type != t_col.snowflake_type {
                        Some(ValueChange {
                            old: b_col.snowflake_type.clone(),
                            new: t_col.snowflake_type.clone(),
                        })
                    } else {
                        None
                    };

                    let nullable = if b_col.nullable != t_col.nullable {
                        // Changing from nullable (true) to non-nullable (false) is breaking
                        if b_col.nullable && !t_col.nullable {
                            is_breaking = true;
                        }
                        Some(ValueChange {
                            old: b_col.nullable,
                            new: t_col.nullable,
                        })
                    } else {
                        None
                    };

                    let precision = if b_col.precision != t_col.precision {
                        // Narrowing precision is breaking
                        if matches!((b_col.precision, t_col.precision), (Some(b), Some(t)) if t < b)
                        {
                            is_breaking = true;
                        }
                        Some(ValueChange {
                            old: b_col.precision,
                            new: t_col.precision,
                        })
                    } else {
                        None
                    };

                    let scale = if b_col.scale != t_col.scale {
                        if matches!((b_col.scale, t_col.scale), (Some(b), Some(t)) if t < b) {
                            is_breaking = true;
                        }
                        Some(ValueChange {
                            old: b_col.scale,
                            new: t_col.scale,
                        })
                    } else {
                        None
                    };

                    let comment = if b_col.comment != t_col.comment {
                        Some(ValueChange {
                            old: b_col.comment.clone(),
                            new: t_col.comment.clone(),
                        })
                    } else {
                        None
                    };

                    if dtype_class.is_some()
                        || snowflake_type.is_some()
                        || nullable.is_some()
                        || precision.is_some()
                        || scale.is_some()
                        || comment.is_some()
                    {
                        cols_modified.push(ColumnDiff {
                            column: b_col.column.clone(),
                            is_breaking,
                            dtype_class,
                            snowflake_type,
                            nullable,
                            precision,
                            scale,
                            comment,
                        });
                    }
                }
            }

            let approx_row_count =
                if base_manifest.approx_row_count != target_manifest.approx_row_count {
                    Some(MetricChange {
                        old: base_manifest.approx_row_count,
                        new: target_manifest.approx_row_count,
                    })
                } else {
                    None
                };

            let bytes = if base_manifest.bytes != target_manifest.bytes {
                Some(MetricChange {
                    old: base_manifest.bytes,
                    new: target_manifest.bytes,
                })
            } else {
                None
            };

            let description = if base_manifest.description != target_manifest.description {
                Some(ValueChange {
                    old: base_manifest.description.clone(),
                    new: target_manifest.description.clone(),
                })
            } else {
                None
            };

            let rights_class = if base_manifest.rights_class != target_manifest.rights_class {
                Some(ValueChange {
                    old: base_manifest.rights_class,
                    new: target_manifest.rights_class,
                })
            } else {
                None
            };

            let has_dataset_changes = !cols_added.is_empty()
                || !cols_removed.is_empty()
                || !cols_modified.is_empty()
                || approx_row_count.is_some()
                || bytes.is_some()
                || description.is_some()
                || rights_class.is_some();

            if has_dataset_changes {
                let is_breaking =
                    !cols_removed.is_empty() || cols_modified.iter().any(|c| c.is_breaking);
                total_columns_added += cols_added.len();
                total_columns_removed += cols_removed.len();
                total_columns_modified += cols_modified.len();

                datasets_modified.push(DatasetDiff {
                    dataset_id: (*id).to_owned(),
                    database: target_manifest.database.clone(),
                    schema: target_manifest.schema.clone(),
                    object: target_manifest.object.clone(),
                    is_breaking,
                    approx_row_count,
                    bytes,
                    description,
                    rights_class,
                    columns_added: cols_added,
                    columns_removed: cols_removed,
                    columns_modified: cols_modified,
                });
            }
        }
    }

    let has_breaking_changes =
        !datasets_removed.is_empty() || datasets_modified.iter().any(|d| d.is_breaking);
    let is_identical =
        datasets_added.is_empty() && datasets_removed.is_empty() && datasets_modified.is_empty();

    CatalogDiff {
        schema_version: DIFF_SCHEMA_VERSION.to_owned(),
        base_snapshot_id: Some(base.provenance.snapshot_id.clone()),
        target_snapshot_id: target.provenance.snapshot_id.clone(),
        summary: CatalogDiffSummary {
            datasets_added: datasets_added.len(),
            datasets_removed: datasets_removed.len(),
            datasets_modified: datasets_modified.len(),
            columns_added: total_columns_added,
            columns_removed: total_columns_removed,
            columns_modified: total_columns_modified,
            has_breaking_changes,
            is_identical,
        },
        datasets_added,
        datasets_removed,
        datasets_modified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DataSourceClass, DatasetKind, Provenance, ProvenanceSource};

    fn dummy_provenance(snapshot_id: &str) -> Provenance {
        Provenance {
            source: ProvenanceSource::InformationSchema,
            data_source: DataSourceClass::Live,
            snapshot_id: snapshot_id.to_string(),
            discovered_at: "2026-09-21T00:00:00Z".to_string(),
            profile_fingerprint: "profile:demo".to_string(),
            object_fingerprint: "object:demo".to_string(),
            command_id: "catalog.scan".to_string(),
            trace_id: "trace-1".to_string(),
            redactions_applied: vec![],
        }
    }

    fn dummy_dataset(id: &str, row_count: Option<u64>) -> DatasetManifest {
        DatasetManifest {
            id: id.to_string(),
            profile: "demo".to_string(),
            database: "ANALYTICS".to_string(),
            schema: "PUBLIC".to_string(),
            object: id.to_ascii_uppercase(),
            kind: DatasetKind::Table,
            rights_class: RightsClass::Internal,
            default_limit: 1000,
            max_rows_without_export: 10000,
            approx_row_count: row_count,
            bytes: Some(1024),
            description: None,
            provenance: dummy_provenance("snap-1"),
            fields: vec![],
        }
    }

    fn dummy_column(
        dataset_id: &str,
        column: &str,
        snowflake_type: &str,
        dtype_class: DtypeClass,
        nullable: bool,
    ) -> ColumnCatalogEntry {
        ColumnCatalogEntry {
            dataset_id: dataset_id.to_string(),
            database: "ANALYTICS".to_string(),
            schema: "PUBLIC".to_string(),
            object: dataset_id.to_ascii_uppercase(),
            column: column.to_string(),
            ordinal: 1,
            snowflake_type: snowflake_type.to_string(),
            dtype_class,
            nullable,
            precision: Some(38),
            scale: Some(0),
            length: None,
            aliases: vec![],
            comment: None,
            tags: vec![],
            provenance: None,
        }
    }

    #[test]
    fn identical_snapshots_produce_identical_summary() {
        let mut snap1 = CatalogSnapshot::empty(dummy_provenance("snap-1"));
        snap1.datasets.push(dummy_dataset("orders", Some(500)));
        snap1.columns.push(dummy_column(
            "orders",
            "ORDER_ID",
            "NUMBER(38,0)",
            DtypeClass::Number,
            false,
        ));

        let snap2 = snap1.clone();
        let diff = diff_snapshots(&snap1, &snap2);

        assert!(diff.summary.is_identical);
        assert!(!diff.summary.has_breaking_changes);
        assert_eq!(diff.summary.datasets_added, 0);
        assert_eq!(diff.summary.datasets_removed, 0);
        assert_eq!(diff.summary.datasets_modified, 0);
        assert_eq!(
            diff.summary_text(),
            "No changes detected (identical catalog)"
        );
    }

    #[test]
    fn added_dataset_is_non_breaking() {
        let mut snap1 = CatalogSnapshot::empty(dummy_provenance("snap-1"));
        snap1.datasets.push(dummy_dataset("orders", Some(500)));

        let mut snap2 = snap1.clone();
        snap2.provenance = dummy_provenance("snap-2");
        snap2.datasets.push(dummy_dataset("customers", Some(200)));

        let diff = diff_snapshots(&snap1, &snap2);
        assert!(!diff.summary.is_identical);
        assert!(!diff.summary.has_breaking_changes);
        assert_eq!(diff.summary.datasets_added, 1);
        assert_eq!(diff.datasets_added[0].id, "customers");
    }

    #[test]
    fn removed_dataset_is_breaking() {
        let mut snap1 = CatalogSnapshot::empty(dummy_provenance("snap-1"));
        snap1.datasets.push(dummy_dataset("orders", Some(500)));

        let snap2 = CatalogSnapshot::empty(dummy_provenance("snap-2"));

        let diff = diff_snapshots(&snap1, &snap2);
        assert!(!diff.summary.is_identical);
        assert!(diff.summary.has_breaking_changes);
        assert_eq!(diff.summary.datasets_removed, 1);
        assert_eq!(diff.datasets_removed[0].id, "orders");
        assert!(diff.summary_text().contains("[BREAKING]"));
    }

    #[test]
    fn column_modifications_and_nullability_breaking_detection() {
        let mut snap1 = CatalogSnapshot::empty(dummy_provenance("snap-1"));
        snap1.datasets.push(dummy_dataset("orders", Some(500)));
        snap1.columns.push(dummy_column(
            "orders",
            "STATUS",
            "VARCHAR",
            DtypeClass::String,
            true, // was nullable
        ));

        let mut snap2 = snap1.clone();
        snap2.provenance = dummy_provenance("snap-2");
        snap2.columns.clear();
        snap2.columns.push(dummy_column(
            "orders",
            "STATUS",
            "VARCHAR",
            DtypeClass::String,
            false, // now NOT nullable -> breaking!
        ));

        let diff = diff_snapshots(&snap1, &snap2);
        assert!(!diff.summary.is_identical);
        assert!(diff.summary.has_breaking_changes);
        assert_eq!(diff.summary.columns_modified, 1);
        assert!(diff.datasets_modified[0].is_breaking);
        assert!(diff.datasets_modified[0].columns_modified[0].is_breaking);
        assert_eq!(
            diff.datasets_modified[0].columns_modified[0].nullable,
            Some(ValueChange {
                old: true,
                new: false
            })
        );
    }

    #[test]
    fn metric_changes_detected_without_breaking_schema() {
        let mut snap1 = CatalogSnapshot::empty(dummy_provenance("snap-1"));
        snap1.datasets.push(dummy_dataset("orders", Some(500)));

        let mut snap2 = snap1.clone();
        snap2.provenance = dummy_provenance("snap-2");
        snap2.datasets[0].approx_row_count = Some(1500);

        let diff = diff_snapshots(&snap1, &snap2);
        assert!(!diff.summary.is_identical);
        assert!(!diff.summary.has_breaking_changes);
        assert_eq!(diff.summary.datasets_modified, 1);
        assert_eq!(
            diff.datasets_modified[0].approx_row_count,
            Some(MetricChange {
                old: Some(500),
                new: Some(1500)
            })
        );
    }

    #[test]
    fn initial_scan_produces_clean_report() {
        let mut snap = CatalogSnapshot::empty(dummy_provenance("snap-init"));
        snap.datasets.push(dummy_dataset("orders", Some(100)));
        snap.columns.push(dummy_column(
            "orders",
            "ID",
            "NUMBER",
            DtypeClass::Number,
            false,
        ));

        let diff = CatalogDiff::initial_scan(&snap);
        assert!(!diff.summary.is_identical);
        assert!(!diff.summary.has_breaking_changes);
        assert_eq!(diff.summary.datasets_added, 1);
        assert_eq!(diff.summary.columns_added, 1);
        assert_eq!(diff.base_snapshot_id, None);
    }
}
