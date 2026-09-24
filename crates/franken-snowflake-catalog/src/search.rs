//! Keyword search over a catalog snapshot (reality-check bead oj0.36): which
//! datasets mention these words in their names, columns, comments, or tags.
//! Deterministic and offline; it reads the snapshot it is given, so results
//! never come from a superseded scan.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::model::{CatalogSnapshot, DatasetManifest};

/// Default number of hits returned.
pub const DEFAULT_SEARCH_LIMIT: usize = 10;

/// Most hits one search returns.
pub const MAX_SEARCH_LIMIT: usize = 100;

/// Where a query word matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchField {
    /// The object name.
    Object,
    /// A column name.
    Column,
    /// A tag (name or value) on the object or a column.
    Tag,
    /// The dataset description (object comment or overlay).
    Description,
    /// A column comment.
    ColumnComment,
    /// The database or schema name.
    Location,
}

impl SearchField {
    /// Relative weight of a whole-word match in this field.
    const fn weight(self) -> u32 {
        match self {
            Self::Object => 50,
            Self::Column => 30,
            Self::Tag | Self::Description => 20,
            Self::ColumnComment => 15,
            Self::Location => 10,
        }
    }
}

/// One place a query word matched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SearchMatch {
    /// The field kind.
    pub field: SearchField,
    /// The matched text (a column name, a tag label, a comment...).
    pub text: String,
    /// The query word it matched.
    pub word: String,
}

/// A dataset that matched, with its score and where it matched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SearchHit {
    /// Dataset id.
    pub dataset_id: String,
    /// `DATABASE.SCHEMA.OBJECT`.
    pub qualified_name: String,
    /// Relevance: each query word counts once, at its best field; whole-word
    /// matches weigh twice a prefix match, and matching every word adds half.
    pub score: u32,
    /// Query words matched / query words.
    pub matched_words: usize,
    /// Where the words matched (best first, at most five).
    pub matches: Vec<SearchMatch>,
}

/// The lower-case words of `text`: runs of letters and digits, so
/// `NET_REVENUE_USD` is `net`, `revenue`, `usd`.
#[must_use]
pub fn search_words(text: &str) -> Vec<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Rank the snapshot's datasets against `query`; datasets matching no word
/// are left out, ties break on dataset id.
#[must_use]
pub fn search_snapshot(snapshot: &CatalogSnapshot, query: &str, limit: usize) -> Vec<SearchHit> {
    let mut words = search_words(query);
    words.sort();
    words.dedup();
    if words.is_empty() {
        return Vec::new();
    }
    let mut hits: Vec<SearchHit> = snapshot
        .datasets
        .iter()
        .filter_map(|dataset| score_dataset(snapshot, dataset, &words))
        .collect();
    hits.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.dataset_id.cmp(&right.dataset_id))
    });
    hits.truncate(limit.min(MAX_SEARCH_LIMIT));
    hits
}

fn score_dataset(
    snapshot: &CatalogSnapshot,
    dataset: &DatasetManifest,
    words: &[String],
) -> Option<SearchHit> {
    let mut texts: Vec<(SearchField, String)> = vec![
        (SearchField::Object, dataset.object.clone()),
        (SearchField::Location, dataset.database.clone()),
        (SearchField::Location, dataset.schema.clone()),
    ];
    if let Some(description) = &dataset.description {
        texts.push((SearchField::Description, description.clone()));
    }
    for column in snapshot.columns_for_dataset(&dataset.id) {
        texts.push((SearchField::Column, column.column.clone()));
        if let Some(comment) = &column.comment {
            texts.push((SearchField::ColumnComment, comment.clone()));
        }
        for tag in &column.tags {
            texts.push((SearchField::Tag, format!("{} {tag}", column.column)));
        }
    }
    for tag in &snapshot.tags {
        if tag.column.is_none()
            && tag.object.database == dataset.database
            && tag.object.schema == dataset.schema
            && tag.object.name == dataset.object
        {
            texts.push((SearchField::Tag, tag.label()));
        }
    }

    // Best (score, field, text) per query word.
    let mut best: BTreeMap<&str, (u32, SearchField, String)> = BTreeMap::new();
    for (field, text) in &texts {
        let text_words = search_words(text);
        for word in words {
            let points = if text_words.iter().any(|candidate| candidate == word) {
                field.weight() * 2
            } else if word.chars().count() >= 3
                && text_words
                    .iter()
                    .any(|candidate| candidate.starts_with(word.as_str()))
            {
                field.weight()
            } else {
                continue;
            };
            let entry = best
                .entry(word.as_str())
                .or_insert((0, *field, String::new()));
            if points > entry.0 || (points == entry.0 && *field < entry.1) {
                *entry = (points, *field, text.clone());
            }
        }
    }
    if best.is_empty() {
        return None;
    }
    let mut score: u32 = best.values().map(|(points, _, _)| *points).sum();
    if best.len() == words.len() && words.len() > 1 {
        score = score.saturating_add(score / 2);
    }
    let mut matches: Vec<SearchMatch> = best
        .iter()
        .map(|(word, (_, field, text))| SearchMatch {
            field: *field,
            text: text.clone(),
            word: (*word).to_owned(),
        })
        .collect();
    matches.sort_by(|left, right| {
        left.field
            .cmp(&right.field)
            .then(left.word.cmp(&right.word))
    });
    matches.truncate(5);
    Some(SearchHit {
        dataset_id: dataset.id.clone(),
        qualified_name: format!("{}.{}.{}", dataset.database, dataset.schema, dataset.object),
        score,
        matched_words: best.len(),
        matches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ColumnCatalogEntry, DataSourceClass, DatasetKind, DtypeClass, ObjectRef, Provenance,
        ProvenanceSource, RightsClass, TagAssignment,
    };

    fn provenance() -> Provenance {
        Provenance {
            source: ProvenanceSource::Fixture,
            data_source: DataSourceClass::Fixture,
            snapshot_id: "snap-search".to_owned(),
            discovered_at: "2026-09-24T00:00:00Z".to_owned(),
            profile_fingerprint: "profile:demo".to_owned(),
            object_fingerprint: "snowflake-scope:DB.PUBLIC.*".to_owned(),
            command_id: "catalog.scan".to_owned(),
            trace_id: "trace".to_owned(),
            redactions_applied: Vec::new(),
        }
    }

    fn dataset(object: &str, description: Option<&str>) -> DatasetManifest {
        DatasetManifest {
            id: format!("db_public_{}", object.to_lowercase()),
            profile: "demo".to_owned(),
            database: "DB".to_owned(),
            schema: "PUBLIC".to_owned(),
            object: object.to_owned(),
            kind: DatasetKind::Table,
            rights_class: RightsClass::Restricted,
            default_limit: 1_000,
            max_rows_without_export: 50_000,
            approx_row_count: None,
            bytes: None,
            description: description.map(str::to_owned),
            provenance: provenance(),
            fields: Vec::new(),
        }
    }

    fn column(
        object: &str,
        name: &str,
        comment: Option<&str>,
        tags: &[&str],
    ) -> ColumnCatalogEntry {
        ColumnCatalogEntry {
            dataset_id: format!("db_public_{}", object.to_lowercase()),
            database: "DB".to_owned(),
            schema: "PUBLIC".to_owned(),
            object: object.to_owned(),
            column: name.to_owned(),
            ordinal: 1,
            snowflake_type: "TEXT".to_owned(),
            dtype_class: DtypeClass::String,
            nullable: true,
            precision: None,
            scale: None,
            length: None,
            aliases: Vec::new(),
            comment: comment.map(str::to_owned),
            tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
            provenance: None,
        }
    }

    fn snapshot() -> CatalogSnapshot {
        let mut snapshot = CatalogSnapshot::empty(provenance());
        snapshot.datasets = vec![
            dataset("ORDERS", Some("one row per order")),
            dataset("CUSTOMERS", None),
            dataset("DAILY_REVENUE", Some("net revenue after refunds")),
            dataset("SHIPMENTS", None),
        ];
        snapshot.columns = vec![
            column("ORDERS", "ORDER_ID", None, &[]),
            column("ORDERS", "GROSS_REVENUE_USD", Some("before refunds"), &[]),
            column("CUSTOMERS", "EMAIL", None, &["GOV.TAGS.PII=email"]),
            column("DAILY_REVENUE", "DAY", None, &[]),
            column("SHIPMENTS", "CARRIER", Some("revenue share partner"), &[]),
        ];
        snapshot.tags = vec![TagAssignment {
            tag: ObjectRef::new("GOV", "TAGS", "TIER"),
            value: Some("gold".to_owned()),
            object: ObjectRef::new("DB", "PUBLIC", "CUSTOMERS"),
            column: None,
        }];
        snapshot
    }

    #[test]
    fn a_word_in_the_object_name_outranks_one_in_a_column_or_comment() {
        let hits = search_snapshot(&snapshot(), "revenue", DEFAULT_SEARCH_LIMIT);
        let order: Vec<&str> = hits.iter().map(|hit| hit.qualified_name.as_str()).collect();
        assert_eq!(
            order,
            vec![
                "DB.PUBLIC.DAILY_REVENUE",
                "DB.PUBLIC.ORDERS",
                "DB.PUBLIC.SHIPMENTS"
            ],
            "{hits:?}"
        );
        assert_eq!(hits[0].matches[0].field, SearchField::Object);
        assert_eq!(hits[1].matches[0].text, "GROSS_REVENUE_USD");
        assert_eq!(hits[2].matches[0].field, SearchField::ColumnComment);
    }

    #[test]
    fn tags_and_prefixes_match_and_every_word_counts() {
        let pii = search_snapshot(&snapshot(), "pii", DEFAULT_SEARCH_LIMIT);
        assert_eq!(pii.len(), 1, "{pii:?}");
        assert_eq!(pii[0].qualified_name, "DB.PUBLIC.CUSTOMERS");
        assert_eq!(pii[0].matches[0].field, SearchField::Tag);
        let gold = search_snapshot(&snapshot(), "gold tier", DEFAULT_SEARCH_LIMIT);
        assert_eq!(gold[0].qualified_name, "DB.PUBLIC.CUSTOMERS");
        assert_eq!(gold[0].matched_words, 2);
        // Prefix: "refund" reaches "refunds".
        let refund = search_snapshot(&snapshot(), "refund", DEFAULT_SEARCH_LIMIT);
        assert_eq!(refund.len(), 2, "{refund:?}");
        // Two-letter words only match whole words.
        assert!(search_snapshot(&snapshot(), "re", DEFAULT_SEARCH_LIMIT).is_empty());
    }

    #[test]
    fn nothing_matching_is_empty_and_the_limit_holds() {
        assert!(search_snapshot(&snapshot(), "zebra", DEFAULT_SEARCH_LIMIT).is_empty());
        assert!(search_snapshot(&snapshot(), "  --  ", DEFAULT_SEARCH_LIMIT).is_empty());
        assert_eq!(search_snapshot(&snapshot(), "db", 2).len(), 2);
        assert_eq!(
            search_words("NET_REVENUE-usd 2024"),
            vec!["net", "revenue", "usd", "2024"]
        );
    }
}
