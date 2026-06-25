//! Structural predicate AST and validation against catalog artifacts.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use crate::model::{ColumnCatalogEntry, normalize_identifier};
use crate::operator::OperatorCatalogEntry;

/// Structural predicate expression. Values are data, never SQL.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PredicateAst {
    /// `and` / `or` / `not` compound expression.
    Compound(CompoundPredicate),
    /// Column/operator/value leaf predicate.
    Leaf(LeafPredicate),
}

/// Compound predicate expression.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CompoundPredicate {
    /// Conjunction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub and: Vec<PredicateAst>,
    /// Disjunction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub or: Vec<PredicateAst>,
    /// Negation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not: Option<Box<PredicateAst>>,
}

/// Leaf predicate expression.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LeafPredicate {
    /// User-supplied column identifier. Validation resolves it to a catalog row.
    pub column: String,
    /// Operator ID.
    pub op: String,
    /// Value or values. Zero-arity operators omit this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

impl LeafPredicate {
    /// Build a one-value leaf predicate.
    #[must_use]
    pub fn new(column: impl Into<String>, op: impl Into<String>, value: Value) -> Self {
        Self {
            column: column.into(),
            op: op.into(),
            value: Some(value),
        }
    }

    /// Build a zero-value leaf predicate.
    #[must_use]
    pub fn without_value(column: impl Into<String>, op: impl Into<String>) -> Self {
        Self {
            column: column.into(),
            op: op.into(),
            value: None,
        }
    }
}

/// Validate a predicate tree against the column and operator catalogs.
pub fn validate_predicate(
    predicate: &PredicateAst,
    columns: &[ColumnCatalogEntry],
    operators: &[OperatorCatalogEntry],
) -> Result<(), Vec<PredicateRefusal>> {
    let mut refusals = Vec::new();
    validate_node(predicate, columns, operators, &mut refusals);
    if refusals.is_empty() {
        Ok(())
    } else {
        Err(refusals)
    }
}

fn validate_node(
    predicate: &PredicateAst,
    columns: &[ColumnCatalogEntry],
    operators: &[OperatorCatalogEntry],
    refusals: &mut Vec<PredicateRefusal>,
) {
    match predicate {
        PredicateAst::Compound(compound) => {
            for child in &compound.and {
                validate_node(child, columns, operators, refusals);
            }
            for child in &compound.or {
                validate_node(child, columns, operators, refusals);
            }
            if let Some(child) = &compound.not {
                validate_node(child, columns, operators, refusals);
            }
        }
        PredicateAst::Leaf(leaf) => validate_leaf(leaf, columns, operators, refusals),
    }
}

fn validate_leaf(
    leaf: &LeafPredicate,
    columns: &[ColumnCatalogEntry],
    operators: &[OperatorCatalogEntry],
    refusals: &mut Vec<PredicateRefusal>,
) {
    let column = find_column(&leaf.column, columns);
    let operator = find_operator(&leaf.op, operators);

    if column.is_none() {
        refusals.push(PredicateRefusal {
            code: PredicateRefusalCode::ColumnUnknown,
            message: format!("unknown column {:?}", leaf.column),
            column: Some(leaf.column.clone()),
            operator: Some(leaf.op.clone()),
            did_you_mean: did_you_mean_columns(&leaf.column, columns),
        });
    }

    if operator.is_none() {
        refusals.push(PredicateRefusal {
            code: PredicateRefusalCode::OperatorUnknown,
            message: format!("unknown operator {:?}", leaf.op),
            column: Some(leaf.column.clone()),
            operator: Some(leaf.op.clone()),
            did_you_mean: Vec::new(),
        });
    }

    let (Some(column), Some(operator)) = (column, operator) else {
        return;
    };

    if !operator.arity.accepts(value_count(&leaf.value)) {
        refusals.push(PredicateRefusal {
            code: PredicateRefusalCode::FilterArity,
            message: format!(
                "operator {:?} expects {} value(s)",
                operator.id,
                operator.arity.label()
            ),
            column: Some(column.column.clone()),
            operator: Some(operator.id.clone()),
            did_you_mean: Vec::new(),
        });
    }

    if !operator.accepts_dtype(column.dtype_class) {
        refusals.push(PredicateRefusal {
            code: PredicateRefusalCode::FilterOperatorDtype,
            message: format!(
                "operator {:?} does not accept dtype {:?}",
                operator.id, column.dtype_class
            ),
            column: Some(column.column.clone()),
            operator: Some(operator.id.clone()),
            did_you_mean: Vec::new(),
        });
    }
}

/// Find a column by normalized exact identifier. Aliases are intentionally not
/// accepted as SQL identifiers; they are suggestions only.
#[must_use]
pub fn find_column<'a>(
    column: &str,
    columns: &'a [ColumnCatalogEntry],
) -> Option<&'a ColumnCatalogEntry> {
    let normalized = normalize_identifier(column);
    columns
        .iter()
        .find(|candidate| normalize_identifier(&candidate.column) == normalized)
}

/// Find an operator by exact ID.
#[must_use]
pub fn find_operator<'a>(
    operator: &str,
    operators: &'a [OperatorCatalogEntry],
) -> Option<&'a OperatorCatalogEntry> {
    operators.iter().find(|candidate| candidate.id == operator)
}

/// Count supplied predicate values.
#[must_use]
pub fn value_count(value: &Option<Value>) -> usize {
    match value {
        None => 0,
        Some(Value::Array(values)) => values.len(),
        Some(_) => 1,
    }
}

/// A validation refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PredicateRefusal {
    /// Stable refusal code.
    pub code: PredicateRefusalCode,
    /// Redacted message.
    pub message: String,
    /// Related column, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
    /// Related operator, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// Suggestions for unknown columns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub did_you_mean: Vec<String>,
}

/// Predicate validation refusal code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PredicateRefusalCode {
    /// Projection or filter column is absent from the column catalog.
    ColumnUnknown,
    /// Predicate operator is absent from the operator catalog.
    OperatorUnknown,
    /// Operator does not accept the column dtype class.
    FilterOperatorDtype,
    /// Operator value count does not match arity.
    FilterArity,
}

impl PredicateRefusalCode {
    /// Stable code string from `docs/catalog_graph_design.md`.
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::ColumnUnknown => "FSNOW_COLUMN_UNKNOWN",
            Self::OperatorUnknown => "FSNOW_OPERATOR_UNKNOWN",
            Self::FilterOperatorDtype => "FSNOW_FILTER_OPERATOR_DTYPE",
            Self::FilterArity => "FSNOW_FILTER_ARITY",
        }
    }
}

impl Serialize for PredicateRefusalCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.stable_code())
    }
}

/// Suggest exact catalog columns based on aliases and edit distance.
#[must_use]
pub fn did_you_mean_columns(input: &str, columns: &[ColumnCatalogEntry]) -> Vec<String> {
    let needle = normalize_identifier(input);
    let mut candidates = BTreeMap::<String, usize>::new();

    for column in columns {
        score_candidate(&needle, &column.column, &column.column, &mut candidates);
        for alias in &column.aliases {
            score_candidate(&needle, alias, &column.column, &mut candidates);
        }
    }

    let mut ranked = candidates.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        left.1.cmp(&right.1).then_with(|| {
            left.0
                .to_ascii_lowercase()
                .cmp(&right.0.to_ascii_lowercase())
        })
    });
    ranked
        .into_iter()
        .take(3)
        .map(|(column, _)| column)
        .collect()
}

fn score_candidate(
    needle: &str,
    candidate: &str,
    column: &str,
    candidates: &mut BTreeMap<String, usize>,
) {
    let candidate_normalized = normalize_identifier(candidate);
    let distance = levenshtein(needle, &candidate_normalized);
    let plausible = candidate_normalized.contains(needle)
        || needle.contains(&candidate_normalized)
        || distance <= 3;
    if !plausible {
        return;
    }

    let entry = candidates.entry(column.to_owned()).or_insert(distance);
    if distance < *entry {
        *entry = distance;
    }
}

fn levenshtein(left: &str, right: &str) -> usize {
    let right_chars = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right_chars.len()).collect::<Vec<_>>();
    let mut current = vec![0; right_chars.len() + 1];

    for (left_index, left_char) in left.chars().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_char) in right_chars.iter().enumerate() {
            let substitution_cost = if left_char == *right_char { 0 } else { 1 };
            let delete = previous[right_index + 1] + 1;
            let insert = current[right_index] + 1;
            let substitute = previous[right_index] + substitution_cost;
            current[right_index + 1] = delete.min(insert).min(substitute);
        }
        core::mem::swap(&mut previous, &mut current);
    }

    previous[right_chars.len()]
}
