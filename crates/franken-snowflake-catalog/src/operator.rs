//! Built-in predicate operator catalog and JSON Schema projection.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::model::DtypeClass;

/// Operator arity contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OperatorArity {
    /// Exactly `count` values.
    Exact { count: usize },
    /// Bounded value list.
    Variadic { min: usize, max: usize },
}

impl OperatorArity {
    /// Whether a supplied value count satisfies this arity.
    #[must_use]
    pub const fn accepts(self, count: usize) -> bool {
        match self {
            Self::Exact { count: expected } => count == expected,
            Self::Variadic { min, max } => count >= min && count <= max,
        }
    }

    /// Human-readable arity summary.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::Exact { count } => count.to_string(),
            Self::Variadic { min, max } => format!("{min}..={max}"),
        }
    }
}

/// Output dtype rule for a predicate operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputDtypeRule {
    /// Predicate output is boolean.
    Boolean,
}

/// One built-in or adapter-provided operator row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCatalogEntry {
    /// Stable operator ID used in predicate ASTs.
    pub id: String,
    /// Value arity.
    pub arity: OperatorArity,
    /// Accepted planner dtype classes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_dtype_classes: Vec<DtypeClass>,
    /// Output dtype rule.
    pub output_dtype_rule: OutputDtypeRule,
    /// Refusal code emitted for dtype mismatches.
    pub refusal_code: String,
    /// JSON Schema contract ID.
    pub json_schema_contract_id: String,
}

impl OperatorCatalogEntry {
    /// Whether this operator accepts a dtype class.
    #[must_use]
    pub fn accepts_dtype(&self, dtype: DtypeClass) -> bool {
        self.accepted_dtype_classes.contains(&dtype)
    }
}

/// Built-in operator catalog required by the MVP contract.
#[must_use]
pub fn built_in_operator_catalog() -> Vec<OperatorCatalogEntry> {
    let scalar = vec![
        DtypeClass::String,
        DtypeClass::Number,
        DtypeClass::Boolean,
        DtypeClass::Date,
        DtypeClass::Time,
        DtypeClass::Timestamp,
        DtypeClass::Binary,
    ];
    let ordered = vec![
        DtypeClass::Number,
        DtypeClass::Date,
        DtypeClass::Time,
        DtypeClass::Timestamp,
    ];
    let all_columns = vec![
        DtypeClass::String,
        DtypeClass::Number,
        DtypeClass::Boolean,
        DtypeClass::Date,
        DtypeClass::Time,
        DtypeClass::Timestamp,
        DtypeClass::Binary,
        DtypeClass::Variant,
        DtypeClass::Unknown,
    ];

    let mut operators = Vec::new();
    for id in ["eq", "neq"] {
        operators.push(operator(id, exact(1), scalar.clone()));
    }
    for id in ["lt", "lte", "gt", "gte"] {
        operators.push(operator(id, exact(1), ordered.clone()));
    }
    operators.push(operator("between", exact(2), ordered));
    operators.push(operator("in", variadic(1, 100), scalar));
    operators.push(operator("is_null", exact(0), all_columns.clone()));
    operators.push(operator("is_not_null", exact(0), all_columns));
    operators.push(operator("contains", exact(1), vec![DtypeClass::String]));
    operators
}

fn exact(count: usize) -> OperatorArity {
    OperatorArity::Exact { count }
}

fn variadic(min: usize, max: usize) -> OperatorArity {
    OperatorArity::Variadic { min, max }
}

fn operator(
    id: &str,
    arity: OperatorArity,
    accepted_dtype_classes: Vec<DtypeClass>,
) -> OperatorCatalogEntry {
    OperatorCatalogEntry {
        id: id.to_owned(),
        arity,
        accepted_dtype_classes,
        output_dtype_rule: OutputDtypeRule::Boolean,
        refusal_code: "FSNOW_FILTER_OPERATOR_DTYPE".to_owned(),
        json_schema_contract_id: format!("franken_snowflake.operator.{id}.v1"),
    }
}

/// Project an operator entry into a JSON Schema 2020-12 predicate-object schema.
#[must_use]
pub fn describe_operator_json_schema(operator: &OperatorCatalogEntry) -> Value {
    let value_schema = match operator.arity {
        OperatorArity::Exact { count: 0 } => json!({
            "not": { "required": ["value"] }
        }),
        OperatorArity::Exact { count: 1 } => json!({
            "properties": {
                "value": scalar_value_schema()
            },
            "required": ["value"]
        }),
        OperatorArity::Exact { count } => json!({
            "properties": {
                "value": {
                    "type": "array",
                    "minItems": count,
                    "maxItems": count,
                    "items": scalar_value_schema()
                }
            },
            "required": ["value"]
        }),
        OperatorArity::Variadic { min, max } => json!({
            "properties": {
                "value": {
                    "type": "array",
                    "minItems": min,
                    "maxItems": max,
                    "items": scalar_value_schema()
                }
            },
            "required": ["value"]
        }),
    };

    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": operator.json_schema_contract_id,
        "title": format!("franken_snowflake operator {}", operator.id),
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "column": { "type": "string", "minLength": 1 },
            "op": { "const": operator.id }
        },
        "required": ["column", "op"],
        "allOf": [value_schema],
        "x-franken-snowflake": {
            "arity": operator.arity.label(),
            "accepted_dtype_classes": operator.accepted_dtype_classes,
            "output_dtype_rule": operator.output_dtype_rule,
            "refusal_code": operator.refusal_code
        }
    })
}

fn scalar_value_schema() -> Value {
    json!({
        "oneOf": [
            { "type": "string" },
            { "type": "number" },
            { "type": "integer" },
            { "type": "boolean" }
        ]
    })
}
