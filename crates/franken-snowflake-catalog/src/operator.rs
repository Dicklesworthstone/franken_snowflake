//! Built-in predicate operator catalog and JSON Schema projection.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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
                "value": {
                    "oneOf": [
                        scalar_value_schema(),
                        single_value_array_schema()
                    ]
                }
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
        // `unevaluatedProperties`, not `additionalProperties`: the `value`
        // property is contributed by the `allOf` sub-schema, and in JSON Schema
        // 2020-12 `additionalProperties` ignores `allOf`-evaluated properties —
        // so `additionalProperties: false` rejected every valid value-bearing
        // predicate (e.g. `{"column":"x","op":"eq","value":5}`).
        // `unevaluatedProperties` honors the `allOf` annotations.
        "unevaluatedProperties": false,
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
        "type": ["string", "number", "boolean"]
    })
}

fn single_value_array_schema() -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "maxItems": 1,
        "items": scalar_value_schema()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_one_operator_schema_accepts_scalar_or_single_value_array() {
        let operator = built_in_operator_catalog()
            .into_iter()
            .find(|operator| operator.id == "eq")
            .expect("eq operator exists");

        let schema = describe_operator_json_schema(&operator);
        let value_schema = &schema["allOf"][0]["properties"]["value"];
        assert_eq!(value_schema["oneOf"][0], scalar_value_schema());
        assert_eq!(value_schema["oneOf"][1], single_value_array_schema());
    }

    #[test]
    fn scalar_value_schema_has_no_overlapping_integer_number_one_of() {
        assert_eq!(
            scalar_value_schema(),
            json!({ "type": ["string", "number", "boolean"] })
        );
    }

    #[test]
    fn value_bearing_operator_schema_admits_the_value_property() {
        // `value` is contributed by the `allOf` sub-schema. With the old
        // `additionalProperties: false`, a 2020-12 validator would reject the
        // canonical `{column, op, value}` instance because `additionalProperties`
        // does not see `allOf`-evaluated properties. The schema must use
        // `unevaluatedProperties` so `value` is admitted while stray keys are not.
        let operator = built_in_operator_catalog()
            .into_iter()
            .find(|operator| operator.id == "eq")
            .expect("eq operator exists");
        let schema = describe_operator_json_schema(&operator);

        assert_eq!(schema["unevaluatedProperties"], json!(false));
        assert!(
            schema.get("additionalProperties").is_none(),
            "additionalProperties would mask the allOf-contributed `value` property"
        );
        // `value` is still constrained by the `allOf` branch (required there).
        assert_eq!(schema["allOf"][0]["required"], json!(["value"]));
    }
}
