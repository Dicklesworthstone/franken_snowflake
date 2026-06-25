//! `franken-snowflake-catalog` -- catalog manifests and safe dataset planning.
//!
//! This crate is intentionally pure: no live transport, no cache repository, and
//! no Snowflake credentials. It owns the three-part dataset model from
//! `docs/dataset_manifest_contract.md`, validates structural predicate ASTs
//! against a column/operator catalog, and compiles fixture-testable dataset query
//! plans with quoted identifiers and positional typed bindings.
//!
//! Live catalog discovery and persistence land in the blocked catalog/cache
//! beads. This code-first slice gives those later crates a stable data model and
//! planner contract to target.

pub mod model;
pub mod operator;
pub mod planner;
pub mod predicate;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Convenient re-exports for callers and tests.
pub mod prelude {
    pub use crate::model::{
        CatalogSnapshot, ColumnCatalogEntry, DataSourceClass, DatasetField, DatasetKind,
        DatasetManifest, DtypeClass, FieldRole, Provenance, ProvenanceSource, RightsClass,
        RoleConfidence, SCHEMA_VERSION,
    };
    pub use crate::operator::{
        built_in_operator_catalog, describe_operator_json_schema, OperatorArity,
        OperatorCatalogEntry, OutputDtypeRule,
    };
    pub use crate::planner::{
        plan_dataset_query, DatasetQueryRequest, PlanGuardrails, PlanMode, PlanRefusal,
        PlanWarning, QueryPlan, TypedBinding,
    };
    pub use crate::predicate::{
        validate_predicate, LeafPredicate, PredicateAst, PredicateRefusal, PredicateRefusalCode,
    };
}
