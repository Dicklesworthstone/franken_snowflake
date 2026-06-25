//! `franken-snowflake-catalog` -- catalog manifests and safe dataset planning.
//!
//! This crate owns the three-part dataset model from
//! `docs/dataset_manifest_contract.md`, validates structural predicate ASTs
//! against a column/operator catalog, compiles fixture-testable dataset query
//! plans with quoted identifiers and positional typed bindings, and turns
//! completed SQL API statement results into deterministic catalog snapshots.
//!
//! Live network I/O stays in `franken-snowflake-sqlapi`/transport. Catalog
//! discovery builds SQL API submit requests and ingests completed statement
//! results, then persists through `franken-snowflake-cache`.

pub mod discovery;
pub mod model;
pub mod operator;
pub mod planner;
pub mod predicate;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Convenient re-exports for callers and tests.
pub mod prelude {
    pub use crate::discovery::{
        CatalogDiscoveryInput, CatalogDiscoverySql, CatalogDiscoveryTables, DiscoveryStatementKind,
        InformationSchemaRow, build_information_schema_requests,
        build_snapshot_from_information_schema, persist_snapshot,
    };
    pub use crate::model::{
        CatalogSnapshot, ColumnCatalogEntry, DataSourceClass, DatasetField, DatasetKind,
        DatasetManifest, DtypeClass, FieldRole, Provenance, ProvenanceSource, RightsClass,
        RoleConfidence, SCHEMA_VERSION,
    };
    pub use crate::operator::{
        OperatorArity, OperatorCatalogEntry, OutputDtypeRule, built_in_operator_catalog,
        describe_operator_json_schema,
    };
    pub use crate::planner::{
        DatasetQueryRequest, PlanGuardrails, PlanMode, PlanRefusal, PlanWarning, PlannerLogLine,
        PredicatePushdownPlan, QueryPlan, RawSqlPlanRequest, TypedBinding, plan_dataset_query,
        plan_raw_sql_dry_run, plan_refusal_log_line, plan_success_log_line,
    };
    pub use crate::predicate::{
        LeafPredicate, PredicateAst, PredicateRefusal, PredicateRefusalCode, validate_predicate,
    };
}
