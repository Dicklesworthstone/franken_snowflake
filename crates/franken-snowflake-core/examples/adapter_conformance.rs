//! A downstream consumer checking an adapter against the public contract.
//!
//! ```text
//! cargo run -p franken-snowflake-core --features adapter-fixtures --example adapter_conformance
//! ```
//!
//! A real integration would probe its own adapter (for example
//! `franken_snowflake_cli::adapter::LocalStoreAdapter`) with ids from its own
//! local store and `DataSource::Live`.

use franken_snowflake_core::adapter::SnowflakeDataLakeAdapter;
use franken_snowflake_core::adapter::conformance::{ConformanceProbe, check_adapter_conformance};
use franken_snowflake_core::adapter::fixtures::FixtureSnowflakeAdapter;
use franken_snowflake_core::ids::{DatasetId, ProfileName, ReceiptHash};
use franken_snowflake_core::outcome::DataSource;

fn main() -> std::process::ExitCode {
    let adapter = FixtureSnowflakeAdapter;
    let probe = ConformanceProbe {
        profile: ProfileName::new("fixture-private-lake"),
        dataset: DatasetId::new("fixture.events_daily"),
        receipt: ReceiptHash::new("blake3:fixture-query-receipt-0001"),
        export_id: Some("export-fixture-0001".to_owned()),
        frame_id: Some("frame-fixture-0001".to_owned()),
        expected_data_source: DataSource::Fixture,
    };
    let violations = check_adapter_conformance(&adapter, &probe);
    let provider = adapter
        .provider_manifest()
        .map(|manifest| manifest.data.provider_id)
        .unwrap_or_default();
    let conforms = violations.is_empty();
    let report = serde_json::json!({
        "provider_id": provider,
        "conforms": conforms,
        "violations": violations,
    });
    println!("{report}");
    if conforms {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
