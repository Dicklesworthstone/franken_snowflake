use std::error::Error;
use std::fs;

use franken_snowflake_testkit::e2e::{E2eHarnessConfig, run_mock_sqlapi_e2e};

#[test]
fn mock_sqlapi_e2e_harness_covers_required_lanes() -> Result<(), Box<dyn Error>> {
    let root = std::env::temp_dir().join("fsnow-e2e-integration");
    let config = E2eHarnessConfig::new(&root, "fsnow-e2e-integration-trace");
    let report = run_mock_sqlapi_e2e(&config)?;

    assert_eq!(report.rows, 4);
    assert_eq!(report.polls, 3);
    assert!(report.partition_fetched);
    assert!(report.cancelled);
    assert!(report.redaction_verified);
    assert_eq!(report.coverage_ratio, 1.0);

    let artifacts = root.join("fsnow-e2e-integration-trace");
    let events = fs::read_to_string(artifacts.join("events.jsonl"))?;
    let report_json = fs::read_to_string(artifacts.join("e2e-report.json"))?;
    assert!(events.contains("\"step\":\"auth-header-construction\""));
    assert!(events.contains("\"step\":\"partition-gzip\""));
    assert!(events.contains("\"step\":\"poll-pagination-complete\""));
    assert!(events.contains("\"step\":\"cancel-endpoint\""));
    assert!(events.contains("\"step\":\"secret-redaction\""));
    assert!(report_json.contains("\"coverage_ratio\": 1.0"));

    Ok(())
}
