# Downstream Integration Contract

Downstream integrations consume Snowflake through
`franken_snowflake_core::adapter::SnowflakeDataLakeAdapter`. The adapter treats
Snowflake as an authenticated private data-lake source and exposes connector
artifacts, not Snowflake SQL API protocol structs.

The public contract is intentionally narrow:

- `provider_manifest`: declares the provider, output contract ids, safety
  facets, and stable error-code families.
- `profile_diagnostics`: returns secret-free profile and credential-reference
  diagnostics.
- `catalog_discovery`: returns a content-addressed catalog snapshot summary.
- `dataset_manifest`: returns object fingerprints, rights metadata, row-limit
  policy, and field role assignments.
- `query_receipt`: returns content-addressed query receipt metadata.
- `content_export`: returns redacted export target metadata and artifact content
  address.
- `frame_ingest`: returns frame schema/provenance for downstream materializers.

Every method returns `franken_snowflake_core::envelope::Envelope<T>` and uses the
same `SnowflakeErrorCode`, `OutcomeKind`, `DataSource`, and `RightsClass`
vocabulary as CLI/MCP outputs. Downstream adapters keep their own command
contracts, storage, rights policy, and user-facing semantics.

## Implementations

- `franken_snowflake_core::adapter::fixtures::FixtureSnowflakeAdapter`
  (`adapter-fixtures` feature): generic, public-safe fixture data.
- `franken_snowflake_cli::adapter::LocalStoreAdapter` (`open()` for the CLI's
  data directory, `open_at(dir, env)` for a given one): the connector's own
  local store, i.e. what `catalog scan`, `query run`, and `export run`
  persisted (dataset manifests with the manifest overlay applied, receipts,
  exports, frames), plus profile diagnostics from the profile's env handles,
  read by name only. Every answer is offline. Artifacts carry the data source
  they were produced with (`live` for live scans and runs); the provider
  manifest and profile diagnostics leave it unspecified.

## Conformance Suite

`franken_snowflake_core::adapter::conformance::check_adapter_conformance`
takes an adapter and a probe (a known profile, dataset, receipt, and optional
export and frame, plus the data source the artifacts truly have) and returns
every violation. It checks the contract id and outcome of every envelope; that
an artifact's provenance agrees with its envelope's data source, so fixture
data relabeled `live` fails; that unknown ids are `ProfileNotFound` or
`MetadataError`, never an empty success; content addresses; and that no answer
carries secret-shaped text. Both implementations above pass it, and
`cargo run -p franken-snowflake-core --features adapter-fixtures --example
adapter_conformance` shows a downstream consumer running it.

## Stability

The trait, the contract structs, and the `fsnow.adapter.*.v1` contract ids are
semver-stable within a minor version: fields may be added (consumers must
ignore unknown fields), none are removed or renamed, and a breaking change
takes a new contract id. Error codes come from the stable `FSNOW-*` registry.

## Fixture Lane

The optional `adapter-fixtures` feature provides a no-account fixture adapter and
contract checker:

```bash
cargo test -p franken-snowflake-core --features adapter-fixtures adapter
```

The fixture checks provider/profile/catalog/dataset/receipt/export/frame outputs,
verifies read-only private-data safety facets, and emits structured JSON-line
logs under `fsnow.adapter.fixture_log.v1`.

The fixture data is generic and public-safe. It never stores raw credentials,
tokens, private keys, account locators, deployment details, or downstream
consumer names.
