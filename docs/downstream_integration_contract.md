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
