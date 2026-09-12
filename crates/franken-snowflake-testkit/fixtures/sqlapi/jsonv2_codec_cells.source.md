# jsonv2 codec cells fixture source

Fixture: `jsonv2_codec_cells.json`

Source: Snowflake SQL API Handling responses documentation:
https://docs.snowflake.com/en/developer-guide/sql-api/handling-responses

Consulted: 2026-06-25

Live status: no Snowflake live credential environment variable names were
present in this workspace, so this golden is document-derived rather than
trial-account-captured. It records the canonical `jsonv2` result shape used by
the official SQL API response schema: `resultSetMetaData.format = "jsonv2"`,
`rowType[]` carries column type metadata, partition 0 is inline in `data`, rows
are arrays, every non-null cell is a JSON string regardless of Snowflake type,
and SQL NULL is JSON `null` when the nullable query parameter is left at its
default.

Encoding rules captured from the same page:

- `FIXED` / `NUMBER`: decimal string, not divided by `scale`.
- `REAL` / `FLOAT`: integer or float string.
- `DECFLOAT`: plain decimal string up to 38 significant digits, otherwise
  scientific notation.
- `BOOLEAN`: `"true"` or `"false"` string.
- `DATE`: integer day count since Unix epoch.
- `TIME`, `TIMESTAMP_NTZ`, `TIMESTAMP_LTZ`: fractional epoch seconds with 9
  decimal places.
- `TIMESTAMP_TZ`: fractional epoch seconds, a space, then encoded offset where
  `timezone_in_minutes = offset - 1440`.
- `BINARY`: hex string.
- `VARIANT`, `OBJECT`, `ARRAY`: embedded JSON text string.
