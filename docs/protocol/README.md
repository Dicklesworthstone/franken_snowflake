# docs/protocol/

Captured Snowflake SQL API protocol schemas and golden packets live here:
request/response JSON for `POST /api/v2/statements`,
`GET /api/v2/statements/{handle}`, the cancel endpoint, status-code variants
(200/202/408/422/429), partition metadata, gzip partition bodies, and the
empirically pinned `jsonv2` wire-codec golden.

This directory is intentionally a placeholder in the Phase 0 scaffold. Its
contents are owned by `fsnow-sqlapi-protocol-schemas-kx6` (schemas + goldens) and
the live `jsonv2` encoding golden `fsnow-native-snowflake-connector-w0i.13`. The
proof lanes these feed are described in `docs/proof_lanes.md`; the wire-codec
rules they pin are in `COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md`
("Result Handling").

`typed_rows.v1.schema.json` is the published JSON Schema (draft 2020-12) of
the typed result rows in `query run` / MCP `query_run` envelopes
(`data.row_encoding = "typed.v1"`): the column descriptor and one
`$defs/cell_<json_repr>` per cell representation. A column's `json_repr` holds
for every cell of that column, so validate cell *i* of each row against the
definition named by column *i*. `typed_rows.v1.example.json` is the exact
projection of the testkit codec fixture (`jsonv2_codec_cells.json`); a CLI
unit test checks both files against the codec, so they cannot drift.

Goldens are committed with `eol=lf` (see the repo `.gitattributes`), compared as
raw bytes, and named in lowercase to stay portable across case-insensitive
filesystems.
