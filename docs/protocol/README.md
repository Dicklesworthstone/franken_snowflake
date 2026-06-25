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

Goldens are committed with `eol=lf` (see the repo `.gitattributes`), compared as
raw bytes, and named in lowercase to stay portable across case-insensitive
filesystems.
