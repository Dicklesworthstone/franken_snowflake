# Optional Frankensearch Text Indexing Design

`franken-snowflake-text-indexing` is an optional indexing lane for long
unstructured text extracted from Snowflake result sets and staged documents. It
is deliberately outside the query, catalog, frame, cache, and CLI cores: a
connector can query Snowflake, materialize frames, export CSV/JSONL, and serve
agent commands without carrying a text index dependency graph.

## Scope

The first supported tiers are:

- `hash`: deterministic Frankensearch hash embedder for cheap lexical-like
  retrieval and no model downloads.
- `lexical`: Frankensearch's Tantivy BM25 backend.

The lane must not enable `semantic`, `model2vec`, `fastembed`, `download`,
`full`, `persistent`, `durable`, `ann`, `api`, or `fastembed-reranker`. Those
features pull model/runtime surfaces that are outside the current Snowflake
connector contract.

The deferred rerank seam is intentionally narrower than retrieval. A reranker is
top-K refinement over already-retrieved long-text candidates. It is never a
catalog-search path, never an initial retriever, and never enabled by default.

## Feature Flags

| Feature | Default | Dependencies | Contract |
|---|---:|---|---|
| none | yes | `franken-snowflake-core`, `serde` | Stable text chunk, handle, rights, and reranker contracts only. |
| `frankensearch` | no | `frankensearch` with `default-features = false`, `features = ["hash", "lexical"]` | Build/query adapters using `IndexBuilder::add_document` and `TwoTierSearcher` with a Tantivy lexical backend. |
| `rerank` | no | none in this bead | Exposes the top-K policy seam. A future native reranker implementation may attach here after a separate forbidden-dependency proof. |

The default workspace build excludes both Frankensearch and rerank. The
feature-gated check lane is:

```bash
export CARGO_TARGET_DIR=/data/tmp/fsnow_targets/pane7
cargo check -p franken-snowflake-text-indexing --features frankensearch
```

The admissibility proof lane, run by the orchestrator rather than individual
code-first workers, is:

```bash
cargo tree -p franken-snowflake-text-indexing --features frankensearch --no-default-features
```

The proof must show no production path to `tokio`, `reqwest`, `hyper`, `axum`,
`tower`, `sqlx`, `diesel`, `sea-orm`, `ort`, `onnx`, `openssl`, or the
Frankensearch `fastembed`/`download` features.

## Inputs

Indexable text comes from two sources:

- Snowflake result chunks: rows selected from text-like columns (`TEXT`,
  `VARCHAR`, `VARIANT`, `OBJECT`, `ARRAY`) with provenance back to a query
  receipt, statement handle, optional query id, dataset id, redacted object name,
  column path, and chunk ordinal.
- Staged documents: exported files or staged document chunks with redacted stage
  URI, object fingerprint, optional dataset id, optional receipt hash, and chunk
  ordinal.

The indexing layer accepts already-extracted text. It does not fetch Snowflake,
parse files from stages, decrypt credentials, or decide whether a query may run.
Those decisions stay in SQL API, export/cache, and guardrail layers.

## Rights Propagation

Each `TextChunk` carries a fail-closed `RightsClass` from the dataset manifest,
profile, or source receipt. Unknown rights labels map to `restricted` through
`franken-snowflake-core`. Indexing never lowers the required rights class. Search
results return the original document handle and rights metadata so CLI/MCP
callers can filter or refuse before rendering snippets.

Sensitivity tags are opaque strings. They are propagated for policy engines but
not interpreted by this crate. Raw secrets are not accepted as source metadata;
stage URIs and object names are redacted before they become handles or logs.

## Stable Handles

The public handle format is:

```text
fsnow-text:v1:<source-kind>:<source-id>:<column-or-path>:<chunk-ordinal>
```

Components are percent-escaped, deterministic, and built from redacted or
content-addressed provenance. The source-id marker itself is part of that escaped
component, for example `receipt%3a...` or `object%3a...`, so `:` remains only the
outer handle delimiter. For query results, the source id is receipt-first; for
staged documents, it is the object fingerprint. A search hit can therefore link
back to the query receipt, dataset manifest, staged-object fingerprint, and chunk
ordinal without embedding raw text or secrets in the handle.

Index builders must refuse chunks with empty text, empty column/path metadata, an
empty query receipt hash, or empty staged-document redacted URI/fingerprint
metadata. Missing source fields otherwise collapse multiple documents into the
same stable handle.

## Search Flow

1. Extract eligible text cells or staged-document chunks under the caller's
   read-only rights policy.
2. Build `TextChunk` values with stable handles, rights metadata, and redacted
   provenance.
3. With the `frankensearch` feature enabled, call Frankensearch
   `IndexBuilder::add_document(handle, text)` for each chunk. The adapter pins a
   hash embedder stack and relies on Frankensearch to write the optional lexical
   index under `index_dir/lexical`.
4. Query with `TwoTierSearcher::search_collect`, attaching the Tantivy lexical
   backend from `index_dir/lexical`.
5. Map `doc_id` values back to `TextDocumentHandle` and then to receipt/source
   metadata maintained by the caller.

The crate does not store the caller's source map. That belongs in the cache
repository once the index location is durable.

## Reranker Seam

`TextReranker` has a no-op implementation that returns hits in exactly the same
order. `RerankPolicy` enforces `top_k <= 50` and carries a latency budget in
milliseconds. A future `rerank` implementation may wrap the pure-Rust
`frankensearch-rerank` `native` cross-encoder only after a separate cargo-tree
proof shows no `ort`, `onnx`, `openssl`, `tokio`, `reqwest`, or `hyper`.

Reranking is limited to long-text result columns and staged documents. It is not
allowed for short catalog labels, table names, column names, or interactive
autocomplete.

## Structured Logs

The crate emits serializable event shapes rather than hard-wiring a logging
backend:

- `index_build_started`
- `index_build_finished`
- `query_started`
- `query_finished`
- `rerank_refused`

Each event includes schema version, feature surface, source kind, document count
or result count, rights class, and whether the event is backed by live,
fixture, or offline data. Tokens, private keys, account identifiers, raw stage
URIs, and raw text snippets are never log fields.

## Why Optional

Most Snowflake connector users need structured SQL rows, catalog discovery,
receipts, and exports. Text indexing is valuable only when a dataset exposes
large unstructured columns or staged documents. Keeping it optional protects the
default agent CLI and library graph from model, index, and Tantivy surfaces until
a caller explicitly asks for them.
