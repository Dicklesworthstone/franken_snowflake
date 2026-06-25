#![forbid(unsafe_code)]

//! Optional text indexing contracts for unstructured Snowflake data.
//!
//! Default builds expose only stable handles, source provenance, rights
//! propagation, and the no-op reranker seam. Enable the `frankensearch` feature
//! to build/query hash + lexical indexes through Frankensearch. The feature is
//! intentionally limited to `hash` and `lexical`; semantic/model/download paths
//! are outside this crate's contract.

use std::error::Error;
use std::fmt;

pub use franken_snowflake_core::guardrails::RightsClass;
use franken_snowflake_core::ids::{DatasetId, QueryId, ReceiptHash, StatementHandle};
use serde::{Deserialize, Serialize};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Text indexing contract schema version.
pub const TEXT_INDEX_SCHEMA_VERSION: u16 = 1;

/// Maximum number of retrieved candidates a future reranker may refine.
pub const DEFAULT_RERANK_MAX_TOP_K: usize = 50;

/// Default rerank latency budget in milliseconds for long text candidates.
pub const DEFAULT_RERANK_LATENCY_BUDGET_MS: u64 = 6_000;

/// Result alias for text indexing contracts.
pub type TextIndexResult<T> = Result<T, TextIndexError>;

/// Errors surfaced by the optional text-indexing contract layer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TextIndexError {
    /// A chunk had no searchable text.
    EmptyText { handle: String },
    /// A requested rerank exceeded the allowed top-K envelope.
    TopKExceeded { requested: usize, max: usize },
    /// The index path or redacted source metadata was missing.
    MissingField { field: &'static str },
}

impl fmt::Display for TextIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyText { handle } => write!(f, "text chunk is empty: {handle}"),
            Self::TopKExceeded { requested, max } => {
                write!(f, "rerank top_k {requested} exceeds maximum {max}")
            }
            Self::MissingField { field } => write!(f, "missing text-index field: {field}"),
        }
    }
}

impl Error for TextIndexError {}

/// Indexable text source kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextSourceKind {
    /// Text extracted from a Snowflake SQL API result set.
    QueryResult,
    /// Text extracted from a staged document or staged export object.
    StagedDocument,
}

impl TextSourceKind {
    #[must_use]
    const fn as_handle_component(self) -> &'static str {
        match self {
            Self::QueryResult => "query",
            Self::StagedDocument => "stage",
        }
    }
}

/// Secret-free provenance for an indexable text source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source_kind", rename_all = "snake_case")]
pub enum TextSourceRef {
    /// A text chunk extracted from query results.
    QueryResult {
        /// Content-addressed receipt for the statement or result.
        receipt_hash: ReceiptHash,
        /// SQL API statement handle when available.
        statement_handle: Option<StatementHandle>,
        /// Snowflake query id when available.
        query_id: Option<QueryId>,
        /// Dataset manifest id when query came from dataset mode.
        dataset_id: Option<DatasetId>,
        /// Redacted table/view/object reference.
        object_ref_redacted: Option<String>,
    },
    /// A text chunk extracted from a staged document.
    StagedDocument {
        /// Optional receipt that authorized or exported the staged object.
        receipt_hash: Option<ReceiptHash>,
        /// Dataset manifest id when the staged object belongs to a dataset.
        dataset_id: Option<DatasetId>,
        /// Redacted stage URI or logical stage path.
        stage_uri_redacted: String,
        /// Stable object fingerprint or redacted content address.
        object_fingerprint: String,
    },
}

impl TextSourceRef {
    /// Return the source kind.
    #[must_use]
    pub const fn kind(&self) -> TextSourceKind {
        match self {
            Self::QueryResult { .. } => TextSourceKind::QueryResult,
            Self::StagedDocument { .. } => TextSourceKind::StagedDocument,
        }
    }

    /// Stable, redacted source id used inside document handles.
    #[must_use]
    pub fn stable_source_id(&self) -> String {
        match self {
            Self::QueryResult { receipt_hash, .. } => {
                escape_component(&format!("receipt:{}", receipt_hash.as_str()))
            }
            Self::StagedDocument {
                object_fingerprint, ..
            } => escape_component(&format!("object:{object_fingerprint}")),
        }
    }

    /// Refuse source refs that cannot produce unique, redacted handles.
    pub fn validate(&self) -> TextIndexResult<()> {
        match self {
            Self::QueryResult { receipt_hash, .. } => {
                if receipt_hash.as_str().trim().is_empty() {
                    return Err(TextIndexError::MissingField {
                        field: "receipt_hash",
                    });
                }
            }
            Self::StagedDocument {
                stage_uri_redacted,
                object_fingerprint,
                ..
            } => {
                if stage_uri_redacted.trim().is_empty() {
                    return Err(TextIndexError::MissingField {
                        field: "stage_uri_redacted",
                    });
                }
                if object_fingerprint.trim().is_empty() {
                    return Err(TextIndexError::MissingField {
                        field: "object_fingerprint",
                    });
                }
            }
        }
        Ok(())
    }
}

/// Stable document handle returned by search hits.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TextDocumentHandle(String);

impl TextDocumentHandle {
    /// Build a stable handle from redacted source provenance and chunk metadata.
    #[must_use]
    pub fn from_source(source: &TextSourceRef, column_or_path: &str, chunk_ordinal: u32) -> Self {
        Self(format!(
            "fsnow-text:v{TEXT_INDEX_SCHEMA_VERSION}:{}:{}:{}:{}",
            source.kind().as_handle_component(),
            source.stable_source_id(),
            escape_component(column_or_path),
            chunk_ordinal
        ))
    }

    /// Wrap an already-validated handle.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the handle as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the handle.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for TextDocumentHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One extracted text chunk ready for indexing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TextChunk {
    /// Stable search document handle.
    pub handle: TextDocumentHandle,
    /// Secret-free source provenance.
    pub source: TextSourceRef,
    /// Column name, JSON path, or staged-document path.
    pub column_or_path: String,
    /// Zero-based chunk ordinal inside the source column/document.
    pub chunk_ordinal: u32,
    /// Optional title or display label.
    pub title: Option<String>,
    /// Extracted text content.
    pub text: String,
    /// Fail-closed rights class inherited from the source manifest/receipt.
    pub rights_class: RightsClass,
    /// Opaque sensitivity tags propagated to policy engines.
    pub sensitivity_tags: Vec<String>,
}

impl TextChunk {
    /// Construct a chunk and derive its stable handle.
    #[must_use]
    pub fn new(
        source: TextSourceRef,
        column_or_path: impl Into<String>,
        chunk_ordinal: u32,
        text: impl Into<String>,
        rights_class: RightsClass,
    ) -> Self {
        let column_or_path = column_or_path.into();
        let handle = TextDocumentHandle::from_source(&source, &column_or_path, chunk_ordinal);
        Self {
            handle,
            source,
            column_or_path,
            chunk_ordinal,
            title: None,
            text: text.into(),
            rights_class,
            sensitivity_tags: Vec::new(),
        }
    }

    /// Attach a title/display label.
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Attach sensitivity tags.
    #[must_use]
    pub fn with_sensitivity_tags(mut self, tags: impl IntoIterator<Item = String>) -> Self {
        self.sensitivity_tags = tags.into_iter().collect();
        self
    }

    /// Refuse empty chunks before they reach an index builder.
    pub fn validate(&self) -> TextIndexResult<()> {
        self.source.validate()?;
        if self.column_or_path.trim().is_empty() {
            return Err(TextIndexError::MissingField {
                field: "column_or_path",
            });
        }
        if self.text.trim().is_empty() {
            return Err(TextIndexError::EmptyText {
                handle: self.handle.to_string(),
            });
        }
        Ok(())
    }
}

/// Text-indexing feature surface for capabilities/doctor output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TextIndexingFeatureReport {
    /// Contract schema version.
    pub schema_version: u16,
    /// Whether Frankensearch adapters are compiled in.
    pub frankensearch_enabled: bool,
    /// Whether the rerank seam feature is compiled in.
    pub rerank_feature_enabled: bool,
    /// Retrieval tiers allowed by this crate.
    pub allowed_tiers: Vec<TextRetrievalTier>,
}

impl TextIndexingFeatureReport {
    /// Current compile-time feature report.
    #[must_use]
    pub fn current() -> Self {
        Self {
            schema_version: TEXT_INDEX_SCHEMA_VERSION,
            frankensearch_enabled: cfg!(feature = "frankensearch"),
            rerank_feature_enabled: cfg!(feature = "rerank"),
            allowed_tiers: vec![TextRetrievalTier::Hash, TextRetrievalTier::Lexical],
        }
    }
}

/// Retrieval tiers intentionally admitted for Snowflake text indexing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextRetrievalTier {
    /// Frankensearch deterministic hash tier.
    Hash,
    /// Frankensearch Tantivy BM25 tier.
    Lexical,
}

/// Search hit after mapping a Frankensearch document id back to Snowflake
/// provenance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TextSearchHit {
    /// Stable text document handle.
    pub handle: TextDocumentHandle,
    /// Zero-based rank.
    pub rank: usize,
    /// Score from the active retrieval/rerank layer.
    pub score: f64,
    /// Rights inherited from the indexed chunk.
    pub rights_class: RightsClass,
    /// Optional redacted snippet.
    pub snippet_redacted: Option<String>,
}

impl TextSearchHit {
    /// Construct a search hit.
    #[must_use]
    pub fn new(
        handle: TextDocumentHandle,
        rank: usize,
        score: f64,
        rights_class: RightsClass,
    ) -> Self {
        Self {
            handle,
            rank,
            score,
            rights_class,
            snippet_redacted: None,
        }
    }
}

/// Rerank request metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RerankRequest {
    /// User query.
    pub query: String,
    /// Number of candidates requested for reranking.
    pub top_k: usize,
    /// Policy envelope for top-K and latency.
    pub policy: RerankPolicy,
}

impl RerankRequest {
    /// Build and validate a rerank request.
    pub fn new(
        query: impl Into<String>,
        top_k: usize,
        policy: RerankPolicy,
    ) -> TextIndexResult<Self> {
        policy.validate_top_k(top_k)?;
        Ok(Self {
            query: query.into(),
            top_k,
            policy,
        })
    }
}

/// Top-K and latency policy for future reranker implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RerankPolicy {
    /// Maximum candidates a reranker may inspect.
    pub max_top_k: usize,
    /// Caller-visible latency budget in milliseconds.
    pub latency_budget_ms: u64,
}

impl Default for RerankPolicy {
    fn default() -> Self {
        Self {
            max_top_k: DEFAULT_RERANK_MAX_TOP_K,
            latency_budget_ms: DEFAULT_RERANK_LATENCY_BUDGET_MS,
        }
    }
}

impl RerankPolicy {
    /// Validate a requested top-K.
    pub fn validate_top_k(&self, requested: usize) -> TextIndexResult<()> {
        if requested > self.max_top_k {
            return Err(TextIndexError::TopKExceeded {
                requested,
                max: self.max_top_k,
            });
        }
        Ok(())
    }
}

/// Reranker seam. The default implementation is order-preserving.
pub trait TextReranker {
    /// Rerank hits for the given request.
    fn rerank(
        &self,
        request: &RerankRequest,
        hits: Vec<TextSearchHit>,
    ) -> TextIndexResult<Vec<TextSearchHit>>;
}

/// No-op reranker used by default and in builds without a native reranker.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopReranker;

impl TextReranker for NoopReranker {
    fn rerank(
        &self,
        request: &RerankRequest,
        hits: Vec<TextSearchHit>,
    ) -> TextIndexResult<Vec<TextSearchHit>> {
        request.policy.validate_top_k(request.top_k)?;
        Ok(hits)
    }
}

/// Serializable structured event for indexing logs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TextIndexEvent {
    /// Event schema version.
    pub schema_version: u16,
    /// Event kind.
    pub kind: TextIndexEventKind,
    /// Whether this event belongs to live, fixture, or offline data.
    pub data_source: TextIndexDataSource,
    /// Active feature surface.
    pub features: TextIndexingFeatureReport,
    /// Source kind if the event belongs to one source.
    pub source_kind: Option<TextSourceKind>,
    /// Document count or result count.
    pub item_count: usize,
    /// Most restrictive rights class represented by the event.
    pub rights_class: Option<RightsClass>,
}

impl TextIndexEvent {
    /// Build a structured event.
    #[must_use]
    pub fn new(kind: TextIndexEventKind) -> Self {
        Self {
            schema_version: TEXT_INDEX_SCHEMA_VERSION,
            kind,
            data_source: TextIndexDataSource::Offline,
            features: TextIndexingFeatureReport::current(),
            source_kind: None,
            item_count: 0,
            rights_class: None,
        }
    }
}

/// Data provenance class for structured text-indexing events.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextIndexDataSource {
    /// Live Snowflake-derived data.
    Live,
    /// Deterministic fixture data.
    Fixture,
    /// Local/offline data with no live Snowflake contact.
    Offline,
}

/// Structured text indexing event vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextIndexEventKind {
    IndexBuildStarted,
    IndexBuildFinished,
    QueryStarted,
    QueryFinished,
    RerankRefused,
}

fn escape_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                escaped.push(char::from(byte));
            }
            _ => {
                escaped.push('%');
                escaped.push(char::from(HEX[usize::from(byte >> 4)]));
                escaped.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
    escaped
}

#[cfg(feature = "frankensearch")]
pub mod frankensearch_adapter {
    //! Hash + lexical Frankensearch adapter.

    use std::path::Path;
    use std::sync::Arc;

    use frankensearch::{
        Cx, Embedder, EmbedderStack, HashEmbedder, IndexBuildStats, IndexBuilder, ScoredResult,
        SearchError, SearchResult, TantivyIndex, TwoTierConfig, TwoTierIndex, TwoTierMetrics,
        TwoTierSearcher,
    };

    use super::TextChunk;

    /// Build a hash + lexical index from validated text chunks.
    pub async fn build_hash_lexical_index(
        cx: &Cx,
        index_dir: impl AsRef<Path>,
        chunks: &[TextChunk],
    ) -> SearchResult<IndexBuildStats> {
        let fast = Arc::new(HashEmbedder::default_256()) as Arc<dyn Embedder>;
        let quality = Arc::new(HashEmbedder::default_384()) as Arc<dyn Embedder>;
        let stack = EmbedderStack::from_parts(fast, Some(quality));
        let mut builder = IndexBuilder::new(index_dir.as_ref()).with_embedder_stack(stack);
        for chunk in chunks {
            chunk.validate().map_err(|err| SearchError::InvalidConfig {
                field: "chunks.text".to_owned(),
                value: chunk.handle.to_string(),
                reason: err.to_string(),
            })?;
            builder = match &chunk.title {
                Some(title) => builder.add_document_with_title(
                    chunk.handle.as_str(),
                    chunk.text.as_str(),
                    title.as_str(),
                ),
                None => builder.add_document(chunk.handle.as_str(), chunk.text.as_str()),
            };
        }
        builder.build(cx).await
    }

    /// Open a hash + lexical searcher over a previously built index.
    pub fn open_hash_lexical_searcher(
        index_dir: impl AsRef<Path>,
    ) -> SearchResult<TwoTierSearcher> {
        let config = TwoTierConfig::default();
        let index = Arc::new(TwoTierIndex::open(index_dir.as_ref(), config.clone())?);
        let fast = Arc::new(HashEmbedder::default_256()) as Arc<dyn Embedder>;
        let lexical = Arc::new(TantivyIndex::open(&index_dir.as_ref().join("lexical"))?);
        Ok(TwoTierSearcher::new(index, fast, config).with_lexical(lexical))
    }

    /// Query a hash + lexical index.
    pub async fn query_hash_lexical_index(
        cx: &Cx,
        index_dir: impl AsRef<Path>,
        query: &str,
        top_k: usize,
    ) -> SearchResult<(Vec<ScoredResult>, TwoTierMetrics)> {
        open_hash_lexical_searcher(index_dir)?
            .search_collect(cx, query, top_k)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_source() -> TextSourceRef {
        TextSourceRef::QueryResult {
            receipt_hash: ReceiptHash::new("receiptabc"),
            statement_handle: Some(StatementHandle::new("stmt-123")),
            query_id: Some(QueryId::new("query-123")),
            dataset_id: Some(DatasetId::new("dataset-news")),
            object_ref_redacted: Some("DB.SCHEMA.NOTES".to_owned()),
        }
    }

    #[test]
    fn stable_handles_escape_components() {
        let handle =
            TextDocumentHandle::from_source(&query_source(), "body/text#0", 7).into_inner();
        assert_eq!(
            handle,
            "fsnow-text:v1:query:receipt%3areceiptabc:body%2ftext%230:7"
        );
        assert_eq!(handle.split(':').count(), 6);
    }

    #[test]
    fn stable_handles_percent_encode_control_and_utf8_bytes() {
        let source = TextSourceRef::StagedDocument {
            receipt_hash: None,
            dataset_id: Some(DatasetId::new("dataset-news")),
            stage_uri_redacted: "@stage/path".to_owned(),
            object_fingerprint: "sha256:\u{03b1}\nnext".to_owned(),
        };
        let handle =
            TextDocumentHandle::from_source(&source, "r\u{00e9}sum\u{00e9}\nbody", 3).into_inner();
        assert_eq!(
            handle,
            "fsnow-text:v1:stage:object%3asha256%3a%ce%b1%0anext:r%c3%a9sum%c3%a9%0abody:3"
        );
        assert!(!handle.contains('\n'));
        assert_eq!(handle.split(':').count(), 6);
    }

    #[test]
    fn noop_reranker_preserves_order() -> TextIndexResult<()> {
        let hits = vec![
            TextSearchHit::new(
                TextDocumentHandle::new("doc-a"),
                0,
                2.0,
                RightsClass::Internal,
            ),
            TextSearchHit::new(
                TextDocumentHandle::new("doc-b"),
                1,
                1.0,
                RightsClass::Internal,
            ),
        ];
        let request = RerankRequest::new("margin commentary", hits.len(), RerankPolicy::default())?;
        let reranked = NoopReranker.rerank(&request, hits.clone())?;
        assert_eq!(reranked, hits);
        Ok(())
    }

    #[test]
    fn rerank_policy_refuses_large_top_k() {
        let result = RerankRequest::new("long text", 51, RerankPolicy::default());
        assert!(matches!(
            result,
            Err(TextIndexError::TopKExceeded {
                requested: 51,
                max: DEFAULT_RERANK_MAX_TOP_K
            })
        ));
    }

    #[test]
    fn empty_chunks_are_refused_before_indexing() {
        let chunk = TextChunk::new(query_source(), "body", 0, "   ", RightsClass::Restricted);
        assert!(matches!(
            chunk.validate(),
            Err(TextIndexError::EmptyText { .. })
        ));
    }

    #[test]
    fn missing_source_and_path_fields_are_refused() {
        let empty_path = TextChunk::new(query_source(), " ", 0, "body", RightsClass::Restricted);
        assert!(matches!(
            empty_path.validate(),
            Err(TextIndexError::MissingField {
                field: "column_or_path"
            })
        ));

        let empty_receipt = TextChunk::new(
            TextSourceRef::QueryResult {
                receipt_hash: ReceiptHash::new(" "),
                statement_handle: None,
                query_id: None,
                dataset_id: None,
                object_ref_redacted: None,
            },
            "body",
            0,
            "body",
            RightsClass::Restricted,
        );
        assert!(matches!(
            empty_receipt.validate(),
            Err(TextIndexError::MissingField {
                field: "receipt_hash"
            })
        ));

        let empty_stage_uri = TextChunk::new(
            TextSourceRef::StagedDocument {
                receipt_hash: None,
                dataset_id: None,
                stage_uri_redacted: " ".to_owned(),
                object_fingerprint: "sha256:abc".to_owned(),
            },
            "body",
            0,
            "body",
            RightsClass::Restricted,
        );
        assert!(matches!(
            empty_stage_uri.validate(),
            Err(TextIndexError::MissingField {
                field: "stage_uri_redacted"
            })
        ));

        let empty_object = TextChunk::new(
            TextSourceRef::StagedDocument {
                receipt_hash: None,
                dataset_id: None,
                stage_uri_redacted: "@redacted/path".to_owned(),
                object_fingerprint: " ".to_owned(),
            },
            "body",
            0,
            "body",
            RightsClass::Restricted,
        );
        assert!(matches!(
            empty_object.validate(),
            Err(TextIndexError::MissingField {
                field: "object_fingerprint"
            })
        ));
    }

    #[test]
    fn structured_events_include_data_source() {
        let event = TextIndexEvent::new(TextIndexEventKind::IndexBuildStarted);
        assert_eq!(event.data_source, TextIndexDataSource::Offline);
    }

    #[cfg(feature = "frankensearch")]
    #[test]
    fn frankensearch_fixture_docs_build_and_query() {
        use crate::frankensearch_adapter::{build_hash_lexical_index, query_hash_lexical_index};

        let Ok(dir) = tempfile::tempdir() else {
            assert!(false, "temp dir should be available");
            return;
        };
        let index_path = dir.path().to_path_buf();
        let chunks = vec![
            TextChunk::new(
                query_source(),
                "notes",
                0,
                "snowflake transcript margin commentary and revenue call notes",
                RightsClass::Internal,
            ),
            TextChunk::new(
                query_source(),
                "notes",
                1,
                "warehouse billing floor and query timeout operational memo",
                RightsClass::Internal,
            ),
        ];

        asupersync::test_utils::run_test_with_cx(|cx| async move {
            let build = build_hash_lexical_index(&cx, &index_path, &chunks).await;
            assert!(build.as_ref().is_ok_and(|stats| stats.doc_count == 2));

            let search = query_hash_lexical_index(&cx, &index_path, "transcript margin", 3).await;
            assert!(
                search
                    .as_ref()
                    .is_ok_and(|(results, _)| !results.is_empty())
            );
        });
    }

    #[cfg(feature = "frankensearch")]
    #[test]
    fn frankensearch_builder_refuses_empty_chunks() {
        use crate::frankensearch_adapter::build_hash_lexical_index;

        let Ok(dir) = tempfile::tempdir() else {
            assert!(false, "temp dir should be available");
            return;
        };
        let index_path = dir.path().to_path_buf();
        let chunks = vec![TextChunk::new(
            query_source(),
            "notes",
            0,
            " ",
            RightsClass::Internal,
        )];

        asupersync::test_utils::run_test_with_cx(|cx| async move {
            let build = build_hash_lexical_index(&cx, &index_path, &chunks).await;
            assert!(matches!(
                build,
                Err(frankensearch::SearchError::InvalidConfig { .. })
            ));
        });
    }
}
