//! `text index` and `text search` (bead acl8): Frankensearch hash + lexical
//! indexes over the text columns of a query result, each document tied back
//! to the statement's receipt. Behind `--features frankensearch` (hash and
//! lexical tiers only: no model, no download); `text index` also needs `live`.
//!
//! Layout under `<data_dir>/text-indexes/<name>/`:
//! - `<version>/manifest.json`: provenance and counts;
//! - `<version>/documents.jsonl`: the indexed chunks (handle, row, column, id,
//!   text), which map a hit back to its cell;
//! - `<version>/index/`: the Frankensearch index;
//! - `current.json`: the version `text search` reads. A rebuild writes a new
//!   version and replaces the pointer by write-then-rename; older versions stay
//!   on disk and are never read again.

#[cfg(feature = "frankensearch")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "frankensearch")]
use std::collections::BTreeMap;
#[cfg(feature = "frankensearch")]
use std::path::{Path, PathBuf};

#[cfg(feature = "frankensearch")]
use franken_snowflake_core::error::SnowflakeErrorCode;
#[cfg(feature = "frankensearch")]
use franken_snowflake_text_indexing::TextChunk;

#[cfg(feature = "frankensearch")]
use crate::catalog_surface::{DATA_SOURCE_CACHE, typed_error};
#[cfg(feature = "frankensearch")]
use crate::{Body, Json, base_envelope, json_array, json_object, json_string, option_json};
use crate::{Outcome, OutputFormat};

/// `manifest.json` schema.
#[cfg(all(feature = "frankensearch", any(feature = "live", test)))]
pub const TEXT_INDEX_SCHEMA: &str = "fsnow.text_index.v1";
/// Hits `text search` returns by default.
#[cfg(feature = "frankensearch")]
pub const DEFAULT_TEXT_SEARCH_LIMIT: usize = 10;
/// Most hits one `text search` returns.
#[cfg(feature = "frankensearch")]
pub const MAX_TEXT_SEARCH_LIMIT: usize = 100;
/// The retrieval engine recorded in each manifest.
#[cfg(all(feature = "frankensearch", any(feature = "live", test)))]
pub const TEXT_INDEX_ENGINE: &str = "frankensearch 0.6 hash + lexical (Tantivy BM25)";
#[cfg(feature = "frankensearch")]
const SNIPPET_CHARS: usize = 240;

/// The parsed `text index` request.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TextIndexSpec {
    pub profile: Option<String>,
    pub sql: Option<String>,
    pub columns: Vec<String>,
    pub id_column: Option<String>,
    pub name: Option<String>,
    pub max_rows: Option<String>,
}

/// What one index version holds and where its text came from.
#[cfg(feature = "frankensearch")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TextIndexManifest {
    pub schema: String,
    pub name: String,
    pub version: String,
    pub profile_id: String,
    pub receipt_hash: String,
    pub statement_handle: String,
    pub sql_preview_redacted: String,
    pub columns: Vec<String>,
    pub id_column: Option<String>,
    pub rows: u64,
    pub documents: u64,
    pub created_at_ms: u64,
    pub engine: String,
}

#[cfg(feature = "frankensearch")]
#[derive(Serialize, Deserialize)]
struct CurrentVersion {
    schema: String,
    version: String,
}

/// Index names are one path component: letters, digits, `_` and `-`, at most
/// 64, not starting with `-`.
///
/// # Errors
/// The rule the name broke.
#[cfg(feature = "frankensearch")]
pub fn validate_index_name(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "index name `{name}` must be 1-64 letters, digits, `_` or `-` (not starting with `-`)"
        ))
    }
}

/// The directory of index `name`.
#[cfg(feature = "frankensearch")]
fn index_root(name: &str) -> Result<PathBuf, String> {
    validate_index_name(name)?;
    crate::local_store::data_dir()
        .map(|dir| dir.join("text-indexes").join(name))
        .ok_or_else(|| "no data directory; set FRANKEN_SNOWFLAKE_DATA_DIR".to_owned())
}

/// Run one Frankensearch future on a fresh current-thread runtime.
#[cfg(feature = "frankensearch")]
fn block_on<T, F: std::future::Future<Output = T>>(
    work: impl FnOnce(asupersync::Cx) -> F,
) -> Result<T, String> {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .map_err(|error| format!("could not start the runtime: {error}"))?;
    runtime.block_on(async move {
        let cx =
            asupersync::Cx::current().ok_or_else(|| "the runtime installed no Cx".to_owned())?;
        Ok(work(cx).await)
    })
}

/// A built index version.
#[cfg(all(feature = "frankensearch", any(feature = "live", test)))]
#[derive(Debug)]
pub struct BuiltIndex {
    pub version: String,
    pub replaced_version: Option<String>,
    pub directory: PathBuf,
}

/// Write `chunks` as a new version of index `manifest.name` and make it the
/// one `text search` reads. The manifest's `version` is assigned here.
///
/// # Errors
/// A message naming the step that failed; the current version is untouched.
#[cfg(all(feature = "frankensearch", any(feature = "live", test)))]
pub fn build_index(
    mut manifest: TextIndexManifest,
    chunks: &[TextChunk],
) -> Result<BuiltIndex, String> {
    let root = index_root(&manifest.name)?;
    let short_receipt: String = manifest.receipt_hash.chars().take(12).collect();
    let base = format!("v{}-{short_receipt}", manifest.created_at_ms);
    let mut version = base.clone();
    let mut attempt = 1_u32;
    while root.join(&version).exists() {
        attempt += 1;
        version = format!("{base}-{attempt}");
    }
    let directory = root.join(&version);
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("could not create {}: {error}", directory.display()))?;
    let mut documents = String::new();
    for chunk in chunks {
        let line = serde_json::to_string(chunk)
            .map_err(|error| format!("could not encode a document: {error}"))?;
        documents.push_str(&line);
        documents.push('\n');
    }
    write_file(&directory.join("documents.jsonl"), documents.as_bytes())?;
    if !chunks.is_empty() {
        let index_dir = directory.join("index");
        block_on(|cx| async move {
            franken_snowflake_text_indexing::frankensearch_adapter::build_hash_lexical_index(
                &cx, &index_dir, chunks,
            )
            .await
        })?
        .map_err(|error| format!("index build failed: {error}"))?;
    }
    manifest.version.clone_from(&version);
    manifest.documents = chunks.len() as u64;
    let bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("could not encode the manifest: {error}"))?;
    write_file(&directory.join("manifest.json"), &bytes)?;
    let replaced_version = read_current(&root).ok();
    let pointer = serde_json::to_vec(&CurrentVersion {
        schema: TEXT_INDEX_SCHEMA.to_owned(),
        version: version.clone(),
    })
    .map_err(|error| format!("could not encode current.json: {error}"))?;
    let staged = root.join(format!("current.json.{version}.tmp"));
    write_file(&staged, &pointer)?;
    std::fs::rename(&staged, root.join("current.json"))
        .map_err(|error| format!("could not publish the new version: {error}"))?;
    Ok(BuiltIndex {
        version,
        replaced_version,
        directory,
    })
}

#[cfg(all(feature = "frankensearch", any(feature = "live", test)))]
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes)
        .map_err(|error| format!("could not write {}: {error}", path.display()))
}

#[cfg(feature = "frankensearch")]
fn read_current(root: &Path) -> Result<String, String> {
    let raw = std::fs::read(root.join("current.json")).map_err(|error| error.to_string())?;
    let current: CurrentVersion =
        serde_json::from_slice(&raw).map_err(|error| format!("current.json: {error}"))?;
    validate_index_name(&current.version)?;
    Ok(current.version)
}

/// One ranked hit, mapped back to its cell.
#[cfg(feature = "frankensearch")]
#[derive(Clone, Debug, Serialize)]
pub struct TextHit {
    pub rank: usize,
    pub score: f32,
    pub lexical_score: Option<f32>,
    pub handle: String,
    pub row: u32,
    pub column: String,
    pub id: Option<String>,
    pub snippet: String,
    pub rights_class: franken_snowflake_core::guardrails::RightsClass,
}

/// Why a search found nothing to search.
#[cfg(feature = "frankensearch")]
#[derive(Debug)]
pub enum SearchFailure {
    /// No index by this name (or no current version).
    Missing(String),
    /// The index is on disk but unreadable.
    Broken(String),
}

/// Search the current version of index `name`.
///
/// # Errors
/// [`SearchFailure::Missing`] without an index; [`SearchFailure::Broken`] when
/// its files or the engine fail.
#[cfg(feature = "frankensearch")]
pub fn search_index(
    name: &str,
    query: &str,
    limit: usize,
) -> Result<(TextIndexManifest, Vec<TextHit>), SearchFailure> {
    let root = index_root(name).map_err(SearchFailure::Missing)?;
    let version = read_current(&root)
        .map_err(|error| SearchFailure::Missing(format!("no text index `{name}` ({error})")))?;
    let directory = root.join(&version);
    let manifest: TextIndexManifest = std::fs::read(directory.join("manifest.json"))
        .map_err(|error| error.to_string())
        .and_then(|raw| serde_json::from_slice(&raw).map_err(|error| error.to_string()))
        .map_err(|error| SearchFailure::Broken(format!("manifest of `{name}`: {error}")))?;
    if manifest.documents == 0 {
        return Ok((manifest, Vec::new()));
    }
    let documents: BTreeMap<String, TextChunk> =
        std::fs::read_to_string(directory.join("documents.jsonl"))
            .map_err(|error| SearchFailure::Broken(format!("documents of `{name}`: {error}")))?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str::<TextChunk>(line)
                    .map(|chunk| (chunk.handle.as_str().to_owned(), chunk))
                    .map_err(|error| {
                        SearchFailure::Broken(format!("documents of `{name}`: {error}"))
                    })
            })
            .collect::<Result<_, _>>()?;
    let index_dir = directory.join("index");
    let owned_query = query.to_owned();
    let (results, _metrics) = block_on(|cx| async move {
        franken_snowflake_text_indexing::frankensearch_adapter::query_hash_lexical_index(
            &cx,
            &index_dir,
            &owned_query,
            limit,
        )
        .await
    })
    .map_err(SearchFailure::Broken)?
    .map_err(|error| SearchFailure::Broken(format!("search of `{name}` failed: {error}")))?;
    let words = query_words(query);
    let hits = results
        .iter()
        .filter_map(|result| {
            documents
                .get(result.doc_id.as_str())
                .map(|chunk| (result, chunk))
        })
        .enumerate()
        .map(|(rank, (result, chunk))| TextHit {
            rank,
            score: result.score,
            lexical_score: result.lexical_score,
            handle: chunk.handle.as_str().to_owned(),
            row: chunk.chunk_ordinal,
            column: chunk.column_or_path.clone(),
            id: chunk.title.clone(),
            snippet: snippet(&chunk.text, &words),
            rights_class: chunk.rights_class,
        })
        .collect();
    Ok((manifest, hits))
}

/// The lower-case words of a query.
#[cfg(feature = "frankensearch")]
fn query_words(query: &str) -> Vec<String> {
    query
        .split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// At most [`SNIPPET_CHARS`] characters of `text`, starting a little before
/// the first query word it contains.
#[cfg(feature = "frankensearch")]
fn snippet(text: &str, words: &[String]) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= SNIPPET_CHARS {
        return text.to_owned();
    }
    let lower: Vec<char> = chars.iter().flat_map(|c| c.to_lowercase()).collect();
    // Lower-casing can change the length (a few scripts); then start at 0.
    let first = if lower.len() == chars.len() {
        words
            .iter()
            .filter_map(|word| {
                let needle: Vec<char> = word.chars().collect();
                lower
                    .windows(needle.len().max(1))
                    .position(|window| window == needle.as_slice())
            })
            .min()
    } else {
        None
    };
    let start = first.map_or(0, |at| at.saturating_sub(SNIPPET_CHARS / 4));
    let end = (start + SNIPPET_CHARS).min(chars.len());
    let mut out = String::new();
    if start > 0 {
        out.push('…');
    }
    out.extend(&chars[start..end]);
    if end < chars.len() {
        out.push('…');
    }
    out
}

/// `text search <name> <query> [--limit n]`: offline, over the current version.
#[cfg(feature = "frankensearch")]
pub fn text_search_outcome(
    format: OutputFormat,
    request_id: String,
    name: String,
    query: String,
    limit: Option<String>,
) -> Outcome {
    const COMMAND: &str = "text.search";
    const CONTRACT: &str = "fsnow.text.search.v1";
    let fail = |code: SnowflakeErrorCode, message: String, next: Vec<String>| {
        typed_error(
            format,
            COMMAND,
            CONTRACT,
            request_id.clone(),
            None,
            code,
            message,
            vec![json_string(format!("index={name}"))],
            next,
            vec![],
            vec![],
        )
    };
    let limit = match limit.as_deref().map(str::parse::<usize>) {
        None => DEFAULT_TEXT_SEARCH_LIMIT,
        Some(Ok(limit)) if (1..=MAX_TEXT_SEARCH_LIMIT).contains(&limit) => limit,
        Some(_) => {
            return fail(
                SnowflakeErrorCode::UsageError,
                format!("--limit must be 1..={MAX_TEXT_SEARCH_LIMIT}"),
                vec![],
            );
        }
    };
    if let Err(message) = validate_index_name(&name) {
        return fail(SnowflakeErrorCode::UsageError, message, vec![]);
    }
    if query_words(&query).is_empty() {
        return fail(
            SnowflakeErrorCode::UsageError,
            "the search query has no words (letters or digits)".to_owned(),
            vec![],
        );
    }
    let (manifest, hits) = match search_index(&name, &query, limit) {
        Ok(found) => found,
        Err(SearchFailure::Missing(message)) => {
            return fail(
                SnowflakeErrorCode::MetadataError,
                message,
                vec![format!(
                    "franken-snowflake text index --profile <profile> --sql <select> --column <COL> --name {name} --json"
                )],
            );
        }
        Err(SearchFailure::Broken(message)) => {
            return fail(
                SnowflakeErrorCode::CacheError,
                message,
                vec![format!(
                    "franken-snowflake text index --profile <profile> --sql <select> --column <COL> --name {name} --json"
                )],
            );
        }
    };
    let mut envelope = base_envelope(
        true,
        "success",
        COMMAND,
        CONTRACT,
        request_id,
        json_object(vec![
            ("index", json_string(name)),
            ("query", json_string(query)),
            ("count", Json::Number(hits.len() as i64)),
            (
                "hits",
                json_array(hits.iter().map(Json::from_value).collect()),
            ),
            ("source", manifest_json(&manifest)),
        ]),
    );
    envelope.data_source = DATA_SOURCE_CACHE;
    envelope.profile_id = Some(manifest.profile_id.clone());
    envelope.safe_next_commands = vec![format!(
        "franken-snowflake receipt show {} --json",
        manifest.receipt_hash
    )];
    Outcome {
        status: franken_snowflake_core::exit::ExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

/// The manifest fields an envelope carries (provenance and counts).
#[cfg(feature = "frankensearch")]
pub fn manifest_json(manifest: &TextIndexManifest) -> Json {
    json_object(vec![
        ("version", json_string(manifest.version.clone())),
        ("profile_id", json_string(manifest.profile_id.clone())),
        ("receipt_hash", json_string(manifest.receipt_hash.clone())),
        (
            "statement_handle",
            json_string(manifest.statement_handle.clone()),
        ),
        (
            "sql_preview_redacted",
            json_string(manifest.sql_preview_redacted.clone()),
        ),
        (
            "columns",
            json_array(manifest.columns.iter().cloned().map(json_string).collect()),
        ),
        ("id_column", option_json(manifest.id_column.clone())),
        (
            "rows",
            Json::Number(i64::try_from(manifest.rows).unwrap_or(i64::MAX)),
        ),
        (
            "documents",
            Json::Number(i64::try_from(manifest.documents).unwrap_or(i64::MAX)),
        ),
        (
            "created_at_ms",
            Json::Number(i64::try_from(manifest.created_at_ms).unwrap_or(i64::MAX)),
        ),
        ("engine", json_string(manifest.engine.clone())),
    ])
}

/// `text index` / `text search` in a build without `frankensearch`.
#[cfg(not(feature = "frankensearch"))]
pub fn feature_off_outcome(
    format: OutputFormat,
    request_id: String,
    command_id: &'static str,
    contract_id: &'static str,
    name: Option<String>,
) -> Outcome {
    crate::feature_disabled(
        format,
        command_id,
        contract_id,
        request_id,
        name,
        franken_snowflake_core::error::SnowflakeErrorCode::UsageError,
        "Text indexing is feature-gated and not linked in this build; rebuild with `--features frankensearch` (and `live` for `text index`).",
        vec!["franken-snowflake capabilities --json".to_string()],
    )
}

#[cfg(all(test, feature = "frankensearch"))]
mod tests {
    use super::*;
    use franken_snowflake_core::guardrails::RightsClass;
    use franken_snowflake_core::ids::ReceiptHash;
    use franken_snowflake_text_indexing::{TextSourceRef, chunks_from_rows};

    fn manifest(name: &str, receipt: &str) -> TextIndexManifest {
        TextIndexManifest {
            schema: TEXT_INDEX_SCHEMA.to_owned(),
            name: name.to_owned(),
            version: String::new(),
            profile_id: "p".to_owned(),
            receipt_hash: receipt.to_owned(),
            statement_handle: "h".to_owned(),
            sql_preview_redacted: "SELECT ...".to_owned(),
            columns: vec!["BODY".to_owned()],
            id_column: Some("ID".to_owned()),
            rows: 2,
            documents: 0,
            created_at_ms: 1_700_000_000_000,
            engine: TEXT_INDEX_ENGINE.to_owned(),
        }
    }

    fn chunks(receipt: &str, rows: &[(&str, &str)]) -> Vec<TextChunk> {
        let source = TextSourceRef::QueryResult {
            receipt_hash: ReceiptHash::new(receipt),
            statement_handle: None,
            query_id: None,
            dataset_id: None,
            object_ref_redacted: None,
        };
        let rows: Vec<Vec<Option<String>>> = rows
            .iter()
            .map(|(id, body)| vec![Some((*id).to_owned()), Some((*body).to_owned())])
            .collect();
        chunks_from_rows(
            &source,
            &[(1, "BODY".to_owned())],
            Some(0),
            &rows,
            RightsClass::Restricted,
        )
    }

    /// A name no earlier run left behind (unit tests share one per-process
    /// data directory, see `local_store::data_dir`).
    fn fresh(label: &str) -> String {
        format!("{label}-{}", crate::local_store::now_unix_ms())
    }

    /// A rebuild replaces what search reads: the old version's text no longer
    /// answers, the new one does, and the top hit maps back to its row and id.
    #[test]
    fn search_reads_only_the_current_version() {
        let name = fresh("rebuild");
        let first = chunks(
            "receipt-one",
            &[
                ("A1", "refund policy for annual plans"),
                ("A2", "warehouse sizing memo"),
            ],
        );
        let built = build_index(manifest(&name, "receipt-one"), &first).expect("build 1");
        assert_eq!(built.replaced_version, None);
        assert!(built.directory.ends_with(&built.version));
        assert!(built.directory.join("manifest.json").is_file());
        let (source, hits) = search_index(&name, "refund", 5).expect("search 1");
        assert_eq!(source.receipt_hash, "receipt-one");
        assert_eq!(hits[0].id.as_deref(), Some("A1"));
        assert_eq!((hits[0].row, hits[0].column.as_str()), (0, "BODY"));

        let second = chunks("receipt-two", &[("B7", "quarterly churn analysis")]);
        let rebuilt = build_index(manifest(&name, "receipt-two"), &second).expect("build 2");
        assert_eq!(
            rebuilt.replaced_version.as_deref(),
            Some(built.version.as_str())
        );
        let (source, stale) = search_index(&name, "refund", 5).expect("search 2");
        assert_eq!(source.receipt_hash, "receipt-two");
        assert!(stale.is_empty(), "a superseded version answered: {stale:?}");
        let (_, current) = search_index(&name, "churn", 5).expect("search 3");
        assert_eq!(current[0].id.as_deref(), Some("B7"));
    }

    /// No index is `Missing`; an index with no text is an empty success.
    #[test]
    fn missing_and_empty_indexes() {
        assert!(matches!(
            search_index(&fresh("absent"), "anything", 5),
            Err(SearchFailure::Missing(_))
        ));
        let blank = fresh("blank");
        build_index(manifest(&blank, "receipt-three"), &[]).expect("empty build");
        let (source, hits) = search_index(&blank, "anything", 5).expect("empty search");
        assert_eq!(source.documents, 0);
        assert!(hits.is_empty());
    }

    #[test]
    fn names_are_one_path_component() {
        for good in ["notes", "a-b_c", "X9"] {
            assert!(validate_index_name(good).is_ok(), "{good}");
        }
        for bad in ["", "../x", "a/b", "-x", "dot.name", &"n".repeat(65)] {
            assert!(validate_index_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn snippets_center_on_the_first_query_word() {
        let long = format!("{} needle {}", "hay ".repeat(100), "straw ".repeat(100));
        let cut = snippet(&long, &["needle".to_owned()]);
        assert!(cut.contains("needle"), "{cut}");
        assert!(cut.starts_with('…') && cut.ends_with('…'), "{cut}");
        assert!(cut.chars().count() <= SNIPPET_CHARS + 2);
        assert_eq!(snippet("short text", &["x".to_owned()]), "short text");
    }
}
