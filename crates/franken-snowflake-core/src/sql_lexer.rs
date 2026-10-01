//! One Snowflake SQL lexer shared by every guard that has to reason about SQL
//! text: statement counting, read/write classification, and redaction.
//!
//! Before this module the connector carried four independent hand-rolled
//! scanners, none of which knew Snowflake's dollar-quoted string constants
//! (`$$ ... $$`). An apostrophe inside a dollar-quoted string therefore opened a
//! phantom single-quoted string that swallowed the real statement separator, so
//! `SELECT $$ it's $$; DROP TABLE t` classified as one read statement and
//! `INSERT ... ($$it's$$); DROP TABLE x` as one DML statement.
//!
//! Lexical rules implemented (Snowflake docs consulted 2026-09-24):
//! - Single-quoted string constants with `''` and backslash escapes, and
//!   dollar-quoted string constants `$$ ... $$`
//!   (<https://docs.snowflake.com/en/sql-reference/data-types-text#string-constants>).
//! - Double-quoted identifiers with `""` escapes
//!   (<https://docs.snowflake.com/en/sql-reference/identifiers-syntax>).
//! - Unquoted identifiers may contain `$` after the first character
//!   (`SYSTEM$TYPEOF`, `a$b`), so `$` only opens a dollar-quoted string when a
//!   `$$` pair appears in code context and is not part of an identifier.
//!   `$1` (positional column in stage queries) and `$name` (session variable)
//!   are single tokens, never strings.
//! - Comments: `--` and `//` to end of line, `/* ... */` blocks
//!   (<https://docs.snowflake.com/en/sql-reference/constructs/comments>).
//!
//! Fail-closed ambiguity: whether Snowflake nests block comments is not
//! documented. Under one reading `/* /* */ DELETE ... */` is all comment, under
//! the other it is a DELETE. The lexer ends a block comment at the first `*/`
//! (the documented, common behavior) and flags any `/*` seen inside a block
//! comment as [`SqlLex::ambiguous`], so guards refuse such input instead of
//! betting on one reading. Unterminated strings and comments are flagged too.

/// The kind of one lexed token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlTokenKind {
    /// Spaces, tabs, newlines.
    Whitespace,
    /// `-- ...`, `// ...` or `/* ... */`.
    Comment,
    /// An unquoted identifier or keyword (letters, digits, `_`, `$`).
    Word,
    /// A double-quoted identifier, quotes included.
    QuotedIdentifier,
    /// A single-quoted string constant, quotes included.
    StringLiteral,
    /// A `$$ ... $$` string constant, delimiters included.
    DollarString,
    /// `$1` / `$name`: a positional column reference or a session variable.
    Variable,
    /// A numeric literal.
    Number,
    /// A top-level statement separator.
    Semicolon,
    /// Any other character (operators, punctuation, non-ASCII symbols).
    Symbol,
}

/// One token: its kind and its exact source text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlToken<'a> {
    pub kind: SqlTokenKind,
    pub text: &'a str,
    pub start: usize,
}

impl SqlToken<'_> {
    /// True for tokens that do not affect meaning (whitespace and comments).
    #[must_use]
    pub const fn is_trivia(&self) -> bool {
        matches!(self.kind, SqlTokenKind::Whitespace | SqlTokenKind::Comment)
    }

    /// Lower-cased text of a [`SqlTokenKind::Word`] token, else `None`.
    #[must_use]
    pub fn word(&self) -> Option<String> {
        (self.kind == SqlTokenKind::Word).then(|| self.text.to_ascii_lowercase())
    }
}

/// The lexed form of one SQL text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlLex<'a> {
    pub tokens: Vec<SqlToken<'a>>,
    /// A string, quoted identifier, dollar string or block comment never closed.
    pub unterminated: bool,
    /// A `/*` appeared inside a block comment (nesting is undocumented).
    pub ambiguous: bool,
}

impl<'a> SqlLex<'a> {
    /// True when guards must refuse rather than trust the token stream.
    #[must_use]
    pub const fn is_unreliable(&self) -> bool {
        self.unterminated || self.ambiguous
    }

    /// Non-trivia tokens in order.
    pub fn significant(&self) -> impl Iterator<Item = &SqlToken<'a>> {
        self.tokens.iter().filter(|token| !token.is_trivia())
    }

    /// Number of statements: top-level `;`-separated segments that contain at
    /// least one significant token. `SELECT 1;` is one statement; `;` is zero.
    #[must_use]
    pub fn statement_count(&self) -> usize {
        let mut count = 0usize;
        let mut segment_has_content = false;
        for token in self.significant() {
            if token.kind == SqlTokenKind::Semicolon {
                if segment_has_content {
                    count += 1;
                }
                segment_has_content = false;
            } else {
                segment_has_content = true;
            }
        }
        if segment_has_content {
            count += 1;
        }
        count
    }

    /// True when a `;` closes a statement with nothing in it (`;;`, a leading
    /// `;`); one trailing `;` after the last statement is not an empty one.
    #[must_use]
    pub fn has_empty_statement(&self) -> bool {
        let mut segment_has_content = false;
        for token in self.significant() {
            if token.kind == SqlTokenKind::Semicolon {
                if !segment_has_content {
                    return true;
                }
                segment_has_content = false;
            } else {
                segment_has_content = true;
            }
        }
        false
    }

    /// Lower-cased executable words (keywords and unquoted identifiers) outside
    /// strings, quoted identifiers and comments, in order.
    #[must_use]
    pub fn words(&self) -> Vec<String> {
        self.tokens.iter().filter_map(SqlToken::word).collect()
    }

    /// The first executable word, lower-cased.
    #[must_use]
    pub fn first_word(&self) -> Option<String> {
        self.significant().find_map(SqlToken::word)
    }
}

/// The text of each statement in `sql`, in order: every top-level
/// `;`-separated segment with a significant token, from its first to its last
/// significant token (surrounding comments and whitespace left out). The
/// count is [`SqlLex::statement_count`].
#[must_use]
pub fn split_statements(sql: &str) -> Vec<&str> {
    let lexed = lex(sql);
    let mut statements = Vec::new();
    let mut span: Option<(usize, usize)> = None;
    for token in lexed.significant() {
        if token.kind == SqlTokenKind::Semicolon {
            if let Some((start, end)) = span.take()
                && let Some(text) = sql.get(start..end)
            {
                statements.push(text);
            }
        } else {
            let end = token.start + token.text.len();
            span = Some(span.map_or((token.start, end), |(start, _)| (start, end)));
        }
    }
    if let Some((start, end)) = span
        && let Some(text) = sql.get(start..end)
    {
        statements.push(text);
    }
    statements
}

/// Lex `sql` into tokens. Never panics; every byte belongs to exactly one token,
/// so concatenating the token texts reproduces the input.
#[must_use]
pub fn lex(sql: &str) -> SqlLex<'_> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut unterminated = false;
    let mut ambiguous = false;
    let mut index = 0usize;

    while index < bytes.len() {
        let start = index;
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        let kind = match byte {
            b if b.is_ascii_whitespace() => {
                while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                    index += 1;
                }
                SqlTokenKind::Whitespace
            }
            b'-' if next == Some(b'-') => {
                index = line_end(bytes, index);
                SqlTokenKind::Comment
            }
            b'/' if next == Some(b'/') => {
                index = line_end(bytes, index);
                SqlTokenKind::Comment
            }
            b'/' if next == Some(b'*') => {
                index += 2;
                let mut closed = false;
                while index < bytes.len() {
                    if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                        index += 2;
                        closed = true;
                        break;
                    }
                    if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
                        ambiguous = true;
                    }
                    index += 1;
                }
                unterminated |= !closed;
                SqlTokenKind::Comment
            }
            b'\'' => {
                index += 1;
                let mut closed = false;
                while index < bytes.len() {
                    match bytes[index] {
                        b'\\' => index += 2,
                        b'\'' if bytes.get(index + 1) == Some(&b'\'') => index += 2,
                        b'\'' => {
                            index += 1;
                            closed = true;
                            break;
                        }
                        _ => index += 1,
                    }
                }
                index = index.min(bytes.len());
                unterminated |= !closed;
                SqlTokenKind::StringLiteral
            }
            b'"' => {
                index += 1;
                let mut closed = false;
                while index < bytes.len() {
                    if bytes[index] == b'"' {
                        if bytes.get(index + 1) == Some(&b'"') {
                            index += 2;
                            continue;
                        }
                        index += 1;
                        closed = true;
                        break;
                    }
                    index += 1;
                }
                unterminated |= !closed;
                SqlTokenKind::QuotedIdentifier
            }
            b'$' if next == Some(b'$') => {
                // `$$` in code context (identifier-internal `$` is consumed by the
                // Word arm below, so reaching here means a string opener).
                index += 2;
                match find_subslice(&bytes[index..], b"$$") {
                    Some(offset) => index += offset + 2,
                    None => {
                        index = bytes.len();
                        unterminated = true;
                    }
                }
                SqlTokenKind::DollarString
            }
            b'$' if next.is_some_and(|n| n.is_ascii_alphanumeric() || n == b'_') => {
                index += 1;
                while index < bytes.len() && is_identifier_byte(bytes[index]) {
                    index += 1;
                }
                SqlTokenKind::Variable
            }
            b';' => {
                index += 1;
                SqlTokenKind::Semicolon
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                while index < bytes.len() && is_identifier_byte(bytes[index]) {
                    index += 1;
                }
                SqlTokenKind::Word
            }
            b if b.is_ascii_digit() => {
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'.')
                {
                    index += 1;
                }
                SqlTokenKind::Number
            }
            _ => {
                // One character, respecting UTF-8 boundaries.
                index += sql[index..].chars().next().map_or(1, char::len_utf8);
                SqlTokenKind::Symbol
            }
        };
        tokens.push(SqlToken {
            kind,
            text: &sql[start..index],
            start,
        });
    }

    SqlLex {
        tokens,
        unterminated,
        ambiguous,
    }
}

const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

fn line_end(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index] != b'\n' {
        index += 1;
    }
    index
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The statement verbs that make a single statement a read on the read path.
const READ_VERBS: &[&str] = &[
    "select", "show", "describe", "desc", "explain", "list", "ls",
];

/// Verbs that change data, schema, grants, session state or stages.
const MUTATING_VERBS: &[&str] = &[
    "alter", "begin", "call", "commit", "copy", "create", "delete", "drop", "execute", "get",
    "grant", "insert", "merge", "put", "remove", "revoke", "rm", "rollback", "set", "truncate",
    "undrop", "unset", "update", "use",
];

/// True when `word` is a mutating statement verb.
#[must_use]
pub fn is_mutating_verb(word: &str) -> bool {
    MUTATING_VERBS.contains(&word)
}

/// Classify one statement as a read.
///
/// Only opening parentheses may precede the statement verb (`(SELECT 1)` is a
/// read; `€€ select` or `*/ select` is not). `WITH` statements are reads only
/// when the main verb after the common table expressions — the first depth-0
/// statement verb — is `SELECT`; a depth-0 mutating verb (`WITH x AS (...)
/// DELETE ...`) makes it a mutation. Words inside CTE bodies (depth ≥ 1), such
/// as the `GET(v, 0)` function, do not taint the classification.
#[must_use]
pub fn is_read_statement(lexed: &SqlLex<'_>) -> bool {
    let mut significant = lexed.significant().skip_while(|token| token.text == "(");
    let Some(first) = significant.next().and_then(SqlToken::word) else {
        return false;
    };
    if READ_VERBS.contains(&first.as_str()) {
        // LIST/LS read stage listings; everything else is a plain read verb.
        return true;
    }
    if first != "with" {
        return false;
    }
    let mut depth = 0usize;
    for token in significant {
        match token.text {
            "(" => depth += 1,
            ")" => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth != 0 {
            continue;
        }
        if let Some(word) = token.word() {
            if word == "select" {
                return true;
            }
            if is_mutating_verb(&word) {
                return false;
            }
        }
    }
    false
}

/// Snowflake system functions that only read state and are therefore allowed on
/// the read path. Every other `SYSTEM$...` function is refused there, because
/// many of them act (cancel queries, abort sessions, resume tasks, refresh
/// pipes). Fail closed: a benign function missing from this list is a refusal,
/// not a silent mutation.
const READ_ONLY_SYSTEM_FUNCTIONS: &[&str] = &[
    "system$allowlist",
    "system$allowlist_privatelink",
    "system$behavior_change_bundle_status",
    "system$clustering_depth",
    "system$clustering_information",
    "system$clustering_ratio",
    "system$current_user_task_name",
    "system$explain_json_to_text",
    "system$explain_plan_json",
    "system$get_predecessor_return_value",
    "system$get_privatelink_config",
    "system$get_tag",
    "system$get_tag_allowed_values",
    "system$get_tag_on_current_column",
    "system$get_tag_on_current_table",
    "system$last_change_commit_time",
    "system$pipe_status",
    "system$stream_get_table_timestamp",
    "system$stream_has_data",
    "system$typeof",
    "system$wait",
    "system$whitelist",
    "system$whitelist_privatelink",
];

/// The first side-effecting construct in a read statement, if any: a
/// `SYSTEM$` function outside [`READ_ONLY_SYSTEM_FUNCTIONS`] or a sequence
/// `NEXTVAL` (which advances the sequence).
#[must_use]
pub fn read_side_effect(lexed: &SqlLex<'_>) -> Option<String> {
    lexed.words().into_iter().find(|word| {
        (word.starts_with("system$") && !READ_ONLY_SYSTEM_FUNCTIONS.contains(&word.as_str()))
            || word == "nextval"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reality-check bead L1: a batch splits at top-level `;` only, and empty
    /// statements are detectable.
    #[test]
    fn statements_split_at_top_level_separators_only() {
        let sql = "select 1; /* a;b */ select 'x;y' ; select $$c;d$$ as \"e;f\" -- g;h\n;";
        assert_eq!(
            split_statements(sql),
            ["select 1", "select 'x;y'", "select $$c;d$$ as \"e;f\""]
        );
        assert_eq!(split_statements(sql).len(), lex(sql).statement_count());
        assert!(split_statements("  -- only a comment\n").is_empty());
        assert!(!lex("select 1; select 2;").has_empty_statement());
        assert!(!lex("select 1").has_empty_statement());
        assert!(lex("select 1;; select 2").has_empty_statement());
        assert!(lex("; select 1").has_empty_statement());
        assert!(lex("select 1; ;").has_empty_statement());
    }

    fn count(sql: &str) -> usize {
        lex(sql).statement_count()
    }

    #[test]
    fn tokens_reproduce_the_input_exactly() {
        let inputs = [
            "SELECT $$ it's $$; DROP TABLE t",
            "select 'a''b\\'c', \"x\"\"y\", $1, $var, a$b -- c\n/* d */ 1.5e3; ",
            "SELECT '日本語；' AS x",
            "select 1 /* unterminated",
        ];
        for sql in inputs {
            let joined: String = lex(sql).tokens.iter().map(|token| token.text).collect();
            assert_eq!(joined, sql);
        }
    }

    #[test]
    fn dollar_quoted_strings_hide_their_contents() {
        assert_eq!(count("SELECT $$ it's $$; DROP TABLE t"), 2);
        assert_eq!(count("INSERT INTO t VALUES ($$it's$$); DROP TABLE x"), 2);
        assert_eq!(count("SELECT $$ ; DROP TABLE t $$"), 1);
        assert_eq!(count("select $$a$$, $$b$$"), 1);
    }

    #[test]
    fn dollar_signs_inside_identifiers_and_variables_are_not_strings() {
        let lexed = lex("SELECT SYSTEM$TYPEOF(1), a$b, $1, $var FROM @stage; SELECT 2");
        assert!(!lexed.is_unreliable());
        assert_eq!(lexed.statement_count(), 2);
        let words = lexed.words();
        assert!(words.contains(&"system$typeof".to_owned()), "{words:?}");
        assert!(words.contains(&"a$b".to_owned()), "{words:?}");
        let variables: Vec<_> = lexed
            .tokens
            .iter()
            .filter(|token| token.kind == SqlTokenKind::Variable)
            .map(|token| token.text)
            .collect();
        assert_eq!(variables, vec!["$1", "$var"]);
    }

    #[test]
    fn quotes_comments_and_escapes_hide_separators() {
        assert_eq!(count("select ';'"), 1);
        assert_eq!(count("select 1 -- a; b"), 1);
        assert_eq!(count("select 1 // a; b"), 1);
        assert_eq!(count("/* a; b */ select 1"), 1);
        assert_eq!(count("select \"a;b\" from t"), 1);
        assert_eq!(count("SELECT 'a\\'; DROP TABLE t; --'"), 1);
        assert_eq!(count("select 1;"), 1);
        assert_eq!(count("select 1 ; -- trailing\n"), 1);
        assert_eq!(count("select 1; select 2"), 2);
        assert_eq!(count(";"), 0);
        // A line comment ends at the newline; the next line is live SQL.
        assert_eq!(count("select 1 -- ;\n; drop table t"), 2);
    }

    #[test]
    fn nested_or_unterminated_constructs_are_flagged_unreliable() {
        assert!(lex("/* /* */ DELETE FROM t WHERE a <> '*/ SELECT 1 --'").ambiguous);
        assert!(lex("select 1 /* unterminated").unterminated);
        assert!(lex("select 'open").unterminated);
        assert!(lex("select $$ open").unterminated);
        assert!(lex("select \"open").unterminated);
        assert!(!lex("select /* one */ 1").is_unreliable());
    }

    #[test]
    fn read_classification_uses_the_statement_verb() {
        let read = |sql: &str| is_read_statement(&lex(sql));
        assert!(read("SELECT 1"));
        assert!(read("  /* c */ show tables"));
        assert!(read("EXPLAIN DELETE FROM t"));
        assert!(read("with x as (select 1) select * from x"));
        assert!(read("WITH RECURSIVE r (n) AS (SELECT 1) SELECT n FROM r"));
        assert!(read("list @stage"));
        assert!(!read("WITH x AS (SELECT 1) DELETE FROM t"));
        assert!(!read("with x as (select 1) insert into t select * from x"));
        assert!(!read("with x as (select 'delete' as w) update t set a = 1"));
        assert!(!read("CALL my_proc()"));
        assert!(!read("EXECUTE IMMEDIATE 'drop table t'"));
        assert!(read("(SELECT 1)"));
        assert!(read("((select 1) union (select 2))"));
        assert!(!read("(delete from t)"));
        assert!(!read(""));
        assert!(!read("€€ select"));
        assert!(!read("*/ select 1"));
        // Mutating words inside strings, comments or CTE bodies do not taint a read.
        assert!(read("with x as (select 'delete' as w) select * from x"));
        assert!(read(
            "with x as (select get(v, 0) as g from t) select * from x"
        ));
        assert!(read("select 1 -- delete from t"));
    }

    #[test]
    fn side_effecting_system_functions_and_nextval_are_detected() {
        let effect = |sql: &str| read_side_effect(&lex(sql));
        assert_eq!(
            effect("SELECT SYSTEM$CANCEL_ALL_QUERIES(1)").as_deref(),
            Some("system$cancel_all_queries")
        );
        assert!(effect("select system$abort_session(1)").is_some());
        assert!(effect("select seq1.nextval").is_some());
        assert!(effect("select system$typeof(1), system$wait(1)").is_none());
        assert!(effect("select 'SYSTEM$CANCEL_ALL_QUERIES(1)'").is_none());
    }

    /// Metamorphic properties over a deterministic corpus: adding comments or
    /// whitespace between tokens, or changing keyword case, never changes the
    /// statement count or the read classification.
    #[test]
    fn metamorphic_transforms_preserve_count_and_class() {
        let corpus = [
            "select 1",
            "select 'a;b', $$c;'d$$ from t",
            "insert into t values ($$it's$$); drop table x",
            "with x as (select 1) select * from x",
            "with x as (select 1) delete from t",
            "select $1, a$b from @s; show tables",
            "call p()",
        ];
        for sql in corpus {
            let base = lex(sql);
            let spaced: String = base
                .tokens
                .iter()
                .map(|token| {
                    if token.is_trivia() {
                        token.text.to_owned()
                    } else {
                        format!("{} /* x */ ", token.text)
                    }
                })
                .collect();
            let upper: String = base
                .tokens
                .iter()
                .map(|token| {
                    if token.kind == SqlTokenKind::Word {
                        token.text.to_ascii_uppercase()
                    } else {
                        token.text.to_owned()
                    }
                })
                .collect();
            for variant in [spaced, upper] {
                let lexed = lex(&variant);
                assert_eq!(lexed.statement_count(), base.statement_count(), "{variant}");
                assert_eq!(
                    is_read_statement(&lexed),
                    is_read_statement(&base),
                    "{variant}"
                );
            }
        }
    }
}
