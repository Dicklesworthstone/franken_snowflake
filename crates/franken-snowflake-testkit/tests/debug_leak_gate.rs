//! Workspace credential `Debug`-leak gate (reality-check bead oj0.10).
//!
//! The auth crate's build script gates its own sources; this test scans every
//! crate's `src/` for structs and enums whose `Debug` would print a
//! credential: a derived `Debug` over a credential-shaped field (by name, by
//! credential type, or a tuple variant named for a credential), or a manual
//! `Debug` that prints such a field or never redacts. A field whose type has
//! its own redacting `Debug` (an impl in the workspace that references
//! `REDACTED`/`redact`) is safe inside a derived `Debug`. Planted controls
//! prove the scanner still catches every shape before the workspace verdict
//! counts.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Whole `snake_case` words that make a field name credential-shaped.
const SECRET_WORDS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "credential",
    "credentials",
    "authorization",
    "bearer",
    "assertion",
    "pat",
];

/// Multi-word names that are credential-shaped wherever they appear.
const SECRET_PHRASES: &[&str] = &["private_key", "api_key", "client_secret"];

/// Tuple-variant names (as `snake_case` words) that carry a credential
/// payload. `assertion` is left out: error enums name test assertions so.
const SECRET_VARIANT_WORDS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passphrase",
    "credential",
    "credentials",
    "bearer",
    "pat",
];

/// Types that hold credential material.
const SECRET_TYPES: &[&str] = &[
    "SecretValue",
    "SecretString",
    "EncodingKey",
    "AuthorizationDescriptor",
];

/// Credential-shaped names that are non-secret by design: descriptors,
/// references, lifetimes, and the write-confirmation token the user is shown
/// and must echo back.
const NON_SECRET_NAMES: &[&str] = &[
    "assertion_source",
    "confirmation_token",
    "credential_handle",
    "credential_ref",
    "expected_validity_seconds",
    "expires_at_unix_seconds",
    "issued_at_unix_seconds",
    "max_validity_seconds",
    "private_key_fingerprint",
    "private_key_passphrase_source",
    "private_key_source",
    "refresh_before_expiry_seconds",
    "requested_validity_seconds",
    "token_source",
    "token_type",
    "token_url",
];

#[derive(Debug)]
struct Field {
    name: String,
    ty: String,
}

#[derive(Debug)]
struct Item {
    kind: &'static str,
    name: String,
    derives_debug: bool,
    fields: Vec<Field>,
}

fn words(name: &str) -> Vec<String> {
    let mut snake = String::new();
    for (index, character) in name.chars().enumerate() {
        if character.is_ascii_uppercase() && index > 0 && !snake.ends_with('_') {
            snake.push('_');
        }
        snake.push(character.to_ascii_lowercase());
    }
    snake
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

fn type_words(ty: &str) -> BTreeSet<String> {
    ty.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Whether `field` holds credential material that `redacting` types do not
/// already hide.
fn is_secret(field: &Field, redacting: &BTreeSet<String>) -> bool {
    let name = field.name.to_ascii_lowercase();
    let types = type_words(&field.ty);
    // A redacting type hides its own material; a SecretSource names where a
    // secret comes from (an env var, a provider handle), never the secret.
    if types
        .iter()
        .any(|ty| redacting.contains(ty) || ty == "SecretSource")
    {
        return false;
    }
    if types.iter().any(|ty| SECRET_TYPES.contains(&ty.as_str())) {
        return true;
    }
    if NON_SECRET_NAMES
        .iter()
        .any(|allowed| name == *allowed || name.ends_with(&format!("_{allowed}")))
        || name.starts_with("redacted_")
    {
        return false;
    }
    let name_words = words(&name);
    name_words
        .iter()
        .any(|word| SECRET_WORDS.contains(&word.as_str()))
        || SECRET_PHRASES.iter().any(|phrase| name.contains(phrase))
}

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The next whole-word occurrence of `word` at or after `from`.
fn find_word(source: &str, word: &str, from: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut start = from;
    while let Some(offset) = source.get(start..)?.find(word) {
        let at = start + offset;
        let before = at.checked_sub(1).map(|index| bytes[index]);
        let after = bytes.get(at + word.len()).copied();
        if !before.is_some_and(is_ident) && !after.is_some_and(is_ident) {
            return Some(at);
        }
        start = at + word.len();
    }
    None
}

fn matching(source: &str, open: usize, open_byte: u8, close_byte: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(open) {
        if *byte == open_byte {
            depth += 1;
        } else if *byte == close_byte {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

/// The outer attributes directly above the item keyword at `at`, past a
/// visibility qualifier and interleaved line/doc comments.
fn preceding_attributes(source: &str, at: usize) -> String {
    let bytes = source.as_bytes();
    let mut end = source[..at].trim_end().len();
    for visibility in ["pub(crate)", "pub(super)", "pub(self)", "pub"] {
        if source[..end].ends_with(visibility) {
            end = source[..end - visibility.len()].trim_end().len();
            break;
        }
    }
    let mut attributes = Vec::new();
    loop {
        end = source[..end].trim_end().len();
        if end > 0 && bytes[end - 1] == b']' {
            let mut depth = 0usize;
            let mut open = None;
            for index in (0..end).rev() {
                match bytes[index] {
                    b']' => depth += 1,
                    b'[' => {
                        depth -= 1;
                        if depth == 0 {
                            open = Some(index);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            match open {
                Some(open) if open > 0 && bytes[open - 1] == b'#' => {
                    attributes.push(&source[open - 1..end]);
                    end = open - 1;
                    continue;
                }
                _ => break,
            }
        }
        let line_start = source[..end].rfind('\n').map_or(0, |index| index + 1);
        if source[line_start..end].trim_start().starts_with("//") {
            end = line_start;
            continue;
        }
        break;
    }
    attributes.join(" ")
}

fn derives_debug(attributes: &str) -> bool {
    attributes.contains("derive") && find_word(attributes, "Debug", 0).is_some()
}

fn split_top_level(body: &str) -> Vec<&str> {
    let bytes = body.as_bytes();
    let (mut angle, mut paren, mut bracket, mut brace) = (0usize, 0usize, 0usize, 0usize);
    let mut parts = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'<' => angle += 1,
            b'>' => angle = angle.saturating_sub(1),
            b'(' => paren += 1,
            b')' => paren = paren.saturating_sub(1),
            b'[' => bracket += 1,
            b']' => bracket = bracket.saturating_sub(1),
            b'{' => brace += 1,
            b'}' => brace = brace.saturating_sub(1),
            b',' if angle == 0 && paren == 0 && bracket == 0 && brace == 0 => {
                parts.push(&body[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&body[start..]);
    parts
}

/// A part without its attribute and doc-comment lines, one line.
fn clean(part: &str) -> String {
    part.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("#[") && !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .trim_start_matches("pub(crate) ")
        .trim_start_matches("pub(super) ")
        .trim_start_matches("pub ")
        .trim()
        .to_owned()
}

fn named_fields(body: &str) -> Vec<Field> {
    split_top_level(body)
        .into_iter()
        .filter_map(|part| {
            let part = clean(part);
            let colon = part.find(':')?;
            let name = part[..colon].trim();
            (!name.is_empty() && name.bytes().all(is_ident)).then(|| Field {
                name: name.to_owned(),
                ty: part[colon + 1..].trim().to_owned(),
            })
        })
        .collect()
}

fn tuple_fields(body: &str, label: &str) -> Vec<Field> {
    split_top_level(body)
        .into_iter()
        .map(clean)
        .filter(|ty| !ty.is_empty())
        .enumerate()
        .map(|(index, ty)| Field {
            name: format!("{label}{index}"),
            ty,
        })
        .collect()
}

/// Enum variants' fields: named fields as themselves, tuple payloads as
/// `<variant>.<n>`, and a tuple variant named for a credential as a field
/// named `token` so the name rule applies.
fn variant_fields(body: &str) -> Vec<Field> {
    let mut fields = Vec::new();
    for part in split_top_level(body) {
        let part = clean(part);
        let name_end = part
            .bytes()
            .position(|byte| !is_ident(byte))
            .unwrap_or(part.len());
        let variant = &part[..name_end];
        let rest = part[name_end..].trim_start();
        if let Some(open) = rest.find('{').filter(|_| rest.starts_with('{')) {
            if let Some(close) = matching(rest, open, b'{', b'}') {
                fields.extend(named_fields(&rest[open + 1..close]));
            }
        } else if rest.starts_with('(')
            && let Some(close) = matching(rest, 0, b'(', b')')
        {
            let mut payload = tuple_fields(&rest[1..close], "");
            if words(variant)
                .iter()
                .any(|word| SECRET_VARIANT_WORDS.contains(&word.as_str()))
            {
                for field in &mut payload {
                    field.name = "token".to_owned();
                }
            }
            fields.extend(payload);
        }
    }
    fields
}

fn items(source: &str) -> Vec<Item> {
    let mut found = Vec::new();
    for kind in ["struct", "enum"] {
        let mut from = 0;
        while let Some(at) = find_word(source, kind, from) {
            from = at + kind.len();
            let line_start = source[..at].rfind('\n').map_or(0, |index| index + 1);
            let prefix = &source[line_start..at];
            if prefix.contains("//") || prefix.contains('"') {
                continue;
            }
            let bytes = source.as_bytes();
            let mut cursor = from;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            let name_start = cursor;
            while cursor < bytes.len() && is_ident(bytes[cursor]) {
                cursor += 1;
            }
            if name_start == cursor {
                continue;
            }
            let name = source[name_start..cursor].to_owned();
            // Skip generics and where clauses up to the body.
            let mut angle = 0usize;
            let mut body = None;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'<' => angle += 1,
                    b'>' => angle = angle.saturating_sub(1),
                    b'{' if angle == 0 => {
                        body =
                            matching(source, cursor, b'{', b'}').map(|close| (b'{', cursor, close));
                        break;
                    }
                    b'(' if angle == 0 && kind == "struct" => {
                        body =
                            matching(source, cursor, b'(', b')').map(|close| (b'(', cursor, close));
                        break;
                    }
                    b';' if angle == 0 => break,
                    _ => {}
                }
                cursor += 1;
            }
            let Some((shape, open, close)) = body else {
                continue;
            };
            let inner = &source[open + 1..close];
            let fields = match (kind, shape) {
                ("enum", _) => variant_fields(inner),
                (_, b'(') => tuple_fields(inner, ""),
                _ => named_fields(inner),
            };
            found.push(Item {
                kind: if kind == "enum" { "enum" } else { "struct" },
                name,
                derives_debug: derives_debug(&preceding_attributes(source, at)),
                fields,
            });
            from = close;
        }
    }
    found
}

/// The body of `impl ... Debug for <name>` (or `Display`), if any.
fn impl_body<'a>(source: &'a str, trait_name: &str, name: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(at) = find_word(source, "impl", from) {
        from = at + 4;
        let header_end = source[at..].find('{').map(|offset| at + offset)?;
        let header = &source[at..header_end];
        let Some(for_at) = find_word(header, "for", 0) else {
            continue;
        };
        let target = header[for_at + 3..].trim();
        let target_name = target
            .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .next()
            .unwrap_or_default();
        if target_name == name && find_word(&header[..for_at], trait_name, 0).is_some() {
            let close = matching(source, header_end, b'{', b'}')?;
            return Some(&source[header_end..close]);
        }
    }
    None
}

/// Whether `body` reads `self.<field>` (the whole field, not a prefix of a
/// longer name such as `self.credential_handle`).
fn prints_field(body: &str, field: &str) -> bool {
    let needle = format!("self.{field}");
    let bytes = body.as_bytes();
    let mut from = 0;
    while let Some(offset) = body[from..].find(&needle) {
        let end = from + offset + needle.len();
        if !bytes.get(end).copied().is_some_and(is_ident) {
            return true;
        }
        from = end;
    }
    false
}

fn redacts(body: &str) -> bool {
    body.contains("REDACTED") || body.contains("redact")
}

/// Types whose manual `Debug` redacts and never prints a credential-named
/// field, across `sources`: holding one is safe under a derived `Debug`.
fn redacting_types(sources: &[String]) -> BTreeSet<String> {
    let none = BTreeSet::new();
    let mut types = BTreeSet::new();
    for source in sources {
        for item in items(source) {
            let Some(body) = impl_body(source, "Debug", &item.name) else {
                continue;
            };
            let prints_secret = item
                .fields
                .iter()
                .filter(|field| is_secret(field, &none))
                .any(|field| prints_field(body, &field.name));
            if (redacts(body) || body.contains("finish_non_exhaustive")) && !prints_secret {
                types.insert(item.name);
            }
        }
    }
    types
}

fn scan(source: &str, redacting: &BTreeSet<String>) -> Vec<String> {
    let mut errors = Vec::new();
    for item in items(source) {
        let secret: Vec<&Field> = item
            .fields
            .iter()
            .filter(|field| is_secret(field, redacting))
            .collect();
        if secret.is_empty() {
            continue;
        }
        let names = secret
            .iter()
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if item.derives_debug {
            errors.push(format!(
                "{} {} derives Debug over credential-shaped field(s): {names}",
                item.kind, item.name
            ));
        }
        for trait_name in ["Debug", "Display"] {
            if let Some(body) = impl_body(source, trait_name, &item.name) {
                if !redacts(body) {
                    errors.push(format!(
                        "{} {} has a {trait_name} impl that never redacts its credential-shaped field(s): {names}",
                        item.kind, item.name
                    ));
                }
                for field in &secret {
                    if prints_field(body, &field.name) {
                        errors.push(format!(
                            "{} {} {trait_name} impl prints self.{}",
                            item.kind, item.name, field.name
                        ));
                    }
                }
            }
        }
    }
    errors
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut paths = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(&path).into_iter().flatten().flatten() {
                pending.push(entry.path());
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.push(path);
        }
    }
    paths.sort();
    paths
}

#[test]
fn the_scanner_catches_every_leak_shape() {
    let redacting = BTreeSet::from(["RedactedHeader".to_owned()]);
    let leaks = [
        (
            "named field",
            "#[derive(Clone, Debug)]\npub struct Leak { api_token: String }",
        ),
        (
            "phrase in a longer name",
            "#[derive(Debug)]\nstruct Leak { db_private_key_pem: String }",
        ),
        (
            "credential type in a tuple struct",
            "#[derive(Debug)]\npub struct Leak(SecretString);",
        ),
        (
            "multi-line derive",
            "#[derive(\n    Clone,\n    Debug,\n)]\npub struct Leak { password: String }",
        ),
        (
            "cfg_attr derive",
            "#[cfg_attr(feature = \"x\", derive(Debug))]\npub struct Leak { bearer: String }",
        ),
        (
            "enum named-field variant",
            "#[derive(Debug)]\npub enum Leak { Basic { user: String, password: String }, None }",
        ),
        (
            "enum tuple variant named for a credential",
            "#[derive(Debug)]\npub enum Leak { Anonymous, Token(String) }",
        ),
        (
            "manual Debug printing the field",
            "pub struct Leak { session_token: String }\nimpl fmt::Debug for Leak { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, \"{} REDACTED\", self.session_token) } }",
        ),
        (
            "manual Debug that never redacts",
            "pub struct Leak { pat: String }\nimpl std::fmt::Debug for Leak { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(\"Leak\") } }",
        ),
    ];
    for (shape, source) in leaks {
        assert!(
            !scan(source, &redacting).is_empty(),
            "the scanner missed a leak: {shape}"
        );
    }
    let safe = [
        (
            "redacting manual Debug",
            "pub struct Ok { api_token: String }\nimpl fmt::Debug for Ok { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct(\"Ok\").field(\"api_token\", &REDACTED).finish() } }",
        ),
        (
            "field typed with a redacting type",
            "#[derive(Debug)]\npub struct Ok { authorization: Option<RedactedHeader> }",
        ),
        (
            "non-secret descriptors",
            "#[derive(Debug)]\npub struct Ok { token_type: String, credential_ref: String, confirmation_token: String, redacted_authorization: String, path: String, partition: u32 }",
        ),
        ("no Debug at all", "pub struct Ok { password: String }"),
        (
            "an assertion-message variant",
            "#[derive(Debug)]\npub enum Ok { Assertion(String) }",
        ),
    ];
    for (shape, source) in safe {
        assert_eq!(scan(source, &redacting), Vec::<String>::new(), "{shape}");
    }
}

#[test]
fn no_crate_derives_debug_over_a_credential() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .to_path_buf();
    let mut files = Vec::new();
    for entry in fs::read_dir(&crates).expect("read crates").flatten() {
        let src = entry.path().join("src");
        if src.is_dir() {
            files.extend(rust_sources(&src));
        }
    }
    assert!(
        files.len() > 50,
        "the gate must scan the workspace, found only {} files",
        files.len()
    );
    let sources: Vec<String> = files
        .iter()
        .map(|path| fs::read_to_string(path).expect("read source"))
        .collect();
    let redacting = redacting_types(&sources);
    assert!(
        redacting.contains("AuthorizationDescriptor"),
        "the bearer descriptor's redacting Debug must be found: {redacting:?}"
    );
    let mut errors = Vec::new();
    for (path, source) in files.iter().zip(&sources) {
        for error in scan(source, &redacting) {
            errors.push(format!("{}: {error}", path.display()));
        }
    }
    assert!(
        errors.is_empty(),
        "credential Debug leaks:\n{}",
        errors.join("\n")
    );
}
