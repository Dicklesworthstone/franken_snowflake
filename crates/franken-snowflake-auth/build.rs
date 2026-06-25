// The credential `Debug`-leak gate (bead fsnow-native-snowflake-connector-w0i.5)
// runs as a build script. Failing the build by panicking is the idiomatic
// build-script mechanism, so the workspace `clippy::panic` / `clippy::expect_used`
// denials — which target library/CLI runtime code — are allowed here. (The
// `allow-*-in-tests` clippy.toml switches do not cover build scripts.)
#![allow(clippy::expect_used, clippy::panic)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

mod redaction_policy {
    include!("src/redaction_policy.rs");
}

use redaction_policy::{
    CREDENTIAL_FIELD_MARKERS, NON_SECRET_CREDENTIAL_FIELD_MARKERS, REDACTED,
    SECRET_VALUE_NEEDLE_PREFIXES,
};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");
    println!("cargo:rerun-if-changed={}", src_dir.display());
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("build.rs").display()
    );

    let mut sources = String::new();
    let mut scanned_files = 0usize;
    for path in rust_sources(&src_dir) {
        println!("cargo:rerun-if-changed={}", path.display());
        let source = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "credential Debug gate could not read {}: {error}",
                path.display()
            )
        });
        sources.push_str(&format!("\n// file: {}\n", path.display()));
        sources.push_str(&source);
        scanned_files = scanned_files.saturating_add(1);
    }

    if let Err(errors) = run_controls() {
        emit_log("failed", scanned_files, &errors);
        panic!(
            "credential Debug gate controls failed:\n{}",
            errors.join("\n")
        );
    }

    if let Err(errors) = scan_source(&sources) {
        emit_log("failed", scanned_files, &errors);
        panic!("credential Debug gate failed:\n{}", errors.join("\n"));
    }

    emit_log("ok", scanned_files, &[]);
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut paths = Vec::new();
    while let Some(path) = pending.pop() {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            let Ok(entries) = fs::read_dir(path) else {
                continue;
            };
            for entry in entries.flatten() {
                pending.push(entry.path());
            }
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            paths.push(path);
        }
    }
    paths.sort();
    paths
}

fn run_controls() -> Result<(), Vec<String>> {
    let positive = r#"
        pub struct ProperlyRedacted {
            api_token: String,
        }

        impl fmt::Debug for ProperlyRedacted {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("ProperlyRedacted")
                    .field("api_token", &REDACTED)
                    .finish()
            }
        }
    "#;
    scan_source(positive)?;

    let negative = r#"
        #[derive(Debug)]
        pub struct LeakyControl {
            api_token: String,
        }
    "#;
    if scan_source(negative).is_ok() {
        return Err(vec![
            "negative control unexpectedly passed: derived Debug leaked api_token".to_string(),
        ]);
    }

    let fail_open_controls = [
        (
            "tuple struct derived Debug leaked SecretValue",
            r#"
                #[derive(Debug)]
                pub struct TupleLeakyControl(SecretValue);
            "#,
        ),
        (
            "prefix impl match leaked missing Debug impl",
            r#"
                pub struct PrefixLeakyControl {
                    api_token: String,
                }

                pub struct PrefixLeakyControlExtra;

                impl fmt::Debug for PrefixLeakyControlExtra {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str(REDACTED)
                    }
                }
            "#,
        ),
        (
            "generic comma field split hid SecretValue type",
            r#"
                #[derive(Debug)]
                pub struct GenericCommaLeakyControl {
                    creds: HashMap<UserId, SecretValue>,
                }
            "#,
        ),
        (
            "destructure Debug impl leaked secret binding",
            r#"
                pub struct DestructureLeakyControl {
                    api_token: String,
                    display_name: String,
                }

                impl fmt::Debug for DestructureLeakyControl {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        let Self { api_token, .. } = self;
                        f.debug_struct("DestructureLeakyControl")
                            .field("display_name", &REDACTED)
                            .field("api_token", &format_args!("{api_token}"))
                            .finish()
                    }
                }
            "#,
        ),
        (
            "multi-line derive Debug leaked token field",
            r#"
                #[derive(
                    Clone,
                    Debug,
                )]
                pub struct MultilineDeriveLeakyControl {
                    api_token: String,
                }
            "#,
        ),
        (
            "cfg_attr derive Debug leaked token field",
            r#"
                #[cfg_attr(feature = "leak", derive(Debug))]
                pub struct CfgAttrDeriveLeakyControl {
                    api_token: String,
                }
            "#,
        ),
    ];
    for (name, source) in fail_open_controls {
        if scan_source(source).is_ok() {
            return Err(vec![format!(
                "negative control unexpectedly passed: {name}"
            )]);
        }
    }

    Ok(())
}

fn scan_source(source: &str) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    for item in structs(source) {
        let secret_fields = item.secret_fields();
        if secret_fields.is_empty() {
            continue;
        }

        if item.derives_debug {
            errors.push(format!(
                "{} derives Debug while carrying credential-shaped field(s): {}",
                item.name,
                secret_fields.join(", ")
            ));
        }

        let debug_impl = impl_body(source, "Debug", &item.name);
        match debug_impl {
            Some(body) => {
                if !body_references_redaction(body) {
                    errors.push(format!(
                        "{} has a manual Debug impl for credential-shaped field(s) but does not reference {REDACTED}",
                        item.name
                    ));
                }
                for field in &secret_fields {
                    if debug_impl_references_field(body, field) {
                        errors.push(format!(
                            "{} Debug impl references credential-shaped field self.{field}",
                            item.name
                        ));
                    }
                }
            }
            None => errors.push(format!(
                "{} carries credential-shaped field(s) but has no hand-written redacting Debug impl",
                item.name
            )),
        }

        if let Some(body) = impl_body(source, "Display", &item.name) {
            if !body_references_redaction(body) {
                errors.push(format!(
                    "{} has a Display impl for credential-shaped field(s) but does not reference {REDACTED}",
                    item.name
                ));
            }
            for field in &secret_fields {
                if debug_impl_references_field(body, field) {
                    errors.push(format!(
                        "{} Display impl references credential-shaped field self.{field}",
                        item.name
                    ));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[derive(Debug)]
struct StructItem {
    name: String,
    derives_debug: bool,
    fields: Vec<FieldItem>,
}

impl StructItem {
    fn secret_fields(&self) -> Vec<String> {
        self.fields
            .iter()
            .filter(|field| is_secret_field(&self.name, field))
            .map(|field| field.name.clone())
            .collect()
    }
}

#[derive(Debug)]
struct FieldItem {
    name: String,
    ty: String,
}

fn structs(source: &str) -> Vec<StructItem> {
    let bytes = source.as_bytes();
    let mut index = 0usize;
    let mut items = Vec::new();
    while let Some(found) = find_word(source, "struct", index) {
        let derives_debug = preceding_attrs_derive_debug(source, found);
        let mut cursor = found + "struct".len();
        skip_ws(bytes, &mut cursor);
        let name_start = cursor;
        while cursor < bytes.len() && is_ident_byte(bytes[cursor]) {
            cursor += 1;
        }
        if name_start == cursor {
            index = cursor.saturating_add(1);
            continue;
        }
        let name = source[name_start..cursor].to_string();
        match next_struct_body(source, cursor) {
            Some(StructBody::Named { open, close }) => {
                let body = &source[open + 1..close];
                items.push(StructItem {
                    name,
                    derives_debug,
                    fields: parse_named_fields(body),
                });
                index = close.saturating_add(1);
            }
            Some(StructBody::Tuple { open, close }) => {
                let body = &source[open + 1..close];
                items.push(StructItem {
                    name,
                    derives_debug,
                    fields: parse_tuple_fields(body),
                });
                index = close.saturating_add(1);
            }
            Some(StructBody::Unit { semicolon }) => {
                index = semicolon.saturating_add(1);
            }
            None => {
                index = cursor.saturating_add(1);
            }
        }
    }
    items
}

enum StructBody {
    Named { open: usize, close: usize },
    Tuple { open: usize, close: usize },
    Unit { semicolon: usize },
}

fn next_struct_body(source: &str, from: usize) -> Option<StructBody> {
    let bytes = source.as_bytes();
    let mut cursor = from;
    let mut angle_depth = 0usize;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'<' => {
                angle_depth = angle_depth.saturating_add(1);
                cursor = cursor.saturating_add(1);
            }
            b'>' => {
                angle_depth = angle_depth.saturating_sub(1);
                cursor = cursor.saturating_add(1);
            }
            b'{' if angle_depth == 0 => {
                let close = matching_delimiter(source, cursor, b'{', b'}')?;
                return Some(StructBody::Named {
                    open: cursor,
                    close,
                });
            }
            b'(' if angle_depth == 0 => {
                let close = matching_delimiter(source, cursor, b'(', b')')?;
                return Some(StructBody::Tuple {
                    open: cursor,
                    close,
                });
            }
            b';' if angle_depth == 0 => {
                return Some(StructBody::Unit { semicolon: cursor });
            }
            _ => cursor = cursor.saturating_add(1),
        }
    }
    None
}

fn parse_named_fields(body: &str) -> Vec<FieldItem> {
    split_top_level_commas(body)
        .filter_map(|raw| {
            let line = raw
                .lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    !trimmed.starts_with("#[") && !trimmed.starts_with("///")
                })
                .collect::<Vec<_>>()
                .join(" ");
            let normalized = line
                .trim()
                .trim_start_matches("pub ")
                .trim_start_matches("pub(crate) ")
                .trim();
            let colon = normalized.find(':')?;
            let name = normalized[..colon].trim();
            if name.is_empty() || !name.bytes().all(is_ident_byte) {
                return None;
            }
            Some(FieldItem {
                name: name.to_string(),
                ty: normalized[colon + 1..].trim().to_string(),
            })
        })
        .collect()
}

fn parse_tuple_fields(body: &str) -> Vec<FieldItem> {
    split_top_level_commas(body)
        .enumerate()
        .filter_map(|(index, raw)| {
            let ty = raw
                .lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    !trimmed.starts_with("#[") && !trimmed.starts_with("///")
                })
                .collect::<Vec<_>>()
                .join(" ");
            let normalized = ty
                .trim()
                .trim_start_matches("pub ")
                .trim_start_matches("pub(crate) ")
                .trim();
            if normalized.is_empty() {
                return None;
            }
            Some(FieldItem {
                name: index.to_string(),
                ty: normalized.to_string(),
            })
        })
        .collect()
}

fn split_top_level_commas(input: &str) -> impl Iterator<Item = &str> {
    let mut spans = Vec::new();
    let bytes = input.as_bytes();
    let mut start = 0usize;
    let mut cursor = 0usize;
    let mut angle = 0usize;
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'<' => angle = angle.saturating_add(1),
            b'>' => angle = angle.saturating_sub(1),
            b'(' => paren = paren.saturating_add(1),
            b')' => paren = paren.saturating_sub(1),
            b'[' => bracket = bracket.saturating_add(1),
            b']' => bracket = bracket.saturating_sub(1),
            b'{' => brace = brace.saturating_add(1),
            b'}' => brace = brace.saturating_sub(1),
            b',' if angle == 0 && paren == 0 && bracket == 0 && brace == 0 => {
                spans.push((start, cursor));
                start = cursor.saturating_add(1);
            }
            _ => {}
        }
        cursor = cursor.saturating_add(1);
    }
    spans.push((start, input.len()));
    spans
        .into_iter()
        .map(move |(start, end)| &input[start..end])
}

fn is_secret_field(struct_name: &str, field: &FieldItem) -> bool {
    let field_name = field.name.to_ascii_lowercase();
    let ty = field.ty.to_ascii_lowercase();
    if NON_SECRET_CREDENTIAL_FIELD_MARKERS
        .iter()
        .any(|marker| field_name == *marker || field_name.ends_with(marker))
    {
        return false;
    }
    if ty.contains("secretsource") {
        return false;
    }
    if struct_name == "SecretValue" {
        return true;
    }
    if ty.contains("secretvalue") || ty.contains("encodingkey") {
        return true;
    }
    CREDENTIAL_FIELD_MARKERS
        .iter()
        .any(|marker| field_name == *marker || field_name.contains(marker))
}

fn preceding_attrs_derive_debug(source: &str, struct_index: usize) -> bool {
    let mut cursor = source[..struct_index].trim_end().len();
    let mut attrs = Vec::new();

    while cursor > 0 && source.as_bytes().get(cursor.saturating_sub(1)) == Some(&b']') {
        let Some(start) = matching_attr_start(source, cursor - 1) else {
            break;
        };
        attrs.push(&source[start..cursor]);
        cursor = source[..start].trim_end().len();
    }

    if attrs.is_empty() {
        for line in source[..struct_index].lines().rev() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("///") || trimmed.starts_with("//") {
                continue;
            }
            if trimmed.starts_with("#[") {
                attrs.push(trimmed);
                continue;
            }
            break;
        }
    }

    attrs.iter().any(|attr| attr_derives_debug(attr))
}

fn attr_derives_debug(attr: &str) -> bool {
    attr.contains("derive") && attr.contains("Debug")
}

fn matching_attr_start(source: &str, close: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut cursor = close;
    loop {
        match bytes[cursor] {
            b']' => depth = depth.saturating_add(1),
            b'[' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    let hash = cursor.checked_sub(1)?;
                    if bytes.get(hash) == Some(&b'#') {
                        return Some(hash);
                    }
                }
            }
            _ => {}
        }
        if cursor == 0 {
            break;
        }
        cursor = cursor.saturating_sub(1);
    }
    None
}

fn impl_body<'a>(source: &'a str, trait_name: &str, type_name: &str) -> Option<&'a str> {
    let candidates = [
        format!("impl fmt::{trait_name} for {type_name}"),
        format!("impl std::fmt::{trait_name} for {type_name}"),
        format!("impl core::fmt::{trait_name} for {type_name}"),
    ];
    let (start, pattern_len) = candidates
        .iter()
        .filter_map(|pattern| {
            let mut search_from = 0usize;
            while let Some(offset) = source[search_from..].find(pattern) {
                let start = search_from + offset;
                let after = start + pattern.len();
                let boundary_ok = source
                    .as_bytes()
                    .get(after)
                    .map_or(true, |byte| !is_ident_byte(*byte));
                if boundary_ok {
                    return Some((start, pattern.len()));
                }
                search_from = after;
            }
            None
        })
        .min_by_key(|(start, _)| *start)?;
    let after_pattern = start + pattern_len;
    let open = source[after_pattern..].find('{')? + after_pattern;
    let close = matching_brace(source, open)?;
    Some(&source[open + 1..close])
}

fn debug_impl_references_field(body: &str, field: &str) -> bool {
    if debug_impl_references_self_field(body, field) {
        return true;
    }
    destructured_bindings(body, field)
        .into_iter()
        .any(|(binding, from)| binding_referenced_after(body, &binding, from))
}

fn debug_impl_references_self_field(body: &str, field: &str) -> bool {
    let direct = format!("self.{field}");
    let mut search_from = 0usize;
    while let Some(offset) = body[search_from..].find(&direct) {
        let index = search_from + offset;
        let after = body.as_bytes().get(index + direct.len()).copied();
        if after.map_or(true, |byte| !is_ident_byte(byte)) {
            return true;
        }
        search_from = index + direct.len();
    }
    false
}

fn destructured_bindings(body: &str, field: &str) -> Vec<(String, usize)> {
    let mut bindings = Vec::new();
    let mut search_from = 0usize;
    while let Some(offset) = body[search_from..].find("let Self") {
        let start = search_from + offset;
        let mut cursor = start + "let Self".len();
        skip_ws(body.as_bytes(), &mut cursor);
        match body.as_bytes().get(cursor) {
            Some(b'{') => {
                let Some(close) = matching_delimiter(body, cursor, b'{', b'}') else {
                    search_from = cursor.saturating_add(1);
                    continue;
                };
                let Some(statement_end) = body[close..].find(';').map(|end| close + end + 1) else {
                    search_from = close.saturating_add(1);
                    continue;
                };
                if !body[close..statement_end].contains("= self") {
                    search_from = statement_end;
                    continue;
                }
                let pattern = &body[cursor + 1..close];
                for part in split_top_level_commas(pattern) {
                    if let Some(binding) = named_destructure_binding(part, field) {
                        bindings.push((binding, statement_end));
                    }
                }
                search_from = statement_end;
            }
            Some(b'(') => {
                let Some(close) = matching_delimiter(body, cursor, b'(', b')') else {
                    search_from = cursor.saturating_add(1);
                    continue;
                };
                let Some(statement_end) = body[close..].find(';').map(|end| close + end + 1) else {
                    search_from = close.saturating_add(1);
                    continue;
                };
                if !body[close..statement_end].contains("= self") {
                    search_from = statement_end;
                    continue;
                }
                if let Ok(position) = field.parse::<usize>() {
                    if let Some(raw) =
                        split_top_level_commas(&body[cursor + 1..close]).nth(position)
                    {
                        if let Some(binding) = normalize_binding(raw) {
                            bindings.push((binding, statement_end));
                        }
                    }
                }
                search_from = statement_end;
            }
            _ => {
                search_from = cursor.saturating_add(1);
            }
        }
    }
    bindings
}

fn named_destructure_binding(part: &str, field: &str) -> Option<String> {
    let normalized = part.trim();
    if normalized == ".." {
        return None;
    }
    if normalized == field {
        return Some(field.to_string());
    }
    let (name, binding) = normalized.split_once(':')?;
    if name.trim() != field {
        return None;
    }
    normalize_binding(binding)
}

fn normalize_binding(raw: &str) -> Option<String> {
    let mut value = raw
        .trim()
        .trim_start_matches("ref ")
        .trim_start_matches("mut ")
        .trim();
    if value.starts_with('&') {
        value = value
            .trim_start_matches('&')
            .trim_start_matches("mut ")
            .trim();
    }
    if value.is_empty()
        || value == "_"
        || value.starts_with('_')
        || !value.bytes().all(is_ident_byte)
    {
        return None;
    }
    Some(value.to_string())
}

fn binding_referenced_after(body: &str, binding: &str, from: usize) -> bool {
    let suffix = &body[from..];
    if suffix.contains(&format!("{{{binding}}}")) {
        return true;
    }
    let mut search_from = 0usize;
    while let Some(offset) = suffix[search_from..].find(binding) {
        let index = search_from + offset;
        let before = index
            .checked_sub(1)
            .and_then(|idx| suffix.as_bytes().get(idx));
        let after = suffix.as_bytes().get(index + binding.len());
        let before_ok = before.map_or(true, |byte| !is_ident_byte(*byte));
        let after_ok = after.map_or(true, |byte| !is_ident_byte(*byte));
        if before_ok && after_ok {
            return true;
        }
        search_from = index + binding.len();
    }
    false
}

fn body_references_redaction(body: &str) -> bool {
    body.contains(REDACTED) || body.contains("REDACTED")
}

fn find_word(source: &str, word: &str, from: usize) -> Option<usize> {
    let mut search_from = from;
    while let Some(offset) = source[search_from..].find(word) {
        let index = search_from + offset;
        let before = index
            .checked_sub(1)
            .and_then(|idx| source.as_bytes().get(idx));
        let after = source.as_bytes().get(index + word.len());
        let before_ok = before.map_or(true, |byte| !is_ident_byte(*byte));
        let after_ok = after.map_or(true, |byte| !is_ident_byte(*byte));
        if before_ok && after_ok {
            return Some(index);
        }
        search_from = index + word.len();
    }
    None
}

fn matching_brace(source: &str, open: usize) -> Option<usize> {
    matching_delimiter(source, open, b'{', b'}')
}

fn matching_delimiter(source: &str, open: usize, open_byte: u8, close_byte: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(open) != Some(&open_byte) {
        return None;
    }
    let mut depth = 0usize;
    let mut index = open;
    while index < bytes.len() {
        match bytes[index] {
            byte if byte == open_byte => depth = depth.saturating_add(1),
            byte if byte == close_byte => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        index = index.saturating_add(1);
    }
    None
}

fn skip_ws(bytes: &[u8], cursor: &mut usize) {
    while *cursor < bytes.len() && bytes[*cursor].is_ascii_whitespace() {
        *cursor = cursor.saturating_add(1);
    }
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn emit_log(status: &str, scanned_files: usize, errors: &[String]) {
    let mut escaped_errors = String::new();
    for (index, error) in errors.iter().enumerate() {
        if index > 0 {
            escaped_errors.push(',');
        }
        escaped_errors.push('"');
        escaped_errors.push_str(&escape_json(error));
        escaped_errors.push('"');
    }
    let log_line = format!(
        "{{\"schema_version\":1,\"event\":\"credential_debug_gate\",\"status\":\"{status}\",\"scanned_files\":{scanned_files},\"needle_prefixes\":{},\"errors\":[{}]}}\n",
        SECRET_VALUE_NEEDLE_PREFIXES.len(),
        escaped_errors
    );
    if status != "ok" {
        eprintln!("{log_line}");
    }
    if let Ok(out_dir) = env::var("OUT_DIR") {
        let _ = fs::write(
            PathBuf::from(out_dir).join("credential_debug_gate.jsonl"),
            log_line,
        );
    }
}

fn escape_json(input: &str) -> String {
    input
        .chars()
        .flat_map(|ch| match ch {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            other => vec![other],
        })
        .collect()
}
