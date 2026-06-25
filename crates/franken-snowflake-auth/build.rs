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
        let next_open = source[cursor..].find('{').map(|offset| cursor + offset);
        let next_semicolon = source[cursor..].find(';').map(|offset| cursor + offset);
        let semicolon_before_open = match (next_semicolon, next_open) {
            (Some(semicolon), Some(open)) => semicolon < open,
            (Some(_), None) => true,
            _ => false,
        };
        if semicolon_before_open {
            index = cursor.saturating_add(1);
            continue;
        }
        let Some(open) = next_open else {
            index = cursor;
            continue;
        };
        let Some(close) = matching_brace(source, open) else {
            index = open.saturating_add(1);
            continue;
        };
        let body = &source[open + 1..close];
        items.push(StructItem {
            name,
            derives_debug,
            fields: parse_fields(body),
        });
        index = close.saturating_add(1);
    }
    items
}

fn parse_fields(body: &str) -> Vec<FieldItem> {
    body.split(',')
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
    let prefix = &source[..struct_index];
    let mut attrs = Vec::new();
    for line in prefix.lines().rev() {
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
    attrs
        .iter()
        .any(|attr| attr.starts_with("#[derive") && attr.contains("Debug"))
}

fn impl_body<'a>(source: &'a str, trait_name: &str, type_name: &str) -> Option<&'a str> {
    let candidates = [
        format!("impl fmt::{trait_name} for {type_name}"),
        format!("impl std::fmt::{trait_name} for {type_name}"),
        format!("impl core::fmt::{trait_name} for {type_name}"),
    ];
    let (start, pattern_len) = candidates
        .iter()
        .filter_map(|pattern| source.find(pattern).map(|start| (start, pattern.len())))
        .min_by_key(|(start, _)| *start)?;
    let after_pattern = start + pattern_len;
    let open = source[after_pattern..].find('{')? + after_pattern;
    let close = matching_brace(source, open)?;
    Some(&source[open + 1..close])
}

fn debug_impl_references_field(body: &str, field: &str) -> bool {
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
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = open;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => depth = depth.saturating_add(1),
            b'}' => {
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
