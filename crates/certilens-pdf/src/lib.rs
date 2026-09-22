//! PDF-specific inspection.
//!
//! This crate answers "what is inside this PDF?" — not "is it authentic?".
//! Authenticity decisions belong to `certilens-crypto` (Phase 2) and
//! `certilens-core` (Phase 3).

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Errors that can occur while reading a PDF.
#[derive(Debug, thiserror::Error)]
pub enum PdfError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PDF parse error: {0}")]
    Parse(#[from] lopdf::Error),
}

/// A signature field discovered in the PDF's AcroForm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureField {
    pub name: String,
    pub object_id: u32,
    pub has_value: bool,
}

/// Crypto-relevant details extracted from a signature's /V dictionary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureDetails {
    pub field_name: String,
    pub object_id: u32,
    pub filter: Option<String>,
    pub sub_filter: Option<String>,
    pub claimed_signer: Option<String>,
    pub claimed_time: Option<String>,
    pub reason: Option<String>,
    pub location: Option<String>,
    pub byte_range: Option<Vec<i64>>,
    pub contents_size: usize,
    pub contents_offset: Option<u64>,
    pub contents_hex_length: Option<u64>,

    // ---- Where does this signature appear? ----
    /// The signature widget's rectangle on the page, in PDF points:
    /// `[x0, y0, x1, y1]` with origin at the bottom-left of the page.
    pub rect: Option<[f64; 4]>,

    /// The 1-based page number this signature appears on.
    pub page_number: Option<usize>,
}

/// A high-level summary of a PDF file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfInfo {
    pub version: String,
    pub pages: usize,
    pub encrypted: bool,
    pub object_count: usize,
    pub signature_fields: Vec<SignatureField>,
    pub signature_details: Vec<SignatureDetails>,
    pub file_size: usize,
    pub startxref_offset: Option<u64>,
    pub eof_marker_count: usize,
    pub incremental_updates: usize,
}

/// Read a PDF from disk and produce a summary.
pub fn inspect(path: &Path) -> Result<PdfInfo, PdfError> {
    let bytes = std::fs::read(path)?;

    let version = read_version(&bytes).unwrap_or_else(|| "unknown".into());

    let doc = lopdf::Document::load_mem(&bytes)?;

    let pages = doc.get_pages().len();
    let object_count = doc.objects.len();
    let encrypted = doc.is_encrypted();
    let signature_fields = find_signature_fields(&doc);
    let signature_details = extract_signature_details(&doc, &bytes, &signature_fields);

    let file_size = bytes.len();
    let startxref_offset = find_startxref_offset(&bytes);
    let eof_marker_count = count_eof_markers(&bytes);
    let incremental_updates = eof_marker_count.saturating_sub(1);

    Ok(PdfInfo {
        version,
        pages,
        encrypted,
        object_count,
        signature_fields,
        signature_details,
        file_size,
        startxref_offset,
        eof_marker_count,
        incremental_updates,
    })
}

/// Extract the version from the `%PDF-x.y` header.
fn read_version(bytes: &[u8]) -> Option<String> {
    const MARKER: &[u8] = b"%PDF-";

    let window = &bytes[..bytes.len().min(1024)];
    let start = window.windows(MARKER.len()).position(|w| w == MARKER)?;
    let after = &window[start + MARKER.len()..];

    let mut end = 0;
    while end < after.len() && (after[end].is_ascii_digit() || after[end] == b'.') {
        end += 1;
    }

    if end == 0 {
        return None;
    }

    Some(String::from_utf8_lossy(&after[..end]).into_owned())
}

/// Walk the AcroForm field tree and collect signature fields.
fn find_signature_fields(doc: &lopdf::Document) -> Vec<SignatureField> {
    let mut out = Vec::new();

    let Ok(catalog) = doc.catalog() else {
        return out;
    };
    let Ok(acroform_ref) = catalog.get(b"AcroForm") else {
        return out;
    };
    let Some(acroform) = resolve(doc, acroform_ref).and_then(|o| o.as_dict().ok()) else {
        return out;
    };
    let Ok(fields) = acroform.get(b"Fields").and_then(|o| o.as_array()) else {
        return out;
    };

    for field in fields {
        walk_field(doc, field, "", None, &mut out);
    }
    out
}

/// Follow an indirect reference if needed.
fn resolve<'a>(doc: &'a lopdf::Document, obj: &'a lopdf::Object) -> Option<&'a lopdf::Object> {
    match obj {
        lopdf::Object::Reference(id) => doc.get_object(*id).ok(),
        other => Some(other),
    }
}

/// Recursively walk one field node.
fn walk_field(
    doc: &lopdf::Document,
    field: &lopdf::Object,
    parent_name: &str,
    inherited_ft: Option<&[u8]>,
    out: &mut Vec<SignatureField>,
) {
    let object_id = match field {
        lopdf::Object::Reference(id) => id.0,
        _ => 0,
    };

    let Some(dict) = resolve(doc, field).and_then(|o| o.as_dict().ok()) else {
        return;
    };

    let partial = dict
        .get(b"T")
        .ok()
        .and_then(|o| o.as_str().ok())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .unwrap_or_default();

    let full_name = match (parent_name.is_empty(), partial.is_empty()) {
        (true, true) => format!("<unnamed #{object_id}>"),
        (true, false) => partial.clone(),
        (false, true) => parent_name.to_string(),
        (false, false) => format!("{parent_name}.{partial}"),
    };

    let ft = dict
        .get(b"FT")
        .ok()
        .and_then(|o| o.as_name().ok())
        .or(inherited_ft);

    let kids = dict.get(b"Kids").and_then(|o| o.as_array()).ok();
    if let Some(kids) = kids {
        for kid in kids {
            walk_field(doc, kid, &full_name, ft, out);
        }
    }

    let is_leaf = kids.is_none();
    if is_leaf && ft == Some(b"Sig") {
        let has_value = dict.get(b"V").is_ok();
        out.push(SignatureField {
            name: full_name,
            object_id,
            has_value,
        });
    }
}

/// For each signed field, pull out the crypto-relevant metadata.
fn extract_signature_details(
    doc: &lopdf::Document,
    raw_bytes: &[u8],
    fields: &[SignatureField],
) -> Vec<SignatureDetails> {
    let mut out = Vec::new();

    for field in fields {
        if !field.has_value {
            continue;
        }

        let Ok(field_obj) = doc.get_object((field.object_id, 0)) else {
            continue;
        };
        let Some(field_dict) = field_obj.as_dict().ok() else {
            continue;
        };
        let Ok(v_ref) = field_dict.get(b"V") else {
            continue;
        };
        let v_id = match v_ref {
            lopdf::Object::Reference(id) => *id,
            _ => continue,
        };

        let Some(sig_dict) = resolve(doc, v_ref).and_then(|o| o.as_dict().ok()) else {
            continue;
        };

        let filter = get_name(sig_dict, b"Filter");
        let sub_filter = get_name(sig_dict, b"SubFilter");
        let claimed_signer = get_str(sig_dict, b"Name");
        let claimed_time = get_str(sig_dict, b"M");
        let reason = get_str(sig_dict, b"Reason");
        let location = get_str(sig_dict, b"Location");

        let byte_range = sig_dict
            .get(b"ByteRange")
            .ok()
            .and_then(|o| o.as_array().ok())
            .map(|arr| {
                arr.iter()
                    .filter_map(|o| o.as_i64().ok())
                    .collect::<Vec<i64>>()
            })
            .filter(|v| !v.is_empty());

        let contents_size = sig_dict
            .get(b"Contents")
            .ok()
            .and_then(|o| o.as_str().ok())
            .map(|s| s.len())
            .unwrap_or(0);

        let (contents_offset, contents_hex_length) = find_contents_span(raw_bytes, v_id.0)
            .map(|(off, len)| (Some(off), Some(len)))
            .unwrap_or((None, None));

        let (rect, page_number) = extract_rect_and_page(doc, field_dict);

        out.push(SignatureDetails {
            field_name: field.name.clone(),
            object_id: v_id.0,
            filter,
            sub_filter,
            claimed_signer,
            claimed_time,
            reason,
            location,
            byte_range,
            contents_size,
            contents_offset,
            contents_hex_length,
            rect,
            page_number,
        });
    }

    out
}

/// Extract the signature widget's rectangle and page number.
///
/// Tries the field dict directly (common case), then falls back to the
/// first kid (rare field/widget split).
fn extract_rect_and_page(
    doc: &lopdf::Document,
    field_dict: &lopdf::Dictionary,
) -> (Option<[f64; 4]>, Option<usize>) {
    // Try the field dict itself.
    if let Some(rect) = rect_of(field_dict) {
        let page = page_of(doc, field_dict);
        return (Some(rect), page);
    }

    // Fall back to the first kid, if any.
    if let Ok(kids) = field_dict.get(b"Kids").and_then(|o| o.as_array()) {
        for kid in kids {
            if let Some(kid_dict) = resolve(doc, kid).and_then(|o| o.as_dict().ok()) {
                if let Some(rect) = rect_of(kid_dict) {
                    let page = page_of(doc, kid_dict);
                    return (Some(rect), page);
                }
            }
        }
    }

    (None, None)
}

/// Read `/Rect` from a dict, if present and well-formed.
fn rect_of(dict: &lopdf::Dictionary) -> Option<[f64; 4]> {
    let arr = dict.get(b"Rect").ok()?.as_array().ok()?;
    if arr.len() != 4 {
        return None;
    }
    let mut out = [0.0f64; 4];
    for (i, obj) in arr.iter().enumerate() {
        out[i] = obj
            .as_float()
            .map(|f| f as f64)
            .ok()
            .or_else(|| obj.as_i64().ok().map(|n| n as f64))?;
    }
    Some(out)
}

/// Read `/P` from a dict and convert it to a 1-based page number.
fn page_of(doc: &lopdf::Document, dict: &lopdf::Dictionary) -> Option<usize> {
    let page_ref = match dict.get(b"P").ok()? {
        lopdf::Object::Reference(id) => *id,
        _ => return None,
    };
    for (num, id) in doc.get_pages() {
        if id == page_ref {
            return Some(num as usize);
        }
    }
    None
}

/// Read a name from a dict key, e.g. /Filter /Adobe.PPKLite.
fn get_name(dict: &lopdf::Dictionary, key: &[u8]) -> Option<String> {
    dict.get(key)
        .ok()
        .and_then(|o| o.as_name().ok())
        .map(|n| String::from_utf8_lossy(n).into_owned())
}

/// Read a text string from a dict key, e.g. /Name (Alice).
fn get_str(dict: &lopdf::Dictionary, key: &[u8]) -> Option<String> {
    dict.get(key)
        .ok()
        .and_then(|o| o.as_str().ok())
        .map(|s| String::from_utf8_lossy(s).into_owned())
}

/// Find the byte span of the `/Contents <hex>` value for object `object_id`.
fn find_contents_span(raw: &[u8], object_id: u32) -> Option<(u64, u64)> {
    let needle = format!("{object_id} 0 obj");
    let obj_start = find_subslice(raw, needle.as_bytes())?;
    let after = &raw[obj_start..];

    let obj_end = find_subslice(after, b"endobj").unwrap_or(after.len());
    let obj = &after[..obj_end];

    let contents_pos = find_subslice(obj, b"/Contents")?;
    let mut i = contents_pos + b"/Contents".len();

    while i < obj.len() && obj[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= obj.len() || obj[i] != b'<' {
        return None;
    }

    let hex_start = i + 1;
    let mut j = hex_start;
    while j < obj.len() && obj[j] != b'>' {
        j += 1;
    }
    if j >= obj.len() {
        return None;
    }

    let offset = (obj_start + i) as u64;
    let length = (j - hex_start) as u64;
    Some((offset, length))
}

/// Decode the hex-encoded `/Contents` value into raw CMS bytes.
pub fn extract_cms_bytes(raw: &[u8], offset: u64, hex_len: u64) -> Result<Vec<u8>, PdfError> {
    let offset = offset as usize;
    let hex_len = hex_len as usize;

    let end = offset
        .checked_add(1)
        .and_then(|o| o.checked_add(hex_len))
        .ok_or_else(|| {
            PdfError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "offset + hex_len overflowed",
            ))
        })?;

    if end > raw.len() {
        return Err(PdfError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "CMS hex span runs past end of file",
        )));
    }

    let hex_slice = &raw[offset + 1..end];

    let mut out = Vec::with_capacity(hex_len / 2);
    let mut hi: Option<u8> = None;

    for &b in hex_slice {
        let nibble = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => {
                return Err(PdfError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("non-hex byte {b:#x} in /Contents"),
                )))
            }
        };

        match hi.take() {
            None => hi = Some(nibble),
            Some(h) => out.push((h << 4) | nibble),
        }
    }

    Ok(out)
}

/// Naive substring search.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Count every occurrence of `%%EOF` in the file.
fn count_eof_markers(bytes: &[u8]) -> usize {
    const MARKER: &[u8] = b"%%EOF";
    bytes.windows(MARKER.len()).filter(|w| *w == MARKER).count()
}

/// Locate the `startxref` marker near the end of the file.
fn find_startxref_offset(bytes: &[u8]) -> Option<u64> {
    const MARKER: &[u8] = b"startxref";
    const SCAN: usize = 2048;

    let tail_start = bytes.len().saturating_sub(SCAN);
    let tail = &bytes[tail_start..];

    let pos = tail.windows(MARKER.len()).rposition(|w| w == MARKER)?;

    let after = &tail[pos + MARKER.len()..];

    let mut i = 0;
    while i < after.len() && after[i].is_ascii_whitespace() {
        i += 1;
    }

    let start = i;
    while i < after.len() && after[i].is_ascii_digit() {
        i += 1;
    }

    if i == start {
        return None;
    }

    std::str::from_utf8(&after[start..i]).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_no_eof_markers() {
        assert_eq!(count_eof_markers(b"hello"), 0);
    }

    #[test]
    fn counts_one_eof_marker() {
        assert_eq!(count_eof_markers(b"x\n%%EOF\n"), 1);
    }

    #[test]
    fn counts_incremental_updates() {
        let data = b"a\n%%EOF\nb\n%%EOF\nc\n%%EOF\n";
        assert_eq!(count_eof_markers(data), 3);
    }

    #[test]
    fn finds_startxref_offset() {
        let data = b"%PDF-1.4\n...\nstartxref\n1234\n%%EOF\n";
        assert_eq!(find_startxref_offset(data), Some(1234));
    }

    #[test]
    fn picks_last_startxref() {
        let data = b"startxref\n100\n%%EOF\nstartxref\n999\n%%EOF\n";
        assert_eq!(find_startxref_offset(data), Some(999));
    }

    #[test]
    fn returns_none_when_missing() {
        assert_eq!(find_startxref_offset(b"%PDF-1.4\n%%EOF\n"), None);
    }

    use lopdf::{dictionary, Object};

    #[test]
    fn finds_signature_field_in_acroform() {
        let mut doc = lopdf::Document::new();

        let sig_dict = dictionary! {
            "FT" => Object::Name(b"Sig".to_vec()),
            "T"  => Object::string_literal("Signature1"),
        };
        let sig_id = doc.add_object(Object::Dictionary(sig_dict));

        let acro_dict = dictionary! {
            "Fields" => Object::Array(vec![Object::Reference(sig_id)]),
        };
        let acro_id = doc.add_object(Object::Dictionary(acro_dict));

        let cat_dict = dictionary! {
            "Type"     => Object::Name(b"Catalog".to_vec()),
            "AcroForm" => Object::Reference(acro_id),
        };
        let cat_id = doc.add_object(Object::Dictionary(cat_dict));

        doc.trailer.set("Root", Object::Reference(cat_id));

        let fields = find_signature_fields(&doc);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "Signature1");
        assert_eq!(fields[0].object_id, sig_id.0);
        assert!(!fields[0].has_value);
    }

    #[test]
    fn inherits_field_type_from_parent() {
        let mut doc = lopdf::Document::new();

        let child_dict = dictionary! {
            "T" => Object::string_literal("Child"),
            "V" => Object::Integer(0),
        };
        let child_id = doc.add_object(Object::Dictionary(child_dict));

        let parent_dict = dictionary! {
            "T"    => Object::string_literal("Form"),
            "FT"   => Object::Name(b"Sig".to_vec()),
            "Kids" => Object::Array(vec![Object::Reference(child_id)]),
        };
        let parent_id = doc.add_object(Object::Dictionary(parent_dict));

        let acro_dict = dictionary! {
            "Fields" => Object::Array(vec![Object::Reference(parent_id)]),
        };
        let acro_id = doc.add_object(Object::Dictionary(acro_dict));

        let cat_dict = dictionary! {
            "Type"     => Object::Name(b"Catalog".to_vec()),
            "AcroForm" => Object::Reference(acro_id),
        };
        let cat_id = doc.add_object(Object::Dictionary(cat_dict));

        doc.trailer.set("Root", Object::Reference(cat_id));

        let fields = find_signature_fields(&doc);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "Form.Child");
        assert!(fields[0].has_value);
    }

    #[test]
    fn ignores_non_signature_fields() {
        let mut doc = lopdf::Document::new();

        let txt_dict = dictionary! {
            "FT" => Object::Name(b"Tx".to_vec()),
            "T"  => Object::string_literal("Name"),
        };
        let txt_id = doc.add_object(Object::Dictionary(txt_dict));

        let acro_dict = dictionary! {
            "Fields" => Object::Array(vec![Object::Reference(txt_id)]),
        };
        let acro_id = doc.add_object(Object::Dictionary(acro_dict));

        let cat_dict = dictionary! {
            "Type"     => Object::Name(b"Catalog".to_vec()),
            "AcroForm" => Object::Reference(acro_id),
        };
        let cat_id = doc.add_object(Object::Dictionary(cat_dict));

        doc.trailer.set("Root", Object::Reference(cat_id));

        assert!(find_signature_fields(&doc).is_empty());
    }

    #[test]
    fn extracts_byte_range_and_contents_size() {
        let mut doc = lopdf::Document::new();

        let sig_dict = dictionary! {
            "Type"      => Object::Name(b"Sig".to_vec()),
            "Filter"    => Object::Name(b"Adobe.PPKLite".to_vec()),
            "SubFilter" => Object::Name(b"adbe.pkcs7.detached".to_vec()),
            "ByteRange" => Object::Array(vec![
                Object::Integer(0),
                Object::Integer(100),
                Object::Integer(200),
                Object::Integer(50),
            ]),
            "Contents"  => Object::String(vec![0u8; 16], lopdf::StringFormat::Hexadecimal),
        };
        let sig_id = doc.add_object(Object::Dictionary(sig_dict));

        let field_dict = dictionary! {
            "FT" => Object::Name(b"Sig".to_vec()),
            "T"  => Object::string_literal("Sig1"),
            "V"  => Object::Reference(sig_id),
        };
        let field_id = doc.add_object(Object::Dictionary(field_dict));

        let acro_dict = dictionary! {
            "Fields" => Object::Array(vec![Object::Reference(field_id)]),
        };
        let acro_id = doc.add_object(Object::Dictionary(acro_dict));

        let cat_dict = dictionary! {
            "Type"     => Object::Name(b"Catalog".to_vec()),
            "AcroForm" => Object::Reference(acro_id),
        };
        let cat_id = doc.add_object(Object::Dictionary(cat_dict));

        doc.trailer.set("Root", Object::Reference(cat_id));

        let fields = find_signature_fields(&doc);
        assert_eq!(fields.len(), 1);
        assert!(fields[0].has_value);

        let details = extract_signature_details(&doc, b"", &fields);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].field_name, "Sig1");
        assert_eq!(
            details[0].sub_filter.as_deref(),
            Some("adbe.pkcs7.detached")
        );
        assert_eq!(details[0].byte_range, Some(vec![0, 100, 200, 50]));
        assert_eq!(details[0].contents_size, 16);
    }

    #[test]
    fn extracts_cms_bytes_from_hex() {
        let raw = b"<4E6F77>";
        let bytes = extract_cms_bytes(raw, 0, 6).expect("decode");
        assert_eq!(bytes, b"Now");
    }

    #[test]
    fn handles_lowercase_hex() {
        let raw = b"<cafebabe>";
        let bytes = extract_cms_bytes(raw, 0, 8).expect("decode");
        assert_eq!(bytes, vec![0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn rejects_run_past_eof() {
        let raw = b"<abcd";
        assert!(extract_cms_bytes(raw, 0, 100).is_err());
    }

    #[test]
    fn skips_whitespace_inside_hex() {
        let raw = b"<4E 6F\n77>";
        let bytes = extract_cms_bytes(raw, 0, 8).expect("decode");
        assert_eq!(bytes, b"Now");
    }
}
