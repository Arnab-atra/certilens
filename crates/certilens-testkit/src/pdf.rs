//! Minimal PDF generation for tests.
//!
//! Produces valid 1-page PDFs with the exact structure `certilens-pdf`
//! expects: a Catalog, a Pages node, and a single Page with a text
//! content stream. These are the fixtures that every downstream test
//! builds on — signed, tampered, expired, and so on.

use std::io::Write;

use lopdf::{dictionary, Document, Object, Stream};
use tempfile::NamedTempFile;

/// Errors from PDF generation.
#[derive(Debug, thiserror::Error)]
pub enum PdfGenError {
    #[error("lopdf error: {0}")]
    Lopdf(#[from] lopdf::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Generate a minimal valid PDF as raw bytes.
///
/// The generated PDF:
///   - has version 1.4
///   - has exactly one page
///   - has MediaBox [0, 0, 612, 792] (US Letter)
///   - contains the text "CertiLens Test" in Helvetica 24pt
///   - has no signatures
///
/// This is the base fixture. Every other generator in this module
/// starts from here.
pub fn minimal_pdf() -> Vec<u8> {
    minimal_pdf_with_text("CertiLens Test")
}

/// Same as [`minimal_pdf`], but the caller controls the visible text.
pub fn minimal_pdf_with_text(text: &str) -> Vec<u8> {
    let mut doc = Document::with_version("1.4");

    // ---- Font resource --------------------------------------------------
    let font = doc.add_object(dictionary! {
        "Type"     => Object::Name(b"Font".to_vec()),
        "Subtype"  => Object::Name(b"Type1".to_vec()),
        "BaseFont" => Object::Name(b"Helvetica".to_vec()),
    });

    // ---- Content stream -------------------------------------------------
    // `BT /F1 24 Tf 100 700 Td (text) Tj ET` is PDF graphics syntax:
    //   BT     begin text
    //   /F1    select font resource "F1"
    //   24 Tf  set font size 24
    //   100 700 Td  move text position
    //   (text) Tj   draw the string
    //   ET     end text
    let escaped = text
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)");
    let content_str = format!("BT /F1 24 Tf 100 700 Td ({escaped}) Tj ET");
    let content = Stream::new(dictionary! {}, content_str.into_bytes());
    let content_id = doc.add_object(content);

    // ---- Resources dict -------------------------------------------------
    let resources = dictionary! {
        "Font" => dictionary! {
            "F1" => Object::Reference(font),
        },
    };

    // ---- Page -----------------------------------------------------------
    let page = dictionary! {
        "Type"      => Object::Name(b"Page".to_vec()),
        "MediaBox"  => Object::Array(vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(612),
            Object::Integer(792),
        ]),
        "Resources" => resources,
        "Contents"  => Object::Reference(content_id),
    };
    let page_id = doc.add_object(page);

    // ---- Pages node -----------------------------------------------------
    let pages_id = doc.add_object(dictionary! {
        "Type"  => Object::Name(b"Pages".to_vec()),
        "Kids"  => Object::Array(vec![Object::Reference(page_id)]),
        "Count" => Object::Integer(1),
    });

    // Set /Parent on the Page now that we know the Pages ID.
    doc.get_object_mut(page_id)
        .expect("page just added")
        .as_dict_mut()
        .expect("page is a dict")
        .set("Parent", Object::Reference(pages_id));

    // ---- Catalog --------------------------------------------------------
    let catalog_id = doc.add_object(dictionary! {
        "Type"  => Object::Name(b"Catalog".to_vec()),
        "Pages" => Object::Reference(pages_id),
    });

    doc.trailer.set("Root", Object::Reference(catalog_id));

    // ---- Serialize ------------------------------------------------------
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).expect("save_to Vec never fails");
    bytes
}

/// Write PDF bytes to a temporary file, returning the file handle.
///
/// The file is automatically deleted when the returned `NamedTempFile`
/// is dropped, which happens at the end of the enclosing test.
pub fn write_temp_pdf(bytes: &[u8]) -> Result<NamedTempFile, PdfGenError> {
    let mut file = NamedTempFile::new()?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pdf_has_header() {
        let bytes = minimal_pdf();
        assert!(
            bytes.starts_with(b"%PDF-1.4"),
            "expected %PDF-1.4 header, got: {:?}",
            &bytes[..bytes.len().min(20)]
        );
    }

    #[test]
    fn generated_pdf_has_eof_marker() {
        let bytes = minimal_pdf();
        let marker = b"%%EOF";
        let found = bytes.windows(marker.len()).any(|w| w == marker);
        assert!(found, "expected %%EOF at end of file");
    }

    #[test]
    fn certilens_pdf_can_read_it() {
        let bytes = minimal_pdf();
        let file = write_temp_pdf(&bytes).expect("write temp pdf");

        let info = certilens_pdf::inspect(file.path()).expect("certilens_pdf::inspect");

        assert_eq!(info.version, "1.4");
        assert_eq!(info.pages, 1);
        assert_eq!(
            info.signature_fields.len(),
            0,
            "unsigned PDF should have no sig fields"
        );
        assert!(!info.encrypted);
    }

    #[test]
    fn custom_text_round_trips() {
        // Just check it doesn't panic and produces a loadable PDF.
        let bytes = minimal_pdf_with_text("Hello, (nested) \\ backslash");
        let file = write_temp_pdf(&bytes).expect("write temp pdf");
        let info = certilens_pdf::inspect(file.path()).expect("certilens_pdf::inspect");
        assert_eq!(info.pages, 1);
    }
}
