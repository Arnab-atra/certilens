//! Safe Rust wrapper around a small subset of Poppler-glib.
//!
//! # What this crate does
//!
//! Given a PDF file path, a page number, and a DPI, returns a Cairo
//! `ImageSurface` containing the fully rendered page. This is exactly
//! what a PDF reader needs, with no extra surface area.
//!
//! # What this crate does not do
//!
//! It does not parse, verify, or inspect PDFs — that's `certilens-pdf`.
//! It does not touch the filesystem beyond reading the PDF. It does not
//! handle encrypted PDFs (yet).
//!
//! # Safety philosophy
//!
//! All FFI calls are hidden behind safe functions in this file. The
//! module `ffi` is private — the caller never sees a raw pointer.

mod ffi;

use std::ffi::{CStr, CString};
use std::os::raw::{c_double, c_int, c_void};
use std::path::Path;
use std::ptr;

use cairo::{Context, FontOptions, Format, HintMetrics, HintStyle, ImageSurface};

/// Errors from the rendering path.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("path is not absolute — Poppler requires an absolute file:// URI")]
    NotAbsolute,

    #[error("path contains a NUL byte and cannot be converted to a C string")]
    NulInPath,

    #[error("could not open PDF: {0}")]
    Open(String),

    #[error("page {0} is out of range (document has {1} pages)")]
    PageOutOfRange(u32, u32),

    #[error("could not get page {0}")]
    GetPage(u32),

    #[error("cairo error: {0}")]
    Cairo(#[from] cairo::Error),
}

/// RAII wrapper for any GObject-owned pointer.
///
/// When this drops, it calls `g_object_unref`. Prevents leaks on early
/// return or panic.
struct GObject<T> {
    ptr: *mut T,
}

impl<T> GObject<T> {
    fn new(ptr: *mut T) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    fn as_ptr(&self) -> *mut T {
        self.ptr
    }
}

impl<T> Drop for GObject<T> {
    fn drop(&mut self) {
        unsafe { ffi::g_object_unref(self.ptr as *mut c_void) };
    }
}

/// Convert a `Path` into a `file://` URI, as Poppler expects.
fn path_to_uri(path: &Path) -> Result<String, RenderError> {
    if !path.is_absolute() {
        return Err(RenderError::NotAbsolute);
    }
    let mut uri = String::from("file://");
    for ch in path.to_string_lossy().chars() {
        match ch {
            ' ' => uri.push_str("%20"),
            '#' => uri.push_str("%23"),
            '?' => uri.push_str("%3F"),
            c => uri.push(c),
        }
    }
    Ok(uri)
}

/// Extract the message from a GError and free it. Consumes the pointer.
unsafe fn read_and_free_gerror(err: *mut ffi::GError) -> String {
    if err.is_null() {
        return "(no error message)".into();
    }
    let msg_ptr = (*err).message;
    let msg = if msg_ptr.is_null() {
        "(null message)".to_string()
    } else {
        CStr::from_ptr(msg_ptr).to_string_lossy().into_owned()
    };
    ffi::g_error_free(err);
    msg
}

/// The number of pages in the PDF at `path`.
pub fn page_count(path: &Path) -> Result<u32, RenderError> {
    let uri = path_to_uri(path)?;
    let uri_c = CString::new(uri).map_err(|_| RenderError::NulInPath)?;

    let mut err: *mut ffi::GError = ptr::null_mut();
    let doc_raw =
        unsafe { ffi::poppler_document_new_from_file(uri_c.as_ptr(), ptr::null(), &mut err) };
    let doc = GObject::new(doc_raw).ok_or_else(|| {
        let msg = unsafe { read_and_free_gerror(err) };
        RenderError::Open(msg)
    })?;

    let n = unsafe { ffi::poppler_document_get_n_pages(doc.as_ptr()) };
    Ok(n.max(0) as u32)
}

/// Render one page of a PDF to a Cairo `ImageSurface`.
///
/// * `page_number` is **1-indexed**.
/// * `dpi` — dots per inch. **Prefer integer multiples of 72** (72, 144,
///   216) for crisp text rendering. Non-integer scale factors (e.g. 150/72)
///   cause Cairo to hint and position glyphs on fractional pixels, which
///   produces soft/blurry text.
pub fn render_page(path: &Path, page_number: u32, dpi: f64) -> Result<ImageSurface, RenderError> {
    if page_number == 0 {
        return Err(RenderError::PageOutOfRange(0, 0));
    }

    // ---- Open the document ----
    let uri = path_to_uri(path)?;
    let uri_c = CString::new(uri).map_err(|_| RenderError::NulInPath)?;

    let mut err: *mut ffi::GError = ptr::null_mut();
    let doc_raw =
        unsafe { ffi::poppler_document_new_from_file(uri_c.as_ptr(), ptr::null(), &mut err) };
    let doc = GObject::new(doc_raw).ok_or_else(|| {
        let msg = unsafe { read_and_free_gerror(err) };
        RenderError::Open(msg)
    })?;

    let n_pages = unsafe { ffi::poppler_document_get_n_pages(doc.as_ptr()) };
    if n_pages < 0 || page_number > n_pages as u32 {
        return Err(RenderError::PageOutOfRange(
            page_number,
            n_pages.max(0) as u32,
        ));
    }

    // ---- Get the page ----
    let page_raw =
        unsafe { ffi::poppler_document_get_page(doc.as_ptr(), (page_number - 1) as c_int) };
    let page = GObject::new(page_raw).ok_or(RenderError::GetPage(page_number))?;

    // ---- Page dimensions (in PDF points, 72/inch) ----
    let mut width_pt: c_double = 0.0;
    let mut height_pt: c_double = 0.0;
    unsafe { ffi::poppler_page_get_size(page.as_ptr(), &mut width_pt, &mut height_pt) };

    let scale = dpi / 72.0;
    let width_px = (width_pt * scale).ceil().max(1.0) as i32;
    let height_px = (height_pt * scale).ceil().max(1.0) as i32;

    // ---- Create the Cairo surface ----
    let surface = ImageSurface::create(Format::ARgb32, width_px, height_px)?;

    // ---- Fill with white (PDFs assume white paper) ----
    {
        let ctx = Context::new(&surface)?;
        ctx.set_source_rgb(1.0, 1.0, 1.0);
        ctx.paint()?;
    }

    // ---- Render the page ----
    {
        let ctx = Context::new(&surface)?;

        // Font hinting options. Without these, Cairo falls back to the
        // system fontconfig defaults, which are tuned for screen
        // rendering at 96 DPI. At 144 DPI we want full hinting and
        // quantized glyph metrics so strokes land on whole pixels.
        let mut font_options = FontOptions::new()?;
        font_options.set_antialias(cairo::Antialias::Gray);
        font_options.set_hint_style(HintStyle::Full);
        font_options.set_hint_metrics(HintMetrics::On);
        ctx.set_font_options(&font_options);

        ctx.scale(scale, scale);

        unsafe {
            let raw_ctx = ctx.to_raw_none() as *mut c_void;
            ffi::poppler_page_render_for_printing_with_options(
                page.as_ptr(),
                raw_ctx,
                ffi::POPPLER_PRINT_DOCUMENT,
            );
        }
    }

    // Cairo defers some drawing until the surface is flushed.
    surface.flush();

    // `page` and `doc` are dropped here, unrefing their GObjects.

    Ok(surface)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Path to a real signed PDF we know how to open.
    /// Skips the test if the file isn't present, so CI doesn't fail.
    fn sample_pdf() -> Option<&'static str> {
        let p = "/home/arnab-patra/Downloads/ErationCard_PHH_RationCardNo_37636685_80923271_21_09_2026 12_03_59.pdf";
        if std::path::Path::new(p).exists() {
            Some(p)
        } else {
            None
        }
    }

    #[test]
    fn reads_page_count() {
        let Some(path) = sample_pdf() else { return };
        let n = page_count(Path::new(path)).expect("page_count");
        assert!(n >= 1);
        println!("page count = {n}");
    }

    #[test]
    fn renders_page_one_to_png() {
        let Some(path) = sample_pdf() else { return };
        // 144 DPI = 2× scale factor (integer). Cleaner text than 150.
        let surface = render_page(Path::new(path), 1, 144.0).expect("render");
        let w = surface.width();
        let h = surface.height();
        println!("rendered at {w}x{h} pixels");
        assert!(w > 100);
        assert!(h > 100);

        // Write it out so we can eyeball it.
        let out = std::env::temp_dir().join("certilens-render-test.png");
        let mut file = std::fs::File::create(&out).expect("create");
        surface.write_to_png(&mut file).expect("write png");
        println!("wrote {}", out.display());
    }

    #[test]
    fn rejects_nonexistent_file() {
        let r = render_page(Path::new("/definitely/missing.pdf"), 1, 144.0);
        assert!(matches!(r, Err(RenderError::Open(_))));
    }

    #[test]
    fn rejects_relative_path() {
        let r = render_page(Path::new("relative.pdf"), 1, 144.0);
        assert!(matches!(r, Err(RenderError::NotAbsolute)));
    }
}
