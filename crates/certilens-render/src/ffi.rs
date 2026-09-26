//! Raw FFI declarations for the small subset of Poppler-glib we use.
//!
//! Everything in this file is `unsafe` to call. All safety invariants
//! are documented on the safe wrappers in `lib.rs`.
//!
//! # Poppler-glib
//!
//! Poppler is the PDF rendering library used by Okular, Evince, and
//! every other Linux PDF viewer. `poppler-glib` is its GObject wrapper —
//! friendlier than the raw C API and stable across versions.

use std::os::raw::{c_char, c_double, c_int, c_void};

/// Opaque pointer types. We never dereference these in Rust — we only
/// pass them back to Poppler functions.
#[repr(C)]
pub struct PopplerDocument {
    _private: [u8; 0],
}

#[repr(C)]
pub struct PopplerPage {
    _private: [u8; 0],
}

/// GLib's `GError`. Read-only — we inspect `.message` on failure.
#[repr(C)]
pub struct GError {
    pub domain: u32,
    pub code: i32,
    pub message: *mut c_char,
}

/// Raw Cairo context pointer.
pub type CairoContext = *mut c_void;

/// Flags for `poppler_page_render_for_printing_with_options`.
///
/// Matches Poppler's `PopplerPrintFlags` enum. `POPPLER_PRINT_DOCUMENT`
/// (value 1) means "render everything except markup annotations" — the
/// default for a viewer.
pub const POPPLER_PRINT_DOCUMENT: c_int = 1;

extern "C" {
    // ---- GObject refcounting ------------------------------------------

    /// Decrement an object's reference count, freeing it if the count
    /// reaches zero.
    pub fn g_object_unref(obj: *mut c_void);

    /// Free a GError returned by a failing Poppler call.
    pub fn g_error_free(err: *mut GError);

    // ---- Document -----------------------------------------------------

    /// Open a PDF. `uri` must be a `file://` URI. Returns NULL on error.
    pub fn poppler_document_new_from_file(
        uri: *const c_char,
        password: *const c_char,
        error: *mut *mut GError,
    ) -> *mut PopplerDocument;

    /// Number of pages in the document.
    pub fn poppler_document_get_n_pages(doc: *mut PopplerDocument) -> c_int;

    /// Get page by index (0-based). Returns a new reference that the
    /// caller must `g_object_unref`.
    pub fn poppler_document_get_page(doc: *mut PopplerDocument, index: c_int) -> *mut PopplerPage;

    // ---- Page ---------------------------------------------------------

    /// Fill `width` and `height` with the page's size, in points (72/inch).
    pub fn poppler_page_get_size(
        page: *mut PopplerPage,
        width: *mut c_double,
        height: *mut c_double,
    );

    /// Render a page onto a Cairo context with explicit options.
    ///
    /// This is the modern API. The older `poppler_page_render_for_printing`
    /// (without `_with_options`) is deprecated and internally calls this
    /// with `POPPLER_PRINT_DOCUMENT`, but going through this symbol
    /// directly is clearer and future-proof.
    ///
    /// The Cairo context must already be scaled to the target DPI.
    pub fn poppler_page_render_for_printing_with_options(
        page: *mut PopplerPage,
        cairo: CairoContext,
        options: c_int,
    );
}
