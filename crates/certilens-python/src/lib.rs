//! PyO3 bridge between Python and `certilens-core`.
//!
//! Python must never make verification decisions itself.
//! This module exposes Rust objects and methods; Python just displays them.

use certilens_core::{Document, VerificationResult, VerificationStatus};
use certilens_crypto::hash_byte_ranges;
use certilens_pdf::{PdfInfo, SignatureDetails, SignatureField};
use pyo3::exceptions::{PyIOError, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

/// Python-visible wrapper around `certilens_core::Document`.
#[pyclass]
struct PyDocument {
    inner: Document,
}

#[pymethods]
impl PyDocument {
    #[getter]
    fn path(&self) -> String {
        self.inner.path.to_string_lossy().into_owned()
    }

    #[getter]
    fn format(&self) -> String {
        self.inner.format_label().to_string()
    }

    /// Run every available check and produce a verdict.
    fn verify(&self) -> PyResult<PyVerificationResult> {
        let path = self.inner.path.to_string_lossy().into_owned();
        assess_document(path.as_str())
    }

    fn pdf_info(&self) -> PyResult<PyPdfInfo> {
        match certilens_pdf::inspect(&self.inner.path) {
            Ok(info) => Ok(PyPdfInfo { inner: info }),
            Err(e) => Err(PyRuntimeError::new_err(format!(
                "Could not inspect PDF: {e}"
            ))),
        }
    }

    fn signature_hash<'py>(&self, py: Python<'py>, index: usize) -> PyResult<Bound<'py, PyBytes>> {
        let raw = std::fs::read(&self.inner.path)
            .map_err(|e| PyIOError::new_err(format!("read failed: {e}")))?;

        let info = certilens_pdf::inspect(&self.inner.path)
            .map_err(|e| PyRuntimeError::new_err(format!("inspect failed: {e}")))?;

        let sig = info.signature_details.get(index).ok_or_else(|| {
            PyRuntimeError::new_err(format!(
                "no signature at index {index} (found {})",
                info.signature_details.len()
            ))
        })?;

        let br = sig
            .byte_range
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("signature has no ByteRange"))?;

        let digest = hash_byte_ranges(&raw, br)
            .map_err(|e| PyRuntimeError::new_err(format!("hash failed: {e}")))?;

        Ok(PyBytes::new_bound(py, &digest))
    }

    fn cms_bytes<'py>(&self, py: Python<'py>, index: usize) -> PyResult<Bound<'py, PyBytes>> {
        let raw = std::fs::read(&self.inner.path)
            .map_err(|e| PyIOError::new_err(format!("read failed: {e}")))?;

        let info = certilens_pdf::inspect(&self.inner.path)
            .map_err(|e| PyRuntimeError::new_err(format!("inspect failed: {e}")))?;

        let sig = info.signature_details.get(index).ok_or_else(|| {
            PyRuntimeError::new_err(format!(
                "no signature at index {index} (found {})",
                info.signature_details.len()
            ))
        })?;

        let (off, hex_len) = match (sig.contents_offset, sig.contents_hex_length) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                return Err(PyRuntimeError::new_err(
                    "/Contents offset unknown for this signature",
                ))
            }
        };

        let bytes = certilens_pdf::extract_cms_bytes(&raw, off, hex_len)
            .map_err(|e| PyRuntimeError::new_err(format!("extract failed: {e}")))?;

        Ok(PyBytes::new_bound(py, &bytes))
    }

    fn __repr__(&self) -> String {
        format!("<Document path={:?} format={}>", self.path(), self.format())
    }
}

/// Python-visible wrapper around `VerificationResult`.
#[pyclass]
struct PyVerificationResult {
    inner: VerificationResult,
}

#[pymethods]
impl PyVerificationResult {
    #[getter]
    fn status(&self) -> String {
        format!("{:?}", self.inner.status)
    }

    #[getter]
    fn status_label(&self) -> String {
        self.inner.status_label().to_string()
    }

    #[getter]
    fn headline(&self) -> String {
        self.inner.headline.clone()
    }

    #[getter]
    fn subtitle(&self) -> String {
        self.inner.subtitle.clone()
    }

    #[getter]
    fn issues(&self) -> Vec<String> {
        self.inner.issues.clone()
    }

    #[getter]
    fn severity_class(&self) -> String {
        self.inner.severity_class().to_string()
    }

    fn __repr__(&self) -> String {
        format!("<VerificationResult status={}>", self.status())
    }
}

/// Python-visible wrapper around `certilens_pdf::PdfInfo`.
#[pyclass]
struct PyPdfInfo {
    inner: PdfInfo,
}

#[pymethods]
impl PyPdfInfo {
    #[getter]
    fn version(&self) -> String {
        self.inner.version.clone()
    }

    #[getter]
    fn pages(&self) -> usize {
        self.inner.pages
    }

    #[getter]
    fn encrypted(&self) -> bool {
        self.inner.encrypted
    }

    #[getter]
    fn object_count(&self) -> usize {
        self.inner.object_count
    }

    #[getter]
    fn signature_fields(&self) -> Vec<PySignatureField> {
        self.inner
            .signature_fields
            .iter()
            .cloned()
            .map(|inner| PySignatureField { inner })
            .collect()
    }

    #[getter]
    fn signature_details(&self) -> Vec<PySignatureDetails> {
        self.inner
            .signature_details
            .iter()
            .cloned()
            .map(|inner| PySignatureDetails { inner })
            .collect()
    }

    #[getter]
    fn file_size(&self) -> usize {
        self.inner.file_size
    }

    #[getter]
    fn startxref_offset(&self) -> Option<u64> {
        self.inner.startxref_offset
    }

    #[getter]
    fn eof_marker_count(&self) -> usize {
        self.inner.eof_marker_count
    }

    #[getter]
    fn incremental_updates(&self) -> usize {
        self.inner.incremental_updates
    }

    fn __repr__(&self) -> String {
        format!(
            "<PdfInfo version={} pages={} encrypted={} objects={} \
             size={} eof={} updates={}>",
            self.inner.version,
            self.inner.pages,
            self.inner.encrypted,
            self.inner.object_count,
            self.inner.file_size,
            self.inner.eof_marker_count,
            self.inner.incremental_updates,
        )
    }
}

/// Python-visible wrapper around `certilens_pdf::SignatureField`.
#[pyclass]
#[derive(Clone)]
struct PySignatureField {
    inner: SignatureField,
}

#[pymethods]
impl PySignatureField {
    #[getter]
    fn name(&self) -> String {
        self.inner.name.clone()
    }

    #[getter]
    fn object_id(&self) -> u32 {
        self.inner.object_id
    }

    #[getter]
    fn has_value(&self) -> bool {
        self.inner.has_value
    }

    fn __repr__(&self) -> String {
        format!(
            "<SignatureField name={:?} object_id={} has_value={}>",
            self.inner.name, self.inner.object_id, self.inner.has_value
        )
    }
}

/// Python-visible wrapper around `certilens_pdf::SignatureDetails`.
#[pyclass]
#[derive(Clone)]
struct PySignatureDetails {
    inner: SignatureDetails,
}

#[pymethods]
impl PySignatureDetails {
    #[getter]
    fn field_name(&self) -> String {
        self.inner.field_name.clone()
    }

    #[getter]
    fn object_id(&self) -> u32 {
        self.inner.object_id
    }

    #[getter]
    fn filter(&self) -> Option<String> {
        self.inner.filter.clone()
    }

    #[getter]
    fn sub_filter(&self) -> Option<String> {
        self.inner.sub_filter.clone()
    }

    #[getter]
    fn claimed_signer(&self) -> Option<String> {
        self.inner.claimed_signer.clone()
    }

    #[getter]
    fn claimed_time(&self) -> Option<String> {
        self.inner.claimed_time.clone()
    }

    #[getter]
    fn reason(&self) -> Option<String> {
        self.inner.reason.clone()
    }

    #[getter]
    fn location(&self) -> Option<String> {
        self.inner.location.clone()
    }

    #[getter]
    fn byte_range(&self) -> Option<Vec<i64>> {
        self.inner.byte_range.clone()
    }

    #[getter]
    fn contents_size(&self) -> usize {
        self.inner.contents_size
    }

    #[getter]
    fn contents_offset(&self) -> Option<u64> {
        self.inner.contents_offset
    }

    #[getter]
    fn contents_hex_length(&self) -> Option<u64> {
        self.inner.contents_hex_length
    }

    fn __repr__(&self) -> String {
        format!(
            "<SignatureDetails field={:?} sub_filter={:?} byte_range={:?} contents={}B>",
            self.inner.field_name,
            self.inner.sub_filter,
            self.inner.byte_range,
            self.inner.contents_size,
        )
    }
}

/// Top-level Python function: `certilens.open_document(path)`.
#[pyfunction]
fn open_document(path: &str) -> PyResult<PyDocument> {
    match Document::open(path) {
        Ok(doc) => Ok(PyDocument { inner: doc }),
        Err(e) => Err(PyIOError::new_err(format!("Could not open {path}: {e}"))),
    }
}

/// Run every available check and produce a verdict.
#[pyfunction]
fn assess_document(path: &str) -> PyResult<PyVerificationResult> {
    let raw = std::fs::read(path).map_err(|e| PyIOError::new_err(format!("read failed: {e}")))?;

    let info = certilens_pdf::inspect(std::path::Path::new(path))
        .map_err(|e| PyRuntimeError::new_err(format!("inspect failed: {e}")))?;

    let mut issues: Vec<String> = Vec::new();
    let mut any_sig = false;

    // Three independent axes of trust.
    let mut crypto_ok = true; // digest match + RSA signature
    let mut validity_ok = true; // cert valid at claimed signing time
    let mut chain_ok = true; // chain reaches a trusted root

    // Load the system trust store once, before the loop.
    let trust_store = certilens_crypto::trust::TrustStore::load_system().ok();

    for (idx, sig) in info.signature_details.iter().enumerate() {
        any_sig = true;

        // ---- Extract CMS ----
        let (off, hex_len) = match (sig.contents_offset, sig.contents_hex_length) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                issues.push(format!("Signature #{idx}: /Contents offset unknown"));
                crypto_ok = false;
                continue;
            }
        };

        let cms = match certilens_pdf::extract_cms_bytes(&raw, off, hex_len) {
            Ok(c) => c,
            Err(e) => {
                issues.push(format!("Signature #{idx}: could not extract CMS: {e}"));
                crypto_ok = false;
                continue;
            }
        };

        let br = match sig.byte_range.as_ref() {
            Some(b) => b,
            None => {
                issues.push(format!("Signature #{idx}: no ByteRange"));
                crypto_ok = false;
                continue;
            }
        };

        // ---- Phase 2a: digest ----
        match certilens_crypto::check_digest(&raw, br, &cms) {
            Ok(d) if d.matches => {}
            Ok(_) => {
                issues.push(format!(
                    "Signature #{idx}: SHA-256 digest MISMATCH — document was modified after signing"
                ));
                crypto_ok = false;
            }
            Err(e) => {
                issues.push(format!("Signature #{idx}: digest check failed: {e}"));
                crypto_ok = false;
            }
        }

        // ---- Phase 2c: cryptographic signature ----
        match certilens_crypto::verify_signer_signature(&cms) {
            Ok(r) if r.valid => {}
            Ok(r) => {
                issues.push(format!(
                    "Signature #{idx}: cryptographic signature INVALID — {}",
                    r.error.unwrap_or_else(|| "no detail".into())
                ));
                crypto_ok = false;
            }
            Err(e) => {
                issues.push(format!("Signature #{idx}: signature verify error: {e}"));
                crypto_ok = false;
            }
        }

        // ---- Phase 2b: certificate validity vs. claimed signing time ----
        match certilens_crypto::extract_signer_certificate(&cms) {
            Ok(cert) => {
                if cert.is_expired {
                    if let Some(claimed) = sig.claimed_time.as_deref() {
                        if claimed.starts_with("D:") && claimed.len() >= 10 {
                            let claimed_ymd = &claimed[2..10];
                            let not_after_ymd: String = cert
                                .not_after
                                .chars()
                                .filter(|c| c.is_ascii_digit())
                                .take(8)
                                .collect();
                            if claimed_ymd > not_after_ymd.as_str() {
                                issues.push(format!(
                                    "Signature #{idx}: certificate expired {} but the claimed signing time is {}",
                                    cert.not_after, claimed
                                ));
                                validity_ok = false;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                issues.push(format!("Signature #{idx}: no signer certificate: {e}"));
                validity_ok = false;
            }
        }

        // ---- Phase 2d: chain (with trust store) ----
        match certilens_crypto::verify_certificate_chain(&cms, trust_store.as_ref()) {
            Ok(report) => {
                if !report.reached_trusted_root {
                    let detail = if let Some(m) = report.missing_issuer {
                        format!("issuer not found in CMS or trust store: {m}")
                    } else if report.reaches_root {
                        "chain reaches a self-signed root not in the trust store".to_string()
                    } else {
                        "chain does not reach a trusted root".to_string()
                    };
                    issues.push(format!(
                        "Signature #{idx}: certificate chain incomplete — {detail}"
                    ));
                    chain_ok = false;
                }
            }
            Err(e) => {
                issues.push(format!("Signature #{idx}: chain verify error: {e}"));
                chain_ok = false;
            }
        }
    }

    // ---- Verdict ----
    let (status, headline, subtitle) = if !any_sig {
        (
            VerificationStatus::Unknown,
            "No digital signatures found".to_string(),
            "The document does not claim to be signed. Nothing to verify.".to_string(),
        )
    } else if !crypto_ok {
        (
            VerificationStatus::Invalid,
            "Signature invalid".to_string(),
            "The cryptographic signature or content digest did not verify.".to_string(),
        )
    } else if !validity_ok || !chain_ok {
        (
            VerificationStatus::Untrusted,
            "Signature valid, trust unresolved".to_string(),
            "The content and signature check out. Trust could not be established.".to_string(),
        )
    } else {
        (
            VerificationStatus::Verified,
            "Signature verified".to_string(),
            "All checks passed.".to_string(),
        )
    };

    Ok(PyVerificationResult {
        inner: VerificationResult {
            status,
            headline,
            subtitle,
            issues,
        },
    })
}

/// Check the digest for signature `index` on the given PDF.
#[pyfunction]
fn check_signature_digest<'py>(
    py: Python<'py>,
    path: &str,
    index: usize,
) -> PyResult<Bound<'py, PyDict>> {
    let raw = std::fs::read(path).map_err(|e| PyIOError::new_err(format!("read failed: {e}")))?;

    let info = certilens_pdf::inspect(std::path::Path::new(path))
        .map_err(|e| PyRuntimeError::new_err(format!("inspect failed: {e}")))?;

    let sig = info.signature_details.get(index).ok_or_else(|| {
        PyRuntimeError::new_err(format!(
            "no signature at index {index} (found {})",
            info.signature_details.len()
        ))
    })?;

    let br = sig
        .byte_range
        .as_ref()
        .ok_or_else(|| PyRuntimeError::new_err("signature has no ByteRange"))?;

    let (off, hex_len) = match (sig.contents_offset, sig.contents_hex_length) {
        (Some(a), Some(b)) => (a, b),
        _ => return Err(PyRuntimeError::new_err("/Contents offset unknown")),
    };

    let cms = certilens_pdf::extract_cms_bytes(&raw, off, hex_len)
        .map_err(|e| PyRuntimeError::new_err(format!("CMS extract failed: {e}")))?;

    let result = certilens_crypto::check_digest(&raw, br, &cms)
        .map_err(|e| PyRuntimeError::new_err(format!("digest check failed: {e}")))?;

    let out = PyDict::new_bound(py);
    out.set_item("algorithm", result.algorithm)?;
    out.set_item("computed", PyBytes::new_bound(py, &result.computed))?;
    out.set_item("claimed", PyBytes::new_bound(py, &result.claimed))?;
    out.set_item("matches", result.matches)?;
    Ok(out)
}

/// Extract the signer's X.509 certificate.
#[pyfunction]
fn extract_signer_certificate<'py>(
    py: Python<'py>,
    path: &str,
    index: usize,
) -> PyResult<Bound<'py, PyDict>> {
    let raw = std::fs::read(path).map_err(|e| PyIOError::new_err(format!("read failed: {e}")))?;

    let info = certilens_pdf::inspect(std::path::Path::new(path))
        .map_err(|e| PyRuntimeError::new_err(format!("inspect failed: {e}")))?;

    let sig = info.signature_details.get(index).ok_or_else(|| {
        PyRuntimeError::new_err(format!(
            "no signature at index {index} (found {})",
            info.signature_details.len()
        ))
    })?;

    let (off, hex_len) = match (sig.contents_offset, sig.contents_hex_length) {
        (Some(a), Some(b)) => (a, b),
        _ => return Err(PyRuntimeError::new_err("/Contents offset unknown")),
    };

    let cms = certilens_pdf::extract_cms_bytes(&raw, off, hex_len)
        .map_err(|e| PyRuntimeError::new_err(format!("CMS extract failed: {e}")))?;

    let cert = certilens_crypto::extract_signer_certificate(&cms)
        .map_err(|e| PyRuntimeError::new_err(format!("certificate extract failed: {e}")))?;

    let out = PyDict::new_bound(py);
    out.set_item("subject", cert.subject)?;
    out.set_item("issuer", cert.issuer)?;
    out.set_item("serial_hex", cert.serial_hex)?;
    out.set_item("not_before", cert.not_before)?;
    out.set_item("not_after", cert.not_after)?;
    out.set_item(
        "public_key_algorithm",
        cert.public_key_algorithm_name.unwrap_or("(unknown)"),
    )?;
    out.set_item("public_key_oid", cert.public_key_algorithm_oid)?;
    out.set_item(
        "signature_algorithm",
        cert.signature_algorithm_name.unwrap_or("(unknown)"),
    )?;
    out.set_item("signature_oid", cert.signature_algorithm_oid)?;
    out.set_item("der_length", cert.der_length)?;
    out.set_item("currently_valid", cert.currently_valid)?;
    out.set_item("is_expired", cert.is_expired)?;
    Ok(out)
}

/// Verify the signer's RSA signature over the CMS signed attributes.
#[pyfunction]
fn verify_signature<'py>(
    py: Python<'py>,
    path: &str,
    index: usize,
) -> PyResult<Bound<'py, PyDict>> {
    let raw = std::fs::read(path).map_err(|e| PyIOError::new_err(format!("read failed: {e}")))?;

    let info = certilens_pdf::inspect(std::path::Path::new(path))
        .map_err(|e| PyRuntimeError::new_err(format!("inspect failed: {e}")))?;

    let sig = info.signature_details.get(index).ok_or_else(|| {
        PyRuntimeError::new_err(format!(
            "no signature at index {index} (found {})",
            info.signature_details.len()
        ))
    })?;

    let (off, hex_len) = match (sig.contents_offset, sig.contents_hex_length) {
        (Some(a), Some(b)) => (a, b),
        _ => return Err(PyRuntimeError::new_err("/Contents offset unknown")),
    };

    let cms = certilens_pdf::extract_cms_bytes(&raw, off, hex_len)
        .map_err(|e| PyRuntimeError::new_err(format!("CMS extract failed: {e}")))?;

    let result = certilens_crypto::verify_signer_signature(&cms)
        .map_err(|e| PyRuntimeError::new_err(format!("signature verify failed: {e}")))?;

    let out = PyDict::new_bound(py);
    out.set_item("valid", result.valid)?;
    out.set_item("digest_algorithm", result.digest_algorithm)?;
    out.set_item("signature_length", result.signature_length)?;
    out.set_item("error", result.error)?;
    Ok(out)
}

/// Verify the certificate chain, using the system trust store for
/// issuers that aren't embedded in the CMS.
#[pyfunction]
fn verify_certificate_chain<'py>(
    py: Python<'py>,
    path: &str,
    index: usize,
) -> PyResult<Bound<'py, PyDict>> {
    let raw = std::fs::read(path).map_err(|e| PyIOError::new_err(format!("read failed: {e}")))?;

    let info = certilens_pdf::inspect(std::path::Path::new(path))
        .map_err(|e| PyRuntimeError::new_err(format!("inspect failed: {e}")))?;

    let sig = info.signature_details.get(index).ok_or_else(|| {
        PyRuntimeError::new_err(format!(
            "no signature at index {index} (found {})",
            info.signature_details.len()
        ))
    })?;

    let (off, hex_len) = match (sig.contents_offset, sig.contents_hex_length) {
        (Some(a), Some(b)) => (a, b),
        _ => return Err(PyRuntimeError::new_err("/Contents offset unknown")),
    };

    let cms = certilens_pdf::extract_cms_bytes(&raw, off, hex_len)
        .map_err(|e| PyRuntimeError::new_err(format!("CMS extract failed: {e}")))?;

    // Load the trust store; if it fails, proceed without it.
    let store = certilens_crypto::trust::TrustStore::load_system().ok();

    let report = certilens_crypto::verify_certificate_chain(&cms, store.as_ref())
        .map_err(|e| PyRuntimeError::new_err(format!("chain verify failed: {e}")))?;

    let links = PyList::empty_bound(py);
    for link in report.links {
        let d = PyDict::new_bound(py);
        d.set_item("subject", link.subject)?;
        d.set_item("issuer", link.issuer)?;
        d.set_item("verified", link.signature_verified)?;
        d.set_item("self_signed", link.self_signed)?;
        d.set_item("from_trust_store", link.from_trust_store)?;
        d.set_item("error", link.error)?;
        links.append(d)?;
    }

    let out = PyDict::new_bound(py);
    out.set_item("links", links)?;
    out.set_item("reaches_root", report.reaches_root)?;
    out.set_item("root_subject", report.root_subject)?;
    out.set_item("missing_issuer", report.missing_issuer)?;
    out.set_item("reached_trusted_root", report.reached_trusted_root)?;
    out.set_item(
        "trust_store_loaded",
        store.as_ref().map(|s| s.count).unwrap_or(0),
    )?;
    Ok(out)
}

/// The Python module: `import certilens._certilens`.
#[pymodule]
fn _certilens(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyDocument>()?;
    m.add_class::<PyVerificationResult>()?;
    m.add_class::<PyPdfInfo>()?;
    m.add_class::<PySignatureField>()?;
    m.add_class::<PySignatureDetails>()?;
    m.add_function(wrap_pyfunction!(open_document, m)?)?;
    m.add_function(wrap_pyfunction!(assess_document, m)?)?;
    m.add_function(wrap_pyfunction!(check_signature_digest, m)?)?;
    m.add_function(wrap_pyfunction!(extract_signer_certificate, m)?)?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;
    m.add_function(wrap_pyfunction!(verify_certificate_chain, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
