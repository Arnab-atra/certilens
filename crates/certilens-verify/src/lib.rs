//! CertiLens verification orchestration.
//!
//! This crate ties together the PDF parser, the crypto layer, and the
//! trust store, and produces a single `VerificationResult`.
//!
//! It does not do any cryptographic work itself — it calls into
//! `certilens-crypto` for that. It does not do any PDF parsing itself —
//! it calls into `certilens-pdf`. Its only job is to sequence the
//! checks and assemble the verdict.

use std::path::Path;

use certilens_core::{VerificationResult, VerificationStatus};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PDF inspection failed: {0}")]
    Pdf(#[from] certilens_pdf::PdfError),
}

/// Run every available check on the document at `path` and produce a
/// verdict.
///
/// This is the top-level orchestration function. Everything the GUI
/// needs to display a result comes out of here.
///
/// # Arguments
/// * `path` — path to the PDF file
///
/// # Returns
/// * `Ok(VerificationResult)` — the document was inspected and assessed
/// * `Err(VerifyError)` — we couldn't even read/inspect the file
pub fn assess(path: &Path) -> Result<VerificationResult, VerifyError> {
    let raw = std::fs::read(path)?;
    let info = certilens_pdf::inspect(path)?;

    let mut issues: Vec<String> = Vec::new();
    let mut any_sig = false;

    // Three independent axes of trust. Failure in one doesn't imply the
    // others failed, so we track them separately and combine at the end.
    let mut crypto_ok = true; // digest match + RSA signature
    let mut validity_ok = true; // cert valid at claimed signing time
    let mut chain_ok = true; // chain reaches a trusted root

    // Load the OS trust store once, before the loop.
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

        // ---- Phase 2a: SHA-256 digest of the signed bytes ----
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

        // ---- Phase 2c: RSA signature over the signed attributes ----
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

        // ---- Phase 2d: certificate chain to a trusted root ----
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

    // ---- Assemble the verdict ----
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

    Ok(VerificationResult {
        status,
        headline,
        subtitle,
        issues,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_returns_io_error() {
        let result = assess(Path::new("/definitely/does/not/exist.pdf"));
        assert!(matches!(result, Err(VerifyError::Io(_))));
    }
}
