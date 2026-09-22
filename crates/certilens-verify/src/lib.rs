//! CertiLens verification orchestration.
//!
//! Ties together the PDF parser, the crypto layer, and the trust store,
//! and produces a single `Assessment` — a verdict plus per-signature
//! evidence.

use std::path::Path;

use certilens_core::{VerificationResult, VerificationStatus};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PDF inspection failed: {0}")]
    Pdf(#[from] certilens_pdf::PdfError),
}

/// Top-level result: a verdict, plus the evidence behind it.
#[derive(Debug)]
pub struct Assessment {
    pub verdict: VerificationResult,
    pub signatures: Vec<SignatureReport>,
}

/// Everything we learned about one signature.
#[derive(Debug)]
pub struct SignatureReport {
    // Claims from the PDF dictionary
    pub field_name: String,
    pub filter: Option<String>,
    pub sub_filter: Option<String>,
    pub claimed_signer: Option<String>,
    pub claimed_time: Option<String>,
    pub reason: Option<String>,
    pub location: Option<String>,
    pub byte_range: Option<Vec<i64>>,
    pub contents_size: usize,

    // Where does this signature appear on the page?
    pub rect: Option<[f64; 4]>,
    pub page_number: Option<usize>,

    // Check results
    pub integrity: CheckOutcome,
    pub signature: CheckOutcome,
    pub certificate: CertificateSummary,
    pub chain: ChainSummary,
}

/// The outcome of a single check (integrity, signature, ...).
#[derive(Debug)]
pub struct CheckOutcome {
    pub passed: bool,
    pub summary: String,
    pub details: Vec<String>,
}

impl CheckOutcome {
    fn not_run() -> Self {
        Self {
            passed: false,
            summary: "not run".into(),
            details: vec![],
        }
    }
}

/// Summary of the signer's certificate.
#[derive(Debug, Default)]
pub struct CertificateSummary {
    pub present: bool,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub public_key_algo: String,
    pub signature_algo: String,
    pub der_length: usize,
    pub validity_note: String,
    pub signing_time_note: Option<String>,
}

/// Summary of the certificate chain walk.
#[derive(Debug, Default)]
pub struct ChainSummary {
    pub reached_trusted_root: bool,
    pub root_subject: Option<String>,
    pub missing_issuer: Option<String>,
    pub links: Vec<ChainLinkSummary>,
    pub note: String,
}

#[derive(Debug)]
pub struct ChainLinkSummary {
    pub subject: String,
    pub issuer: String,
    pub verified: bool,
    pub self_signed: bool,
    pub from_trust_store: bool,
    pub error: Option<String>,
}

/// Run every available check on the document at `path`.
pub fn assess(path: &Path) -> Result<Assessment, VerifyError> {
    let raw = std::fs::read(path)?;
    let info = certilens_pdf::inspect(path)?;

    let mut issues: Vec<String> = Vec::new();
    let mut reports: Vec<SignatureReport> = Vec::new();
    let mut any_sig = false;

    let mut crypto_ok = true;
    let mut validity_ok = true;
    let mut chain_ok = true;

    let trust_store = certilens_crypto::trust::TrustStore::load_system().ok();

    for (idx, sig) in info.signature_details.iter().enumerate() {
        any_sig = true;

        let mut report = SignatureReport {
            field_name: sig.field_name.clone(),
            filter: sig.filter.clone(),
            sub_filter: sig.sub_filter.clone(),
            claimed_signer: sig.claimed_signer.clone(),
            claimed_time: sig.claimed_time.clone(),
            reason: sig.reason.clone(),
            location: sig.location.clone(),
            byte_range: sig.byte_range.clone(),
            contents_size: sig.contents_size,
            rect: sig.rect,
            page_number: sig.page_number,
            integrity: CheckOutcome::not_run(),
            signature: CheckOutcome::not_run(),
            certificate: CertificateSummary::default(),
            chain: ChainSummary::default(),
        };

        // ---- Extract CMS bytes ----
        let (off, hex_len) = match (sig.contents_offset, sig.contents_hex_length) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                let msg = format!("Signature #{idx}: /Contents offset unknown");
                issues.push(msg.clone());
                report.integrity = CheckOutcome {
                    passed: false,
                    summary: msg,
                    details: vec![],
                };
                crypto_ok = false;
                reports.push(report);
                continue;
            }
        };

        let cms = match certilens_pdf::extract_cms_bytes(&raw, off, hex_len) {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("Signature #{idx}: could not extract CMS: {e}");
                issues.push(msg.clone());
                report.integrity = CheckOutcome {
                    passed: false,
                    summary: msg,
                    details: vec![],
                };
                crypto_ok = false;
                reports.push(report);
                continue;
            }
        };

        let br = match sig.byte_range.as_ref() {
            Some(b) => b,
            None => {
                let msg = format!("Signature #{idx}: no ByteRange");
                issues.push(msg.clone());
                report.integrity = CheckOutcome {
                    passed: false,
                    summary: msg,
                    details: vec![],
                };
                crypto_ok = false;
                reports.push(report);
                continue;
            }
        };

        // ---- Integrity (SHA-256 of ByteRange vs CMS digest) ----
        report.integrity = match certilens_crypto::check_digest(&raw, br, &cms) {
            Ok(d) if d.matches => CheckOutcome {
                passed: true,
                summary: format!("{} digest matches", d.algorithm.unwrap_or("SHA-256")),
                details: vec![format!("Computed: {}", hex(&d.computed))],
            },
            Ok(d) => {
                let msg = format!(
                    "Signature #{idx}: SHA-256 digest MISMATCH — document was modified after signing"
                );
                issues.push(msg.clone());
                crypto_ok = false;
                CheckOutcome {
                    passed: false,
                    summary: "digest mismatch — document was modified".into(),
                    details: vec![
                        format!("Computed:   {}", hex(&d.computed)),
                        format!("CMS claims: {}", hex(&d.claimed)),
                    ],
                }
            }
            Err(e) => {
                let msg = format!("Signature #{idx}: digest check failed: {e}");
                issues.push(msg.clone());
                crypto_ok = false;
                CheckOutcome {
                    passed: false,
                    summary: msg,
                    details: vec![],
                }
            }
        };

        // ---- Signature (RSA over signed attributes) ----
        report.signature = match certilens_crypto::verify_signer_signature(&cms) {
            Ok(r) if r.valid => CheckOutcome {
                passed: true,
                summary: format!(
                    "{} signature verifies ({} bytes)",
                    r.digest_algorithm.unwrap_or("RSA"),
                    r.signature_length,
                ),
                details: vec![],
            },
            Ok(r) => {
                let detail = r
                    .error
                    .clone()
                    .unwrap_or_else(|| "signature did not verify".into());
                let msg = format!("Signature #{idx}: cryptographic signature INVALID — {detail}");
                issues.push(msg.clone());
                crypto_ok = false;
                CheckOutcome {
                    passed: false,
                    summary: detail,
                    details: vec![],
                }
            }
            Err(e) => {
                let msg = format!("Signature #{idx}: signature verify error: {e}");
                issues.push(msg.clone());
                crypto_ok = false;
                CheckOutcome {
                    passed: false,
                    summary: msg,
                    details: vec![],
                }
            }
        };

        // ---- Certificate ----
        match certilens_crypto::extract_signer_certificate(&cms) {
            Ok(cert) => {
                let mut summary = CertificateSummary {
                    present: true,
                    subject: cert.subject.clone(),
                    issuer: cert.issuer.clone(),
                    serial: cert.serial_hex.clone(),
                    not_before: cert.not_before.clone(),
                    not_after: cert.not_after.clone(),
                    public_key_algo: cert.public_key_algorithm_name.unwrap_or("unknown").into(),
                    signature_algo: cert.signature_algorithm_name.unwrap_or("unknown").into(),
                    der_length: cert.der_length,
                    validity_note: String::new(),
                    signing_time_note: None,
                };

                if cert.is_expired {
                    summary.validity_note = format!("expired {}", cert.not_after);
                } else if cert.currently_valid {
                    summary.validity_note = "currently valid".into();
                } else {
                    summary.validity_note = format!("not yet valid (starts {})", cert.not_before);
                }

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
                                summary.signing_time_note = Some(format!(
                                    "claimed signing time ({claimed}) is AFTER certificate expiry"
                                ));
                                issues.push(format!(
                                    "Signature #{idx}: certificate expired {} but the claimed signing time is {}",
                                    cert.not_after, claimed
                                ));
                                validity_ok = false;
                            }
                        }
                    }
                }

                report.certificate = summary;
            }
            Err(e) => {
                let msg = format!("Signature #{idx}: no signer certificate: {e}");
                issues.push(msg.clone());
                validity_ok = false;
                report.certificate = CertificateSummary {
                    validity_note: msg,
                    ..Default::default()
                };
            }
        }

        // ---- Chain ----
        match certilens_crypto::verify_certificate_chain(&cms, trust_store.as_ref()) {
            Ok(cr) => {
                let mut chain_summary = ChainSummary {
                    reached_trusted_root: cr.reached_trusted_root,
                    root_subject: cr.root_subject.clone(),
                    missing_issuer: cr.missing_issuer.clone(),
                    links: cr
                        .links
                        .iter()
                        .map(|l| ChainLinkSummary {
                            subject: l.subject.clone(),
                            issuer: l.issuer.clone(),
                            verified: l.signature_verified,
                            self_signed: l.self_signed,
                            from_trust_store: l.from_trust_store,
                            error: l.error.clone(),
                        })
                        .collect(),
                    note: String::new(),
                };

                if cr.reached_trusted_root {
                    chain_summary.note = "chain verified to a trusted root".into();
                } else if let Some(m) = &cr.missing_issuer {
                    chain_summary.note = format!("issuer not found: {m}");
                    issues.push(format!(
                        "Signature #{idx}: certificate chain incomplete — issuer not found in CMS or trust store: {m}"
                    ));
                    chain_ok = false;
                } else if cr.reaches_root {
                    chain_summary.note =
                        "chain reaches a self-signed root not in the trust store".into();
                    issues.push(format!(
                        "Signature #{idx}: certificate chain incomplete — chain reaches a self-signed root not in the trust store"
                    ));
                    chain_ok = false;
                } else {
                    chain_summary.note = "chain does not reach a trusted root".into();
                    issues.push(format!(
                        "Signature #{idx}: certificate chain incomplete — chain does not reach a trusted root"
                    ));
                    chain_ok = false;
                }

                report.chain = chain_summary;
            }
            Err(e) => {
                let msg = format!("Signature #{idx}: chain verify error: {e}");
                issues.push(msg.clone());
                chain_ok = false;
                report.chain = ChainSummary {
                    note: msg,
                    ..Default::default()
                };
            }
        }

        reports.push(report);
    }

    // ---- Verdict ----
    let (status, headline, subtitle) = if !any_sig {
        (
            VerificationStatus::Unknown,
            "No digital signatures found",
            "The document does not claim to be signed. Nothing to verify.",
        )
    } else if !crypto_ok {
        (
            VerificationStatus::Invalid,
            "Signature invalid",
            "The cryptographic signature or content digest did not verify.",
        )
    } else if !validity_ok || !chain_ok {
        (
            VerificationStatus::Untrusted,
            "Signature valid, trust unresolved",
            "The content and signature check out. Trust could not be established.",
        )
    } else {
        (
            VerificationStatus::Verified,
            "Signature verified",
            "All checks passed.",
        )
    };

    Ok(Assessment {
        verdict: VerificationResult {
            status,
            headline: headline.to_string(),
            subtitle: subtitle.to_string(),
            issues,
        },
        signatures: reports,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
