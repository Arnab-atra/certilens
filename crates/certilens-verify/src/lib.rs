//! CertiLens verification orchestration.
//!
//! This crate coordinates PDF inspection and cryptographic verification.
//! CMS/X.509 implementation details remain inside `certilens-crypto`.

use std::path::Path;
use std::sync::OnceLock;

use certilens_core::{VerificationResult, VerificationStatus};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PDF inspection failed: {0}")]
    Pdf(#[from] certilens_pdf::PdfError),
}

#[derive(Debug)]
pub struct Assessment {
    pub verdict: VerificationResult,
    pub signatures: Vec<SignatureReport>,
}

#[derive(Debug)]
pub struct SignatureReport {
    pub field_name: String,
    pub filter: Option<String>,
    pub sub_filter: Option<String>,
    pub claimed_signer: Option<String>,
    pub claimed_time: Option<String>,
    pub reason: Option<String>,
    pub location: Option<String>,
    pub byte_range: Option<Vec<i64>>,
    pub contents_size: usize,
    pub rect: Option<[f64; 4]>,
    pub page_number: Option<usize>,
    pub integrity: CheckOutcome,
    pub signature: CheckOutcome,
    pub certificate: CertificateSummary,
    pub chain: ChainSummary,
}

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
            details: Vec::new(),
        }
    }
}

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

/// Load the system trust store once and cache the certificates.
fn system_trust_certificates() -> &'static [x509_cert::Certificate] {
    static TRUST_CERTS: OnceLock<Vec<x509_cert::Certificate>> = OnceLock::new();

    TRUST_CERTS.get_or_init(
        || match certilens_crypto::trust::TrustStore::load_system() {
            Ok(store) => {
                eprintln!(
                    "Loaded system trust store from {:?} ({} certificates)",
                    store.source_path, store.count
                );
                store.all_certificates()
            }
            Err(e) => {
                eprintln!("Could not load system trust store: {e}");
                Vec::new()
            }
        },
    )
}

/// Verify a PDF document.
pub fn assess(path: &Path) -> Result<Assessment, VerifyError> {
    let raw = std::fs::read(path)?;
    let info = certilens_pdf::inspect(path)?;

    let mut issues = Vec::new();
    let mut reports = Vec::new();

    let mut any_signature = false;
    let mut crypto_ok = true;
    let mut validity_ok = true;
    let mut chain_ok = true;

    // Load system CAs once for the whole document.
    let trust_certs = system_trust_certificates();

    for (idx, sig) in info.signature_details.iter().enumerate() {
        any_signature = true;

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

        // ---------------------------------------------------------------
        // CMS extraction
        // ---------------------------------------------------------------

        let (contents_offset, contents_hex_length) =
            match (sig.contents_offset, sig.contents_hex_length) {
                (Some(offset), Some(length)) => (offset, length),
                _ => {
                    let msg = format!("Signature #{idx}: /Contents offset unknown");

                    issues.push(msg.clone());

                    report.integrity = CheckOutcome {
                        passed: false,
                        summary: msg,
                        details: Vec::new(),
                    };

                    crypto_ok = false;
                    reports.push(report);
                    continue;
                }
            };

        let cms = match certilens_pdf::extract_cms_bytes(&raw, contents_offset, contents_hex_length)
        {
            Ok(cms) => cms,
            Err(error) => {
                let msg = format!("Signature #{idx}: could not extract CMS: {error}");

                issues.push(msg.clone());

                report.integrity = CheckOutcome {
                    passed: false,
                    summary: msg,
                    details: Vec::new(),
                };

                crypto_ok = false;
                reports.push(report);
                continue;
            }
        };

        // ---------------------------------------------------------------
        // ByteRange
        // ---------------------------------------------------------------

        let byte_range = match sig.byte_range.as_ref() {
            Some(range) => range,
            None => {
                let msg = format!("Signature #{idx}: no ByteRange");

                issues.push(msg.clone());

                report.integrity = CheckOutcome {
                    passed: false,
                    summary: msg,
                    details: Vec::new(),
                };

                crypto_ok = false;
                reports.push(report);
                continue;
            }
        };

        // ---------------------------------------------------------------
        // Document digest
        // ---------------------------------------------------------------

        report.integrity = match certilens_crypto::check_digest(&raw, byte_range, &cms) {
            Ok(result) if result.matches => CheckOutcome {
                passed: true,
                summary: format!("{} digest matches", result.algorithm),
                details: vec![format!("Computed: {}", hex(&result.computed))],
            },

            Ok(result) => {
                let msg = format!("Signature #{idx}: digest mismatch");

                issues.push(msg);

                crypto_ok = false;

                CheckOutcome {
                    passed: false,
                    summary: "digest mismatch — signed document bytes differ".into(),
                    details: vec![
                        format!("Computed:   {}", hex(&result.computed)),
                        format!("CMS claims: {}", hex(&result.claimed)),
                    ],
                }
            }

            Err(error) => {
                let msg = format!("Signature #{idx}: digest check failed: {error}");

                issues.push(msg.clone());

                crypto_ok = false;

                CheckOutcome {
                    passed: false,
                    summary: msg,
                    details: Vec::new(),
                }
            }
        };

        // ---------------------------------------------------------------
        // CMS signature
        // ---------------------------------------------------------------

        report.signature = match certilens_crypto::verify_signer_signature(&cms) {
            Ok(result) if result.valid => CheckOutcome {
                passed: true,
                summary: format!(
                    "{} signature verifies ({} bytes)",
                    result.digest_algorithm.unwrap_or("RSA-SHA256"),
                    result.signature_length
                ),
                details: Vec::new(),
            },

            Ok(result) => {
                let detail = result
                    .error
                    .clone()
                    .unwrap_or_else(|| "signature did not verify".into());

                let msg = format!(
                    "Signature #{idx}: cryptographic signature invalid — \
                         {detail}"
                );

                issues.push(msg);

                crypto_ok = false;

                CheckOutcome {
                    passed: false,
                    summary: detail,
                    details: Vec::new(),
                }
            }

            Err(error) => {
                let msg = format!("Signature #{idx}: signature verification error: {error}");

                issues.push(msg.clone());

                crypto_ok = false;

                CheckOutcome {
                    passed: false,
                    summary: msg,
                    details: Vec::new(),
                }
            }
        };

        // ---------------------------------------------------------------
        // Signer certificate
        // ---------------------------------------------------------------

        let signer = match certilens_crypto::extract_signer_certificate(&cms) {
            Ok(value) => value,
            Err(error) => {
                let msg = format!("Signature #{idx}: no signer certificate: {error}");

                issues.push(msg.clone());
                validity_ok = false;

                report.certificate = CertificateSummary {
                    present: false,
                    validity_note: msg,
                    ..Default::default()
                };

                reports.push(report);
                continue;
            }
        };

        // The crypto crate owns the X.509 implementation type. Convert it
        // into a display-friendly public structure there.
        let certificate_info = certilens_crypto::certificate_summary(&signer.certificate);

        report.certificate = CertificateSummary {
            present: true,
            subject: certificate_info.subject,
            issuer: certificate_info.issuer,
            serial: certificate_info.serial,
            not_before: certificate_info.not_before,
            not_after: certificate_info.not_after,
            public_key_algo: certificate_info.public_key_algo,
            signature_algo: certificate_info.signature_algo,
            der_length: certificate_info.der_length,
            validity_note: certificate_info.validity_note,
            signing_time_note: None,
        };

        // ---------------------------------------------------------------
        // Certificate chain (with system trust store)
        // ---------------------------------------------------------------

        let chain = certilens_crypto::verify_certificate_chain_from_cms(
            &signer.certificate,
            &cms,
            trust_certs,
        );

        let links = chain
            .links
            .iter()
            .map(|link| ChainLinkSummary {
                subject: link.subject.clone(),
                issuer: link.issuer.clone(),
                verified: link.signature_valid,
                self_signed: link.subject == link.issuer,
                from_trust_store: link.trusted,
                error: link.error.clone(),
            })
            .collect::<Vec<_>>();

        let root_subject = chain
            .links
            .iter()
            .rev()
            .find(|link| link.subject == link.issuer)
            .map(|link| link.subject.clone());

        let missing_issuer = chain
            .error
            .as_deref()
            .filter(|error| error.to_ascii_lowercase().contains("issuer"))
            .map(str::to_owned);

        let note = if chain.trusted {
            "certificate chain verified to a trusted certificate".into()
        } else if chain.valid {
            chain_ok = false;

            issues.push(format!(
                "Signature #{idx}: certificate chain is cryptographically \
                 valid but trust could not be established"
            ));

            "certificate chain signatures are valid, but no trusted \
             certificate was found in the system store"
                .into()
        } else if let Some(error) = chain.error.as_deref() {
            chain_ok = false;

            issues.push(format!(
                "Signature #{idx}: certificate chain verification failed: \
                 {error}"
            ));

            format!("certificate chain verification failed: {error}")
        } else {
            chain_ok = false;

            issues.push(format!(
                "Signature #{idx}: certificate chain could not be established"
            ));

            "certificate chain could not be established".into()
        };

        report.chain = ChainSummary {
            reached_trusted_root: chain.trusted,
            root_subject,
            missing_issuer,
            links,
            note,
        };

        reports.push(report);
    }

    // ---------------------------------------------------------------
    // Final verdict
    // ---------------------------------------------------------------

    let (status, headline, subtitle) = if !any_signature {
        (
            VerificationStatus::Unknown,
            "No digital signatures found",
            "The document does not contain a digital signature that \
             CertiLens can verify.",
        )
    } else if !crypto_ok {
        (
            VerificationStatus::Invalid,
            "Signature invalid",
            "The cryptographic signature or signed document digest \
             did not verify.",
        )
    } else if !validity_ok || !chain_ok {
        (
            VerificationStatus::Untrusted,
            "Signature valid, trust unresolved",
            "The cryptographic signature is valid, but certificate \
             validity or trust could not be fully established.",
        )
    } else {
        (
            VerificationStatus::Verified,
            "Signature verified",
            "The signature and certificate checks passed.",
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
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
