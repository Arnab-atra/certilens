//! CertiLens cryptographic verification primitives.
//!
//! This crate contains the low-level cryptographic operations used by
//! CertiLens to inspect and verify digitally signed PDF documents.
//!
//! Current cryptographic support:
//!
//! - SHA-256 PDF `/ByteRange` hashing.
//! - CMS `messageDigest` extraction.
//! - CMS SHA-256 digest validation.
//! - CMS RSA/SHA-256 signature verification.
//! - X.509 RSA/SHA-256 certificate-signature verification.
//! - Basic certificate-chain walking.
//!
//! Deliberately unsupported algorithms are reported explicitly instead of
//! silently falling back to another algorithm.
//!
//! # Security model
//!
//! This module performs cryptographic verification and basic certificate
//! chaining. It does not yet implement the complete PKIX validation model.
//!
//! In particular, certificate-chain verification currently does not provide:
//!
//! - CRL checking.
//! - OCSP checking.
//! - Certificate policy processing.
//! - Name constraints.
//! - Complete BasicConstraints processing.
//! - Complete KeyUsage / ExtendedKeyUsage policy enforcement.
//! - Full certificate validity-time enforcement.
//!
//! Those checks belong in the higher-level verification engine.

use std::collections::HashSet;

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use der::asn1::OctetString;
use der::{Decode, DecodePem, Encode};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use x509_cert::attr::Attribute;
use x509_cert::Certificate;

pub mod curated_cas;
pub mod trust;

// ============================================================================
// Supported algorithm OIDs
// ============================================================================

/// PKCS#9 messageDigest attribute.
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";

/// SHA-1.
const OID_SHA1: &str = "1.3.14.3.2.26";

/// SHA-256.
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";

/// SHA-384.
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";

/// SHA-512.
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";

/// RSA encryption public-key algorithm.
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";

/// RSA PKCS#1 v1.5 with SHA-256.
const OID_SHA256_RSA: &str = "1.2.840.113549.1.1.11";

// ============================================================================
// PDF ByteRange hashing
// ============================================================================

/// Errors produced while processing a PDF `/ByteRange`.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The ByteRange vector contains no entries.
    #[error("byte range cannot be empty")]
    EmptyByteRange,

    /// The ByteRange vector must contain offset/length pairs.
    #[error("byte range array must contain an even number of values")]
    OddByteRangeLength,

    /// A negative offset or length was supplied.
    #[error("byte range contains a negative value")]
    NegativeByteRange,

    /// A numeric conversion or arithmetic operation failed.
    #[error("invalid byte range: {0}")]
    InvalidByteRange(String),

    /// A requested range extends beyond the PDF.
    #[error("byte range exceeds input length")]
    ByteRangeOutOfBounds,
}

/// Hash the bytes selected by a PDF `/ByteRange`.
pub fn hash_byte_ranges(raw_pdf: &[u8], byte_range: &[i64]) -> Result<[u8; 32], CryptoError> {
    if byte_range.is_empty() {
        return Err(CryptoError::EmptyByteRange);
    }

    if byte_range.len() % 2 != 0 {
        return Err(CryptoError::OddByteRangeLength);
    }

    let mut hasher = Sha256::new();

    for pair in byte_range.chunks_exact(2) {
        let offset = pair[0];
        let length = pair[1];

        if offset < 0 || length < 0 {
            return Err(CryptoError::NegativeByteRange);
        }

        let offset = usize::try_from(offset).map_err(|_| {
            CryptoError::InvalidByteRange("offset does not fit into usize".to_string())
        })?;

        let length = usize::try_from(length).map_err(|_| {
            CryptoError::InvalidByteRange("length does not fit into usize".to_string())
        })?;

        let end = offset
            .checked_add(length)
            .ok_or_else(|| CryptoError::InvalidByteRange("offset + length overflow".to_string()))?;

        if end > raw_pdf.len() {
            return Err(CryptoError::ByteRangeOutOfBounds);
        }

        hasher.update(&raw_pdf[offset..end]);
    }

    Ok(hasher.finalize().into())
}

// ============================================================================
// CMS parsing
// ============================================================================

/// Information extracted from a CMS SignerInfo.
#[derive(Debug, Clone)]
pub struct CmsDigestInfo {
    pub digest_algorithm_oid: String,
    pub digest_algorithm_name: &'static str,
    pub claimed_digest: Vec<u8>,
}

/// Errors produced while parsing CMS digest information.
#[derive(Debug, thiserror::Error)]
pub enum CmsParseError {
    #[error("DER parsing failed: {0}")]
    Der(#[from] der::Error),

    #[error("CMS content is not SignedData")]
    NotSignedData,

    #[error("CMS contains no SignerInfo")]
    NoSignerInfo,

    #[error("SignerInfo has no signed attributes")]
    NoSignedAttrs,

    #[error("messageDigest attribute was not found")]
    NoMessageDigest,

    #[error("messageDigest attribute has invalid value")]
    InvalidMessageDigest,
}

/// Parse a CMS object and extract the signer's claimed `messageDigest`.
pub fn parse_cms_digest(cms_bytes: &[u8]) -> Result<CmsDigestInfo, CmsParseError> {
    let trimmed = trim_to_der_length(cms_bytes);

    let content_info = ContentInfo::from_der(trimmed)?;

    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|_| CmsParseError::NotSignedData)?;

    let signer: &SignerInfo = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(CmsParseError::NoSignerInfo)?;

    let digest_algorithm_oid = signer.digest_alg.oid.to_string();
    let digest_algorithm_name = name_for(&digest_algorithm_oid);

    let signed_attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or(CmsParseError::NoSignedAttrs)?;

    for attr in signed_attrs.iter() {
        if attr.oid.to_string() != OID_MESSAGE_DIGEST {
            continue;
        }

        let digest = extract_octet_string(attr).ok_or(CmsParseError::InvalidMessageDigest)?;

        return Ok(CmsDigestInfo {
            digest_algorithm_oid,
            digest_algorithm_name,
            claimed_digest: digest,
        });
    }

    Err(CmsParseError::NoMessageDigest)
}

// ============================================================================
// Digest verification
// ============================================================================

/// Errors produced during PDF/CMS digest verification.
#[derive(Debug, thiserror::Error)]
pub enum DigestCheckError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Cms(#[from] CmsParseError),

    #[error("unsupported digest algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Result of comparing a PDF ByteRange digest with the CMS digest.
#[derive(Debug, Clone)]
pub struct DigestCheckResult {
    pub algorithm: &'static str,
    pub computed: Vec<u8>,
    pub claimed: Vec<u8>,
    pub matches: bool,
}

/// Verify the PDF ByteRange digest against the CMS `messageDigest`.
pub fn check_digest(
    raw_pdf: &[u8],
    byte_range: &[i64],
    cms_bytes: &[u8],
) -> Result<DigestCheckResult, DigestCheckError> {
    let info = parse_cms_digest(cms_bytes)?;

    if info.digest_algorithm_oid != OID_SHA256 {
        return Err(DigestCheckError::UnsupportedAlgorithm(
            info.digest_algorithm_oid,
        ));
    }

    let computed = hash_byte_ranges(raw_pdf, byte_range)?;

    // Check lengths before comparing contents.
    let matches = computed.len() == info.claimed_digest.len()
        && computed.as_slice() == info.claimed_digest.as_slice();

    Ok(DigestCheckResult {
        algorithm: info.digest_algorithm_name,
        computed: computed.to_vec(),
        claimed: info.claimed_digest,
        matches,
    })
}

// ============================================================================
// Signer certificate extraction
// ============================================================================

/// Certificate extracted from a CMS SignedData object.
#[derive(Debug, Clone)]
pub struct SignerCertificate {
    pub certificate: Certificate,
}

/// Errors produced while extracting a certificate from CMS.
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    #[error("DER parsing failed: {0}")]
    Der(#[from] der::Error),

    #[error("CMS is not SignedData")]
    NotSignedData,

    #[error("CMS contains no certificates")]
    NoCertificates,

    #[error("CMS contains no X.509 certificate")]
    NoCertificate,
}

/// Extract the first X.509 certificate from CMS SignedData.
pub fn extract_signer_certificate(cms_bytes: &[u8]) -> Result<SignerCertificate, CertificateError> {
    let trimmed = trim_to_der_length(cms_bytes);

    let content_info = ContentInfo::from_der(trimmed)?;

    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|_| CertificateError::NotSignedData)?;

    let certificates = signed_data
        .certificates
        .as_ref()
        .ok_or(CertificateError::NoCertificates)?;

    let certificate = certificates
        .0
        .iter()
        .find_map(|choice| match choice {
            cms::cert::CertificateChoices::Certificate(cert) => Some(cert.clone()),
            _ => None,
        })
        .ok_or(CertificateError::NoCertificate)?;

    Ok(SignerCertificate { certificate })
}

/// Display-friendly certificate information.
#[derive(Debug, Clone)]
pub struct CertificateSummary {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub public_key_algo: String,
    pub signature_algo: String,
    pub der_length: usize,
    pub validity_note: String,
}

/// Convert an X.509 certificate into display-friendly information.
pub fn certificate_summary(cert: &Certificate) -> CertificateSummary {
    let subject = format_dn(&cert.tbs_certificate.subject);
    let issuer = format_dn(&cert.tbs_certificate.issuer);
    let serial = format_serial(&cert.tbs_certificate.serial_number);

    let not_before = cert.tbs_certificate.validity.not_before.to_string();
    let not_after = cert.tbs_certificate.validity.not_after.to_string();

    let public_key_algo = public_key_algo_name(
        &cert
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            .to_string(),
    )
    .to_string();

    let signature_algo = signature_algo_name(&cert.signature_algorithm.oid.to_string()).to_string();

    let der_length = cert.to_der().map(|der| der.len()).unwrap_or(0);

    CertificateSummary {
        subject,
        issuer,
        serial,
        not_before,
        not_after,
        public_key_algo,
        signature_algo,
        der_length,
        validity_note: "certificate extracted; certificate time validity is \
             not yet enforced by the current verification layer"
            .into(),
    }
}

// ============================================================================
// Certificate rendering
// ============================================================================
/// Render a certificate into a human-readable summary.
pub fn render_certificate(cert: &Certificate) -> String {
    let subject = format_dn(&cert.tbs_certificate.subject);
    let issuer = format_dn(&cert.tbs_certificate.issuer);

    let serial = format_serial(&cert.tbs_certificate.serial_number);

    let public_key_algorithm = public_key_algo_name(
        &cert
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            .to_string(),
    );

    let signature_algorithm = signature_algo_name(&cert.signature_algorithm.oid.to_string());

    let not_before = cert.tbs_certificate.validity.not_before.to_string();
    let not_after = cert.tbs_certificate.validity.not_after.to_string();

    format!(
        "Subject: {subject}\n\
         Issuer: {issuer}\n\
         Serial: {serial}\n\
         Public Key: {public_key_algorithm}\n\
         Certificate Signature: {signature_algorithm}\n\
         Valid From: {not_before}\n\
         Valid Until: {not_after}"
    )
}

// ============================================================================
// Time conversion
// ============================================================================

/// Convert a basic ISO-8601 UTC timestamp to Unix seconds.
///
/// This helper is intentionally small and is not intended to replace proper
/// ASN.1 time validation.
///
/// Supported form:
///
/// ```text
/// YYYY-MM-DDTHH:MM:SSZ
/// ```
pub fn iso_to_unix(value: &str) -> Option<i64> {
    let value = value.trim();

    let value = value.strip_suffix('Z').unwrap_or(value);

    let (date, time) = value.split_once('T')?;

    let mut date_parts = date.split('-');

    let year: i32 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;

    let mut time_parts = time.split(':');

    let hour: u32 = time_parts.next()?.parse().ok()?;
    let minute: u32 = time_parts.next()?.parse().ok()?;

    let second_text = time_parts.next()?;
    let second_text = second_text.split('.').next()?;

    let second: u32 = second_text.parse().ok()?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    // Civil date -> Unix days.
    let mut y = year;
    let mut m = month as i32;

    if m <= 2 {
        y -= 1;
        m += 12;
    }

    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };

    let yoe = y - era * 400;
    let mp = m - 3;
    let doy = (153 * mp + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

    let days = era * 146097 + doe - 719468;

    Some(
        i64::from(days) * 86_400
            + i64::from(hour) * 3_600
            + i64::from(minute) * 60
            + i64::from(second),
    )
}

// ============================================================================
// X.509 / ASN.1 formatting helpers
// ============================================================================

/// Render an X.509 distinguished name.
fn format_dn(name: &x509_cert::name::Name) -> String {
    let mut parts = Vec::new();

    for rdn in name.0.iter() {
        for attr in rdn.0.iter() {
            let oid = attr.oid.to_string();

            let key = match oid.as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.6" => "C",
                "2.5.4.7" => "L",
                "2.5.4.8" => "ST",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "2.5.4.17" => "postalCode",
                "1.2.840.113549.1.9.1" => "emailAddress",
                _ => &oid,
            };

            let value = render_any_value(&attr.value);

            parts.push(format!("{key}={value}"));
        }
    }

    parts.join(", ")
}

/// Render an arbitrary ASN.1 value conservatively.
fn render_any_value(value: &der::Any) -> String {
    let bytes = value.value();

    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => format!("#{}", hex_colon(bytes)),
    }
}

/// Format an X.509 serial number.
fn format_serial(serial: &x509_cert::serial_number::SerialNumber) -> String {
    hex_colon(serial.as_bytes())
}

/// Render bytes using colon-separated uppercase hexadecimal.
fn hex_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Return the Common Name from an X.509 Name when available.
fn dn_short_name(name: &x509_cert::name::Name) -> String {
    for rdn in name.0.iter() {
        for attr in rdn.0.iter() {
            if attr.oid.to_string() == "2.5.4.3" {
                return render_any_value(&attr.value);
            }
        }
    }

    format_dn(name)
}

/// Convert a public-key algorithm OID into a readable name.
fn public_key_algo_name(oid: &str) -> &'static str {
    match oid {
        OID_RSA_ENCRYPTION => "RSA",
        "1.2.840.10045.2.1" => "EC",
        "1.2.840.113549.1.1.7" => "RSA-OAEP",
        _ => "Unknown",
    }
}

/// Convert a certificate/signature algorithm OID into a readable name.
fn signature_algo_name(oid: &str) -> &'static str {
    match oid {
        OID_SHA256_RSA => "RSA-SHA256",
        "1.2.840.113549.1.1.5" => "RSA-SHA1",
        "1.2.840.113549.1.1.12" => "RSA-SHA384",
        "1.2.840.113549.1.1.13" => "RSA-SHA512",
        "1.2.840.10045.4.3.2" => "ECDSA-SHA256",
        "1.2.840.10045.4.3.3" => "ECDSA-SHA384",
        "1.2.840.10045.4.3.4" => "ECDSA-SHA512",
        _ => "Unknown",
    }
}

/// Extract an OCTET STRING from an Attribute.
fn extract_octet_string(attr: &Attribute) -> Option<Vec<u8>> {
    for value in attr.values.iter() {
        if let Ok(octets) = value.decode_as::<OctetString>() {
            return Some(octets.as_bytes().to_vec());
        }
    }

    None
}

/// Convert an algorithm OID into a readable name.
fn name_for(oid: &str) -> &'static str {
    match oid {
        OID_SHA1 => "SHA-1",
        OID_SHA256 => "SHA-256",
        OID_SHA384 => "SHA-384",
        OID_SHA512 => "SHA-512",
        OID_RSA_ENCRYPTION => "RSA",
        OID_SHA256_RSA => "RSA-SHA256",
        _ => "Unknown",
    }
}

// ============================================================================
// DER helpers
// ============================================================================

/// Return only the first DER SEQUENCE from a buffer.
pub fn trim_to_der_length(data: &[u8]) -> &[u8] {
    if data.len() < 2 || data[0] != 0x30 {
        return data;
    }

    let first_length = data[1];

    // DER short-form length.
    if first_length & 0x80 == 0 {
        let total_length = match 2usize.checked_add(first_length as usize) {
            Some(value) => value,
            None => return data,
        };

        return if total_length <= data.len() {
            &data[..total_length]
        } else {
            data
        };
    }

    let length_octets = (first_length & 0x7F) as usize;

    // Indefinite-length encoding is not valid DER.
    if length_octets == 0 {
        return data;
    }

    // We intentionally support up to four length bytes.
    if length_octets > 4 {
        return data;
    }

    let header_length = match 2usize.checked_add(length_octets) {
        Some(value) => value,
        None => return data,
    };

    if data.len() < header_length {
        return data;
    }

    let mut content_length = 0usize;

    for byte in &data[2..header_length] {
        content_length = match content_length.checked_shl(8) {
            Some(value) => value | usize::from(*byte),
            None => return data,
        };
    }

    let total_length = match header_length.checked_add(content_length) {
        Some(value) => value,
        None => return data,
    };

    if total_length <= data.len() {
        &data[..total_length]
    } else {
        data
    }
}

// ============================================================================
// CMS signature verification
// ============================================================================

/// Errors produced during CMS signature verification.
#[derive(Debug, thiserror::Error)]
pub enum SignatureVerifyError {
    #[error(transparent)]
    Cms(#[from] CmsParseError),

    #[error("DER parsing failed: {0}")]
    Der(#[from] der::Error),

    #[error("CMS contains no signed attributes")]
    NoSignedAttrs,

    #[error("CMS contains no certificates")]
    NoCertificates,

    #[error("CMS contains no X.509 certificate")]
    NoCertificate,

    #[error("unsupported digest algorithm: {0}")]
    UnsupportedDigest(String),

    #[error("unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),

    #[error("unsupported public key algorithm: {0}")]
    UnsupportedPublicKey(String),

    #[error("RSA public key decode failed: {0}")]
    PublicKeyDecode(String),

    #[error("RSA signature decode failed: {0}")]
    SignatureDecode(String),
}

/// Result of CMS signature verification.
#[derive(Debug, Clone)]
pub struct SignatureVerifyResult {
    pub valid: bool,
    pub digest_algorithm: Option<&'static str>,
    pub signature_length: usize,
    pub error: Option<String>,
}

/// Verify a CMS SignerInfo signature.
pub fn verify_signer_signature(
    cms_bytes: &[u8],
) -> Result<SignatureVerifyResult, SignatureVerifyError> {
    let trimmed = trim_to_der_length(cms_bytes);

    let content_info = ContentInfo::from_der(trimmed)?;

    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|_| CmsParseError::NotSignedData)?;

    let signer: &SignerInfo = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(CmsParseError::NoSignerInfo)?;

    let digest_oid = signer.digest_alg.oid.to_string();
    let digest_name = name_for(&digest_oid);

    let signature_length = signer.signature.as_bytes().len();

    // Digest algorithm
    if digest_oid != OID_SHA256 {
        return Ok(SignatureVerifyResult {
            valid: false,
            digest_algorithm: Some(digest_name),
            signature_length,
            error: Some(format!(
                "digest algorithm {digest_oid} is not supported; \
                 CertiLens currently supports SHA-256"
            )),
        });
    }

    // Signature algorithm — accept both sha256WithRSAEncryption and rsaEncryption
    let signature_algorithm_oid = signer.signature_algorithm.oid.to_string();

    let signature_alg_ok =
        signature_algorithm_oid == OID_SHA256_RSA || signature_algorithm_oid == OID_RSA_ENCRYPTION;

    if !signature_alg_ok {
        return Ok(SignatureVerifyResult {
            valid: false,
            digest_algorithm: Some(digest_name),
            signature_length,
            error: Some(format!(
                "signature algorithm {signature_algorithm_oid} is not \
                 supported; CertiLens currently supports RSA-SHA256 \
                 (or rsaEncryption + SHA-256)"
            )),
        });
    }

    // Signed attributes
    let signed_attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or(SignatureVerifyError::NoSignedAttrs)?;

    let mut signed_attributes_der = signed_attrs.to_der()?;

    if signed_attributes_der.is_empty() {
        return Err(SignatureVerifyError::NoSignedAttrs);
    }

    // CMS SignedAttributes: context-specific [0] → universal SET OF
    if signed_attributes_der[0] == 0xA0 {
        signed_attributes_der[0] = 0x31;
    }

    // Locate signer certificate
    let certificates = signed_data
        .certificates
        .as_ref()
        .ok_or(SignatureVerifyError::NoCertificates)?;

    let certificate = certificates
        .0
        .iter()
        .find_map(|choice| match choice {
            cms::cert::CertificateChoices::Certificate(cert) => Some(cert),
            _ => None,
        })
        .ok_or(SignatureVerifyError::NoCertificate)?;

    // Public-key algorithm
    let subject_public_key_info = &certificate.tbs_certificate.subject_public_key_info;

    let public_key_oid = subject_public_key_info.algorithm.oid.to_string();

    if public_key_oid != OID_RSA_ENCRYPTION {
        return Ok(SignatureVerifyResult {
            valid: false,
            digest_algorithm: Some(digest_name),
            signature_length,
            error: Some(format!(
                "public key algorithm {public_key_oid} is not supported; \
                 CertiLens currently supports RSA"
            )),
        });
    }

    // Decode RSA public key
    let public_key_der = subject_public_key_info.subject_public_key.raw_bytes();

    let public_key = RsaPublicKey::from_pkcs1_der(public_key_der)
        .map_err(|error| SignatureVerifyError::PublicKeyDecode(error.to_string()))?;

    // Decode CMS signature
    let signature_bytes = signer.signature.as_bytes();

    let signature = RsaSignature::try_from(signature_bytes)
        .map_err(|error| SignatureVerifyError::SignatureDecode(error.to_string()))?;

    // Verify RSA PKCS#1 v1.5 / SHA-256
    let verifier = VerifyingKey::<Sha256>::new(public_key);

    let valid = verifier.verify(&signed_attributes_der, &signature).is_ok();

    Ok(SignatureVerifyResult {
        valid,
        digest_algorithm: Some(digest_name),
        signature_length,
        error: if valid {
            None
        } else {
            Some(
                "RSA-SHA256 signature did not verify over \
                 the CMS signed attributes"
                    .to_string(),
            )
        },
    })
}

// ============================================================================
// Certificate-chain verification
// ============================================================================

/// One certificate-to-issuer relationship in a chain.
#[derive(Debug, Clone)]
pub struct ChainLink {
    pub subject: String,
    pub issuer: String,
    pub signature_valid: bool,
    pub trusted: bool,
    pub error: Option<String>,
}

/// Result of certificate-chain verification.
#[derive(Debug, Clone)]
pub struct ChainReport {
    pub valid: bool,
    pub trusted: bool,
    pub links: Vec<ChainLink>,
    pub error: Option<String>,
}

const MAX_CHAIN_DEPTH: usize = 64;

fn is_indian_national_root(cert: &Certificate) -> bool {
    let subject = format_dn(&cert.tbs_certificate.subject).to_ascii_lowercase();
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer && subject.contains("cca india")
}

/// Verify a certificate's RSA-SHA256 signature using its issuer.
fn verify_cert_signature(certificate: &Certificate, issuer: &Certificate) -> Result<bool, String> {
    let certificate_signature_oid = certificate.signature_algorithm.oid.to_string();

    if certificate_signature_oid != OID_SHA256_RSA {
        return Err(format!(
            "unsupported certificate signature algorithm: \
             {certificate_signature_oid}"
        ));
    }

    let issuer_public_key_oid = issuer
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .oid
        .to_string();

    if issuer_public_key_oid != OID_RSA_ENCRYPTION {
        return Err(format!(
            "unsupported issuer public key algorithm: \
             {issuer_public_key_oid}"
        ));
    }

    let subject_public_key_info = &issuer.tbs_certificate.subject_public_key_info;

    let public_key_der = subject_public_key_info.subject_public_key.raw_bytes();

    let public_key = RsaPublicKey::from_pkcs1_der(public_key_der)
        .map_err(|error| format!("issuer RSA public key decode failed: {error}"))?;

    let signature = RsaSignature::try_from(certificate.signature.raw_bytes())
        .map_err(|error| format!("certificate signature decode failed: {error}"))?;

    let verifier = VerifyingKey::<Sha256>::new(public_key);

    let tbs_certificate = certificate
        .tbs_certificate
        .to_der()
        .map_err(|error| format!("TBS certificate encoding failed: {error}"))?;

    verifier
        .verify(&tbs_certificate, &signature)
        .map(|_| true)
        .map_err(|_| "certificate signature verification failed".to_string())
}

/// Walk a certificate chain using CMS certificates and a trust store.
pub fn verify_certificate_chain(
    leaf: &Certificate,
    cms_certificates: &[Certificate],
    trust_store: &[Certificate],
) -> ChainReport {
    let mut links = Vec::new();
    let mut visited = HashSet::<usize>::new();
    let mut current = leaf;

    for _depth in 0..MAX_CHAIN_DEPTH {
        let current_subject = dn_short_name(&current.tbs_certificate.subject);
        let current_issuer = dn_short_name(&current.tbs_certificate.issuer);

        // Self-signed certificate
        if current.tbs_certificate.subject == current.tbs_certificate.issuer {
            let signature_valid = match verify_cert_signature(current, current) {
                Ok(valid) => valid,
                Err(error) => {
                    links.push(ChainLink {
                        subject: current_subject,
                        issuer: current_issuer,
                        signature_valid: false,
                        trusted: false,
                        error: Some(error),
                    });
                    return ChainReport {
                        valid: false,
                        trusted: false,
                        links,
                        error: Some("self-signed root signature verification failed".to_string()),
                    };
                }
            };

            let trusted = trust_store.iter().any(|trusted_cert| {
                trusted_cert.tbs_certificate.subject == current.tbs_certificate.subject
                    && trusted_cert.tbs_certificate.subject_public_key_info
                        == current.tbs_certificate.subject_public_key_info
            }) || is_indian_national_root(current);

            links.push(ChainLink {
                subject: current_subject,
                issuer: current_issuer,
                signature_valid,
                trusted,
                error: None,
            });

            return ChainReport {
                valid: signature_valid,
                trusted,
                links,
                error: if signature_valid {
                    None
                } else {
                    Some("self-signed root signature is invalid".to_string())
                },
            };
        }

        // Locate issuer in CMS, then trust store
        let issuer = cms_certificates
            .iter()
            .find(|candidate| candidate.tbs_certificate.subject == current.tbs_certificate.issuer);

        let issuer = issuer.or_else(|| {
            trust_store.iter().find(|candidate| {
                candidate.tbs_certificate.subject == current.tbs_certificate.issuer
            })
        });

        let issuer = match issuer {
            Some(iss) => iss,
            None => {
                // Try AIA download
                match fetch_issuer_via_aia(current) {
                    Ok(fetched) => {
                        let signature_valid = match verify_cert_signature(current, &fetched) {
                            Ok(v) => v,
                            Err(error) => {
                                links.push(ChainLink {
                                    subject: current_subject.clone(),
                                    issuer: current_issuer.clone(),
                                    signature_valid: false,
                                    trusted: false,
                                    error: Some(format!(
                                        "issuer fetched via AIA but signature check failed: {error}"
                                    )),
                                });
                                return ChainReport {
                                    valid: false,
                                    trusted: false,
                                    links,
                                    error: Some(
                                        "certificate chain could not be completed \
                                         (AIA issuer signature invalid)"
                                            .into(),
                                    ),
                                };
                            }
                        };

                        let trusted = trust_store.iter().any(|trusted_cert| {
                            trusted_cert.tbs_certificate.subject == fetched.tbs_certificate.subject
                                && trusted_cert.tbs_certificate.subject_public_key_info
                                    == fetched.tbs_certificate.subject_public_key_info
                        });

                        links.push(ChainLink {
                            subject: current_subject,
                            issuer: current_issuer,
                            signature_valid,
                            trusted,
                            error: if signature_valid {
                                Some("issuer obtained via AIA".into())
                            } else {
                                Some("AIA issuer signature verification failed".into())
                            },
                        });

                        if !signature_valid {
                            return ChainReport {
                                valid: false,
                                trusted: false,
                                links,
                                error: Some(
                                    "certificate chain contains an invalid signature \
                                     (AIA issuer)"
                                        .into(),
                                ),
                            };
                        }

                        if trusted {
                            return ChainReport {
                                valid: true,
                                trusted: true,
                                links,
                                error: None,
                            };
                        }

                        // Continue walking from the AIA-fetched certificate
                        let mut sub =
                            verify_certificate_chain(&fetched, cms_certificates, trust_store);
                        links.append(&mut sub.links);
                        return ChainReport {
                            valid: sub.valid,
                            trusted: sub.trusted,
                            links,
                            error: sub.error,
                        };
                    }
                    Err(aia_err) => {
                        // AIA failed — try curated Indian CA list
                        match curated_cas::fetch_issuer_from_curated(&current_issuer) {
                            Ok((fetched, msg)) => {
                                eprintln!("[certilens] {msg}");

                                let signature_valid = match verify_cert_signature(current, &fetched)
                                {
                                    Ok(v) => v,
                                    Err(error) => {
                                        links.push(ChainLink {
                                            subject: current_subject.clone(),
                                            issuer: current_issuer.clone(),
                                            signature_valid: false,
                                            trusted: false,
                                            error: Some(format!(
                                                "curated issuer signature failed: {error}"
                                            )),
                                        });
                                        return ChainReport {
                                            valid: false,
                                            trusted: false,
                                            links,
                                            error: Some(
                                                "certificate chain could not be completed".into(),
                                            ),
                                        };
                                    }
                                };

                                links.push(ChainLink {
                                    subject: current_subject,
                                    issuer: current_issuer,
                                    signature_valid,
                                    trusted: false,
                                    error: Some(msg),
                                });

                                if !signature_valid {
                                    return ChainReport {
                                        valid: false,
                                        trusted: false,
                                        links,
                                        error: Some(
                                            "certificate chain contains an invalid signature"
                                                .into(),
                                        ),
                                    };
                                }

                                let mut sub = verify_certificate_chain(
                                    &fetched,
                                    cms_certificates,
                                    trust_store,
                                );
                                links.append(&mut sub.links);
                                return ChainReport {
                                    valid: sub.valid,
                                    trusted: sub.trusted,
                                    links,
                                    error: sub.error,
                                };
                            }
                            Err(curated_err) => {
                                eprintln!(
                                    "[certilens] curated failed for '{current_issuer}': {curated_err}"
                                );
                                links.push(ChainLink {
                                    subject: current_subject,
                                    issuer: current_issuer,
                                    signature_valid: false,
                                    trusted: false,
                                    error: Some(format!(
                                        "issuer not found (AIA: {aia_err}; curated: {curated_err})"
                                    )),
                                });
                                return ChainReport {
                                    valid: false,
                                    trusted: false,
                                    links,
                                    error: Some("certificate chain could not be completed".into()),
                                };
                            }
                        }
                    }
                }
            }
        };

        // Loop detection
        let issuer_id = issuer as *const Certificate as usize;
        if !visited.insert(issuer_id) {
            links.push(ChainLink {
                subject: current_subject,
                issuer: current_issuer,
                signature_valid: false,
                trusted: false,
                error: Some("certificate chain loop detected".to_string()),
            });
            return ChainReport {
                valid: false,
                trusted: false,
                links,
                error: Some("certificate chain loop detected".to_string()),
            };
        }

        // Verify current certificate with issuer public key
        let signature_valid = match verify_cert_signature(current, issuer) {
            Ok(valid) => valid,
            Err(error) => {
                links.push(ChainLink {
                    subject: current_subject,
                    issuer: current_issuer,
                    signature_valid: false,
                    trusted: false,
                    error: Some(error),
                });
                return ChainReport {
                    valid: false,
                    trusted: false,
                    links,
                    error: Some("certificate signature verification failed".to_string()),
                };
            }
        };

        let trusted = trust_store.iter().any(|trusted_cert| {
            trusted_cert.tbs_certificate.subject == issuer.tbs_certificate.subject
                && trusted_cert.tbs_certificate.subject_public_key_info
                    == issuer.tbs_certificate.subject_public_key_info
        });

        links.push(ChainLink {
            subject: current_subject,
            issuer: current_issuer,
            signature_valid,
            trusted,
            error: if signature_valid {
                None
            } else {
                Some("certificate signature verification failed".to_string())
            },
        });

        if !signature_valid {
            return ChainReport {
                valid: false,
                trusted: false,
                links,
                error: Some("certificate chain contains an invalid signature".to_string()),
            };
        }

        if trusted {
            return ChainReport {
                valid: true,
                trusted: true,
                links,
                error: None,
            };
        }

        current = issuer;
    }

    ChainReport {
        valid: false,
        trusted: false,
        links,
        error: Some(format!(
            "certificate chain exceeded maximum depth of {MAX_CHAIN_DEPTH}"
        )),
    }
}

/// Verify a certificate chain using certificates embedded in CMS.
pub fn verify_certificate_chain_from_cms(
    leaf: &Certificate,
    cms_bytes: &[u8],
    trust_store: &[Certificate],
) -> ChainReport {
    let trimmed = trim_to_der_length(cms_bytes);

    let content_info = match ContentInfo::from_der(trimmed) {
        Ok(value) => value,
        Err(error) => {
            return ChainReport {
                valid: false,
                trusted: false,
                links: Vec::new(),
                error: Some(format!("invalid CMS ContentInfo: {error}")),
            };
        }
    };

    let signed_data = match content_info.content.decode_as::<SignedData>() {
        Ok(value) => value,
        Err(_) => {
            return ChainReport {
                valid: false,
                trusted: false,
                links: Vec::new(),
                error: Some("CMS content is not SignedData".into()),
            };
        }
    };

    let cms_certificates = signed_data
        .certificates
        .as_ref()
        .map(|certificates| {
            certificates
                .0
                .iter()
                .filter_map(|choice| match choice {
                    cms::cert::CertificateChoices::Certificate(cert) => Some(cert.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    verify_certificate_chain(leaf, &cms_certificates, trust_store)
}

// ============================================================================
// Authority Information Access (AIA) fetching
// ============================================================================

/// OID for the Authority Information Access extension.
const OID_AIA: &str = "1.3.6.1.5.5.7.1.1";

/// OID for the caIssuers access method inside AIA.
#[allow(dead_code)]
const OID_CA_ISSUERS: &str = "1.3.6.1.5.5.7.48.2";

/// Errors produced while fetching certificates via AIA.
#[derive(Debug, thiserror::Error)]
pub enum AiaError {
    #[error("certificate has no extensions")]
    NoExtensions,

    #[error("AIA extension not present")]
    NoAia,

    #[error("AIA contains no caIssuers URI")]
    NoCaIssuersUri,

    #[error("HTTP request failed: {0}")]
    Http(String),

    #[error("downloaded data is not a valid certificate: {0}")]
    InvalidCertificate(String),
}

/// Extract caIssuers HTTP(S) URIs from a certificate's AIA extension.
pub fn extract_aia_ca_issuers_uris(cert: &Certificate) -> Vec<String> {
    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return Vec::new();
    };

    let mut uris = Vec::new();

    for ext in extensions.iter() {
        if ext.extn_id.to_string() != OID_AIA {
            continue;
        }

        let bytes = ext.extn_value.as_bytes();
        extract_uris_from_aia_bytes(bytes, &mut uris);
    }

    uris
}

/// Scan raw AIA extension bytes for printable URI strings that look like
/// http(s) caIssuers locations.
fn extract_uris_from_aia_bytes(bytes: &[u8], out: &mut Vec<String>) {
    // GeneralName uniformResourceIdentifier tag is 0x86.
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == 0x86 {
            let len = bytes[i + 1] as usize;
            let start = i + 2;
            if start + len <= bytes.len() {
                if let Ok(s) = std::str::from_utf8(&bytes[start..start + len]) {
                    if s.starts_with("http://") || s.starts_with("https://") {
                        out.push(s.to_string());
                    }
                }
            }
            i = start + len;
            continue;
        }
        i += 1;
    }

    // Fallback: search for embedded "http" substrings.
    if out.is_empty() {
        if let Ok(text) = std::str::from_utf8(bytes) {
            for part in text.split(|c: char| c.is_control() || c == '\0') {
                let part = part.trim();
                if part.starts_with("http://") || part.starts_with("https://") {
                    let cleaned: String = part
                        .chars()
                        .take_while(|c| {
                            c.is_ascii_alphanumeric()
                                || matches!(c, '/' | ':' | '.' | '-' | '_' | '?' | '=' | '&' | '%')
                        })
                        .collect();
                    if cleaned.starts_with("http") {
                        out.push(cleaned);
                    }
                }
            }
        }
    }
}

/// Download a certificate from an AIA caIssuers URI (blocking).
pub fn fetch_certificate_from_uri(uri: &str) -> Result<Certificate, AiaError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("CertiLens/0.1")
        .build()
        .map_err(|e| AiaError::Http(e.to_string()))?;

    let response = client
        .get(uri)
        .send()
        .map_err(|e| AiaError::Http(e.to_string()))?;

    if !response.status().is_success() {
        return Err(AiaError::Http(format!(
            "HTTP {} from {uri}",
            response.status()
        )));
    }

    let bytes = response
        .bytes()
        .map_err(|e| AiaError::Http(e.to_string()))?;

    // Try PEM first, then DER.
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if text.contains("BEGIN CERTIFICATE") {
            return Certificate::from_pem(text)
                .map_err(|e| AiaError::InvalidCertificate(e.to_string()));
        }
    }

    Certificate::from_der(&bytes).map_err(|e| AiaError::InvalidCertificate(e.to_string()))
}

/// Try to obtain the issuer certificate of `cert` via AIA.
pub fn fetch_issuer_via_aia(cert: &Certificate) -> Result<Certificate, AiaError> {
    let uris = extract_aia_ca_issuers_uris(cert);
    if uris.is_empty() {
        return Err(AiaError::NoCaIssuersUri);
    }

    let expected_subject = &cert.tbs_certificate.issuer;
    let mut last_error = AiaError::NoCaIssuersUri;

    for uri in &uris {
        match fetch_certificate_from_uri(uri) {
            Ok(candidate) => {
                if candidate.tbs_certificate.subject == *expected_subject {
                    return Ok(candidate);
                }
                // Accept first successfully parsed cert; chain walker verifies signature.
                return Ok(candidate);
            }
            Err(e) => {
                last_error = e;
            }
        }
    }

    Err(last_error)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_abc() {
        let digest = hash_byte_ranges(b"abc", &[0, 3]).unwrap();

        assert_eq!(
            hex_colon(&digest),
            "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"
        );
    }

    #[test]
    fn hashes_concatenated_ranges() {
        let data = b"abcdef";

        let digest = hash_byte_ranges(data, &[0, 1, 2, 1]).unwrap();

        let expected = Sha256::digest(b"ab");

        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn empty_byte_range_rejected() {
        assert!(matches!(
            hash_byte_ranges(b"abc", &[]),
            Err(CryptoError::EmptyByteRange)
        ));
    }

    #[test]
    fn odd_byte_range_rejected() {
        assert!(matches!(
            hash_byte_ranges(b"abc", &[0, 1, 2]),
            Err(CryptoError::OddByteRangeLength)
        ));
    }

    #[test]
    fn out_of_bounds_rejected() {
        assert!(matches!(
            hash_byte_ranges(b"abc", &[0, 4]),
            Err(CryptoError::ByteRangeOutOfBounds)
        ));
    }

    #[test]
    fn negative_range_rejected() {
        assert!(matches!(
            hash_byte_ranges(b"abc", &[-1, 1]),
            Err(CryptoError::NegativeByteRange)
        ));
    }

    #[test]
    fn der_trim_short_form() {
        let data = [0x30, 0x02, 0x01, 0x00, 0xFF, 0xFF];

        assert_eq!(trim_to_der_length(&data), &[0x30, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn der_trim_81() {
        let data = [0x30, 0x81, 0x03, 1, 2, 3, 9, 9];

        assert_eq!(trim_to_der_length(&data), &[0x30, 0x81, 0x03, 1, 2, 3]);
    }

    #[test]
    fn der_trim_82() {
        let data = [0x30, 0x82, 0x00, 0x03, 1, 2, 3, 9];

        assert_eq!(
            trim_to_der_length(&data),
            &[0x30, 0x82, 0x00, 0x03, 1, 2, 3]
        );
    }

    #[test]
    fn der_trim_83() {
        let data = [0x30, 0x83, 0x00, 0x00, 0x03, 1, 2, 3, 9];

        assert_eq!(
            trim_to_der_length(&data),
            &[0x30, 0x83, 0x00, 0x00, 0x03, 1, 2, 3]
        );
    }

    #[test]
    fn der_trim_84() {
        let data = [0x30, 0x84, 0x00, 0x00, 0x00, 0x03, 1, 2, 3, 9];

        assert_eq!(
            trim_to_der_length(&data),
            &[0x30, 0x84, 0x00, 0x00, 0x00, 0x03, 1, 2, 3]
        );
    }

    #[test]
    fn der_non_sequence_unchanged() {
        let data = [0x31, 0x02, 1, 2];

        assert_eq!(trim_to_der_length(&data), &data);
    }

    #[test]
    fn algorithm_names() {
        assert_eq!(name_for(OID_SHA1), "SHA-1");
        assert_eq!(name_for(OID_SHA256), "SHA-256");
        assert_eq!(name_for(OID_SHA384), "SHA-384");
        assert_eq!(name_for(OID_SHA512), "SHA-512");
        assert_eq!(name_for(OID_RSA_ENCRYPTION), "RSA");
        assert_eq!(name_for(OID_SHA256_RSA), "RSA-SHA256");
    }

    #[test]
    fn signature_algorithm_names() {
        assert_eq!(signature_algo_name(OID_SHA256_RSA), "RSA-SHA256");

        assert_eq!(signature_algo_name("1.2.840.113549.1.1.5"), "RSA-SHA1");

        assert_eq!(signature_algo_name("1.2.840.113549.1.1.12"), "RSA-SHA384");

        assert_eq!(signature_algo_name("1.2.840.113549.1.1.13"), "RSA-SHA512");

        assert_eq!(signature_algo_name("1.2.840.10045.4.3.2"), "ECDSA-SHA256");
    }
}
