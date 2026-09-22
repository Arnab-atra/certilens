//! Cryptographic primitives for CertiLens.
//!
//! Rules:
//!   * We use established implementations. We do not write our own
//!     SHA-256, RSA, ECDSA, etc.
//!   * Every function here operates on explicit byte ranges so callers
//!     can see exactly what was hashed or verified.
//!   * Nothing here "decides" anything. The decision logic lives in
//!     `certilens-core` (Phase 3).

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use der::asn1::OctetString;
use der::{Decode, Encode};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use x509_cert::attr::Attribute;
use x509_cert::Certificate;

pub mod trust;

// =====================================================================
// SHA-256 hashing of PDF byte ranges
// =====================================================================

/// Errors from the crypto layer.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("byte range [{start}..{end}] is out of file bounds (file is {len} bytes)")]
    RangeOutOfBounds { start: u64, end: u64, len: usize },

    #[error("byte range array must have an even number of elements (got {0})")]
    OddRange(usize),

    #[error("byte range array is empty")]
    EmptyRange,
}

/// Concatenate every `[start, length]` pair from `ranges` and return
/// the SHA-256 digest of the concatenation.
pub fn hash_byte_ranges(raw: &[u8], ranges: &[i64]) -> Result<[u8; 32], CryptoError> {
    if ranges.is_empty() {
        return Err(CryptoError::EmptyRange);
    }
    if ranges.len() % 2 != 0 {
        return Err(CryptoError::OddRange(ranges.len()));
    }

    let mut hasher = Sha256::new();

    for chunk in ranges.chunks_exact(2) {
        let start = chunk[0];
        let length = chunk[1];

        if start < 0 || length < 0 {
            return Err(CryptoError::RangeOutOfBounds {
                start: start.max(0) as u64,
                end: 0,
                len: raw.len(),
            });
        }

        let start = start as usize;
        let length = length as usize;
        let end = start
            .checked_add(length)
            .ok_or(CryptoError::RangeOutOfBounds {
                start: start as u64,
                end: u64::MAX,
                len: raw.len(),
            })?;

        if end > raw.len() {
            return Err(CryptoError::RangeOutOfBounds {
                start: start as u64,
                end: end as u64,
                len: raw.len(),
            });
        }

        hasher.update(&raw[start..end]);
    }

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

// =====================================================================
// CMS / PKCS#7 parsing
// =====================================================================

#[derive(Debug, Clone)]
pub struct CmsDigestInfo {
    pub digest_algorithm_oid: String,
    pub digest_algorithm_name: Option<&'static str>,
    pub claimed_digest: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum CmsParseError {
    #[error("CMS parse error: {0}")]
    Der(#[from] der::Error),

    #[error("CMS does not contain SignedData")]
    NotSignedData,

    #[error("CMS contains no signer info")]
    NoSignerInfo,

    #[error("signer info has no signed attributes")]
    NoSignedAttrs,

    #[error("signed attributes contain no messageDigest")]
    NoMessageDigest,

    #[error("messageDigest attribute has wrong structure")]
    BadMessageDigest,
}

const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_SHA1: &str = "1.3.14.3.2.26";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";

pub fn parse_cms_digest(cms_bytes: &[u8]) -> Result<CmsDigestInfo, CmsParseError> {
    let trimmed = trim_to_der_length(cms_bytes);

    let ci = ContentInfo::from_der(trimmed)?;
    let sd = ci
        .content
        .decode_as::<SignedData>()
        .map_err(|_| CmsParseError::NotSignedData)?;

    let signer: &SignerInfo = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(CmsParseError::NoSignerInfo)?;

    let signed_attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or(CmsParseError::NoSignedAttrs)?;

    for attr in signed_attrs.iter() {
        if attr.oid.to_string() == OID_MESSAGE_DIGEST {
            let digest = extract_octet_string(attr)?;
            let algo_oid = signer.digest_alg.oid.to_string();
            return Ok(CmsDigestInfo {
                digest_algorithm_name: name_for(&algo_oid),
                digest_algorithm_oid: algo_oid,
                claimed_digest: digest,
            });
        }
    }

    Err(CmsParseError::NoMessageDigest)
}

// =====================================================================
// X.509 certificate extraction (Phase 2b)
// =====================================================================

#[derive(Debug, Clone)]
pub struct SignerCertificate {
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub public_key_algorithm_oid: String,
    pub public_key_algorithm_name: Option<&'static str>,
    pub signature_algorithm_oid: String,
    pub signature_algorithm_name: Option<&'static str>,
    pub der_length: usize,
    pub currently_valid: bool,
    pub is_expired: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    #[error("CMS has no certificates")]
    NoCertificates,

    #[error("certificate decode error: {0}")]
    Decode(#[from] der::Error),

    #[error("CMS does not contain SignedData")]
    NotSignedData,

    #[error(transparent)]
    CmsParse(#[from] CmsParseError),
}

pub fn extract_signer_certificate(cms_bytes: &[u8]) -> Result<SignerCertificate, CertificateError> {
    let trimmed = trim_to_der_length(cms_bytes);

    let ci = ContentInfo::from_der(trimmed)?;
    let sd = ci
        .content
        .decode_as::<SignedData>()
        .map_err(|_| CertificateError::NotSignedData)?;

    let certs = sd
        .certificates
        .as_ref()
        .ok_or(CertificateError::NoCertificates)?;

    for choice in certs.0.iter() {
        if let cms::cert::CertificateChoices::Certificate(cert) = choice {
            return Ok(render_certificate(cert)?);
        }
    }

    Err(CertificateError::NoCertificates)
}

fn render_certificate(
    cert: &x509_cert::Certificate,
) -> Result<SignerCertificate, CertificateError> {
    let tbs = &cert.tbs_certificate;

    let subject = format_dn(&tbs.subject);
    let issuer = format_dn(&tbs.issuer);
    let serial_hex = format_serial(&tbs.serial_number);
    let not_before = tbs.validity.not_before.to_string();
    let not_after = tbs.validity.not_after.to_string();

    let pk_oid = tbs.subject_public_key_info.algorithm.oid.to_string();
    let sig_oid = tbs.signature.oid.to_string();

    let der = cert.to_der()?;

    let nb_unix = iso_to_unix(&not_before);
    let na_unix = iso_to_unix(&not_after);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let currently_valid = now_unix >= nb_unix && now_unix <= na_unix;
    let is_expired = now_unix > na_unix;

    Ok(SignerCertificate {
        subject,
        issuer,
        serial_hex,
        not_before,
        not_after,
        public_key_algorithm_name: public_key_algo_name(&pk_oid),
        public_key_algorithm_oid: pk_oid,
        signature_algorithm_name: signature_algo_name(&sig_oid),
        signature_algorithm_oid: sig_oid,
        der_length: der.len(),
        currently_valid,
        is_expired,
    })
}

fn iso_to_unix(s: &str) -> u64 {
    if s.len() < 19 {
        return 0;
    }
    let year: i64 = match s[0..4].parse() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let month: u32 = match s[5..7].parse() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let day: u32 = match s[8..10].parse() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let hour: u32 = match s[11..13].parse() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let min: u32 = match s[14..16].parse() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let sec: u32 = match s[17..19].parse() {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe as i64 - 719468;

    let secs = days * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64;
    if secs < 0 {
        0
    } else {
        secs as u64
    }
}

fn format_dn(name: &x509_cert::name::Name) -> String {
    let mut parts = Vec::new();

    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            let oid = atv.oid.to_string();
            let label = dn_short_name(&oid).unwrap_or(&oid).to_string();
            let value = render_any_value(&atv.value);
            parts.push(format!("{label}={value}"));
        }
    }

    parts.join(", ")
}

fn render_any_value(any: &der::Any) -> String {
    use der::asn1::{Ia5StringRef, PrintableStringRef, Utf8StringRef};

    if let Ok(s) = any.decode_as::<Utf8StringRef>() {
        return s.as_str().to_string();
    }
    if let Ok(s) = any.decode_as::<PrintableStringRef>() {
        return s.as_str().to_string();
    }
    if let Ok(s) = any.decode_as::<Ia5StringRef>() {
        return s.as_str().to_string();
    }
    hex_colon(any.value())
}

fn format_serial(serial: &x509_cert::serial_number::SerialNumber) -> String {
    hex_colon(serial.as_bytes())
}

fn hex_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn dn_short_name(oid: &str) -> Option<&'static str> {
    match oid {
        "2.5.4.3" => Some("CN"),
        "2.5.4.17" => Some("postalCode"),
        "2.5.4.4" => Some("SN"),
        "2.5.4.42" => Some("GN"),
        "2.5.4.9" => Some("street"),
        "2.5.4.15" => Some("businessCategory"),
        "2.5.4.12" => Some("title"),
        "2.5.4.6" => Some("C"),
        "2.5.4.7" => Some("L"),
        "2.5.4.8" => Some("ST"),
        "2.5.4.10" => Some("O"),
        "2.5.4.11" => Some("OU"),
        "2.5.4.5" => Some("serialNumber"),
        "1.2.840.113549.1.9.1" => Some("E"),
        _ => None,
    }
}

fn public_key_algo_name(oid: &str) -> Option<&'static str> {
    match oid {
        "1.2.840.113549.1.1.1" => Some("RSA"),
        "1.2.840.10045.2.1" => Some("EC"),
        "1.2.840.10040.4.1" => Some("DSA"),
        "1.3.101.112" => Some("Ed25519"),
        _ => None,
    }
}

fn signature_algo_name(oid: &str) -> Option<&'static str> {
    match oid {
        "1.2.840.113549.1.1.5" => Some("SHA1-RSA"),
        "1.2.840.113549.1.1.11" => Some("SHA256-RSA"),
        "1.2.840.113549.1.1.12" => Some("SHA384-RSA"),
        "1.2.840.113549.1.1.13" => Some("SHA512-RSA"),
        "1.2.840.10045.4.3.2" => Some("ECDSA-SHA256"),
        "1.2.840.10045.4.3.3" => Some("ECDSA-SHA384"),
        "1.2.840.10045.4.3.4" => Some("ECDSA-SHA512"),
        _ => None,
    }
}

fn extract_octet_string(attr: &Attribute) -> Result<Vec<u8>, CmsParseError> {
    for value in attr.values.iter() {
        if let Ok(os) = value.decode_as::<OctetString>() {
            return Ok(os.as_bytes().to_vec());
        }
    }
    Err(CmsParseError::BadMessageDigest)
}

fn name_for(oid: &str) -> Option<&'static str> {
    match oid {
        OID_SHA1 => Some("SHA-1"),
        OID_SHA256 => Some("SHA-256"),
        OID_SHA384 => Some("SHA-384"),
        OID_SHA512 => Some("SHA-512"),
        _ => None,
    }
}

fn trim_to_der_length(data: &[u8]) -> &[u8] {
    if data.len() < 2 {
        return data;
    }
    if data[0] != 0x30 {
        return data;
    }

    let lb = data[1];
    let (header_len, content_len) = if lb < 0x80 {
        (2usize, lb as usize)
    } else if lb == 0x81 && data.len() >= 3 {
        (3, data[2] as usize)
    } else if lb == 0x82 && data.len() >= 4 {
        (4, ((data[2] as usize) << 8) | (data[3] as usize))
    } else if lb == 0x83 && data.len() >= 5 {
        (
            5,
            ((data[2] as usize) << 16) | ((data[3] as usize) << 8) | (data[4] as usize),
        )
    } else if lb == 0x84 && data.len() >= 6 {
        (
            6,
            ((data[2] as usize) << 24)
                | ((data[3] as usize) << 16)
                | ((data[4] as usize) << 8)
                | (data[5] as usize),
        )
    } else {
        return data;
    };

    let total = header_len + content_len;
    if total <= data.len() {
        &data[..total]
    } else {
        data
    }
}

// =====================================================================
// Combined digest check (Phase 2a)
// =====================================================================

#[derive(Debug, Clone)]
pub struct DigestCheckResult {
    pub algorithm: Option<&'static str>,
    pub computed: Vec<u8>,
    pub claimed: Vec<u8>,
    pub matches: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum DigestCheckError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Cms(#[from] CmsParseError),
}

pub fn check_digest(
    raw_pdf: &[u8],
    byte_range: &[i64],
    cms_bytes: &[u8],
) -> Result<DigestCheckResult, DigestCheckError> {
    let computed = hash_byte_ranges(raw_pdf, byte_range)?;
    let info = parse_cms_digest(cms_bytes)?;
    let matches = computed.as_slice() == info.claimed_digest.as_slice();
    Ok(DigestCheckResult {
        algorithm: info.digest_algorithm_name,
        computed: computed.to_vec(),
        claimed: info.claimed_digest,
        matches,
    })
}

// =====================================================================
// Signature verification (Phase 2c)
// =====================================================================

#[derive(Debug, thiserror::Error)]
pub enum SignatureVerifyError {
    #[error("CMS parse error: {0}")]
    Cms(#[from] CmsParseError),

    #[error("CMS has no signed attributes")]
    NoSignedAttrs,

    #[error("CMS has no certificates")]
    NoCertificates,

    #[error("no X.509 certificate in CMS")]
    NoCertificate,

    #[error("unsupported digest algorithm: {0}")]
    UnsupportedDigest(String),

    #[error("unsupported public key algorithm: {0}")]
    UnsupportedPublicKey(String),

    #[error("public key decode failed: {0}")]
    PublicKeyDecode(String),

    #[error("signature decode failed: {0}")]
    SignatureDecode(String),

    #[error("DER re-encode failed: {0}")]
    Der(#[from] der::Error),
}

#[derive(Debug, Clone)]
pub struct SignatureVerifyResult {
    pub valid: bool,
    pub digest_algorithm: Option<&'static str>,
    pub signature_length: usize,
    pub error: Option<String>,
}

pub fn verify_signer_signature(
    cms_bytes: &[u8],
) -> Result<SignatureVerifyResult, SignatureVerifyError> {
    let trimmed = trim_to_der_length(cms_bytes);

    let ci = ContentInfo::from_der(trimmed)?;
    let sd = ci
        .content
        .decode_as::<SignedData>()
        .map_err(|_| CmsParseError::NotSignedData)?;

    let signer: &SignerInfo = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(CmsParseError::NoSignerInfo)?;

    let digest_oid = signer.digest_alg.oid.to_string();
    let digest_name = name_for(&digest_oid);

    if digest_oid != OID_SHA256 {
        return Ok(SignatureVerifyResult {
            valid: false,
            digest_algorithm: digest_name,
            signature_length: signer.signature.as_bytes().len(),
            error: Some(format!(
                "digest algorithm {digest_oid} not yet supported (Phase 2c handles SHA-256)"
            )),
        });
    }

    let signed_attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or(SignatureVerifyError::NoSignedAttrs)?;

    let mut tbs = signed_attrs.to_der()?;
    if tbs.is_empty() {
        return Err(SignatureVerifyError::NoSignedAttrs);
    }
    if tbs[0] == 0xA0 {
        tbs[0] = 0x31;
    }

    let certs = sd
        .certificates
        .as_ref()
        .ok_or(SignatureVerifyError::NoCertificates)?;
    let cert = certs
        .0
        .iter()
        .find_map(|c| match c {
            cms::cert::CertificateChoices::Certificate(x) => Some(x),
            _ => None,
        })
        .ok_or(SignatureVerifyError::NoCertificate)?;

    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pk_oid = spki.algorithm.oid.to_string();
    if pk_oid != "1.2.840.113549.1.1.1" {
        return Ok(SignatureVerifyResult {
            valid: false,
            digest_algorithm: digest_name,
            signature_length: signer.signature.as_bytes().len(),
            error: Some(format!(
                "public key algorithm {pk_oid} not yet supported (Phase 2c handles RSA)"
            )),
        });
    }

    let pk_der = spki.subject_public_key.raw_bytes();
    let pk = RsaPublicKey::from_pkcs1_der(pk_der)
        .map_err(|e| SignatureVerifyError::PublicKeyDecode(e.to_string()))?;

    let sig_bytes = signer.signature.as_bytes();
    let sig = RsaSignature::try_from(sig_bytes)
        .map_err(|e| SignatureVerifyError::SignatureDecode(e.to_string()))?;

    let vk = VerifyingKey::<Sha256>::new(pk);
    let valid = vk.verify(&tbs, &sig).is_ok();

    Ok(SignatureVerifyResult {
        valid,
        digest_algorithm: digest_name,
        signature_length: sig_bytes.len(),
        error: if valid {
            None
        } else {
            Some("RSA signature did not verify over the signed attributes".into())
        },
    })
}

// =====================================================================
// Certificate chain verification (Phase 2d)
// =====================================================================

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("CMS parse error: {0}")]
    Cms(#[from] CmsParseError),

    #[error("no certificates in CMS")]
    NoCertificates,

    #[error("certificate decode failed: {0}")]
    Decode(#[from] der::Error),

    #[error("could not build verifier: {0}")]
    Verifier(String),
}

#[derive(Debug, Clone)]
pub struct ChainLink {
    pub index: usize,
    pub subject: String,
    pub issuer: String,
    pub signature_verified: bool,
    pub self_signed: bool,
    /// True if this certificate came from the system trust store
    /// rather than from the CMS blob embedded in the PDF.
    pub from_trust_store: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChainReport {
    pub links: Vec<ChainLink>,
    pub reaches_root: bool,
    pub root_subject: Option<String>,
    pub missing_issuer: Option<String>,
    /// True if the chain reached a self-signed root AND that root is
    /// present in the system trust store.
    pub reached_trusted_root: bool,
}

/// Verify a single certificate's signature using its issuer's public key.
///
/// Phase 2d: only RSA + SHA-256 is supported. Other algorithm pairs
/// return an error string; the chain walker records it and moves on.
fn verify_cert_signature(cert: &Certificate, issuer: &Certificate) -> Result<(), String> {
    let sig_alg_oid = cert.tbs_certificate.signature.oid.to_string();
    let pk_oid = issuer
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .oid
        .to_string();

    if pk_oid != "1.2.840.113549.1.1.1" {
        return Err(format!(
            "issuer public key algorithm {pk_oid} not supported"
        ));
    }
    if sig_alg_oid != "1.2.840.113549.1.1.11" {
        return Err(format!(
            "cert signature algorithm {sig_alg_oid} not supported"
        ));
    }

    let pk_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let pk = RsaPublicKey::from_pkcs1_der(pk_der)
        .map_err(|e| format!("issuer public key decode failed: {e}"))?;

    let tbs_der = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| format!("tbs_certificate to_der failed: {e}"))?;

    let sig_bytes = cert.signature.raw_bytes();
    let sig =
        RsaSignature::try_from(sig_bytes).map_err(|e| format!("signature decode failed: {e}"))?;

    let vk = VerifyingKey::<Sha256>::new(pk);
    vk.verify(&tbs_der, &sig)
        .map_err(|e| format!("RSA verify failed: {e}"))
}

pub fn verify_certificate_chain(
    cms_bytes: &[u8],
    store: Option<&trust::TrustStore>,
) -> Result<ChainReport, ChainError> {
    let trimmed = trim_to_der_length(cms_bytes);

    let ci = ContentInfo::from_der(trimmed)?;
    let sd = ci
        .content
        .decode_as::<SignedData>()
        .map_err(|_| CmsParseError::NotSignedData)?;

    let cert_set = sd.certificates.as_ref().ok_or(ChainError::NoCertificates)?;

    struct WalkCert {
        cert: Certificate,
        from_trust_store: bool,
    }

    let mut certs: Vec<WalkCert> = Vec::new();
    for choice in cert_set.0.iter() {
        if let cms::cert::CertificateChoices::Certificate(c) = choice {
            certs.push(WalkCert {
                cert: c.clone(),
                from_trust_store: false,
            });
        }
    }
    if certs.is_empty() {
        return Err(ChainError::NoCertificates);
    }

    let mut current = 0usize;
    let mut links = Vec::new();
    let mut missing_issuer = None;
    let mut reached_trusted_root = false;

    for _ in 0..(certs.len() + 8) {
        let cert = certs[current].cert.clone();
        let from_store = certs[current].from_trust_store;

        let subject_dn = format_dn(&cert.tbs_certificate.subject);
        let issuer_dn = format_dn(&cert.tbs_certificate.issuer);
        let subject_key = trust::dn_key(&cert.tbs_certificate.subject);
        let issuer_key = trust::dn_key(&cert.tbs_certificate.issuer);
        let self_signed = subject_key == issuer_key;

        let issuer_idx = if self_signed {
            current
        } else {
            let existing = certs
                .iter()
                .position(|c| trust::dn_key(&c.cert.tbs_certificate.subject) == issuer_key);
            if let Some(i) = existing {
                i
            } else if let Some(store) = store {
                if let Some(store_cert) = store.find_by_subject_key(&issuer_key) {
                    certs.push(WalkCert {
                        cert: store_cert.clone(),
                        from_trust_store: true,
                    });
                    certs.len() - 1
                } else {
                    usize::MAX
                }
            } else {
                usize::MAX
            }
        };

        let (signature_verified, error) = if issuer_idx == usize::MAX {
            (false, Some(format!("issuer not found: {issuer_dn}")))
        } else {
            match verify_cert_signature(&cert, &certs[issuer_idx].cert) {
                Ok(()) => (true, None),
                Err(e) => (false, Some(e)),
            }
        };

        let root_in_store = if self_signed {
            store
                .map(|s| s.contains_subject_key(&subject_key))
                .unwrap_or(false)
        } else {
            false
        };

        links.push(ChainLink {
            index: current,
            subject: subject_dn.clone(),
            issuer: issuer_dn.clone(),
            signature_verified,
            self_signed,
            from_trust_store: from_store,
            error,
        });

        if self_signed {
            reached_trusted_root = signature_verified && root_in_store;
            break;
        }

        if issuer_idx == usize::MAX {
            missing_issuer = Some(issuer_dn);
            break;
        }
        if issuer_idx == current {
            break;
        }
        current = issuer_idx;
    }

    let root_subject = links
        .last()
        .filter(|l| l.self_signed)
        .map(|l| l.subject.clone());

    // Compute this BEFORE moving `links` into the struct.
    let reaches_root = links
        .last()
        .map(|l| l.self_signed && l.signature_verified)
        .unwrap_or(false);

    Ok(ChainReport {
        links,
        reaches_root,
        root_subject,
        missing_issuer,
        reached_trusted_root,
    })
}
// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256_ABC_HEX: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hashes_a_single_range() {
        let digest = hash_byte_ranges(b"abc", &[0, 3]).unwrap();
        assert_eq!(hex(&digest), SHA256_ABC_HEX);
    }

    #[test]
    fn hashes_two_concatenated_ranges() {
        let digest = hash_byte_ranges(b"abXXXc", &[0, 2, 5, 1]).unwrap();
        assert_eq!(hex(&digest), SHA256_ABC_HEX);
    }

    #[test]
    fn rejects_empty_range() {
        assert!(hash_byte_ranges(b"abc", &[]).is_err());
    }

    #[test]
    fn rejects_odd_range() {
        assert!(hash_byte_ranges(b"abc", &[0, 3, 5]).is_err());
    }

    #[test]
    fn rejects_out_of_bounds() {
        assert!(hash_byte_ranges(b"abc", &[0, 100]).is_err());
    }

    #[test]
    fn trims_trailing_zeros() {
        let mut data = vec![0x30, 0x03, 0x02, 0x01, 0x05];
        data.extend_from_slice(&[0u8; 100]);
        let trimmed = trim_to_der_length(&data);
        assert_eq!(trimmed.len(), 5);
    }
}
