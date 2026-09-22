//! System trust store loading and lookup.
//!
//! Phase 2d-iii: reads the OS CA bundle (PEM) and indexes certificates
//! by subject DN. Used by the chain walker to resolve issuers that are
//! not embedded in the CMS.

use der::DecodePem;
use std::collections::HashMap;
use std::path::Path;
use x509_cert::Certificate;

/// Candidate paths for the OS CA bundle, in order of preference.
const CANDIDATE_PATHS: &[&str] = &[
    // Debian / Ubuntu
    "/etc/ssl/certs/ca-certificates.crt",
    // RHEL / Fedora / CentOS
    "/etc/pki/tls/certs/ca-bundle.crt",
    // openSUSE
    "/etc/ssl/ca-bundle.pem",
    // Alpine / some BSDs
    "/etc/ssl/cert.pem",
    // Arch
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
];

#[derive(Debug, thiserror::Error)]
pub enum TrustStoreError {
    #[error("no system CA bundle found (tried {0} paths)")]
    NotFound(usize),

    #[error("I/O error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("no valid certificates parsed from {path}")]
    Empty { path: String },
}

/// A set of trusted CA certificates indexed by subject DN.
#[derive(Debug, Default)]
pub struct TrustStore {
    /// Map from subject DN string (as our `format_dn` renders it) to certs.
    by_subject: HashMap<String, Vec<Certificate>>,
    /// Path we loaded from, for reporting.
    pub source_path: Option<String>,
    /// How many certificates are in the store.
    pub count: usize,
}

impl TrustStore {
    /// Load the system trust store.
    pub fn load_system() -> Result<Self, TrustStoreError> {
        for path in CANDIDATE_PATHS {
            if Path::new(path).exists() {
                return Self::load_from(path);
            }
        }
        Err(TrustStoreError::NotFound(CANDIDATE_PATHS.len()))
    }

    /// Load a PEM bundle from a specific path.
    pub fn load_from(path: &str) -> Result<Self, TrustStoreError> {
        let data = std::fs::read_to_string(path).map_err(|e| TrustStoreError::Io {
            path: path.to_string(),
            source: e,
        })?;

        let mut by_subject: HashMap<String, Vec<Certificate>> = HashMap::new();
        let mut count = 0usize;

        // The bundle is concatenated PEM blocks. Split on the header line.
        const HEADER: &str = "-----BEGIN CERTIFICATE-----";
        const FOOTER: &str = "-----END CERTIFICATE-----";

        let mut rest = data.as_str();
        while let Some(start) = rest.find(HEADER) {
            let after_header = &rest[start..];
            let Some(end_rel) = after_header.find(FOOTER) else {
                break;
            };
            let end = start + end_rel + FOOTER.len();
            let block = &rest[start..end];

            if let Ok(cert) = Certificate::from_pem(block) {
                // `format_dn` isn't public in lib.rs; we use the same
                // string-key idea by hashing the DN's Debug render. To keep
                // things simple for the lookup, we instead key by the
                // DER-encoded Name.
                let key = dn_key(&cert.tbs_certificate.subject);
                by_subject.entry(key).or_default().push(cert);
                count += 1;
            }

            rest = &rest[end..];
        }

        if count == 0 {
            return Err(TrustStoreError::Empty {
                path: path.to_string(),
            });
        }

        Ok(Self {
            by_subject,
            source_path: Some(path.to_string()),
            count,
        })
    }

    /// Find a trust-store certificate whose subject matches `dn_key`.
    pub fn find_by_subject_key(&self, dn_key: &str) -> Option<&Certificate> {
        self.by_subject.get(dn_key).and_then(|v| v.first())
    }

    /// True if any certificate in the store has this subject key.
    pub fn contains_subject_key(&self, dn_key: &str) -> bool {
        self.by_subject.contains_key(dn_key)
    }
}

/// Stable key for a Name. Uses the DER encoding of the Name, which is
/// the canonical form. Two Names that encode differently but mean the
/// same thing will not match — this is rare in practice.
pub fn dn_key(name: &x509_cert::name::Name) -> String {
    use der::Encode;
    match name.to_der() {
        Ok(bytes) => {
            // Hex-encode for a stable string key.
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
        Err(_) => String::from("<invalid>"),
    }
}
