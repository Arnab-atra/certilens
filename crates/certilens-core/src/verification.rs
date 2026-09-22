use serde::{Deserialize, Serialize};

/// The overall outcome shown at the top of the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Verified,
    Invalid,
    Modified,
    Untrusted,
    Expired,
    Revoked,
    Unsupported,
    Unknown,
    Error,
}

/// The result of verifying a document.
///
/// `headline` and `subtitle` drive the top banner. `issues` drives the
/// bullet list of specific findings below it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub status: VerificationStatus,
    /// One-line summary, e.g. "Signature valid, trust unresolved".
    pub headline: String,
    /// Longer explanation shown under the headline.
    pub subtitle: String,
    /// Specific issues the verifier wants to surface to the user.
    pub issues: Vec<String>,
}

impl VerificationResult {
    pub fn not_yet_verified() -> Self {
        Self {
            status: VerificationStatus::Unknown,
            headline: "Not yet verified".into(),
            subtitle: String::new(),
            issues: Vec::new(),
        }
    }

    pub fn status_label(&self) -> &'static str {
        match self.status {
            VerificationStatus::Verified => "Verified",
            VerificationStatus::Invalid => "Invalid",
            VerificationStatus::Modified => "Modified",
            VerificationStatus::Untrusted => "Untrusted",
            VerificationStatus::Expired => "Expired",
            VerificationStatus::Revoked => "Revoked",
            VerificationStatus::Unsupported => "Unsupported",
            VerificationStatus::Unknown => "Not yet verified",
            VerificationStatus::Error => "Error",
        }
    }

    /// CSS class for the banner: 'ok', 'warn', or 'err'.
    pub fn severity_class(&self) -> &'static str {
        match self.status {
            VerificationStatus::Verified => "ok",
            VerificationStatus::Unknown | VerificationStatus::Unsupported => "warn",
            _ => "err",
        }
    }
}
