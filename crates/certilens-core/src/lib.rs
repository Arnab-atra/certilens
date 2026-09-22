//! CertiLens core: the verification "brain".
//!
//! This crate knows nothing about GTK, Python, or file pickers.
//! It only defines the vocabulary of documents and verification.

pub mod document;
pub mod verification;

/// A convenience re-export so callers can write `certilens_core::Document`.
pub use document::Document;
pub use verification::{VerificationResult, VerificationStatus};
