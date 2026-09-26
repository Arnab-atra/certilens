use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A document the user has opened.
///
/// For now we only store the path and a very  rough format guess.
/// Later we'll add metadata, embedded signatures, and and content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub path: PathBuf,
    pub format: DocumentFormat,
}

/// Very rough format classification. NOT authenticity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentFormat {
    Pdf,
    Unknown,
}

impl Document {
    /// Open a file and guess its format for the extension.
    ///
    /// This does *no* verification. It only answers
    /// "what kind of file does this look like?"
    /// Note: The file is checked for existence but not locked.
    /// If the file is deleted/moved after this call but before use.
    /// operations on this Document will fail gracefully.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        // Ensure the file exists.
        std::fs::metadata(&path)?;

        let format = match path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            Some("pdf") => DocumentFormat::Pdf,
            _ => DocumentFormat::Unknown,
        };
        Ok(Self { path, format })
    }

    /// A short human-readable label for the UI.
    pub fn format_label(&self) -> &'static str {
        match self.format {
            DocumentFormat::Pdf => "PDF",
            DocumentFormat::Unknown => "Unknown",
        }
    }
}
