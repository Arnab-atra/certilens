"""CertiLens — local-first document authenticity and verification.

This package is thin. It exposes:
  * The compiled Rust extension (`certilens._certilens`)
  * The GTK4 GUI (see `certilens.app`)

Everything verification-related comes from Rust. Python only displays
what Rust decides.
"""

from . import _certilens as _rust  # type: ignore

__version__ = _rust.__version__


def open_document(path: str):
    """Open a document and return a handle.

    Verification decisions are made entirely in Rust.
    Python just receives the result and displays it.
    """
    return _rust.open_document(path)


def check_signature_digest(path: str, index: int):
    """Run the Phase 2a digest check for signature `index` on `path`.

    Returns a dict:
      {
        "algorithm": str | None,
        "computed":  bytes,
        "claimed":   bytes,
        "matches":   bool,
      }

    "computed" is the SHA-256 of the ByteRange we hashed ourselves.
    "claimed"  is the digest the CMS signed-attributes say we should get.
    If they match, the signed bytes are intact.
    """
    return _rust.check_signature_digest(path, index)


def extract_signer_certificate(path: str, index: int):
    """Extract the signer's X.509 certificate from the CMS blob."""
    return _rust.extract_signer_certificate(path, index)


def verify_signature(path: str, index: int):
    """Verify the signer's RSA signature over the CMS signed attributes."""
    return _rust.verify_signature(path, index)


def verify_certificate_chain(path: str, index: int):
    """Walk the X.509 chain embedded in the CMS."""
    return _rust.verify_certificate_chain(path, index)


__all__ = [
    "open_document",
    "check_signature_digest",
    "extract_signer_certificate",
    "verify_signature",
    "verify_certificate_chain",
    "__version__",
]
