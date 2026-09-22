# CertiLens

**CertiLens** is a local-first PDF signature verifier for GNOME.

Its job is to:

> Identify a document → discover available authenticity evidence → verify
> that evidence → explain exactly what was and wasn't verified.

## Status

Early development. The crypto core, PDF parser, and trust chain work;
the GNOME GUI is in progress. The Python prototype was retired in favor
of a single pure-Rust binary.

## Architecture

Everything is Rust:
crates/
├── certilens-core/ — types (Document, VerificationResult, ...)
├── certilens-pdf/ — PDF parsing (header, xref, AcroForm, ByteRange, CMS)
├── certilens-crypto/ — SHA-256, RSA, X.509, chain, system trust store
├── certilens-verify/ — orchestration (the "brain" that produces a verdict)
└── certilens-gtk/ — GTK4 + libadwaita GUI

**Design principle:** the GUI displays what the verification layer
determines. No verification decision is ever made in the UI.

## What it checks

For every signature in a PDF, CertiLens runs these checks independently:

1. **Content integrity** — SHA-256 of the `/ByteRange` matches the CMS digest
2. **Signature** — RSA signature over the CMS signed attributes verifies
3. **Certificate** — X.509 parse, validity window vs. the claimed signing time
4. **Trust chain** — walk the embedded certificates to a self-signed root,
   consulting the system trust store (`/etc/ssl/certs/...`)

The verdict is not "verified" or "not verified." It's a sentence that
explains what _was_ and _wasn't_ proven.

## Building

Requires GTK 4.10+ and libadwaita 1.4+.

```bash
sudo apt install libgtk-4-dev libadwaita-1-dev
cargo build --release
```
