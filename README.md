# CertiLens Project Analysis

## Overview

**CertiLens** is a local-first PDF signature verifier for GNOME, built entirely in Rust. It provides a secure way to verify digital signatures in PDF documents with detailed explanations of what was and wasn't verified.

**Status:** Early development  
**License:** MIT  
**Language:** Rust (Edition 2021)  
**Version:** 0.1.0

## Project Purpose

CertiLens is designed to:

1. Identify a document
2. Discover available authenticity evidence (digital signatures)
3. Verify that evidence using cryptographic checks
4. Explain exactly what was and wasn't verified

The key principle: **the GUI displays what the verification layer determines. No verification decision is ever made in the UI.**

## Architecture Overview

CertiLens follows a modular architecture with 6 specialized crates in a Rust workspace:

```
certilens/
├── crates/
│   ├── certilens-core/      → Data types and structures
│   ├── certilens-pdf/       → PDF parsing and extraction
│   ├── certilens-crypto/    → Cryptographic operations
│   ├── certilens-verify/    → Verification orchestration ("the brain")
│   ├── certilens-gtk/       → GNOME GUI (GTK4 + libadwaita)
│   └── certilens-render/    → Rendering utilities (Cairo)
├── Cargo.toml              → Workspace configuration
├── Cargo.lock              → Dependency lock file
├── LICENSE                 → MIT License
└── README.md               → Documentation
```

## Crate Responsibilities

### 1. **certilens-core** — Foundation Types

**Purpose:** Define core data structures and types used throughout the application

**Dependencies:**

- `serde` — Serialization/deserialization framework
- `serde_json` — JSON handling
- `thiserror` — Error handling utilities

**Responsibility:** Defines `Document`, `VerificationResult`, and other shared types that other crates depend on.

---

### 2. **certilens-pdf** — PDF Parsing Engine

**Purpose:** Extract and parse PDF files, particularly signature data

**Dependencies:**

- `lopdf` (v0.34) — Pure Rust PDF parser
- `serde` — Data structure serialization
- `thiserror` — Error handling

**Responsibilities:**

- Parse PDF file structure
- Extract PDF headers and cross-reference tables (xref)
- Parse AcroForm (PDF form data)
- Extract ByteRange information (critical for signature verification)
- Parse CMS (Cryptographic Message Syntax) signatures

---

### 3. **certilens-crypto** — Cryptographic Operations

**Purpose:** Implement all cryptographic checks needed for signature verification

**Dependencies:**

- `sha2` (v0.10, with OID support) — SHA-256 hashing
- `cms` (v0.2) — Cryptographic Message Syntax handling
- `der` (v0.7) — Distinguished Encoding Rules (ASN.1 encoding)
- `x509-cert` (v0.2) — X.509 certificate parsing and validation
- `rsa` (v0.9) — RSA signature verification

**Responsibilities:**

- SHA-256 hash computation
- RSA signature verification
- X.509 certificate parsing
- Certificate validity checking (date/time validation)
- Certificate chain validation
- System trust store integration

---

### 4. **certilens-verify** — Verification Orchestration

**Purpose:** The "brain" that coordinates all verification checks and produces the final verdict

**Dependencies:**

- `certilens-core` — Core types
- `certilens-pdf` — PDF parsing
- `certilens-crypto` — Cryptographic operations

**Responsibilities:**

- Orchestrates verification workflow
- Runs checks independently for each signature:
  1. **Content Integrity** — Verify SHA-256 of `/ByteRange` matches CMS digest
  2. **Signature Validity** — Verify RSA signature over CMS signed attributes
  3. **Certificate Validity** — Parse X.509 cert and check validity window vs. signing time
  4. **Trust Chain** — Walk embedded certificates to self-signed root, consulting system trust store

- Produces human-readable verdicts explaining what was/wasn't proven

---

### 5. **certilens-gtk** — GNOME User Interface

**Purpose:** Provide an intuitive GTK4-based GUI for the GNOME desktop

**Dependencies:**

- `gtk4` (v0.11.5, v4_22 features) — GTK4 toolkit
- `libadwaita` (v0.9.2, v1_9 features) — GNOME design system
- `poppler` (v0.6.0, render features) — PDF rendering
- `cairo-rs` (v0.22, PNG support) — 2D graphics rendering
- Internal crates: `certilens-pdf`, `certilens-verify`, `certilens-core`

**Responsibilities:**

- Display PDF documents with visual signature indicators
- Show verification results in user-friendly format
- Render certificate chains and trust information
- Follow GNOME Human Interface Guidelines via libadwaita
- Call verification engine and display results (no verification logic in UI)

---

### 6. **certilens-render** — Rendering Utilities

**Purpose:** Provide rendering functionality for visualization

**Dependencies:**

- `cairo-rs` (v0.22, PNG support) — 2D vector graphics
- pkg-config (build-time) — Find system libraries

**Responsibilities:**

- Generate visual representations of verification results
- Possibly create signature annotations on PDFs
- Support image export (PNG format)

---

## Verification Workflow

When CertiLens verifies a signed PDF, it performs these checks **independently** for each signature:

```
PDF File
   ↓
[PDF Parser] → Extract signatures, certificates, ByteRange
   ↓
[For each signature]
   ├─→ [Content Integrity Check]
   │   └─ SHA-256(/ByteRange) == CMS digest?
   │
   ├─→ [Signature Check]
   │   └─ RSA(CMS signed attributes) verified?
   │
   ├─→ [Certificate Check]
   │   ├─ Parse X.509 certificate
   │   └─ Validity window includes signing time?
   │
   └─→ [Trust Chain Check]
       ├─ Walk embedded certificates to root
       └─ Root matches system trust store (/etc/ssl/certs/...)?
   ↓
[Verification Engine] → Produces verdict
   ↓
[GUI] → Displays result
```

## Key Design Principles

1. **Pure Rust Implementation** — Everything in Rust, no external C dependencies (except GTK4/libadwaita)
2. **Local-First** — No network calls, entirely offline operation
3. **Transparent Verification** — GUI doesn't make verification decisions; it displays what the verification layer determines
4. **Detailed Reporting** — Verdicts explain what was and wasn't proven, not just "verified/not verified"
5. **Modular Architecture** — Each component has a single responsibility, testable in isolation

## Build Requirements

### Runtime Dependencies

- **GTK 4.10+** — GNOME GUI framework
- **libadwaita 1.4+** — GNOME design library

### Build Commands

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install libgtk-4-dev libadwaita-1-dev

# Build release binary
cargo build --release

# Build will produce: target/release/certilens
```

## Dependency Ecosystem

### Cryptography Stack

- `sha2` — SHA-256 hashing
- `rsa` — RSA signatures (via RustCrypto)
- `x509-cert` — Certificate parsing (RustCrypto ecosystem)
- `cms` — CMS/PKCS#7 support
- `der` — ASN.1 DER encoding

### PDF Handling

- `lopdf` — Pure Rust PDF library (no external dependencies)

### UI Framework

- `gtk4` — GTK4 bindings
- `libadwaita` — GNOME design system
- `poppler` — PDF rendering engine
- `cairo-rs` — Graphics rendering

### Utilities

- `serde` + `serde_json` — Serialization
- `thiserror` — Error handling

## Project Status & Notes

### Current State

✅ Crypto core working  
✅ PDF parser functional  
✅ Trust chain implementation complete  
⏳ GNOME GUI in progress  
🛑 Python prototype retired in favor of pure Rust

### Development Notes

- Single-threaded verification for now
- No performance optimization yet (early dev stage)
- Focus on correctness over speed
- System trust store integration via standard Linux `/etc/ssl/certs/` path

## Security Considerations

1. **Local Verification Only** — No external validation servers
2. **Standard Cryptography** — Uses well-established algorithms (SHA-256, RSA, X.509)
3. **System Trust Store** — Leverages OS-provided trusted certificates
4. **Transparent Results** — Users can see exactly what was checked and verified
5. **No Signature** — Not signed, distributed directly (as of v0.1.0)

## Future Development Potential

- Performance optimization (parallel signature verification)
- Signature timestamping support
- OCSP (Online Certificate Status Protocol) integration
- Enhanced UI for certificate chain visualization
- CLI tool alongside GUI
- Export functionality (verification reports, annotated PDFs)
