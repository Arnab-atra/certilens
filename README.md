# CertiLens

**CertiLens** is a local-first document authenticity and verification application.

Its job is to:

> Identify a document → discover available authenticity evidence → verify that evidence → explain exactly what was and wasn't verified.

## Status

Early development. Phase 0 (foundation) is in progress.

## Architecture

- **Rust core** (`crates/certilens-core`): all verification decisions.
- **Rust PyO3 bridge** (`crates/certilens-python`): exposes the core to Python.
- **Python GTK4 app** (`python/certilens`): presentation only.

Python displays verification results. Rust determines them.

## License

MIT
