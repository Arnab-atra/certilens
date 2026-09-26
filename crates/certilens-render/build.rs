//! Build script for `certilens-render`.
//!
//! Uses `pkg-config` to locate `libpoppler-glib` on the system, and emits
//! the linker flags Cargo needs to compile and link against it.

fn main() {
    pkg_config::Config::new()
        .atleast_version("0.18")
        .probe("poppler-glib")
        .expect("poppler-glib not found — install libpoppler-glib-dev");
}
