//! End-to-end containment against real VMs, mvm on macOS and Linux and
//! Hyper-V on Windows (and real opencode 2.2.2 for the session tests).
//! These create VMs, so they are ignored by a plain `cargo test`. Run them
//! with:
//!
//!     cargo test --test contain -- --ignored --test-threads=1
//!
//! Explicitly requested tests fail when the patched HVF supervisor, mvmctl,
//! or the pinned opencode prerequisite is unavailable; they never pass by skipping.

// Canaries and the mvm network suite are Unix-only; the rest run on every
// backend: mvm on macOS and Linux, Hyper-V on Windows.
#[cfg(unix)]
mod canary;
mod copy;
mod exec;
mod files;
mod harness;
mod invariants;
mod leak;
#[cfg(unix)]
mod network;
mod session;
