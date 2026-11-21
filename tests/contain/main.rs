//! End-to-end containment against real mvm (and real opencode 2.2.2 for
//! the session tests). These create microVMs, so they are ignored by a
//! plain `cargo test`. Run them with:
//!
//!     cargo test --test contain -- --ignored --test-threads=1
//!
//! Explicitly requested tests fail when the patched HVF supervisor, mvmctl,
//! or the pinned opencode prerequisite is unavailable; they never pass by skipping.

#[cfg(unix)]
mod canary;
#[cfg(unix)]
mod copy;
#[cfg(unix)]
mod exec;
#[cfg(unix)]
mod files;
#[cfg(unix)]
mod harness;
// The backend invariants run on every backend: mvm on macOS and Linux,
// Hyper-V on Windows.
mod invariants;
#[cfg(unix)]
mod leak;
#[cfg(unix)]
mod network;
#[cfg(unix)]
mod session;
