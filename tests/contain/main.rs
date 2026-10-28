//! End-to-end containment against real mvm (and real opencode 2.1.4 for
//! the session tests). These create microVMs, so they are ignored by a
//! plain `cargo test`. Run them with:
//!
//!     cargo test --test contain -- --ignored --test-threads=1
//!
//! Each test skips, printing why, when mvmctl or opencode is not usable.

mod copy;
mod exec;
mod files;
mod harness;
mod leak;
mod session;
