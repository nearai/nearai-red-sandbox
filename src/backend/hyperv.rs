//! The Windows backend: a Hyper-V compute system per session, booted
//! from rts's own kernel and initramfs, reached only over hvsocket. See
//! docs/design/linux-windows-backends.md section 5. The document and
//! protocol pieces are portable and tested everywhere.

pub mod doc;
pub mod exec;
pub mod props;
#[cfg(windows)]
pub mod hvsock;
#[cfg(windows)]
pub mod hcs;
