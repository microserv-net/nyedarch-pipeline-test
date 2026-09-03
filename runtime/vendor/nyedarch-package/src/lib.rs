//! nyedarch-package — versioned package format, streaming compress+encrypt
//! pipeline, manifest, and restore. Depends on `nyedarch-crypto` for all sealing;
//! contains no authorization logic (the caller supplies the derived key).

#![forbid(unsafe_code)]

#[cfg(feature = "builder")]
pub mod build;
pub mod format;
pub mod manifest;
pub mod pipeline;
pub mod restore;

#[cfg(feature = "builder")]
pub use build::{collect, seal_package, FileSrc};
pub use format::{Argon2ParamsSer, Header, Parsed, COMPRESSION_DEFLATE, COMPRESSION_ZSTD};
pub use manifest::{Entry, Kind, Manifest};
pub use restore::{restore, RestoreReport};
