#![forbid(unsafe_code)]

pub mod archive;
pub mod chunker;
pub mod compress;
pub mod container;
pub mod crypto;
pub mod model;

pub use archive::{
    create_archive, extract_archive, list_archive, verify_archive, CreateOptions, UnlockOptions,
};
pub use model::{ArchiveFormat, CompressionMode, CustomCompression};
