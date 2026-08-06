use serde::{Deserialize, Serialize};
use std::{fmt, path::Path, str::FromStr};

pub const FORMAT_VERSION: u16 = 1;
pub const DEFAULT_MIN_CHUNK: usize = 256 * 1024;
pub const DEFAULT_AVG_CHUNK: usize = 1024 * 1024;
pub const DEFAULT_MAX_CHUNK: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ArchiveFormat {
    Khz = 1,
    Khpak = 2,
    Khx = 3,
    Khaz = 4,
    Khcz = 5,
}

impl ArchiveFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Khz => "khz",
            Self::Khpak => "khpak",
            Self::Khx => "khx",
            Self::Khaz => "khaz",
            Self::Khcz => "khcz",
        }
    }

    pub fn from_output(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        Self::from_str(&ext).ok()
    }

    pub fn allows_password(self) -> bool {
        matches!(self, Self::Khz | Self::Khx | Self::Khaz)
    }

    pub fn requires_password(self) -> bool {
        matches!(self, Self::Khaz)
    }

    pub fn is_split(self) -> bool {
        self == Self::Khx
    }
}

impl TryFrom<u8> for ArchiveFormat {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Khz),
            2 => Ok(Self::Khpak),
            3 => Ok(Self::Khx),
            4 => Ok(Self::Khaz),
            5 => Ok(Self::Khcz),
            _ => anyhow::bail!("unsupported archive format id {value}"),
        }
    }
}

impl FromStr for ArchiveFormat {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .as_str()
        {
            "khz" => Ok(Self::Khz),
            "khpak" => Ok(Self::Khpak),
            "khx" => Ok(Self::Khx),
            "khaz" => Ok(Self::Khaz),
            "khcz" => Ok(Self::Khcz),
            other => anyhow::bail!("unknown format: {other}"),
        }
    }
}

impl fmt::Display for ArchiveFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.extension())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CompressionMode {
    Fast = 1,
    Balanced = 2,
    Extreme = 3,
    Custom = 4,
}

impl TryFrom<u8> for CompressionMode {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Fast),
            2 => Ok(Self::Balanced),
            3 => Ok(Self::Extreme),
            4 => Ok(Self::Custom),
            _ => anyhow::bail!("unsupported compression mode id {value}"),
        }
    }
}

impl FromStr for CompressionMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "fast" | "quick" => Ok(Self::Fast),
            "balanced" | "normal" => Ok(Self::Balanced),
            "extreme" | "max" => Ok(Self::Extreme),
            "custom" => Ok(Self::Custom),
            other => anyhow::bail!("unknown compression mode: {other}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomCompression {
    pub zstd_level: i32,
    pub brotli_quality: u32,
    pub lzma_level: u32,
    pub min_chunk: usize,
    pub avg_chunk: usize,
    pub max_chunk: usize,
}

impl Default for CustomCompression {
    fn default() -> Self {
        Self {
            zstd_level: 9,
            brotli_quality: 7,
            lzma_level: 7,
            min_chunk: DEFAULT_MIN_CHUNK,
            avg_chunk: DEFAULT_AVG_CHUNK,
            max_chunk: DEFAULT_MAX_CHUNK,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Codec {
    None = 0,
    Zstd = 1,
    Brotli = 2,
    Lzma2 = 3,
}

impl TryFrom<u8> for Codec {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Zstd),
            2 => Ok(Self::Brotli),
            3 => Ok(Self::Lzma2),
            _ => anyhow::bail!("unsupported codec id {value}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkIndex {
    pub id: [u8; 32],
    pub record_offset: u64,
    pub plain_len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    pub modified_unix: i64,
    pub unix_mode: u32,
    pub chunks: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u16,
    pub format: ArchiveFormat,
    pub mode: CompressionMode,
    pub created_unix: i64,
    pub files: Vec<FileEntry>,
    pub chunks: Vec<ChunkIndex>,
    pub merkle_root: [u8; 32],
    pub original_bytes: u64,
    pub unique_bytes: u64,
}
