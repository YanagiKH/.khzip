use crate::{
    compress,
    crypto::{self, KeyMaterial, FLAG_DEVICE_BOUND, FLAG_DOUBLE_ENCRYPTED, FLAG_ENCRYPTED},
    model::{ArchiveFormat, Codec, CompressionMode, Manifest, FORMAT_VERSION},
};
use anyhow::{anyhow, Context, Result};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

pub const HEADER_LEN: usize = 128;
const HEADER_MAGIC: &[u8; 8] = b"KHZIP001";
const RECORD_MAGIC: &[u8; 4] = b"KHR1";
const TRAILER_MAGIC: &[u8; 8] = b"KHTRLR01";
const TRAILER_LEN: usize = 48;
const RECORD_HEADER_LEN: usize = 64;
const INNER_METADATA_LEN: usize = 41;
const MAX_PLAIN_RECORD_LEN: u64 = 256 * 1024 * 1024;
const RECORD_CHUNK: u8 = 1;
const RECORD_MANIFEST: u8 = 2;

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u16,
    pub format: ArchiveFormat,
    pub mode: CompressionMode,
    pub flags: u32,
    pub salt: [u8; 16],
    pub nonce_prefix1: [u8; 16],
    pub nonce_prefix2: [u8; 16],
    pub index_offset: u64,
    pub chunk_count: u64,
    pub file_count: u64,
}

impl Header {
    pub fn new(format: ArchiveFormat, mode: CompressionMode, encrypted: bool) -> Self {
        let mut flags = 0;
        if encrypted || format == ArchiveFormat::Khcz {
            flags |= FLAG_ENCRYPTED;
        }
        if format == ArchiveFormat::Khaz {
            flags |= FLAG_DOUBLE_ENCRYPTED;
        }
        if format == ArchiveFormat::Khcz {
            flags |= FLAG_DEVICE_BOUND;
        }
        Self {
            version: FORMAT_VERSION,
            format,
            mode,
            flags,
            salt: crypto::random_array(),
            nonce_prefix1: crypto::random_array(),
            nonce_prefix2: crypto::random_array(),
            index_offset: 0,
            chunk_count: 0,
            file_count: 0,
        }
    }

    pub fn encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }

    pub fn double_encrypted(&self) -> bool {
        self.flags & FLAG_DOUBLE_ENCRYPTED != 0
    }

    pub fn device_bound(&self) -> bool {
        self.flags & FLAG_DEVICE_BOUND != 0
    }

    pub fn aad_prefix(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(72);
        aad.extend_from_slice(HEADER_MAGIC);
        aad.extend_from_slice(&self.version.to_le_bytes());
        aad.push(self.format as u8);
        aad.push(self.mode as u8);
        aad.extend_from_slice(&self.flags.to_le_bytes());
        aad.extend_from_slice(&self.salt);
        aad.extend_from_slice(&self.nonce_prefix1);
        aad.extend_from_slice(&self.nonce_prefix2);
        aad
    }

    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0_u8; HEADER_LEN];
        out[..8].copy_from_slice(HEADER_MAGIC);
        out[8..10].copy_from_slice(&self.version.to_le_bytes());
        out[10] = self.format as u8;
        out[11] = self.mode as u8;
        out[12..16].copy_from_slice(&self.flags.to_le_bytes());
        out[16..32].copy_from_slice(&self.salt);
        out[32..48].copy_from_slice(&self.nonce_prefix1);
        out[48..64].copy_from_slice(&self.nonce_prefix2);
        out[64..72].copy_from_slice(&self.index_offset.to_le_bytes());
        out[72..80].copy_from_slice(&self.chunk_count.to_le_bytes());
        out[80..88].copy_from_slice(&self.file_count.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self> {
        anyhow::ensure!(&bytes[..8] == HEADER_MAGIC, "not a .khzip container");
        let version = u16::from_le_bytes(bytes[8..10].try_into()?);
        anyhow::ensure!(
            version == FORMAT_VERSION,
            "unsupported container version {version}"
        );
        Ok(Self {
            version,
            format: ArchiveFormat::try_from(bytes[10])?,
            mode: CompressionMode::try_from(bytes[11])?,
            flags: u32::from_le_bytes(bytes[12..16].try_into()?),
            salt: bytes[16..32].try_into()?,
            nonce_prefix1: bytes[32..48].try_into()?,
            nonce_prefix2: bytes[48..64].try_into()?,
            index_offset: u64::from_le_bytes(bytes[64..72].try_into()?),
            chunk_count: u64::from_le_bytes(bytes[72..80].try_into()?),
            file_count: u64::from_le_bytes(bytes[80..88].try_into()?),
        })
    }
}

#[derive(Debug, Clone)]
pub struct RecordHeader {
    pub kind: u8,
    pub codec: Codec,
    pub flags: u16,
    pub ordinal: u64,
    pub plain_len: u64,
    pub payload_len: u64,
    pub content_id: [u8; 32],
}

impl RecordHeader {
    fn encode(&self) -> [u8; RECORD_HEADER_LEN] {
        let mut out = [0_u8; RECORD_HEADER_LEN];
        out[..4].copy_from_slice(RECORD_MAGIC);
        out[4] = self.kind;
        out[5] = self.codec as u8;
        out[6..8].copy_from_slice(&self.flags.to_le_bytes());
        out[8..16].copy_from_slice(&self.ordinal.to_le_bytes());
        out[16..24].copy_from_slice(&self.plain_len.to_le_bytes());
        out[24..32].copy_from_slice(&self.payload_len.to_le_bytes());
        out[32..64].copy_from_slice(&self.content_id);
        out
    }

    fn decode(bytes: &[u8; RECORD_HEADER_LEN]) -> Result<Self> {
        anyhow::ensure!(&bytes[..4] == RECORD_MAGIC, "invalid record magic");
        Ok(Self {
            kind: bytes[4],
            codec: Codec::try_from(bytes[5])?,
            flags: u16::from_le_bytes(bytes[6..8].try_into()?),
            ordinal: u64::from_le_bytes(bytes[8..16].try_into()?),
            plain_len: u64::from_le_bytes(bytes[16..24].try_into()?),
            payload_len: u64::from_le_bytes(bytes[24..32].try_into()?),
            content_id: bytes[32..64].try_into()?,
        })
    }

    pub fn aad(&self, container: &Header) -> Vec<u8> {
        let mut aad = container.aad_prefix();
        aad.push(self.kind);
        aad.push(self.codec as u8);
        aad.extend_from_slice(&self.flags.to_le_bytes());
        aad.extend_from_slice(&self.ordinal.to_le_bytes());
        aad.extend_from_slice(&self.plain_len.to_le_bytes());
        aad.extend_from_slice(&self.content_id);
        aad
    }
}

pub struct ContainerWriter {
    file: File,
    pub header: Header,
    keys: Option<KeyMaterial>,
    ordinal: u64,
}

impl ContainerWriter {
    pub fn create(path: &Path, header: Header, keys: Option<KeyMaterial>) -> Result<Self> {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)?;
        file.write_all(&header.encode())?;
        Ok(Self {
            file,
            header,
            keys,
            ordinal: 0,
        })
    }

    pub fn write_chunk(
        &mut self,
        id: [u8; 32],
        plain_len: u64,
        codec: Codec,
        compressed: &[u8],
    ) -> Result<u64> {
        self.write_record(RECORD_CHUNK, id, plain_len, codec, compressed)
    }

    pub fn write_manifest(&mut self, manifest: &Manifest) -> Result<u64> {
        let serialized =
            postcard::to_allocvec(manifest).context("manifest serialization failed")?;
        let compressed = zstd::stream::encode_all(std::io::Cursor::new(&serialized), 6)?;
        let id = *blake3::hash(&serialized).as_bytes();
        self.write_record(
            RECORD_MANIFEST,
            id,
            serialized.len() as u64,
            Codec::Zstd,
            &compressed,
        )
    }

    fn write_record(
        &mut self,
        kind: u8,
        id: [u8; 32],
        plain_len: u64,
        codec: Codec,
        compressed: &[u8],
    ) -> Result<u64> {
        let offset = self.file.stream_position()?;
        anyhow::ensure!(
            plain_len <= MAX_PLAIN_RECORD_LEN,
            "record plaintext exceeds safety limit"
        );
        let encrypted = self.keys.is_some();
        let mut record = RecordHeader {
            kind,
            codec: if encrypted { Codec::None } else { codec },
            flags: if encrypted { 1 } else { 0 },
            ordinal: self.ordinal,
            plain_len: if encrypted { 0 } else { plain_len },
            payload_len: 0,
            content_id: if encrypted { [0_u8; 32] } else { id },
        };
        let payload = if let Some(keys) = &self.keys {
            let mut inner = Vec::with_capacity(INNER_METADATA_LEN + compressed.len());
            inner.push(codec as u8);
            inner.extend_from_slice(&plain_len.to_le_bytes());
            inner.extend_from_slice(&id);
            inner.extend_from_slice(compressed);
            let aad = record.aad(&self.header);
            crypto::encrypt(
                &inner,
                keys,
                &self.header.nonce_prefix1,
                &self.header.nonce_prefix2,
                self.ordinal,
                &aad,
                self.header.double_encrypted(),
            )?
        } else {
            compressed.to_vec()
        };
        record.payload_len = payload.len() as u64;
        self.file.write_all(&record.encode())?;
        self.file.write_all(&payload)?;
        self.ordinal += 1;
        Ok(offset)
    }

    pub fn finish(mut self, index_offset: u64, chunk_count: u64, file_count: u64) -> Result<()> {
        self.header.index_offset = index_offset;
        if self.header.encrypted() {
            self.header.chunk_count = 0;
            self.header.file_count = 0;
        } else {
            self.header.chunk_count = chunk_count;
            self.header.file_count = file_count;
        }
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.header.encode())?;
        self.file.flush()?;

        let end = self.file.seek(SeekFrom::End(0))?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut remaining = end;
        let mut buffer = vec![0_u8; 1024 * 1024];
        let mut hasher = blake3::Hasher::new();
        while remaining > 0 {
            let take = usize::try_from(remaining.min(buffer.len() as u64))?;
            self.file.read_exact(&mut buffer[..take])?;
            hasher.update(&buffer[..take]);
            remaining -= take as u64;
        }
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(TRAILER_MAGIC)?;
        self.file.write_all(&index_offset.to_le_bytes())?;
        self.file.write_all(hasher.finalize().as_bytes())?;
        self.file.sync_all()?;
        Ok(())
    }
}

pub struct ContainerReader {
    file: File,
    pub header: Header,
    keys: Option<KeyMaterial>,
}

impl ContainerReader {
    pub fn open(path: &Path, keys: Option<KeyMaterial>) -> Result<Self> {
        let mut file = File::open(path)?;
        verify_trailer(&mut file)?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = [0_u8; HEADER_LEN];
        file.read_exact(&mut bytes)?;
        let header = Header::decode(&bytes)?;
        anyhow::ensure!(
            header.encrypted() == keys.is_some(),
            "archive unlock key requirement mismatch"
        );
        Ok(Self { file, header, keys })
    }

    pub fn read_manifest(&mut self) -> Result<Manifest> {
        let (record, compressed) = self.read_record_at(self.header.index_offset)?;
        anyhow::ensure!(
            record.kind == RECORD_MANIFEST,
            "index does not point to a manifest"
        );
        let serialized = compress::decompress(
            &compressed,
            record.codec,
            usize::try_from(record.plain_len)?,
        )?;
        anyhow::ensure!(
            blake3::hash(&serialized).as_bytes() == &record.content_id,
            "manifest hash mismatch"
        );
        postcard::from_bytes(&serialized).context("manifest parsing failed")
    }

    pub fn read_chunk(&mut self, offset: u64) -> Result<([u8; 32], Vec<u8>)> {
        let (record, compressed) = self.read_record_at(offset)?;
        anyhow::ensure!(record.kind == RECORD_CHUNK, "record is not a chunk");
        let plain = compress::decompress(
            &compressed,
            record.codec,
            usize::try_from(record.plain_len)?,
        )?;
        anyhow::ensure!(
            blake3::hash(&plain).as_bytes() == &record.content_id,
            "chunk hash mismatch"
        );
        Ok((record.content_id, plain))
    }

    fn read_record_at(&mut self, offset: u64) -> Result<(RecordHeader, Vec<u8>)> {
        self.file.seek(SeekFrom::Start(offset))?;
        let mut bytes = [0_u8; RECORD_HEADER_LEN];
        self.file.read_exact(&mut bytes)?;
        let record = RecordHeader::decode(&bytes)?;
        let payload_len =
            usize::try_from(record.payload_len).context("record payload too large")?;
        anyhow::ensure!(
            payload_len <= 128 * 1024 * 1024,
            "record payload exceeds safety limit"
        );
        let mut payload = vec![0_u8; payload_len];
        self.file.read_exact(&mut payload)?;
        if record.flags & 1 != 0 {
            let keys = self
                .keys
                .as_ref()
                .ok_or_else(|| anyhow!("archive is encrypted"))?;
            let aad = record.aad(&self.header);
            let inner = crypto::decrypt(
                &payload,
                keys,
                &self.header.nonce_prefix1,
                &self.header.nonce_prefix2,
                record.ordinal,
                &aad,
                self.header.double_encrypted(),
            )?;
            anyhow::ensure!(
                inner.len() >= INNER_METADATA_LEN,
                "encrypted record metadata is truncated"
            );
            let codec = Codec::try_from(inner[0])?;
            let plain_len = u64::from_le_bytes(inner[1..9].try_into()?);
            anyhow::ensure!(
                plain_len <= MAX_PLAIN_RECORD_LEN,
                "record plaintext exceeds safety limit"
            );
            let content_id = inner[9..41].try_into()?;
            let decoded = RecordHeader {
                codec,
                plain_len,
                content_id,
                ..record
            };
            Ok((decoded, inner[INNER_METADATA_LEN..].to_vec()))
        } else {
            anyhow::ensure!(
                record.plain_len <= MAX_PLAIN_RECORD_LEN,
                "record plaintext exceeds safety limit"
            );
            Ok((record, payload))
        }
    }
}

fn verify_trailer(file: &mut File) -> Result<()> {
    let len = file.metadata()?.len();
    anyhow::ensure!(
        len >= (HEADER_LEN + TRAILER_LEN) as u64,
        "archive is truncated"
    );
    file.seek(SeekFrom::End(-(TRAILER_LEN as i64)))?;
    let mut trailer = [0_u8; TRAILER_LEN];
    file.read_exact(&mut trailer)?;
    anyhow::ensure!(&trailer[..8] == TRAILER_MAGIC, "archive trailer is missing");
    let index_offset = u64::from_le_bytes(trailer[8..16].try_into()?);
    anyhow::ensure!(
        index_offset >= HEADER_LEN as u64 && index_offset < len - TRAILER_LEN as u64,
        "invalid index offset"
    );

    file.seek(SeekFrom::Start(0))?;
    let mut remaining = len - TRAILER_LEN as u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut hasher = blake3::Hasher::new();
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))?;
        file.read_exact(&mut buffer[..take])?;
        hasher.update(&buffer[..take]);
        remaining -= take as u64;
    }
    anyhow::ensure!(
        hasher.finalize().as_bytes() == &trailer[16..48],
        "archive checksum mismatch"
    );
    Ok(())
}
