use crate::{
    chunker::{stream_chunks, ChunkConfig},
    compress::{choose_codec, compress},
    container::{ContainerReader, ContainerWriter, Header},
    crypto::{self, KeyMaterial},
    model::{
        ArchiveFormat, ChunkIndex, CompressionMode, CustomCompression, EntryKind, FileEntry, Manifest,
        DEFAULT_AVG_CHUNK, DEFAULT_MAX_CHUNK, DEFAULT_MIN_CHUNK, FORMAT_VERSION,
    },
};
use anyhow::{anyhow, Context, Result};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub inputs: Vec<PathBuf>,
    pub output: PathBuf,
    pub format: ArchiveFormat,
    pub mode: CompressionMode,
    pub password: Option<String>,
    pub custom: CustomCompression,
    pub split_size: u64,
}

impl CreateOptions {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.inputs.is_empty(), "at least one input is required");
        anyhow::ensure!(self.split_size >= 1024 * 1024, "split size must be at least 1 MiB");
        if self.format == ArchiveFormat::Khpak {
            anyhow::ensure!(self.password.is_none(), ".khpak does not support encryption");
        }
        if self.format == ArchiveFormat::Khcz {
            anyhow::ensure!(self.password.is_none(), ".khcz uses the local device key and does not accept a password");
        }
        if self.format.requires_password() {
            anyhow::ensure!(self.password.as_deref().is_some_and(|p| p.len() >= 12), ".khaz requires a password of at least 12 characters");
        }
        if let Some(password) = &self.password {
            anyhow::ensure!(self.format.allows_password(), "the selected format does not allow passwords");
            anyhow::ensure!(password.len() >= 10, "password must contain at least 10 characters");
        }
        for input in &self.inputs {
            anyhow::ensure!(input.exists(), "input does not exist: {}", input.display());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct UnlockOptions {
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ArchiveSummary {
    pub format: ArchiveFormat,
    pub files: usize,
    pub chunks: usize,
    pub original_bytes: u64,
    pub unique_bytes: u64,
    pub merkle_root: [u8; 32],
}

pub fn create_archive(options: &CreateOptions) -> Result<ArchiveSummary> {
    options.validate()?;
    let parent = options.output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = NamedTempFile::new_in(parent)?;
    let temp_path = temp.path().to_path_buf();
    drop(temp);

    let encrypted = options.password.is_some() || options.format == ArchiveFormat::Khcz;
    let effective_mode = if matches!(options.format, ArchiveFormat::Khaz | ArchiveFormat::Khcz) {
        CompressionMode::Extreme
    } else {
        options.mode
    };
    let header = Header::new(options.format, effective_mode, encrypted);
    let keys = create_keys(&header, options.password.as_deref())?;
    let mut writer = ContainerWriter::create(&temp_path, header, keys)?;
    let chunk_config = chunk_config(options)?;
    let entries = collect_entries(&options.inputs)?;
    let mut manifest_files = Vec::with_capacity(entries.len());
    let mut chunk_lookup: HashMap<[u8; 32], ChunkIndex> = HashMap::new();
    let mut chunk_order = Vec::new();
    let mut original_bytes = 0_u64;
    let mut unique_bytes = 0_u64;

    for source in entries {
        if source.kind == EntryKind::Directory {
            manifest_files.push(source.into_manifest(Vec::new(), 0));
            continue;
        }
        let mut ids = Vec::new();
        let file = File::open(&source.source).with_context(|| format!("cannot open {}", source.source.display()))?;
        let mut reader = BufReader::new(file);
        stream_chunks(&mut reader, chunk_config, |chunk| {
            original_bytes = original_bytes.checked_add(chunk.len() as u64).ok_or_else(|| anyhow!("archive size overflow"))?;
            let id = *blake3::hash(chunk).as_bytes();
            ids.push(id);
            if let std::collections::hash_map::Entry::Vacant(entry) = chunk_lookup.entry(id) {
                let preferred = choose_codec(chunk, effective_mode);
                let mut stored = compress(chunk, preferred, effective_mode, &options.custom)?;
                let codec = if stored.len() == chunk.len() { crate::model::Codec::None } else { preferred };
                if codec == crate::model::Codec::None {
                    stored.clear();
                    stored.extend_from_slice(chunk);
                }
                let offset = writer.write_chunk(id, chunk.len() as u64, codec, &stored)?;
                let index = ChunkIndex { id, record_offset: offset, plain_len: chunk.len() as u64 };
                unique_bytes = unique_bytes.checked_add(chunk.len() as u64).ok_or_else(|| anyhow!("archive size overflow"))?;
                chunk_order.push(id);
                entry.insert(index);
            }
            Ok(())
        })?;
        let size = fs::metadata(&source.source)?.len();
        manifest_files.push(source.into_manifest(ids, size));
    }

    let chunks: Vec<ChunkIndex> = chunk_order.iter().map(|id| chunk_lookup[id].clone()).collect();
    let manifest = Manifest {
        version: FORMAT_VERSION,
        format: options.format,
        mode: effective_mode,
        created_unix: now_unix(),
        files: manifest_files,
        chunks,
        merkle_root: merkle_root(&chunk_order),
        original_bytes,
        unique_bytes,
    };
    let index_offset = writer.write_manifest(&manifest)?;
    writer.finish(index_offset, manifest.chunks.len() as u64, manifest.files.len() as u64)?;

    if options.format.is_split() {
        split_archive(&temp_path, &options.output, options.split_size)?;
        fs::remove_file(&temp_path).ok();
    } else {
        atomic_replace(&temp_path, &options.output)?;
    }

    Ok(summary(&manifest))
}

pub fn list_archive(path: &Path, unlock: &UnlockOptions) -> Result<(ArchiveSummary, Vec<FileEntry>)> {
    with_joined_archive(path, |actual| {
        let mut reader = open_reader(actual, unlock)?;
        let manifest = reader.read_manifest()?;
        verify_manifest_header(&reader.header, &manifest)?;
        Ok((summary(&manifest), manifest.files))
    })
}

pub fn verify_archive(path: &Path, unlock: &UnlockOptions) -> Result<ArchiveSummary> {
    with_joined_archive(path, |actual| {
        let mut reader = open_reader(actual, unlock)?;
        let manifest = reader.read_manifest()?;
        verify_manifest_header(&reader.header, &manifest)?;
        let mut ids = Vec::with_capacity(manifest.chunks.len());
        for chunk in &manifest.chunks {
            let (id, plain) = reader.read_chunk(chunk.record_offset)?;
            anyhow::ensure!(id == chunk.id, "chunk index mismatch");
            anyhow::ensure!(plain.len() as u64 == chunk.plain_len, "chunk length mismatch");
            ids.push(id);
        }
        anyhow::ensure!(merkle_root(&ids) == manifest.merkle_root, "Merkle root mismatch");
        Ok(summary(&manifest))
    })
}

pub fn extract_archive(path: &Path, output: &Path, unlock: &UnlockOptions, overwrite: bool) -> Result<ArchiveSummary> {
    with_joined_archive(path, |actual| {
        let mut reader = open_reader(actual, unlock)?;
        let manifest = reader.read_manifest()?;
        verify_manifest_header(&reader.header, &manifest)?;
        fs::create_dir_all(output)?;
        let chunks: HashMap<[u8; 32], ChunkIndex> = manifest.chunks.iter().cloned().map(|c| (c.id, c)).collect();

        for entry in manifest.files.iter().filter(|e| e.kind == EntryKind::Directory) {
            let target = safe_join(output, &entry.path)?;
            fs::create_dir_all(target)?;
        }
        for entry in manifest.files.iter().filter(|e| e.kind == EntryKind::File) {
            let target = safe_join(output, &entry.path)?;
            if target.exists() && !overwrite {
                anyhow::bail!("refusing to overwrite {}; pass --overwrite", target.display());
            }
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let temp = target.with_extension(format!("{}.khzip-part", target.extension().and_then(|e| e.to_str()).unwrap_or_default()));
            let file = File::create(&temp)?;
            let mut writer = BufWriter::new(file);
            for id in &entry.chunks {
                let chunk = chunks.get(id).ok_or_else(|| anyhow!("missing chunk index"))?;
                let (actual_id, plain) = reader.read_chunk(chunk.record_offset)?;
                anyhow::ensure!(&actual_id == id, "chunk id mismatch during extraction");
                writer.write_all(&plain)?;
            }
            writer.flush()?;
            drop(writer);
            let actual_size = fs::metadata(&temp)?.len();
            anyhow::ensure!(actual_size == entry.size, "extracted file size mismatch for {}", entry.path);
            if overwrite && target.exists() {
                fs::remove_file(&target)?;
            }
            fs::rename(&temp, &target)?;
            restore_permissions(&target, entry.unix_mode)?;
        }
        Ok(summary(&manifest))
    })
}

fn open_reader(path: &Path, unlock: &UnlockOptions) -> Result<ContainerReader> {
    let mut raw = File::open(path)?;
    let mut header_bytes = [0_u8; crate::container::HEADER_LEN];
    raw.read_exact(&mut header_bytes)?;
    drop(raw);
    let header = parse_header_for_unlock(&header_bytes)?;
    let keys = if header.encrypted() {
        if header.device_bound() {
            Some(crypto::device_keys(&header.salt)?)
        } else {
            let password = unlock.password.as_deref().ok_or_else(|| anyhow!("archive password is required"))?;
            Some(crypto::password_keys(password, &header.salt)?)
        }
    } else {
        None
    };
    ContainerReader::open(path, keys)
}

fn parse_header_for_unlock(bytes: &[u8; crate::container::HEADER_LEN]) -> Result<Header> {
    // ContainerReader validates the complete header and trailer. This minimal parse only determines key type.
    anyhow::ensure!(&bytes[..8] == b"KHZIP001", "not a .khzip container");
    let format = ArchiveFormat::try_from(bytes[10])?;
    let mode = CompressionMode::try_from(bytes[11])?;
    let flags = u32::from_le_bytes(bytes[12..16].try_into()?);
    Ok(Header {
        version: u16::from_le_bytes(bytes[8..10].try_into()?),
        format,
        mode,
        flags,
        salt: bytes[16..32].try_into()?,
        nonce_prefix1: bytes[32..48].try_into()?,
        nonce_prefix2: bytes[48..64].try_into()?,
        index_offset: u64::from_le_bytes(bytes[64..72].try_into()?),
        chunk_count: u64::from_le_bytes(bytes[72..80].try_into()?),
        file_count: u64::from_le_bytes(bytes[80..88].try_into()?),
    })
}

fn create_keys(header: &Header, password: Option<&str>) -> Result<Option<KeyMaterial>> {
    if header.device_bound() {
        return Ok(Some(crypto::device_keys(&header.salt)?));
    }
    password.map(|value| crypto::password_keys(value, &header.salt)).transpose()
}

fn chunk_config(options: &CreateOptions) -> Result<ChunkConfig> {
    let config = if options.mode == CompressionMode::Custom {
        ChunkConfig { min: options.custom.min_chunk, avg: options.custom.avg_chunk, max: options.custom.max_chunk }
    } else {
        ChunkConfig { min: DEFAULT_MIN_CHUNK, avg: DEFAULT_AVG_CHUNK, max: DEFAULT_MAX_CHUNK }
    };
    config.validate()
}

#[derive(Debug)]
struct SourceEntry {
    source: PathBuf,
    archive_path: String,
    kind: EntryKind,
    modified_unix: i64,
    unix_mode: u32,
}

impl SourceEntry {
    fn into_manifest(self, chunks: Vec<[u8; 32]>, size: u64) -> FileEntry {
        FileEntry { path: self.archive_path, kind: self.kind, size, modified_unix: self.modified_unix, unix_mode: self.unix_mode, chunks }
    }
}

fn collect_entries(inputs: &[PathBuf]) -> Result<Vec<SourceEntry>> {
    let mut entries = Vec::new();
    let mut names = HashSet::new();
    for input in inputs {
        let canonical = fs::canonicalize(input)?;
        let root_name = input.file_name().ok_or_else(|| anyhow!("input has no file name: {}", input.display()))?.to_string_lossy().to_string();
        anyhow::ensure!(names.insert(root_name.clone()), "duplicate archive root name: {root_name}");
        let metadata = fs::symlink_metadata(&canonical)?;
        anyhow::ensure!(!metadata.file_type().is_symlink(), "symbolic links are rejected: {}", input.display());
        if metadata.is_file() {
            entries.push(source_entry(canonical, root_name, EntryKind::File, &metadata));
        } else if metadata.is_dir() {
            for item in WalkDir::new(&canonical).follow_links(false).sort_by_file_name() {
                let item = item?;
                let metadata = fs::symlink_metadata(item.path())?;
                anyhow::ensure!(!metadata.file_type().is_symlink(), "symbolic links are rejected: {}", item.path().display());
                let relative = item.path().strip_prefix(&canonical)?;
                let archive_path = if relative.as_os_str().is_empty() {
                    root_name.clone()
                } else {
                    format!("{root_name}/{}", relative.to_string_lossy().replace('\\', "/"))
                };
                let kind = if metadata.is_dir() { EntryKind::Directory } else if metadata.is_file() { EntryKind::File } else { continue };
                entries.push(source_entry(item.path().to_path_buf(), archive_path, kind, &metadata));
            }
        } else {
            anyhow::bail!("unsupported input type: {}", input.display());
        }
    }
    Ok(entries)
}

fn source_entry(source: PathBuf, archive_path: String, kind: EntryKind, metadata: &fs::Metadata) -> SourceEntry {
    SourceEntry {
        source,
        archive_path,
        kind,
        modified_unix: metadata.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs() as i64),
        unix_mode: unix_mode(metadata),
    }
}

fn verify_manifest_header(header: &Header, manifest: &Manifest) -> Result<()> {
    anyhow::ensure!(manifest.version == FORMAT_VERSION, "unsupported manifest version");
    anyhow::ensure!(manifest.format == header.format, "header and manifest format mismatch");
    anyhow::ensure!(manifest.mode == header.mode, "header and manifest mode mismatch");
    anyhow::ensure!(manifest.files.len() as u64 == header.file_count, "file count mismatch");
    anyhow::ensure!(manifest.chunks.len() as u64 == header.chunk_count, "chunk count mismatch");
    Ok(())
}

fn summary(manifest: &Manifest) -> ArchiveSummary {
    ArchiveSummary {
        format: manifest.format,
        files: manifest.files.iter().filter(|e| e.kind == EntryKind::File).count(),
        chunks: manifest.chunks.len(),
        original_bytes: manifest.original_bytes,
        unique_bytes: manifest.unique_bytes,
        merkle_root: manifest.merkle_root,
    }
}

fn merkle_root(ids: &[[u8; 32]]) -> [u8; 32] {
    if ids.is_empty() {
        return *blake3::hash(b"khzip-empty-merkle-v1").as_bytes();
    }
    let mut level: Vec<[u8; 32]> = ids
        .iter()
        .map(|id| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"khzip-leaf-v1");
            hasher.update(id);
            *hasher.finalize().as_bytes()
        })
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"khzip-node-v1");
            hasher.update(&pair[0]);
            hasher.update(right);
            next.push(*hasher.finalize().as_bytes());
        }
        level = next;
    }
    level[0]
}

fn safe_join(base: &Path, archive_path: &str) -> Result<PathBuf> {
    anyhow::ensure!(!archive_path.contains('\0'), "archive path contains NUL");
    let path = Path::new(archive_path);
    anyhow::ensure!(!path.is_absolute(), "archive path is absolute");
    for component in path.components() {
        anyhow::ensure!(matches!(component, Component::Normal(_)), "unsafe archive path: {archive_path}");
    }
    Ok(base.join(path))
}

fn split_archive(source: &Path, output: &Path, split_size: u64) -> Result<()> {
    let base = if output.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("khx")) {
        output.to_path_buf()
    } else {
        output.with_extension("khx")
    };
    let mut reader = BufReader::new(File::open(source)?);
    let mut part = 1_u32;
    let mut buffer = vec![0_u8; usize::try_from(split_size.min(16 * 1024 * 1024))?];
    loop {
        let part_path = PathBuf::from(format!("{}.{part:03}", base.display()));
        let mut writer = BufWriter::new(File::create(&part_path)?);
        let mut written = 0_u64;
        while written < split_size {
            let take = usize::try_from((split_size - written).min(buffer.len() as u64))?;
            let count = reader.read(&mut buffer[..take])?;
            if count == 0 {
                writer.flush()?;
                if written == 0 {
                    fs::remove_file(part_path).ok();
                }
                return Ok(());
            }
            writer.write_all(&buffer[..count])?;
            written += count as u64;
        }
        writer.flush()?;
        part += 1;
    }
}

fn with_joined_archive<T>(path: &Path, operation: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
    if is_split_part(path) {
        let directory = tempfile::tempdir()?;
        let joined = directory.path().join("joined.khzip");
        join_parts(path, &joined)?;
        operation(&joined)
    } else {
        operation(path)
    }
}

fn is_split_part(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|ext| ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit()))
}

fn join_parts(first: &Path, destination: &Path) -> Result<()> {
    let text = first.to_string_lossy();
    let base = text.rsplit_once('.').ok_or_else(|| anyhow!("invalid split archive part name"))?.0.to_string();
    let mut writer = BufWriter::new(File::create(destination)?);
    for part in 1_u32.. {
        let path = PathBuf::from(format!("{base}.{part:03}"));
        if !path.exists() {
            anyhow::ensure!(part > 1, "split archive part not found: {}", path.display());
            break;
        }
        let mut reader = BufReader::new(File::open(path)?);
        std::io::copy(&mut reader, &mut writer)?;
    }
    writer.flush()?;
    Ok(())
}

fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        anyhow::bail!("output already exists: {}", destination.display());
    }
    fs::rename(source, destination).or_else(|_| {
        fs::copy(source, destination)?;
        fs::remove_file(source)?;
        Ok::<(), std::io::Error>(())
    })?;
    Ok(())
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

#[cfg(unix)]
fn unix_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn unix_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn restore_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if mode != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restore_permissions(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}
