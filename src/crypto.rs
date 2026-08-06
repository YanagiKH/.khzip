use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use directories::ProjectDirs;
use rand::{rngs::OsRng, RngCore};
use std::{fs, path::PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const FLAG_ENCRYPTED: u32 = 1;
pub const FLAG_DOUBLE_ENCRYPTED: u32 = 1 << 1;
pub const FLAG_DEVICE_BOUND: u32 = 1 << 2;
pub const FLAG_KEY_SLOTS: u32 = 1 << 3;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial {
    pub primary: [u8; 32],
    pub secondary: [u8; 32],
}

impl KeyMaterial {
    pub fn from_master(master: &[u8; 32]) -> Self {
        expand_keys(master)
    }
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn password_keys(password: &str, salt: &[u8; 16]) -> Result<KeyMaterial> {
    let params = Params::new(128 * 1024, 3, 1, Some(32))
        .map_err(|error| anyhow!("invalid Argon2 parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut base = [0_u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut base)
        .map_err(|error| anyhow!("Argon2id key derivation failed: {error}"))?;
    let keys = expand_keys(&base);
    base.zeroize();
    Ok(keys)
}

pub fn device_keys(salt: &[u8; 16]) -> Result<KeyMaterial> {
    let mut device = load_device_key()?;
    let mut material = Vec::with_capacity(48);
    material.extend_from_slice(&device);
    material.extend_from_slice(salt);
    let mut base = blake3::derive_key("khzip device-bound archive key v1", &material);
    device.zeroize();
    material.zeroize();
    let keys = expand_keys(&base);
    base.zeroize();
    Ok(keys)
}

fn expand_keys(base: &[u8; 32]) -> KeyMaterial {
    KeyMaterial {
        primary: blake3::derive_key("khzip xchacha20-poly1305 primary v1", base),
        secondary: blake3::derive_key("khzip xchacha20-poly1305 secondary v1", base),
    }
}

pub fn encrypt(
    payload: &[u8],
    keys: &KeyMaterial,
    prefix1: &[u8; 16],
    prefix2: &[u8; 16],
    ordinal: u64,
    aad: &[u8],
    double: bool,
) -> Result<Vec<u8>> {
    let first = seal(&keys.primary, prefix1, ordinal, aad, payload)?;
    if double {
        let mut outer_aad = Vec::with_capacity(aad.len() + 8);
        outer_aad.extend_from_slice(aad);
        outer_aad.extend_from_slice(b"outer-v1");
        seal(&keys.secondary, prefix2, ordinal, &outer_aad, &first)
    } else {
        Ok(first)
    }
}

pub fn decrypt(
    payload: &[u8],
    keys: &KeyMaterial,
    prefix1: &[u8; 16],
    prefix2: &[u8; 16],
    ordinal: u64,
    aad: &[u8],
    double: bool,
) -> Result<Vec<u8>> {
    let inner = if double {
        let mut outer_aad = Vec::with_capacity(aad.len() + 8);
        outer_aad.extend_from_slice(aad);
        outer_aad.extend_from_slice(b"outer-v1");
        open(&keys.secondary, prefix2, ordinal, &outer_aad, payload)?
    } else {
        payload.to_vec()
    };
    open(&keys.primary, prefix1, ordinal, aad, &inner)
}

fn seal(
    key: &[u8; 32],
    prefix: &[u8; 16],
    ordinal: u64,
    aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = nonce(prefix, ordinal);
    cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: payload, aad })
        .map_err(|_| anyhow!("authenticated encryption failed"))
}

fn open(
    key: &[u8; 32],
    prefix: &[u8; 16],
    ordinal: u64,
    aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = nonce(prefix, ordinal);
    cipher
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: payload, aad })
        .map_err(|_| anyhow!("authentication failed: wrong key or modified archive"))
}

fn nonce(prefix: &[u8; 16], ordinal: u64) -> [u8; 24] {
    let mut nonce = [0_u8; 24];
    nonce[..16].copy_from_slice(prefix);
    nonce[16..].copy_from_slice(&ordinal.to_le_bytes());
    nonce
}

pub fn device_key_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("dev", "YanagiKH", "khzip")
        .ok_or_else(|| anyhow!("cannot determine configuration directory"))?;
    Ok(dirs.config_dir().join("device.key"))
}

pub fn init_device_key(force: bool) -> Result<PathBuf> {
    let path = device_key_path()?;
    if path.exists() && !force {
        anyhow::bail!(
            "device key already exists at {}; use --force to replace it",
            path.display()
        );
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("invalid device key path"))?;
    fs::create_dir_all(parent)?;
    let key = random_array::<32>();
    fs::write(&path, key)?;
    set_private_permissions(&path)?;
    Ok(path)
}

fn load_device_key() -> Result<[u8; 32]> {
    let path = device_key_path()?;
    let bytes = fs::read(&path).with_context(|| {
        format!(
            "device key not found at {}; run `khzip device-key init`",
            path.display()
        )
    })?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("device key has an invalid length"))
}

#[cfg(unix)]
fn set_private_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}
