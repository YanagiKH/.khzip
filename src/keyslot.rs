use crate::crypto::{self, KeyMaterial};
use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use hpke::{
    aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305,
    kdf::{HkdfSha256, Kdf, KdfShake128, KdfTurboShake128},
    kem::{MlKem768, X25519HkdfSha256, XWing},
    single_shot_open, single_shot_seal, Deserializable, Kem as KemTrait, OpModeR,
    OpModeS, Serializable,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use zeroize::{Zeroize, Zeroizing};

const SLOT_MAGIC: &[u8; 8] = b"KHKS0001";
const SLOT_VERSION: u16 = 1;
const SLOT_HEADER_LEN: usize = 16;
const SLOT_ENTRY_HEADER_LEN: usize = 44;
const MAX_KEY_SLOTS: usize = 64;
pub const MAX_KEY_SLOT_AREA: usize = 4 * 1024 * 1024;
const KEY_FILE_VERSION: u16 = 1;
const HPKE_INFO: &[u8] = b"khzip hpke archive master key v2";
const PASSWORD_AAD: &[u8] = b"khzip password archive master key v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyAlgorithm {
    X25519,
    MlKem768,
    XWing,
}

impl KeyAlgorithm {
    fn id(self) -> u8 {
        match self {
            Self::X25519 => 1,
            Self::MlKem768 => 2,
            Self::XWing => 3,
        }
    }

    fn from_id(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::X25519),
            2 => Ok(Self::MlKem768),
            3 => Ok(Self::XWing),
            _ => anyhow::bail!("unsupported key algorithm id {value}"),
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X25519 => f.write_str("x25519"),
            Self::MlKem768 => f.write_str("ml-kem-768"),
            Self::XWing => f.write_str("x-wing"),
        }
    }
}

impl FromStr for KeyAlgorithm {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().replace('_', "-").as_str() {
            "x25519" | "hpke-x25519" => Ok(Self::X25519),
            "ml-kem-768" | "mlkem768" | "ml-kem" => Ok(Self::MlKem768),
            "x-wing" | "xwing" | "hybrid" => Ok(Self::XWing),
            other => anyhow::bail!("unknown key algorithm: {other}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub algorithm: KeyAlgorithm,
    pub fingerprint: [u8; 32],
    pub has_secret: bool,
}

#[derive(Debug, Clone)]
struct Recipient {
    algorithm: KeyAlgorithm,
    public_key: Vec<u8>,
    fingerprint: [u8; 32],
}

#[derive(Debug, Clone)]
struct Identity {
    algorithm: KeyAlgorithm,
    public_key: Vec<u8>,
    secret_key: Zeroizing<Vec<u8>>,
    fingerprint: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyFile {
    version: u16,
    kind: String,
    algorithm: KeyAlgorithm,
    public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret_key: Option<String>,
    fingerprint: String,
}

#[derive(Debug, Clone)]
struct KeySlot {
    kind: u8,
    fingerprint: [u8; 32],
    encapped: Vec<u8>,
    wrapped: Vec<u8>,
}

pub struct ArchiveKeySetup {
    pub keys: Option<KeyMaterial>,
    pub key_slots: Vec<u8>,
}

pub fn generate_keypair(
    algorithm: KeyAlgorithm,
    public_path: &Path,
    secret_path: &Path,
    force: bool,
) -> Result<KeyInfo> {
    if !force {
        anyhow::ensure!(
            !public_path.exists(),
            "public key already exists: {}",
            public_path.display()
        );
        anyhow::ensure!(
            !secret_path.exists(),
            "secret key already exists: {}",
            secret_path.display()
        );
    }
    if let Some(parent) = public_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = secret_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let (secret_key, public_key) = match algorithm {
        KeyAlgorithm::X25519 => serialize_keypair::<X25519HkdfSha256>(),
        KeyAlgorithm::MlKem768 => serialize_keypair::<MlKem768>(),
        KeyAlgorithm::XWing => serialize_keypair::<XWing>(),
    };
    let fingerprint = key_fingerprint(algorithm, &public_key);
    let public_file = KeyFile {
        version: KEY_FILE_VERSION,
        kind: "khzip-public-key".to_string(),
        algorithm,
        public_key: hex::encode(&public_key),
        secret_key: None,
        fingerprint: hex::encode(fingerprint),
    };
    let secret_file = KeyFile {
        version: KEY_FILE_VERSION,
        kind: "khzip-secret-key".to_string(),
        algorithm,
        public_key: hex::encode(&public_key),
        secret_key: Some(hex::encode(&secret_key)),
        fingerprint: hex::encode(fingerprint),
    };
    fs::write(public_path, serde_json::to_vec_pretty(&public_file)?)?;
    fs::write(secret_path, serde_json::to_vec_pretty(&secret_file)?)?;
    set_private_permissions(secret_path)?;

    Ok(KeyInfo {
        algorithm,
        fingerprint,
        has_secret: true,
    })
}

pub fn inspect_key(path: &Path) -> Result<KeyInfo> {
    let file = load_key_file(path)?;
    let public_key = hex::decode(&file.public_key).context("invalid public key encoding")?;
    let fingerprint = validate_fingerprint(&file, &public_key)?;
    Ok(KeyInfo {
        algorithm: file.algorithm,
        fingerprint,
        has_secret: file.secret_key.is_some(),
    })
}

pub fn create_archive_keys(
    password: Option<&str>,
    recipient_paths: &[PathBuf],
    salt: &[u8; 16],
    device_bound: bool,
    encrypted: bool,
) -> Result<ArchiveKeySetup> {
    if device_bound {
        return Ok(ArchiveKeySetup {
            keys: Some(crypto::device_keys(salt)?),
            key_slots: Vec::new(),
        });
    }
    if !encrypted {
        return Ok(ArchiveKeySetup {
            keys: None,
            key_slots: Vec::new(),
        });
    }

    let mut master = Zeroizing::new(crypto::random_array::<32>());
    let keys = KeyMaterial::from_master(&master);
    let mut slots = Vec::new();
    if let Some(password) = password {
        slots.push(wrap_password(password, salt, &master)?);
    }
    for path in recipient_paths {
        let recipient = load_recipient(path)?;
        slots.push(wrap_recipient(&recipient, salt, &master)?);
    }
    anyhow::ensure!(
        !slots.is_empty(),
        "encrypted archive has no password, device key, or recipient"
    );
    let key_slots = encode_slots(&slots)?;
    master.zeroize();
    Ok(ArchiveKeySetup {
        keys: Some(keys),
        key_slots,
    })
}

pub fn unlock_archive_keys(
    password: Option<&str>,
    identity_paths: &[PathBuf],
    salt: &[u8; 16],
    bytes: &[u8],
) -> Result<KeyMaterial> {
    let slots = decode_slots(bytes)?;
    if let Some(password) = password {
        for slot in slots.iter().filter(|slot| slot.kind == 0) {
            if let Ok(master) = unwrap_password(password, salt, slot) {
                return Ok(KeyMaterial::from_master(&master));
            }
        }
    }

    let identities = identity_paths
        .iter()
        .map(|path| load_identity(path))
        .collect::<Result<Vec<_>>>()?;
    for identity in &identities {
        for slot in slots.iter().filter(|slot| {
            slot.kind == identity.algorithm.id() && slot.fingerprint == identity.fingerprint
        }) {
            if let Ok(master) = unwrap_recipient(identity, salt, slot) {
                return Ok(KeyMaterial::from_master(&master));
            }
        }
    }

    let available = slots
        .iter()
        .filter_map(|slot| {
            if slot.kind == 0 {
                Some("password".to_string())
            } else {
                KeyAlgorithm::from_id(slot.kind).ok().map(|algorithm| {
                    format!(
                        "{}:{}",
                        algorithm,
                        hex::encode(&slot.fingerprint[..8])
                    )
                })
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::bail!(
        "no supplied password or identity could unlock this archive; available slots: {available}"
    )
}

pub fn slot_descriptions(bytes: &[u8]) -> Result<Vec<String>> {
    decode_slots(bytes)?
        .iter()
        .map(|slot| {
            if slot.kind == 0 {
                Ok("password".to_string())
            } else {
                Ok(format!(
                    "{}:{}",
                    KeyAlgorithm::from_id(slot.kind)?,
                    hex::encode(&slot.fingerprint[..8])
                ))
            }
        })
        .collect()
}

fn serialize_keypair<Kem>() -> (Vec<u8>, Vec<u8>)
where
    Kem: KemTrait,
{
    let (secret, public) = Kem::gen_keypair();
    (
        secret.to_bytes().as_ref().to_vec(),
        public.to_bytes().as_ref().to_vec(),
    )
}

fn load_recipient(path: &Path) -> Result<Recipient> {
    let file = load_key_file(path)?;
    anyhow::ensure!(
        file.kind == "khzip-public-key" || file.kind == "khzip-secret-key",
        "not a .khzip public or secret key file"
    );
    let public_key = hex::decode(&file.public_key).context("invalid public key encoding")?;
    let fingerprint = validate_fingerprint(&file, &public_key)?;
    validate_public_key(file.algorithm, &public_key)?;
    Ok(Recipient {
        algorithm: file.algorithm,
        public_key,
        fingerprint,
    })
}

fn load_identity(path: &Path) -> Result<Identity> {
    let file = load_key_file(path)?;
    anyhow::ensure!(file.kind == "khzip-secret-key", "identity is not a secret key");
    let public_key = hex::decode(&file.public_key).context("invalid public key encoding")?;
    let secret_key = Zeroizing::new(hex::decode(
        file.secret_key
            .as_deref()
            .ok_or_else(|| anyhow!("identity has no secret key"))?,
    )?);
    let fingerprint = validate_fingerprint(&file, &public_key)?;
    validate_keypair(file.algorithm, &secret_key, &public_key)?;
    Ok(Identity {
        algorithm: file.algorithm,
        public_key,
        secret_key,
        fingerprint,
    })
}

fn load_key_file(path: &Path) -> Result<KeyFile> {
    let bytes = fs::read(path).with_context(|| format!("cannot read key {}", path.display()))?;
    let file: KeyFile = serde_json::from_slice(&bytes).context("invalid .khzip key JSON")?;
    anyhow::ensure!(file.version == KEY_FILE_VERSION, "unsupported key file version");
    Ok(file)
}

fn validate_fingerprint(file: &KeyFile, public_key: &[u8]) -> Result<[u8; 32]> {
    let expected = key_fingerprint(file.algorithm, public_key);
    let encoded = hex::decode(&file.fingerprint).context("invalid key fingerprint encoding")?;
    let actual: [u8; 32] = encoded
        .try_into()
        .map_err(|_| anyhow!("key fingerprint has an invalid length"))?;
    anyhow::ensure!(actual == expected, "key fingerprint mismatch");
    Ok(actual)
}

fn validate_public_key(algorithm: KeyAlgorithm, public_key: &[u8]) -> Result<()> {
    match algorithm {
        KeyAlgorithm::X25519 => {
            <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(public_key)?;
        }
        KeyAlgorithm::MlKem768 => {
            <MlKem768 as KemTrait>::PublicKey::from_bytes(public_key)?;
        }
        KeyAlgorithm::XWing => {
            <XWing as KemTrait>::PublicKey::from_bytes(public_key)?;
        }
    }
    Ok(())
}

fn validate_keypair(algorithm: KeyAlgorithm, secret_key: &[u8], public_key: &[u8]) -> Result<()> {
    match algorithm {
        KeyAlgorithm::X25519 => validate_keypair_for::<X25519HkdfSha256>(secret_key, public_key),
        KeyAlgorithm::MlKem768 => validate_keypair_for::<MlKem768>(secret_key, public_key),
        KeyAlgorithm::XWing => validate_keypair_for::<XWing>(secret_key, public_key),
    }
}

fn validate_keypair_for<Kem>(secret_key: &[u8], public_key: &[u8]) -> Result<()>
where
    Kem: KemTrait,
{
    let secret = <Kem as KemTrait>::PrivateKey::from_bytes(secret_key)?;
    let public = <Kem as KemTrait>::PublicKey::from_bytes(public_key)?;
    anyhow::ensure!(Kem::sk_to_pk(&secret) == public, "public and secret key do not match");
    Ok(())
}

fn key_fingerprint(algorithm: KeyAlgorithm, public_key: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"khzip recipient fingerprint v1");
    hasher.update(&[algorithm.id()]);
    hasher.update(public_key);
    *hasher.finalize().as_bytes()
}

fn wrap_password(password: &str, salt: &[u8; 16], master: &[u8; 32]) -> Result<KeySlot> {
    let keys = crypto::password_keys(password, salt)?;
    let nonce = crypto::random_array::<24>();
    let cipher = XChaCha20Poly1305::new((&keys.primary).into());
    let aad = password_aad(salt);
    let wrapped = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: master,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("password key-slot encryption failed"))?;
    Ok(KeySlot {
        kind: 0,
        fingerprint: [0_u8; 32],
        encapped: nonce.to_vec(),
        wrapped,
    })
}

fn unwrap_password(password: &str, salt: &[u8; 16], slot: &KeySlot) -> Result<[u8; 32]> {
    anyhow::ensure!(slot.encapped.len() == 24, "invalid password key-slot nonce");
    let keys = crypto::password_keys(password, salt)?;
    let cipher = XChaCha20Poly1305::new((&keys.primary).into());
    let aad = password_aad(salt);
    let plain = cipher
        .decrypt(
            XNonce::from_slice(&slot.encapped),
            Payload {
                msg: &slot.wrapped,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("password key-slot authentication failed"))?;
    plain
        .try_into()
        .map_err(|_| anyhow!("invalid archive master-key length"))
}

fn wrap_recipient(recipient: &Recipient, salt: &[u8; 16], master: &[u8; 32]) -> Result<KeySlot> {
    let (encapped, wrapped) = match recipient.algorithm {
        KeyAlgorithm::X25519 => seal_hpke::<X25519HkdfSha256, HkdfSha256>(
            &recipient.public_key,
            master,
            salt,
            recipient.algorithm,
            &recipient.fingerprint,
        )?,
        KeyAlgorithm::MlKem768 => seal_hpke::<MlKem768, KdfShake128>(
            &recipient.public_key,
            master,
            salt,
            recipient.algorithm,
            &recipient.fingerprint,
        )?,
        KeyAlgorithm::XWing => seal_hpke::<XWing, KdfTurboShake128>(
            &recipient.public_key,
            master,
            salt,
            recipient.algorithm,
            &recipient.fingerprint,
        )?,
    };
    Ok(KeySlot {
        kind: recipient.algorithm.id(),
        fingerprint: recipient.fingerprint,
        encapped,
        wrapped,
    })
}

fn unwrap_recipient(identity: &Identity, salt: &[u8; 16], slot: &KeySlot) -> Result<[u8; 32]> {
    let plain = match identity.algorithm {
        KeyAlgorithm::X25519 => open_hpke::<X25519HkdfSha256, HkdfSha256>(
            &identity.secret_key,
            &identity.public_key,
            &slot.encapped,
            &slot.wrapped,
            salt,
            identity.algorithm,
            &identity.fingerprint,
        )?,
        KeyAlgorithm::MlKem768 => open_hpke::<MlKem768, KdfShake128>(
            &identity.secret_key,
            &identity.public_key,
            &slot.encapped,
            &slot.wrapped,
            salt,
            identity.algorithm,
            &identity.fingerprint,
        )?,
        KeyAlgorithm::XWing => open_hpke::<XWing, KdfTurboShake128>(
            &identity.secret_key,
            &identity.public_key,
            &slot.encapped,
            &slot.wrapped,
            salt,
            identity.algorithm,
            &identity.fingerprint,
        )?,
    };
    plain
        .try_into()
        .map_err(|_| anyhow!("invalid archive master-key length"))
}

fn seal_hpke<Kem, KdfImpl>(
    public_key: &[u8],
    master: &[u8; 32],
    salt: &[u8; 16],
    algorithm: KeyAlgorithm,
    fingerprint: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>)>
where
    Kem: KemTrait,
    KdfImpl: Kdf,
{
    let public = <Kem as KemTrait>::PublicKey::from_bytes(public_key)?;
    let info = hpke_info(salt, algorithm);
    let aad = hpke_aad(fingerprint);
    let (encapped, ciphertext) = single_shot_seal::<HpkeChaCha20Poly1305, KdfImpl, Kem>(
        &OpModeS::Base,
        &public,
        &info,
        master,
        &aad,
    )?;
    Ok((encapped.to_bytes().as_ref().to_vec(), ciphertext))
}

fn open_hpke<Kem, KdfImpl>(
    secret_key: &[u8],
    public_key: &[u8],
    encapped: &[u8],
    ciphertext: &[u8],
    salt: &[u8; 16],
    algorithm: KeyAlgorithm,
    fingerprint: &[u8; 32],
) -> Result<Vec<u8>>
where
    Kem: KemTrait,
    KdfImpl: Kdf,
{
    let secret = <Kem as KemTrait>::PrivateKey::from_bytes(secret_key)?;
    let public = <Kem as KemTrait>::PublicKey::from_bytes(public_key)?;
    anyhow::ensure!(Kem::sk_to_pk(&secret) == public, "identity keypair mismatch");
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(encapped)?;
    let info = hpke_info(salt, algorithm);
    let aad = hpke_aad(fingerprint);
    Ok(single_shot_open::<HpkeChaCha20Poly1305, KdfImpl, Kem>(
        &OpModeR::Base,
        &secret,
        &encapped,
        &info,
        ciphertext,
        &aad,
    )?)
}

fn hpke_info(salt: &[u8; 16], algorithm: KeyAlgorithm) -> Vec<u8> {
    let mut info = Vec::with_capacity(HPKE_INFO.len() + 17);
    info.extend_from_slice(HPKE_INFO);
    info.push(algorithm.id());
    info.extend_from_slice(salt);
    info
}

fn hpke_aad(fingerprint: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(48);
    aad.extend_from_slice(b"khzip recipient slot v2");
    aad.extend_from_slice(fingerprint);
    aad
}

fn password_aad(salt: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PASSWORD_AAD.len() + salt.len());
    aad.extend_from_slice(PASSWORD_AAD);
    aad.extend_from_slice(salt);
    aad
}

fn encode_slots(slots: &[KeySlot]) -> Result<Vec<u8>> {
    anyhow::ensure!(slots.len() <= MAX_KEY_SLOTS, "too many key slots");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SLOT_MAGIC);
    bytes.extend_from_slice(&SLOT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(slots.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    for slot in slots {
        let encapped_len = u32::try_from(slot.encapped.len())?;
        let wrapped_len = u32::try_from(slot.wrapped.len())?;
        bytes.push(slot.kind);
        bytes.push(0);
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&slot.fingerprint);
        bytes.extend_from_slice(&encapped_len.to_le_bytes());
        bytes.extend_from_slice(&wrapped_len.to_le_bytes());
        bytes.extend_from_slice(&slot.encapped);
        bytes.extend_from_slice(&slot.wrapped);
    }
    anyhow::ensure!(
        bytes.len() <= MAX_KEY_SLOT_AREA,
        "key-slot area exceeds safety limit"
    );
    Ok(bytes)
}

fn decode_slots(bytes: &[u8]) -> Result<Vec<KeySlot>> {
    anyhow::ensure!(
        bytes.len() <= MAX_KEY_SLOT_AREA,
        "key-slot area exceeds safety limit"
    );
    anyhow::ensure!(bytes.len() >= SLOT_HEADER_LEN, "key-slot area is truncated");
    anyhow::ensure!(&bytes[..8] == SLOT_MAGIC, "invalid key-slot magic");
    let version = u16::from_le_bytes(bytes[8..10].try_into()?);
    anyhow::ensure!(version == SLOT_VERSION, "unsupported key-slot version");
    let count = usize::from(u16::from_le_bytes(bytes[10..12].try_into()?));
    anyhow::ensure!(count <= MAX_KEY_SLOTS, "too many key slots");
    let mut cursor = SLOT_HEADER_LEN;
    let mut slots = Vec::with_capacity(count);
    for _ in 0..count {
        let header_end = cursor
            .checked_add(SLOT_ENTRY_HEADER_LEN)
            .ok_or_else(|| anyhow!("key-slot length overflow"))?;
        anyhow::ensure!(header_end <= bytes.len(), "key-slot entry is truncated");
        let kind = bytes[cursor];
        if kind != 0 {
            KeyAlgorithm::from_id(kind)?;
        }
        let fingerprint = bytes[cursor + 4..cursor + 36].try_into()?;
        let encapped_len =
            usize::try_from(u32::from_le_bytes(bytes[cursor + 36..cursor + 40].try_into()?))?;
        let wrapped_len =
            usize::try_from(u32::from_le_bytes(bytes[cursor + 40..cursor + 44].try_into()?))?;
        cursor = header_end;
        let encapped_end = cursor
            .checked_add(encapped_len)
            .ok_or_else(|| anyhow!("key-slot length overflow"))?;
        let wrapped_end = encapped_end
            .checked_add(wrapped_len)
            .ok_or_else(|| anyhow!("key-slot length overflow"))?;
        anyhow::ensure!(wrapped_end <= bytes.len(), "key-slot payload is truncated");
        slots.push(KeySlot {
            kind,
            fingerprint,
            encapped: bytes[cursor..encapped_end].to_vec(),
            wrapped: bytes[encapped_end..wrapped_end].to_vec(),
        });
        cursor = wrapped_end;
    }
    anyhow::ensure!(cursor == bytes.len(), "unexpected trailing key-slot bytes");
    Ok(slots)
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_decoder_rejects_trailing_data() {
        let slot = KeySlot {
            kind: 0,
            fingerprint: [0_u8; 32],
            encapped: vec![0_u8; 24],
            wrapped: vec![0_u8; 48],
        };
        let mut bytes = encode_slots(&[slot]).unwrap();
        bytes.push(1);
        assert!(decode_slots(&bytes).is_err());
    }
}
