//! The vault: header, op log, merge, rollback detection, audit.

use crate::crypto::{
    Hex, KdfParams, SecretKey, derive_kek, hex_enc, open, random, random_zeroizing, seal, verr,
};
use crate::fsutil::{atomic_write, lock_exclusive, publish_new};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use warden_core::{
    Clock, DeviceId, Item, ItemId, Result, SecretValue, SystemClock, VaultId, WardenError,
};
use zeroize::Zeroizing;

/// On-disk header format version. Version 2 binds the version, the KDF parameters and the
/// salt into the AAD of the wrapped vault key. Version 1 is read and migrated at the next
/// unlock.
const VERSION: u32 = 2;
/// Format version of the op envelope.
const OP_VERSION: u32 = 1;
/// Largest Argon2 memory that a header may ask for (1 GiB, in KiB).
const MAX_KDF_KIB: u32 = 1024 * 1024;
/// Name of the lock file in the local state dir.
const LOCK_FILE: &str = "vault.lock";
/// `prev` hash of the first op of a device.
const ZERO: [u8; 32] = [0u8; 32];

/// A registered device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEntry {
    /// Device id.
    pub id: DeviceId,
    /// Display name.
    pub name: String,
    /// Ed25519 public key, lowercase hex.
    pub public_key: String,
}

/// Kind of an audited change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    /// A new item version.
    Put,
    /// A tombstone.
    Delete,
}

/// One record of the audit log (one op of the chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Device that wrote the op.
    pub device_id: DeviceId,
    /// Name of that device.
    pub device_name: String,
    /// Sequence number in the device chain.
    pub seq: u64,
    /// Time of the op.
    pub at: DateTime<Utc>,
    /// Lamport clock of the op.
    pub lamport: u64,
    /// Affected item.
    pub item_id: ItemId,
    /// Item name (not set for a tombstone).
    pub item_name: Option<String>,
    /// Put or delete.
    pub action: AuditAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Sealed {
    nonce: Hex,
    ct: Hex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Header {
    version: u32,
    vault_id: VaultId,
    kdf: KdfParams,
    salt: Hex,
    wrapped_key: Sealed,
    devices: Sealed,
}

#[derive(Serialize, Deserialize)]
struct LocalDevice {
    device_id: DeviceId,
    key: Sealed,
    /// Display name, kept to repair a registry that lost this device.
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Seen {
    devices: BTreeMap<String, SeenEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeenEntry {
    seq: u64,
    hash: Hex,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u32,
    device: DeviceId,
    seq: u64,
    item: ItemId,
    prev: Hex,
    nonce: Hex,
    ct: Hex,
    sig: Hex,
}

#[derive(Serialize, Deserialize)]
struct OpBody {
    lamport: u64,
    at: DateTime<Utc>,
    item: Option<Item>,
    #[serde(default, serialize_with = "ser_secrets")]
    secrets: BTreeMap<String, SecretValue>,
}

fn ser_secrets<S: Serializer>(
    m: &BTreeMap<String, SecretValue>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.collect_map(m.iter().map(|(k, v)| (k, v.expose())))
}

type Secrets = BTreeMap<String, SecretValue>;

struct Entry {
    lamport: u64,
    device: DeviceId,
    content: Option<(Item, Secrets)>,
}

#[derive(Default)]
struct Loaded {
    entries: HashMap<ItemId, Entry>,
    audit: Vec<AuditRecord>,
    chains: BTreeMap<DeviceId, (u64, [u8; 32])>,
    max_lamport: u64,
}

/// AAD of the wrapped vault key. Version 2 binds version, KDF parameters and salt.
fn wrap_aad(h: &Header) -> Vec<u8> {
    if h.version < 2 {
        return [b"warden/wrap/v1".as_slice(), h.vault_id.0.as_bytes()].concat();
    }
    [
        b"warden/wrap/v2".as_slice(),
        h.vault_id.0.as_bytes(),
        &h.version.to_be_bytes(),
        &h.kdf.m_kib.to_be_bytes(),
        &h.kdf.t.to_be_bytes(),
        &h.kdf.p.to_be_bytes(),
        &h.salt.0,
    ]
    .concat()
}

fn devices_aad(v: &VaultId) -> Vec<u8> {
    [b"warden/devices/v1".as_slice(), v.0.as_bytes()].concat()
}

fn devkey_aad(v: &VaultId, d: &DeviceId) -> Vec<u8> {
    [
        b"warden/devkey/v1".as_slice(),
        v.0.as_bytes(),
        d.0.as_bytes(),
    ]
    .concat()
}

fn op_aad(v: &VaultId, item: &ItemId, dev: &DeviceId, seq: u64, prev: &[u8; 32]) -> Vec<u8> {
    [
        v.0.as_bytes().as_slice(),
        item.0.as_bytes(),
        dev.0.as_bytes(),
        &seq.to_be_bytes(),
        prev,
    ]
    .concat()
}

fn op_hash(aad: &[u8], nonce: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"warden/op/v1");
    h.update(aad);
    h.update(nonce);
    h.update(ct);
    *h.finalize().as_bytes()
}

fn read_header(dir: &Path) -> Result<Header> {
    let h: Header = serde_json::from_slice(&fs::read(dir.join("header.json"))?)?;
    if h.version != VERSION && h.version != 1 {
        return Err(verr(format!("unsupported vault version {}", h.version)));
    }
    if h.kdf.m_kib > MAX_KDF_KIB || h.kdf.t > 64 || h.kdf.p > 64 {
        return Err(verr("kdf parameters out of range"));
    }
    Ok(h)
}

fn write_header(dir: &Path, h: &Header) -> Result<()> {
    atomic_write(
        &dir.join("header.json"),
        &serde_json::to_vec_pretty(h)?,
        false,
    )?;
    Ok(())
}

/// A 32-byte key that zeroizes on drop.
type Key32 = Zeroizing<[u8; 32]>;

/// Unlock the header. Returns the vault key and the key-encryption key.
fn unlock(h: &Header, password: &str, sk: &SecretKey) -> Result<(Key32, Key32)> {
    let kek = derive_kek(password.as_bytes(), sk, &h.salt.0, &h.kdf)?;
    let pt = open(
        &kek,
        &wrap_aad(h),
        &h.wrapped_key.nonce.arr()?,
        &h.wrapped_key.ct.0,
    )
    .map_err(|_| verr("wrong password or secret key"))?;
    if pt.len() != 32 {
        return Err(verr("bad vault key length"));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&pt);
    Ok((key, kek))
}

/// Wrap the vault key into the header with the current format (version 2).
fn wrap_key(h: &mut Header, kek: &[u8; 32], vault_key: &[u8; 32]) -> Result<()> {
    h.version = VERSION;
    let (n, c) = seal(kek, &wrap_aad(h), vault_key)?;
    h.wrapped_key = Sealed {
        nonce: Hex(n.to_vec()),
        ct: Hex(c),
    };
    Ok(())
}

/// Rewrite a version 1 header in the version 2 format. Call it after a successful unlock.
fn migrate_header(dir: &Path, local: &Path, kek: &[u8; 32], vault_key: &[u8; 32]) -> Result<()> {
    let _lock = lock_exclusive(&local.join(LOCK_FILE))?;
    let mut h = read_header(dir)?;
    if h.version >= VERSION {
        return Ok(());
    }
    wrap_key(&mut h, kek, vault_key)?;
    write_header(dir, &h)
}

fn read_registry(h: &Header, key: &[u8; 32]) -> Result<Vec<DeviceEntry>> {
    let pt = open(
        key,
        &devices_aad(&h.vault_id),
        &h.devices.nonce.arr()?,
        &h.devices.ct.0,
    )
    .map_err(|_| verr("device registry rejected (wrong vault key or tampered header)"))?;
    Ok(serde_json::from_slice(&pt)?)
}

fn seal_registry(h: &mut Header, key: &[u8; 32], devices: &[DeviceEntry]) -> Result<()> {
    let (nonce, ct) = seal(
        key,
        &devices_aad(&h.vault_id),
        &serde_json::to_vec(devices)?,
    )?;
    h.devices = Sealed {
        nonce: Hex(nonce.to_vec()),
        ct: Hex(ct),
    };
    Ok(())
}

/// Add the devices in `wanted` that the registry in the header file lacks (union by device
/// id). Writes the header only when it changes. Returns the current header and registry.
fn ensure_registry(
    dir: &Path,
    local: &Path,
    key: &[u8; 32],
    wanted: &[DeviceEntry],
) -> Result<(Header, Vec<DeviceEntry>)> {
    let missing = |devs: &[DeviceEntry]| -> Vec<DeviceEntry> {
        wanted
            .iter()
            .filter(|w| !devs.iter().any(|d| d.id == w.id))
            .cloned()
            .collect()
    };
    let h = read_header(dir)?;
    let devs = read_registry(&h, key)?;
    if missing(&devs).is_empty() {
        return Ok((h, devs));
    }
    let _lock = lock_exclusive(&local.join(LOCK_FILE))?;
    let mut h = read_header(dir)?;
    let mut devs = read_registry(&h, key)?;
    let add = missing(&devs);
    if !add.is_empty() {
        devs.extend(add);
        seal_registry(&mut h, key, &devs)?;
        write_header(dir, &h)?;
    }
    Ok((h, devs))
}

/// Add a device to the registry stored in the header file.
fn enroll(
    dir: &Path,
    local: &Path,
    key: &[u8; 32],
    entry: DeviceEntry,
) -> Result<(Header, Vec<DeviceEntry>)> {
    let h = read_header(dir)?;
    if read_registry(&h, key)?.iter().any(|d| d.id == entry.id) {
        return Err(verr("device id already registered"));
    }
    ensure_registry(dir, local, key, &[entry])
}

fn device_entry(id: DeviceId, name: &str, sk: &SigningKey) -> DeviceEntry {
    DeviceEntry {
        id,
        name: name.to_owned(),
        public_key: hex_enc(sk.verifying_key().as_bytes()),
    }
}

fn new_device(
    key: &[u8; 32],
    vault_id: &VaultId,
    local: &Path,
    name: &str,
) -> Result<(DeviceId, SigningKey)> {
    let id = DeviceId::new();
    let seed = random_zeroizing::<32>();
    let sk = SigningKey::from_bytes(&seed);
    let (nonce, ct) = seal(key, &devkey_aad(vault_id, &id), &*seed)?;
    let ld = LocalDevice {
        device_id: id,
        key: Sealed {
            nonce: Hex(nonce.to_vec()),
            ct: Hex(ct),
        },
        name: Some(name.to_owned()),
    };
    atomic_write(
        &local.join("device.json"),
        &serde_json::to_vec_pretty(&ld)?,
        true,
    )?;
    Ok((id, sk))
}

fn load_signing(
    key: &[u8; 32],
    vault_id: &VaultId,
    local: &Path,
) -> Result<(DeviceId, SigningKey, Option<String>)> {
    let raw = fs::read(local.join("device.json"))
        .map_err(|_| verr("device not enrolled in this local state dir (use join)"))?;
    let ld: LocalDevice = serde_json::from_slice(&raw)?;
    let seed = open(
        key,
        &devkey_aad(vault_id, &ld.device_id),
        &ld.key.nonce.arr()?,
        &ld.key.ct.0,
    )?;
    if seed.len() != 32 {
        return Err(verr("bad device key length"));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&seed);
    Ok((ld.device_id, SigningKey::from_bytes(&bytes), ld.name))
}

fn read_seen(local: &Path) -> Result<Seen> {
    match fs::read(local.join("seen.json")) {
        Ok(b) => Ok(serde_json::from_slice(&b)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Seen::default()),
        Err(e) => Err(e.into()),
    }
}

fn list_dir(p: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut v = Vec::new();
    for e in fs::read_dir(p)? {
        let e = e?;
        v.push((e.file_name().to_string_lossy().into_owned(), e.path()));
    }
    Ok(v)
}

/// Read every op file, verify the chains, decrypt, and merge.
fn load_ops(
    dir: &Path,
    vault_id: &VaultId,
    key: &[u8; 32],
    devices: &[DeviceEntry],
    seen: &Seen,
) -> Result<Loaded> {
    let mut out = Loaded::default();
    let ops_dir = dir.join("ops");
    if ops_dir.is_dir() {
        for (name, path) in list_dir(&ops_dir)? {
            if name.starts_with('.') || !path.is_dir() {
                continue;
            }
            let Ok(did) = name.parse::<DeviceId>() else {
                tracing::warn!("skip ops directory with a bad device name: {name}");
                continue;
            };
            let Some(dev) = devices.iter().find(|d| d.id == did) else {
                // Do not trust ops of a device that the registry does not list.
                tracing::warn!("skip ops of unregistered device {did}");
                continue;
            };
            let pk_bytes: [u8; 32] = decode_hex(&dev.public_key)?
                .try_into()
                .map_err(|_| verr("bad device public key"))?;
            let vk =
                VerifyingKey::from_bytes(&pk_bytes).map_err(|_| verr("bad device public key"))?;
            let mut seqs: Vec<u64> = list_dir(&path)?
                .into_iter()
                .filter_map(|(n, _)| n.strip_suffix(".op").and_then(|s| s.parse().ok()))
                .collect();
            seqs.sort_unstable();
            for (i, s) in seqs.iter().enumerate() {
                if *s != i as u64 + 1 {
                    return Err(verr(format!(
                        "missing op {} of device {did} (dropped op)",
                        i + 1
                    )));
                }
            }
            let mut prev = ZERO;
            for seq in 1..=seqs.len() as u64 {
                let raw = fs::read(path.join(format!("{seq}.op")))?;
                let env: Envelope = serde_json::from_slice(&raw)
                    .map_err(|e| verr(format!("op {seq} of {did} is corrupt: {e}")))?;
                if env.v != OP_VERSION || env.device != did || env.seq != seq {
                    return Err(verr(format!("op {seq} of {did} has a bad envelope")));
                }
                if env.prev.0 != prev {
                    return Err(verr(format!("hash chain broken at op {seq} of {did}")));
                }
                let aad = op_aad(vault_id, &env.item, &did, seq, &prev);
                let nonce: [u8; 24] = env.nonce.arr()?;
                let hash = op_hash(&aad, &nonce, &env.ct.0);
                let sig = Signature::from_bytes(&env.sig.arr::<64>()?);
                vk.verify_strict(&hash, &sig)
                    .map_err(|_| verr(format!("bad signature on op {seq} of {did}")))?;
                if let Some(s) = seen.devices.get(&did.to_string())
                    && s.seq == seq
                    && s.hash.0 != hash
                {
                    return Err(verr(format!(
                        "history of device {did} was rewritten at op {seq}"
                    )));
                }
                let pt = open(key, &aad, &nonce, &env.ct.0)
                    .map_err(|_| verr(format!("op {seq} of {did} failed decryption")))?;
                let body: OpBody = serde_json::from_slice(&pt)?;
                if body.item.as_ref().is_some_and(|i| i.id != env.item) {
                    return Err(verr(format!("op {seq} of {did} has a mismatched item")));
                }
                out.max_lamport = out.max_lamport.max(body.lamport);
                out.audit.push(AuditRecord {
                    device_id: did,
                    device_name: dev.name.clone(),
                    seq,
                    at: body.at,
                    lamport: body.lamport,
                    item_id: env.item,
                    item_name: body.item.as_ref().map(|i| i.name.clone()),
                    action: if body.item.is_some() {
                        AuditAction::Put
                    } else {
                        AuditAction::Delete
                    },
                });
                let wins = out
                    .entries
                    .get(&env.item)
                    .is_none_or(|e| (body.lamport, did) > (e.lamport, e.device));
                if wins {
                    out.entries.insert(
                        env.item,
                        Entry {
                            lamport: body.lamport,
                            device: did,
                            content: body.item.map(|i| (i, body.secrets)),
                        },
                    );
                }
                prev = hash;
            }
            out.chains.insert(did, (seqs.len() as u64, prev));
        }
    }
    for (d, e) in &seen.devices {
        let did: DeviceId = d.parse().map_err(|_| verr("bad local state"))?;
        match out.chains.get(&did) {
            Some((n, _)) if *n >= e.seq => {}
            _ => {
                return Err(verr(format!(
                    "rollback detected: device {did} was at op {}, ops are missing",
                    e.seq
                )));
            }
        }
    }
    out.audit.sort_by_key(|a| (a.lamport, a.device_id, a.seq));
    Ok(out)
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    serde_json::from_value::<Hex>(serde_json::Value::String(s.to_owned()))
        .map(|h| h.0)
        .map_err(|_| verr("bad hex"))
}

/// An open vault.
pub struct Vault {
    dir: PathBuf,
    local: PathBuf,
    header: Header,
    vault_key: Zeroizing<[u8; 32]>,
    devices: Vec<DeviceEntry>,
    device_id: DeviceId,
    device_name: String,
    signing: SigningKey,
    clock: Arc<dyn Clock>,
    loaded: Loaded,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("vault_id", &self.header.vault_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Create a new vault in `dir` with production KDF parameters.
    /// Returns the vault and the Secret Key (generated when `secret_key` is `None`).
    pub fn create(
        dir: &Path,
        password: &str,
        secret_key: Option<SecretKey>,
        device_name: &str,
        local_state_dir: &Path,
    ) -> Result<(Vault, SecretKey)> {
        Self::create_with_params(
            dir,
            password,
            secret_key,
            device_name,
            local_state_dir,
            KdfParams::DEFAULT,
        )
    }

    /// Like [`Vault::create`] with explicit KDF parameters. Use low values in tests only.
    pub fn create_with_params(
        dir: &Path,
        password: &str,
        secret_key: Option<SecretKey>,
        device_name: &str,
        local_state_dir: &Path,
        kdf: KdfParams,
    ) -> Result<(Vault, SecretKey)> {
        if dir.join("header.json").exists() {
            return Err(verr("a vault already exists in this directory"));
        }
        fs::create_dir_all(dir.join("ops"))?;
        fs::create_dir_all(local_state_dir)?;
        let sk = secret_key.unwrap_or_else(SecretKey::generate);
        let vault_id = VaultId::new();
        let salt: [u8; 16] = random();
        let vault_key = random_zeroizing::<32>();
        let kek = derive_kek(password.as_bytes(), &sk, &salt, &kdf)?;
        let (device_id, signing) = new_device(&vault_key, &vault_id, local_state_dir, device_name)?;
        let devices = vec![DeviceEntry {
            id: device_id,
            name: device_name.to_owned(),
            public_key: hex_enc(signing.verifying_key().as_bytes()),
        }];
        let mut header = Header {
            version: VERSION,
            vault_id,
            kdf,
            salt: Hex(salt.to_vec()),
            wrapped_key: Sealed {
                nonce: Hex(Vec::new()),
                ct: Hex(Vec::new()),
            },
            devices: Sealed {
                nonce: Hex(Vec::new()),
                ct: Hex(Vec::new()),
            },
        };
        wrap_key(&mut header, &kek, &vault_key)?;
        seal_registry(&mut header, &vault_key, &devices)?;
        write_header(dir, &header)?;
        let mut v = Vault {
            dir: dir.to_owned(),
            local: local_state_dir.to_owned(),
            header,
            vault_key,
            devices,
            device_id,
            device_name: device_name.to_owned(),
            signing,
            clock: Arc::new(SystemClock),
            loaded: Loaded::default(),
        };
        v.reload()?;
        Ok((v, sk))
    }

    /// Open an existing vault with the password and the Secret Key.
    pub fn open(
        dir: &Path,
        password: &str,
        secret_key: &SecretKey,
        local_state_dir: &Path,
    ) -> Result<Vault> {
        let h = read_header(dir)?;
        let (key, kek) = unlock(&h, password, secret_key)?;
        if h.version < VERSION {
            migrate_header(dir, local_state_dir, &kek, &key)?;
        }
        Self::open_inner(dir, &key, local_state_dir)
    }

    /// Open an existing vault with a cached vault key (see [`crate::keychain`]).
    pub fn open_with_key(
        dir: &Path,
        vault_key: &[u8; 32],
        local_state_dir: &Path,
    ) -> Result<Vault> {
        Self::open_inner(dir, vault_key, local_state_dir)
    }

    /// Join a vault from a new device. Unlocks with the password and the Secret Key,
    /// creates a device key in `local_state_dir`, and registers the device in the header.
    pub fn join(
        dir: &Path,
        password: &str,
        secret_key: &SecretKey,
        device_name: &str,
        local_state_dir: &Path,
    ) -> Result<Vault> {
        let h = read_header(dir)?;
        let (key, kek) = unlock(&h, password, secret_key)?;
        if local_state_dir.join("device.json").exists() {
            return Err(verr(
                "this local state dir already holds a device (use open)",
            ));
        }
        fs::create_dir_all(local_state_dir)?;
        let (id, sk) = new_device(&key, &h.vault_id, local_state_dir, device_name)?;
        enroll(
            dir,
            local_state_dir,
            &key,
            device_entry(id, device_name, &sk),
        )?;
        if h.version < VERSION {
            migrate_header(dir, local_state_dir, &kek, &key)?;
        }
        Self::open_inner(dir, &key, local_state_dir)
    }

    fn open_inner(dir: &Path, key: &[u8; 32], local: &Path) -> Result<Vault> {
        let header = read_header(dir)?;
        let devices = read_registry(&header, key)?;
        let (device_id, signing, name) = load_signing(key, &header.vault_id, local)?;
        let device_name = name
            .or_else(|| {
                devices
                    .iter()
                    .find(|d| d.id == device_id)
                    .map(|d| d.name.clone())
            })
            .unwrap_or_else(|| format!("device-{device_id}"));
        // An offline join on two devices can lose one registry entry. `reload` repairs the
        // entry of this device (union by device id).
        let mut v = Vault {
            dir: dir.to_owned(),
            local: local.to_owned(),
            header,
            vault_key: Zeroizing::new(*key),
            devices,
            device_id,
            device_name,
            signing,
            clock: Arc::new(SystemClock),
            loaded: Loaded::default(),
        };
        v.reload()?;
        Ok(v)
    }

    /// Replace the time source (for tests).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Read all op files again (after a sync), verify them, and merge.
    /// Fails on a tampered op, a missing op, or a rollback.
    pub fn reload(&mut self) -> Result<()> {
        // Merge the registries: the registry that this device knows, this device itself, and the
        // registry in the header (union by device id). A header that lost an entry after an
        // offline join is repaired here.
        let mut wanted = self.devices.clone();
        if !wanted.iter().any(|d| d.id == self.device_id) {
            wanted.push(device_entry(
                self.device_id,
                &self.device_name,
                &self.signing,
            ));
        }
        let (header, devices) = ensure_registry(&self.dir, &self.local, &self.vault_key, &wanted)?;
        self.header = header;
        self.devices = devices;
        let mut seen = read_seen(&self.local)?;
        let loaded = load_ops(
            &self.dir,
            &self.header.vault_id,
            &self.vault_key,
            &self.devices,
            &seen,
        )?;
        let mut changed = false;
        for (d, (n, h)) in &loaded.chains {
            let k = d.to_string();
            if seen.devices.get(&k).is_none_or(|e| e.seq < *n) {
                seen.devices.insert(
                    k,
                    SeenEntry {
                        seq: *n,
                        hash: Hex(h.to_vec()),
                    },
                );
                changed = true;
            }
        }
        if changed {
            atomic_write(
                &self.local.join("seen.json"),
                &serde_json::to_vec_pretty(&seen)?,
                true,
            )?;
        }
        self.loaded = loaded;
        Ok(())
    }

    /// Id of the vault.
    pub fn vault_id(&self) -> VaultId {
        self.header.vault_id
    }

    /// Id of this device.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Registered devices.
    pub fn devices(&self) -> &[DeviceEntry] {
        &self.devices
    }

    /// Register a device identity that was created elsewhere.
    pub fn add_device(&mut self, id: DeviceId, name: &str, public_key: &[u8; 32]) -> Result<()> {
        VerifyingKey::from_bytes(public_key).map_err(|_| verr("bad device public key"))?;
        let (h, d) = enroll(
            &self.dir,
            &self.local,
            &self.vault_key,
            DeviceEntry {
                id,
                name: name.to_owned(),
                public_key: hex_enc(public_key),
            },
        )?;
        self.header = h;
        self.devices = d;
        Ok(())
    }

    /// All live items, sorted by name then id.
    pub fn items(&self) -> Vec<&Item> {
        let mut v: Vec<&Item> = self
            .loaded
            .entries
            .values()
            .filter_map(|e| e.content.as_ref().map(|(i, _)| i))
            .collect();
        v.sort_by(|a, b| (&a.name, a.id).cmp(&(&b.name, b.id)));
        v
    }

    /// Get one live item.
    pub fn get(&self, id: &ItemId) -> Option<&Item> {
        self.loaded
            .entries
            .get(id)?
            .content
            .as_ref()
            .map(|(i, _)| i)
    }

    /// Names of the secrets of an item.
    pub fn secret_names(&self, id: &ItemId) -> Vec<String> {
        self.loaded
            .entries
            .get(id)
            .and_then(|e| e.content.as_ref())
            .map(|(_, s)| s.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Get one named secret of an item.
    pub fn secret(&self, item_id: &ItemId, name: &str) -> Result<SecretValue> {
        self.loaded
            .entries
            .get(item_id)
            .and_then(|e| e.content.as_ref())
            .and_then(|(_, s)| s.get(name))
            .cloned()
            .ok_or_else(|| WardenError::NotFound(format!("secret {name} of item {item_id}")))
    }

    /// Write a new version of an item. `secrets` replaces the whole secret map.
    pub fn put(&mut self, item: Item, secrets: BTreeMap<String, SecretValue>) -> Result<()> {
        let id = item.id;
        self.append(id, Some(item), secrets)
    }

    /// Delete an item (writes a tombstone).
    pub fn delete(&mut self, id: &ItemId) -> Result<()> {
        if self.get(id).is_none() {
            return Err(WardenError::NotFound(format!("item {id}")));
        }
        self.append(*id, None, BTreeMap::new())
    }

    /// Return the vault key for the keychain cache.
    pub fn export_vault_key(&self) -> Zeroizing<[u8; 32]> {
        self.vault_key.clone()
    }

    /// The audit log: every op of every device chain, ordered by Lamport clock.
    pub fn audit(&self) -> Vec<AuditRecord> {
        self.loaded.audit.clone()
    }

    fn append(&mut self, item_id: ItemId, item: Option<Item>, secrets: Secrets) -> Result<()> {
        let (last_seq, prev) = self
            .loaded
            .chains
            .get(&self.device_id)
            .copied()
            .unwrap_or((0, ZERO));
        let seq = last_seq + 1;
        let body = OpBody {
            lamport: self.loaded.max_lamport + 1,
            at: self.clock.now(),
            item,
            secrets,
        };
        let pt = Zeroizing::new(serde_json::to_vec(&body)?);
        let aad = op_aad(&self.header.vault_id, &item_id, &self.device_id, seq, &prev);
        let (nonce, ct) = seal(&self.vault_key, &aad, &pt)?;
        let hash = op_hash(&aad, &nonce, &ct);
        let sig = self.signing.sign(&hash);
        let env = Envelope {
            v: OP_VERSION,
            device: self.device_id,
            seq,
            item: item_id,
            prev: Hex(prev.to_vec()),
            nonce: Hex(nonce.to_vec()),
            ct: Hex(ct),
            sig: Hex(sig.to_bytes().to_vec()),
        };
        let path = self
            .dir
            .join("ops")
            .join(self.device_id.to_string())
            .join(format!("{seq}.op"));
        let lock = lock_exclusive(&self.local.join(LOCK_FILE))?;
        // Never replace an op: a second writer of this device fails here.
        let published = publish_new(&path, &serde_json::to_vec(&env)?, false);
        // `reload` takes the lock again for a registry repair: release it first.
        drop(lock);
        if let Err(e) = published {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                return Err(verr("op file exists already (stale vault, reload first)"));
            }
            return Err(e.into());
        }
        self.reload()
    }
}

#[cfg(test)]
#[path = "vault_tests.rs"]
mod tests;
