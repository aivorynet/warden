use super::*;
use proptest::prelude::*;
use std::collections::BTreeSet;
use warden_core::{ItemKind, McpPolicy, ProviderKind, ProviderRef, RotationPolicy};

fn fast() -> KdfParams {
    KdfParams::new(8, 1, 1)
}

fn item_with(id: ItemId, name: &str) -> Item {
    Item {
        id,
        name: name.into(),
        slug: "slug".into(),
        kind: ItemKind::Admin,
        provider: ProviderRef {
            kind: ProviderKind::Manual,
            config: serde_json::Value::Null,
        },
        provider_token_id: None,
        expires_at: None,
        created_at: Utc::now(),
        rotated_at: None,
        policy: RotationPolicy::default(),
        sinks: Vec::new(),
        mcp: McpPolicy::default(),
        rotator_device: DeviceId::new(),
        tags: Vec::new(),
    }
}

fn secrets(v: &str) -> BTreeMap<String, SecretValue> {
    BTreeMap::from([("token".to_owned(), SecretValue::new(v))])
}

struct Env {
    _t: tempfile::TempDir,
    dir: PathBuf,
    local: PathBuf,
}

fn env() -> Env {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("vault");
    let local = t.path().join("local");
    Env { _t: t, dir, local }
}

fn create(e: &Env) -> (Vault, SecretKey) {
    Vault::create_with_params(&e.dir, "pw", None, "laptop", &e.local, fast()).unwrap()
}

fn op_files(dir: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if !dir.join("ops").is_dir() {
        return v;
    }
    for (_, d) in list_dir(&dir.join("ops")).unwrap() {
        for (_, f) in list_dir(&d).unwrap() {
            v.push(f);
        }
    }
    v.sort();
    v
}

#[test]
fn roundtrip_create_put_reopen_get() {
    let e = env();
    let (mut v, sk) = create(&e);
    let id = ItemId::new();
    v.put(item_with(id, "gitlab"), secrets("glpat-synthetic"))
        .unwrap();
    let key = v.export_vault_key();
    drop(v);
    let v2 = Vault::open(&e.dir, "pw", &sk, &e.local).unwrap();
    assert_eq!(v2.get(&id).unwrap().name, "gitlab");
    assert_eq!(v2.secret(&id, "token").unwrap().expose(), "glpat-synthetic");
    assert!(v2.secret(&id, "nope").is_err());
    let v3 = Vault::open_with_key(&e.dir, &key, &e.local).unwrap();
    assert_eq!(v3.items().len(), 1);
    assert_eq!(v3.audit().len(), 1);
}

#[test]
fn delete_and_overwrite() {
    let e = env();
    let (mut v, _) = create(&e);
    let id = ItemId::new();
    v.put(item_with(id, "a"), secrets("1")).unwrap();
    v.put(item_with(id, "b"), secrets("2")).unwrap();
    assert_eq!(v.get(&id).unwrap().name, "b");
    assert_eq!(v.secret(&id, "token").unwrap().expose(), "2");
    v.delete(&id).unwrap();
    assert!(v.get(&id).is_none());
    assert!(v.delete(&id).is_err());
    let a = v.audit();
    assert_eq!(a.len(), 3);
    assert_eq!(a[2].action, AuditAction::Delete);
}

#[test]
fn wrong_password_and_secret_key_rejected() {
    let e = env();
    let (_v, sk) = create(&e);
    assert!(Vault::open(&e.dir, "bad", &sk, &e.local).is_err());
    assert!(Vault::open(&e.dir, "pw", &SecretKey::generate(), &e.local).is_err());
    assert!(Vault::open(&e.dir, "pw", &sk, &e.local).is_ok());
}

#[test]
fn tampered_op_rejected() {
    let e = env();
    let (mut v, sk) = create(&e);
    v.put(item_with(ItemId::new(), "x"), secrets("s")).unwrap();
    let f = op_files(&e.dir).remove(0);
    let mut raw = fs::read(&f).unwrap();
    let pos = String::from_utf8_lossy(&raw).find("\"ct\":\"").unwrap() + 8;
    raw[pos] ^= 1; // flips one bit; the hex digit stays a valid hex digit
    fs::write(&f, &raw).unwrap();
    let err = Vault::open(&e.dir, "pw", &sk, &e.local).unwrap_err();
    assert!(err.to_string().contains("signature"), "{err}");
}

#[test]
fn dropped_op_detected() {
    let e = env();
    let (mut v, sk) = create(&e);
    for n in ["a", "b", "c"] {
        v.put(item_with(ItemId::new(), n), secrets("s")).unwrap();
    }
    let files = op_files(&e.dir);
    let saved = fs::read(&files[1]).unwrap();
    fs::remove_file(&files[1]).unwrap();
    let err = Vault::open(&e.dir, "pw", &sk, &e.local).unwrap_err();
    assert!(err.to_string().contains("missing op 2"), "{err}");
    fs::write(&files[1], saved).unwrap();
    fs::remove_file(&files[2]).unwrap();
    let err = Vault::open(&e.dir, "pw", &sk, &e.local).unwrap_err();
    assert!(err.to_string().contains("rollback"), "{err}");
}

#[test]
fn join_second_device_and_merge() {
    let e = env();
    let (mut a, sk) = create(&e);
    let b_local = e._t.path().join("local-b");
    let mut b = Vault::join(&e.dir, "pw", &sk, "phone", &b_local).unwrap();
    assert_eq!(b.devices().len(), 2);
    let id = ItemId::new();
    a.put(item_with(id, "one"), secrets("1")).unwrap();
    b.reload().unwrap();
    assert_eq!(b.secret(&id, "token").unwrap().expose(), "1");
    b.put(item_with(id, "two"), secrets("2")).unwrap();
    a.reload().unwrap();
    assert_eq!(a.get(&id).unwrap().name, "two");
    let names: BTreeSet<_> = a.audit().iter().map(|r| r.device_name.clone()).collect();
    assert_eq!(names.len(), 2);
    assert!(Vault::join(&e.dir, "bad", &sk, "x", &e._t.path().join("l3")).is_err());
}

type Snap = Vec<(Item, BTreeMap<String, String>)>;

fn snapshot(v: &Vault) -> Snap {
    v.items()
        .into_iter()
        .map(|i| {
            let s = v
                .secret_names(&i.id)
                .into_iter()
                .map(|n| {
                    let val = v.secret(&i.id, &n).unwrap().expose().to_owned();
                    (n, val)
                })
                .collect();
            (i.clone(), s)
        })
        .collect()
}

fn copy_ops(from: &Path, to: &Path, seed: u64) {
    let mut files = op_files(from);
    files.sort_by_key(|f| {
        let mut h = blake3::Hasher::new();
        h.update(&seed.to_be_bytes());
        h.update(f.to_string_lossy().as_bytes());
        *h.finalize().as_bytes()
    });
    for f in files {
        let rel = f.strip_prefix(from).unwrap();
        let dst = to.join(rel);
        fs::create_dir_all(dst.parent().unwrap()).unwrap();
        fs::copy(&f, dst).unwrap();
    }
}

fn copy_all(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    fs::copy(from.join("header.json"), to.join("header.json")).unwrap();
    copy_ops(from, to, 0);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn replicas_converge(
        ops in proptest::collection::vec((0u8..2, 0usize..4, any::<bool>(), 0u8..8), 0..24),
        seeds in (any::<u64>(), any::<u64>(), any::<u64>()),
    ) {
        let e = env();
        let root = e._t.path().to_owned();
        let (a0, sk) = create(&e);
        let key = a0.export_vault_key();
        drop(a0);
        Vault::join(&e.dir, "pw", &sk, "b", &root.join("lb")).unwrap();
        Vault::join(&e.dir, "pw", &sk, "r", &root.join("lr")).unwrap();
        let (db, dr) = (root.join("vb"), root.join("vr"));
        copy_all(&e.dir, &db);
        copy_all(&e.dir, &dr);
        let mut va = Vault::open_with_key(&e.dir, &key, &e.local).unwrap();
        let mut vb = Vault::open_with_key(&db, &key, &root.join("lb")).unwrap();
        let mut vr = Vault::open_with_key(&dr, &key, &root.join("lr")).unwrap();
        let ids: Vec<ItemId> = (0..4).map(|_| ItemId::new()).collect();
        for (rep, idx, del, val) in ops {
            let v = if rep == 0 { &mut va } else { &mut vb };
            if del {
                if v.get(&ids[idx]).is_some() {
                    v.delete(&ids[idx]).unwrap();
                }
            } else {
                v.put(item_with(ids[idx], &format!("n{val}")), secrets(&val.to_string())).unwrap();
            }
        }
        copy_ops(&db, &e.dir, seeds.0);
        copy_ops(&e.dir, &db, seeds.1);
        copy_ops(&e.dir, &dr, seeds.2);
        copy_ops(&db, &dr, seeds.2 ^ 1);
        va.reload().unwrap();
        vb.reload().unwrap();
        vr.reload().unwrap();
        prop_assert_eq!(snapshot(&va), snapshot(&vb));
        prop_assert_eq!(snapshot(&va), snapshot(&vr));
        prop_assert_eq!(va.audit(), vr.audit());
    }
}
