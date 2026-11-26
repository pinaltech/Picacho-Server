//! Content-addressed storage for messages and attachments.
//!
//! Backends: local disk, any S3-compatible store, or the metadata database.
//! Large attachments can be split into a separate store and deduplicated;
//! the message is then kept as a manifest of byte segments, reassembled
//! exactly on read. Optional AES-256-GCM encryption covers both stores.
use crate::config::{BlobConfig, BlobKind, Config, S3Config};
use crate::db::Db;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use object_store::{path::Path as ObjPath, ObjectStore, PutPayload};
use parking_lot::Mutex;
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

const MANIFEST_MAGIC: &[u8] = b"\0PMSEG1\n";
const ENC_MAGIC: &[u8] = b"PME1";

#[derive(Clone)]
pub enum Backend {
    Local(PathBuf),
    Object { store: Arc<dyn ObjectStore>, prefix: String, desc: String },
    Database(Db),
}

impl Backend {
    pub(crate) fn build(kind: &BlobKind, path: &Option<PathBuf>, s3: &Option<S3Config>, default_dir: PathBuf, db: Option<&Db>) -> Result<Self> {
        Ok(match kind {
            BlobKind::Local => {
                let dir = path.clone().unwrap_or(default_dir);
                std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
                Backend::Local(dir)
            }
            BlobKind::Database => Backend::Database(db.ok_or_else(|| anyhow!("database store needs a database"))?.clone()),
            BlobKind::S3 => {
                let s3 = s3.as_ref().ok_or_else(|| anyhow!("s3 storage needs an [s3] section"))?;
                let mut b = object_store::aws::AmazonS3Builder::from_env().with_bucket_name(&s3.bucket);
                if let Some(r) = &s3.region {
                    b = b.with_region(r);
                }
                if let Some(e) = &s3.endpoint {
                    b = b.with_endpoint(e);
                }
                if let Some(k) = &s3.access_key_id {
                    b = b.with_access_key_id(k);
                }
                let secret = match &s3.secret_access_key_file {
                    Some(f) => Some(std::fs::read_to_string(f)?.trim().to_string()),
                    None => s3.secret_access_key.clone(),
                };
                if let Some(s) = secret {
                    b = b.with_secret_access_key(s);
                }
                b = b.with_virtual_hosted_style_request(!s3.path_style).with_allow_http(s3.allow_http);
                let store = b.build()?;
                let prefix = s3.prefix.clone().unwrap_or_default().trim_matches('/').to_string();
                Backend::Object {
                    store: Arc::new(store),
                    desc: format!("s3://{}/{}", s3.bucket, prefix),
                    prefix,
                }
            }
        })
    }

    pub fn describe(&self) -> String {
        match self {
            Backend::Local(p) => format!("local: {}", p.display()),
            Backend::Object { desc, .. } => desc.clone(),
            Backend::Database(_) => "database".into(),
        }
    }

    fn local_path(dir: &std::path::Path, key: &str) -> PathBuf {
        let k = key.trim_start_matches("a/");
        dir.join(&k[0..2]).join(&k[2..4]).join(k)
    }

    fn obj_path(prefix: &str, key: &str) -> ObjPath {
        let k = key.trim_start_matches("a/");
        if prefix.is_empty() {
            ObjPath::from(format!("{}/{}", &k[0..2], k))
        } else {
            ObjPath::from(format!("{prefix}/{}/{}", &k[0..2], k))
        }
    }

    /// Every key in the store (sweeps and backups).
    pub async fn list(&self) -> Result<Vec<String>> {
        match self {
            Backend::Local(dir) => {
                let dir = dir.clone();
                tokio::task::spawn_blocking(move || {
                    let mut out = vec![];
                    let mut stack = vec![dir];
                    while let Some(d) = stack.pop() {
                        let Ok(rd) = std::fs::read_dir(&d) else { continue };
                        for e in rd.flatten() {
                            let p = e.path();
                            let name = e.file_name().to_string_lossy().to_string();
                            if p.is_dir() {
                                stack.push(p);
                            } else if !name.starts_with(".tmp-") && name.len() > 4 {
                                out.push(name);
                            }
                        }
                    }
                    out
                })
                .await
                .map_err(|e| anyhow!(e))
            }
            Backend::Object { store, prefix, .. } => {
                use futures::StreamExt;
                let p = if prefix.is_empty() { None } else { Some(ObjPath::from(prefix.as_str())) };
                let mut s = store.list(p.as_ref());
                let mut out = vec![];
                while let Some(m) = s.next().await {
                    let m = m?;
                    if let Some(name) = m.location.filename() {
                        out.push(name.to_string());
                    }
                }
                Ok(out)
            }
            Backend::Database(db) => {
                use sqlx::Row;
                Ok(sqlx::query("SELECT key FROM blob_data").fetch_all(&db.pool).await?.iter().map(|r| r.get::<String, _>(0)).collect())
            }
        }
    }

    /// Stored bytes as-is (still encrypted / a manifest), for backups.
    pub async fn get_raw(&self, key: &str) -> Result<Vec<u8>> {
        self.get(key).await
    }

    pub async fn put_raw(&self, key: &str, data: Vec<u8>) -> Result<()> {
        self.put(key, data).await
    }

    pub async fn delete_raw(&self, key: &str) -> Result<()> {
        self.delete(key).await
    }

    async fn put(&self, key: &str, data: Vec<u8>) -> Result<()> {
        match self {
            Backend::Local(dir) => {
                let path = Self::local_path(dir, key);
                if tokio::fs::try_exists(&path).await.unwrap_or(false) {
                    return Ok(());
                }
                let parent = path.parent().unwrap().to_path_buf();
                tokio::task::spawn_blocking(move || -> Result<()> {
                    use std::io::Write;
                    std::fs::create_dir_all(&parent)?;
                    let tmp = parent.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
                    let mut f = std::fs::File::create(&tmp)?;
                    f.write_all(&data)?;
                    f.sync_data()?;
                    drop(f);
                    crate::util::restrict_permissions(&tmp);
                    std::fs::rename(&tmp, &path)?;
                    Ok(())
                })
                .await??;
                Ok(())
            }
            Backend::Object { store, prefix, .. } => {
                store.put(&Self::obj_path(prefix, key), PutPayload::from(data)).await?;
                Ok(())
            }
            Backend::Database(db) => db.blob_put(key, &data).await,
        }
    }

    async fn exists(&self, key: &str) -> bool {
        match self {
            Backend::Local(dir) => tokio::fs::try_exists(Self::local_path(dir, key)).await.unwrap_or(false),
            Backend::Object { store, prefix, .. } => store.head(&Self::obj_path(prefix, key)).await.is_ok(),
            Backend::Database(db) => db.blob_get(key).await.ok().flatten().is_some(),
        }
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        match self {
            Backend::Local(dir) => {
                let p = Self::local_path(dir, key);
                tokio::fs::read(&p).await.with_context(|| format!("read blob {key}"))
            }
            Backend::Object { store, prefix, .. } => {
                Ok(store.get(&Self::obj_path(prefix, key)).await?.bytes().await?.to_vec())
            }
            Backend::Database(db) => db.blob_get(key).await?.ok_or_else(|| anyhow!("blob {key} missing")),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        match self {
            Backend::Local(dir) => {
                let _ = tokio::fs::remove_file(Self::local_path(dir, key)).await;
                Ok(())
            }
            Backend::Object { store, prefix, .. } => {
                let _ = store.delete(&Self::obj_path(prefix, key)).await;
                Ok(())
            }
            Backend::Database(db) => db.blob_delete(key).await,
        }
    }
}

struct Cache {
    map: HashMap<String, Arc<Vec<u8>>>,
    order: VecDeque<String>,
    bytes: usize,
    max: usize,
}

impl Cache {
    fn get(&self, k: &str) -> Option<Arc<Vec<u8>>> {
        self.map.get(k).cloned()
    }
    fn put(&mut self, k: String, v: Arc<Vec<u8>>) {
        if v.len() > self.max / 4 || self.map.contains_key(&k) {
            return;
        }
        self.bytes += v.len();
        self.order.push_back(k.clone());
        self.map.insert(k, v);
        while self.bytes > self.max {
            let Some(old) = self.order.pop_front() else { break };
            if let Some(v) = self.map.remove(&old) {
                self.bytes -= v.len();
            }
        }
    }
    fn remove(&mut self, k: &str) {
        if let Some(v) = self.map.remove(k) {
            self.bytes -= v.len();
            self.order.retain(|x| x != k);
        }
    }
    fn retain_prefix_not(&mut self, prefix: &str) {
        let gone: Vec<String> = self.map.keys().filter(|k| k.starts_with(prefix)).cloned().collect();
        for k in gone {
            self.remove(&k);
        }
    }
}

pub struct BlobStore {
    pub messages: Backend,
    pub attachments: Option<(Backend, usize)>,
    cipher: Option<Aes256Gcm>,
    name_key: Option<[u8; 32]>,
    db: Db,
    cache: Mutex<Cache>,
    msg_locks: Vec<tokio::sync::Mutex<()>>,
    att_locks: Vec<tokio::sync::Mutex<()>>,
}

fn parse_key_file(bytes: &[u8]) -> Result<[u8; 32]> {
    use base64::Engine;
    if bytes.len() == 32 {
        return Ok(bytes.try_into().unwrap());
    }
    let text = std::str::from_utf8(bytes).unwrap_or("").trim();
    if let Ok(h) = hex::decode(text) {
        if h.len() == 32 {
            return Ok(h.try_into().unwrap());
        }
    }
    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(text) {
        if b.len() == 32 {
            return Ok(b.try_into().unwrap());
        }
    }
    bail!("encryption key must be 32 bytes (raw, hex or base64)")
}

impl BlobStore {
    pub fn new(cfg: &Config, db: &Db) -> Result<Self> {
        let BlobConfig { kind, path, s3 } = &cfg.storage.messages;
        let messages = Backend::build(kind, path, s3, cfg.data_path("messages"), Some(db))?;
        let attachments = match &cfg.storage.attachments {
            Some(a) => Some((
                Backend::build(&a.kind, &a.path, &a.s3, cfg.data_path("attachments"), Some(db))?,
                a.threshold_bytes.max(1024),
            )),
            None => None,
        };
        let key = if cfg.storage.encrypt || cfg.storage.encryption_key_file.is_some() {
            let file = cfg.storage.encryption_key_file.clone().unwrap_or_else(|| cfg.data_path("storage.key"));
            if !file.exists() {
                if cfg.storage.encryption_key_file.is_some() {
                    bail!("encryption key file {} not found", file.display());
                }
                std::fs::create_dir_all(&cfg.storage.data_dir)?;
                std::fs::write(&file, hex::encode(crate::util::random_bytes::<32>()))?;
                crate::util::restrict_permissions(&file);
                tracing::warn!("generated storage encryption key at {}: back it up, mail is unreadable without it", file.display());
            }
            Some(parse_key_file(&std::fs::read(&file)?)?)
        } else {
            None
        };
        let (cipher, name_key) = match key {
            Some(k) => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&k).unwrap();
                m.update(b"picacho-blob-names");
                let nk: [u8; 32] = m.finalize().into_bytes().into();
                (Some(Aes256Gcm::new_from_slice(&k).unwrap()), Some(nk))
            }
            None => (None, None),
        };
        Ok(Self {
            messages,
            attachments,
            cipher,
            name_key,
            db: db.clone(),
            msg_locks: (0..256).map(|_| tokio::sync::Mutex::new(())).collect(),
            att_locks: (0..256).map(|_| tokio::sync::Mutex::new(())).collect(),
            cache: Mutex::new(Cache {
                map: HashMap::new(),
                order: VecDeque::new(),
                bytes: 0,
                max: cfg.storage.cache_mb.max(1) * 1024 * 1024,
            }),
        })
    }

    pub fn encrypted(&self) -> bool {
        self.cipher.is_some()
    }

    /// (name, backend) of each configured store, for backups.
    pub fn all_backends(&self) -> Vec<(String, Backend)> {
        let mut v = vec![("messages".to_string(), self.messages.clone())];
        if let Some((a, _)) = &self.attachments {
            v.push(("attachments".to_string(), a.clone()));
        }
        v
    }

    /// Encrypt for storage when encryption is on (DAV objects).
    pub fn seal_bytes(&self, data: &[u8]) -> Vec<u8> {
        self.seal(data)
    }

    pub fn open_bytes(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        self.open(data)
    }

    /// Content address. Keyed when encrypting, so names reveal nothing.
    fn name(&self, data: &[u8]) -> String {
        match &self.name_key {
            Some(k) => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(k).unwrap();
                m.update(data);
                hex::encode(m.finalize().into_bytes())
            }
            None => crate::util::sha256_hex(data),
        }
    }

    fn seal(&self, data: &[u8]) -> Vec<u8> {
        match &self.cipher {
            Some(c) => {
                let nonce = crate::util::random_bytes::<12>();
                let ct = c.encrypt(Nonce::from_slice(&nonce), data).expect("encrypt");
                let mut out = Vec::with_capacity(ENC_MAGIC.len() + 12 + ct.len());
                out.extend_from_slice(ENC_MAGIC);
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&ct);
                out
            }
            None => data.to_vec(),
        }
    }

    fn open(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        if data.starts_with(ENC_MAGIC) && data.len() >= ENC_MAGIC.len() + 12 + 16 {
            let c = self.cipher.as_ref().ok_or_else(|| anyhow!("blob is encrypted but no key is configured"))?;
            let nonce = &data[ENC_MAGIC.len()..ENC_MAGIC.len() + 12];
            return c
                .decrypt(Nonce::from_slice(nonce), &data[ENC_MAGIC.len() + 12..])
                .map_err(|_| anyhow!("blob decryption failed (wrong key or corrupted data)"));
        }
        Ok(data)
    }

    fn lock_for<'a>(locks: &'a [tokio::sync::Mutex<()>], key: &str) -> &'a tokio::sync::Mutex<()> {
        let h = key.bytes().fold(0usize, |a, b| a.wrapping_mul(31).wrapping_add(b as usize));
        &locks[h % locks.len()]
    }

    async fn ref_count(&self, key: &str) -> Result<i64> {
        use sqlx::Row;
        Ok(sqlx::query("SELECT refs FROM blob_refs WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.db.pool)
            .await?
            .map(|r| r.get::<i64, _>(0))
            .unwrap_or(0))
    }

    /// Store a raw message and take one reference to it; returns its key.
    ///
    /// Writes and deletes of the same key are serialized, and a delete
    /// re-checks the reference count under that lock, so a deduplicated blob
    /// can never be removed while a new message is starting to use it.
    pub async fn put_message(&self, raw: &[u8]) -> Result<String> {
        let key = self.name(raw);
        let _g = Self::lock_for(&self.msg_locks, &key).lock().await;
        let refs = self.db.incr_blob(&key, raw.len() as i64).await?;
        if refs > 1 && self.messages.exists(&key).await {
            return Ok(key);
        }
        let res = self.write_message(&key, raw).await;
        if let Err(e) = res {
            let _ = self.db.release_blob(&key).await;
            return Err(e);
        }
        Ok(key)
    }

    async fn write_message(&self, key: &str, raw: &[u8]) -> Result<()> {
        let mut stored = None;
        if let Some((att, threshold)) = &self.attachments {
            let spans = crate::mime::attachment_spans(raw, *threshold);
            if !spans.is_empty() {
                let mut manifest = MANIFEST_MAGIC.to_vec();
                let mut pos = 0;
                for (start, end) in spans {
                    let part = &raw[start..end];
                    let akey = format!("a/{}", self.name(part));
                    {
                        let _ag = Self::lock_for(&self.att_locks, &akey).lock().await;
                        let n = self.db.incr_blob(&akey, part.len() as i64).await?;
                        if n == 1 || !att.exists(&akey).await {
                            att.put(&akey, self.seal(part)).await?;
                        }
                    }
                    push_inline(&mut manifest, &raw[pos..start]);
                    manifest.push(1);
                    manifest.extend_from_slice(&((end - start) as u64).to_be_bytes());
                    manifest.extend_from_slice(&(akey.len() as u16).to_be_bytes());
                    manifest.extend_from_slice(akey.as_bytes());
                    pos = end;
                }
                push_inline(&mut manifest, &raw[pos..]);
                stored = Some(manifest);
            }
        }
        if stored.is_none() && raw.first() == Some(&0) {
            // Never let raw data be mistaken for a manifest.
            let mut m = MANIFEST_MAGIC.to_vec();
            push_inline(&mut m, raw);
            stored = Some(m);
        }
        let data = stored.unwrap_or_else(|| raw.to_vec());
        self.messages.put(key, self.seal(&data)).await
    }

    /// Store an already sealed zero-access message (src/za.rs) as-is: it's
    /// ciphertext under the account's own keys, not the server's.
    pub async fn put_sealed(&self, key: &str, data: Vec<u8>) -> Result<()> {
        let _g = Self::lock_for(&self.msg_locks, key).lock().await;
        self.db.incr_blob(key, data.len() as i64).await?;
        if let Err(e) = self.messages.put(key, data).await {
            let _ = self.db.release_blob(key).await;
            return Err(e);
        }
        Ok(())
    }

    /// Drop cached plaintext of one account's sealed messages (keys locked).
    pub fn forget_prefix(&self, prefix: &str) {
        self.cache.lock().retain_prefix_not(prefix);
    }

    pub async fn get(&self, key: &str) -> Result<Arc<Vec<u8>>> {
        if let Some(v) = self.cache.lock().get(key) {
            return Ok(v);
        }
        if key.starts_with(crate::za::BLOB_PREFIX) {
            // Zero-access: only with the account's keys in memory (Open mode).
            let sealed = self.messages.get(key).await?;
            let v = Arc::new(crate::za::open_blob(key, &sealed)?);
            self.cache.lock().put(key.to_string(), v.clone());
            return Ok(v);
        }
        let data = self.open(self.messages.get(key).await?)?;
        let data = if data.starts_with(MANIFEST_MAGIC) { self.assemble(&data).await? } else { data };
        let v = Arc::new(data);
        self.cache.lock().put(key.to_string(), v.clone());
        Ok(v)
    }

    async fn assemble(&self, manifest: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for seg in parse_manifest(manifest)? {
            match seg {
                Segment::Inline(b) => out.extend_from_slice(b),
                Segment::Attachment(k, len) => {
                    let (att, _) = self.attachments.as_ref().ok_or_else(|| anyhow!("attachment store not configured"))?;
                    let data = self.open(att.get(&k).await?)?;
                    if data.len() != len {
                        bail!("attachment {k} has the wrong length");
                    }
                    out.extend_from_slice(&data);
                }
            }
        }
        Ok(out)
    }

    /// Delete a blob whose last reference was released. Skipped when a
    /// concurrent writer has taken a new reference meanwhile.
    pub async fn delete(&self, key: &str) -> Result<()> {
        self.cache.lock().remove(key);
        if key.starts_with("a/") {
            let _g = Self::lock_for(&self.att_locks, key).lock().await;
            if self.ref_count(key).await? > 0 {
                return Ok(());
            }
            if let Some((att, _)) = &self.attachments {
                att.delete(key).await?;
            }
            return Ok(());
        }
        let _g = Self::lock_for(&self.msg_locks, key).lock().await;
        if self.ref_count(key).await? > 0 {
            return Ok(());
        }
        if let Ok(raw) = self.messages.get(key).await {
            if let Ok(m) = self.open(raw) {
                if m.starts_with(MANIFEST_MAGIC) {
                    for seg in parse_manifest(&m)? {
                        if let Segment::Attachment(k, _) = seg {
                            if self.db.release_blob(&k).await.unwrap_or(false) {
                                let _ag = Self::lock_for(&self.att_locks, &k).lock().await;
                                if self.ref_count(&k).await? == 0 {
                                    if let Some((att, _)) = &self.attachments {
                                        att.delete(&k).await?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        self.cache.lock().remove(key);
        self.messages.delete(key).await
    }

    pub async fn delete_all(&self, keys: &[String]) {
        for k in keys {
            if let Err(e) = self.delete(k).await {
                tracing::warn!("blob delete {k}: {e}");
            }
        }
    }
}

fn push_inline(m: &mut Vec<u8>, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    m.push(0);
    m.extend_from_slice(&(data.len() as u64).to_be_bytes());
    m.extend_from_slice(data);
}

enum Segment<'a> {
    Inline(&'a [u8]),
    Attachment(String, usize),
}

fn parse_manifest(m: &[u8]) -> Result<Vec<Segment<'_>>> {
    let mut i = MANIFEST_MAGIC.len();
    let mut out = vec![];
    let bad = || anyhow!("corrupt message manifest");
    while i < m.len() {
        let tag = m[i];
        i += 1;
        let len = u64::from_be_bytes(m.get(i..i + 8).ok_or_else(bad)?.try_into().unwrap()) as usize;
        i += 8;
        match tag {
            0 => {
                out.push(Segment::Inline(m.get(i..i + len).ok_or_else(bad)?));
                i += len;
            }
            1 => {
                let kl = u16::from_be_bytes(m.get(i..i + 2).ok_or_else(bad)?.try_into().unwrap()) as usize;
                i += 2;
                let k = std::str::from_utf8(m.get(i..i + kl).ok_or_else(bad)?)?.to_string();
                i += kl;
                out.push(Segment::Attachment(k, len));
            }
            _ => return Err(bad()),
        }
    }
    Ok(out)
}

/// Check storage settings without changing anything: (what, Ok(detail) | Err(problem)).
pub async fn test_storage(st: &crate::config::Storage) -> Vec<(String, std::result::Result<String, String>)> {
    let mut out = vec![];
    let dir = st.data_dir.clone();
    let probe = dir.join(format!(".probe-{}", uuid::Uuid::new_v4().simple()));
    let r = std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&probe, b"ok")).and_then(|_| std::fs::remove_file(&probe));
    out.push(("Data directory".into(), r.map(|_| format!("{} is writable", dir.display())).map_err(|e| format!("{}: {e}", dir.display()))));
    let db = &st.database;
    let db_result = match db.kind {
        crate::config::DatabaseKind::Sqlite => Ok("SQLite in the data directory".to_string()),
        crate::config::DatabaseKind::Postgres => {
            let url = match (&db.url_file, &db.url) {
                (Some(f), _) => std::fs::read_to_string(f).map(|u| u.trim().to_string()).map_err(|e| format!("{}: {e}", f.display())),
                (None, Some(u)) => Ok(u.clone()),
                (None, None) => Err("Enter a PostgreSQL URL.".to_string()),
            };
            match url {
                Err(e) => Err(e),
                Ok(url) => {
                    sqlx::any::install_default_drivers();
                    let conn = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        sqlx::any::AnyPoolOptions::new().max_connections(1).connect(&url),
                    )
                    .await;
                    match conn {
                        Ok(Ok(pool)) => {
                            pool.close().await;
                            Ok("Connected to PostgreSQL".to_string())
                        }
                        Ok(Err(e)) => Err(format!("Couldn't connect: {e}")),
                        Err(_) => Err("Connection timed out.".to_string()),
                    }
                }
            }
        }
    };
    out.push(("Database".into(), db_result));
    let mut stores = vec![("Messages", st.messages.kind.clone(), st.messages.path.clone(), st.messages.s3.clone(), dir.join("messages"))];
    if let Some(a) = &st.attachments {
        stores.push(("Attachments", a.kind.clone(), a.path.clone(), a.s3.clone(), dir.join("attachments")));
    }
    for (name, kind, path, s3, default_dir) in stores {
        if kind == BlobKind::Database {
            out.push((name.into(), Ok("Stored in the database".into())));
            continue;
        }
        let res = async {
            let b = Backend::build(&kind, &path, &s3, default_dir, None).map_err(|e| e.to_string())?;
            let key = format!("{:0>64}", hex::encode(crate::util::random_bytes::<16>()));
            b.put(&key, b"picacho storage probe".to_vec()).await.map_err(|e| format!("Write failed: {e}"))?;
            let back = b.get(&key).await.map_err(|e| format!("Read failed: {e}"))?;
            b.delete(&key).await.map_err(|e| format!("Delete failed: {e}"))?;
            if back != b"picacho storage probe" {
                return Err("Read back different data.".to_string());
            }
            Ok(format!("Wrote, read and deleted a test object ({})", b.describe()))
        }
        .await;
        out.push((name.into(), res));
    }
    out
}
