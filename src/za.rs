//! Zero-access mail: Pinal's zero-access storage for Pinal Mail accounts.
//!
//! An account is *zero-access* once its person has turned on Private or Open
//! mode for Mail at Pinal Accounts (accounts.pinal.tech → Privacy). Pinal
//! Accounts then holds a mail service keypair for it; this server only ever
//! gets the **public** half, so from then on:
//!
//! - **Arrival.** Every message is filtered as usual (spam, Sieve) and then
//!   sealed: a fresh content key encrypts the raw message (stored as a `z/`
//!   blob, `PZA1` chunked AES-256-GCM, without the server's own storage key)
//!   and its search index (envelope, body structure, body text, subject,
//!   sender, metadata), and the content key is sealed to the account's public
//!   key with HPKE (RFC 9180). Message-IDs are kept only as keyed hashes, for
//!   threading. The plaintext is dropped.
//! - **Private mode.** Nothing here can open it. IMAP, POP and JMAP mail
//!   refuse to read the account (see `auth::login_service`); Pinal's own apps
//!   read ciphertext over the REST API and decrypt on the device.
//! - **Open mode.** Standard mail apps sign in with an *app password* made in
//!   the Privacy tab. Pinal Accounts checks its auth half and hands back the
//!   service keys wrapped by its other half, which only the app sends. The
//!   keys are opened in memory, used to open rows and blobs while the app is
//!   connected ([`open_row`], [`open_blob`]), re-checked every minute, and
//!   dropped (zeroized) soon after the last session ends.
//!
//! Formats are Pinal's `za.js` (Pinal Technologies/zero-access): the same
//! HPKE suite, `wrap`, chunked files and labels.
use crate::db::MessageRow;
use crate::state::State;
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Payload}};
use anyhow::{Context, Result, anyhow, bail, ensure};
use hkdf::Hkdf;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable, aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

type Kem = X25519HkdfSha256;
type PrivateKey = <Kem as hpke::Kem>::PrivateKey;
type PublicKey = <Kem as hpke::Kem>::PublicKey;
type EncappedKey = <Kem as hpke::Kem>::EncappedKey;

const CHUNK: usize = 64 * 1024;
const TAG: usize = 16;
const HEADER: usize = 16;
/// Row marker in `messages.envelope` for a sealed message.
const ROW: &str = "za1:";
/// Blob key prefix (`z/<account>/<random>`) and header magic of a sealed message.
pub const BLOB_PREFIX: &str = "z/";
const BLOB_MAGIC: &[u8; 4] = b"PZM1";

// ── Encoding and primitives (as za.js) ───────────────────────────────────────

pub fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
pub fn unb64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('='))?)
}
fn array32(b: &[u8]) -> Result<[u8; 32]> {
    b.try_into().ok().context("expected 32 bytes")
}
pub fn hkdf(ikm: &[u8], info: &str) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ikm).expand(info.as_bytes(), out.as_mut()).expect("32 bytes");
    out
}
fn random<const N: usize>() -> [u8; N] {
    crate::util::random_bytes::<N>()
}
fn gcm_seal(key: &[u8; 32], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    Aes256Gcm::new(key.into()).encrypt(nonce.into(), Payload { msg: plaintext, aad }).expect("AES-GCM seal")
}
fn gcm_open(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    Aes256Gcm::new(key.into())
        .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
        .map_err(|_| anyhow!("can't be opened with these keys"))
}

/// `wrap` from za.js: 01 | nonce(12) | AES-256-GCM(key, secret, aad).
pub fn wrap(key: &[u8; 32], secret: &[u8], aad: &str) -> Vec<u8> {
    let nonce = random::<12>();
    let mut out = vec![1u8];
    out.extend_from_slice(&nonce);
    out.extend(gcm_seal(key, &nonce, secret, aad.as_bytes()));
    out
}
pub fn unwrap(key: &[u8; 32], wrapped: &[u8], aad: &str) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(wrapped.len() > 13 + TAG && wrapped[0] == 1, "unknown wrapping");
    Ok(Zeroizing::new(gcm_open(key, &wrapped[1..13], &wrapped[13..], aad.as_bytes())?))
}

/// HPKE single-shot seal to a public key (base mode).
pub fn seal(public: &[u8; 32], plaintext: &[u8], info: &str, aad: &str) -> Result<Vec<u8>> {
    let pk = PublicKey::from_bytes(public).map_err(|_| anyhow!("bad public key"))?;
    let mut rng = rand_core::OsRng;
    let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Kem, _>(&OpModeS::Base, &pk, info.as_bytes(), plaintext, aad.as_bytes(), &mut rng)
        .map_err(|_| anyhow!("HPKE seal failed"))?;
    let mut out = enc.to_bytes().to_vec();
    out.extend(ct);
    Ok(out)
}
pub fn open(private: &[u8; 32], sealed: &[u8], info: &str, aad: &str) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(sealed.len() >= 32 + TAG, "sealed data too short");
    let sk = PrivateKey::from_bytes(private).map_err(|_| anyhow!("bad private key"))?;
    let enc = EncappedKey::from_bytes(&sealed[..32]).map_err(|_| anyhow!("bad sealed key"))?;
    hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(&OpModeR::Base, &sk, &enc, info.as_bytes(), &sealed[32..], aad.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("can't be opened with these keys"))
}

fn nonce(prefix: &[u8], index: usize, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..7].copy_from_slice(prefix);
    n[7..11].copy_from_slice(&(index as u32).to_be_bytes());
    n[11] = last as u8;
    n
}

/// za.js `encryptFile`: "PZA1" | 01 | prefix(7) | chunk u32, then chunks.
pub fn encrypt_file(content_key: &[u8; 32], part: &str, plaintext: &[u8]) -> Vec<u8> {
    let key = hkdf(content_key, &format!("pinal-za/v1 file:{part}"));
    let prefix = random::<7>();
    let mut header = Vec::with_capacity(HEADER);
    header.extend_from_slice(b"PZA1");
    header.push(1);
    header.extend_from_slice(&prefix);
    header.extend_from_slice(&(CHUNK as u32).to_be_bytes());
    let count = plaintext.len().div_ceil(CHUNK).max(1);
    let mut out = Vec::with_capacity(HEADER + plaintext.len() + count * TAG);
    out.extend_from_slice(&header);
    for i in 0..count {
        let piece = &plaintext[(i * CHUNK).min(plaintext.len())..((i + 1) * CHUNK).min(plaintext.len())];
        out.extend(gcm_seal(&key, &nonce(&prefix, i, i + 1 == count), piece, &header));
    }
    out
}

pub fn decrypt_file(content_key: &[u8; 32], part: &str, data: &[u8]) -> Result<Vec<u8>> {
    ensure!(data.len() >= HEADER + TAG && &data[..4] == b"PZA1" && data[4] == 1, "not an encrypted Pinal file");
    let header = &data[..HEADER];
    let chunk = u32::from_be_bytes(data[12..16].try_into()?) as usize;
    ensure!((1024..=16 << 20).contains(&chunk), "bad chunk size");
    let key = hkdf(content_key, &format!("pinal-za/v1 file:{part}"));
    let body = &data[HEADER..];
    let count = body.len().div_ceil(chunk + TAG).max(1);
    let mut out = Vec::with_capacity(body.len());
    for (i, sealed) in body.chunks(chunk + TAG).enumerate() {
        out.extend(gcm_open(&key, &nonce(&data[5..12], i, i + 1 == count), sealed, header)?);
    }
    Ok(out)
}

// ── Sealing a message (arrival) ──────────────────────────────────────────────

/// An account's mail public key, as Pinal Accounts publishes it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MailKey {
    pub version: u64,
    pub public: [u8; 32],
    pub mode: String,
}

/// The search index sealed with each message (what `mime::summarize` makes).
#[derive(Serialize, Deserialize)]
struct Index {
    envelope: String,
    bodystructure: String,
    body: String,
    subject: String,
    from: String,
    meta: String,
    msgid: String,
}

/// What `store_message` writes for a sealed message.
pub struct Sealed {
    pub blob_key: String,
    pub blob: Vec<u8>,
    /// The `envelope` column: `za1:<account>:<version>:<ek>:<index>`.
    pub row: String,
    pub msgid: String,
    pub refs: Vec<String>,
}

/// Message-IDs are kept only as hashes keyed by the account (threading).
pub fn hash_msgid(account_id: i64, msgid: &str) -> String {
    if msgid.is_empty() {
        return String::new();
    }
    let mut h = Sha256::new();
    h.update(format!("pinal-za/v1 msgid:{account_id}:{msgid}"));
    format!("z:{}", &hex::encode(h.finalize())[..40])
}

pub fn seal_message(account_id: i64, key: &MailKey, raw: &[u8], s: &crate::mime::Summary) -> Result<Sealed> {
    let blob_key = format!("{BLOB_PREFIX}{account_id}/{}", hex::encode(random::<16>()));
    let content_key = Zeroizing::new(random::<32>());
    let ek = seal(&key.public, content_key.as_ref(), "pinal-za/v1 content-key", &format!("item:{blob_key}"))?;
    let index = Zeroizing::new(serde_json::to_vec(&Index {
        envelope: s.envelope.clone(),
        bodystructure: s.bodystructure.clone(),
        body: s.body.clone(),
        subject: s.subject.clone(),
        from: s.from.clone(),
        meta: s.meta.clone(),
        msgid: s.msgid.clone(),
    })?);
    let sealed_index = wrap(&hkdf(content_key.as_ref(), "pinal-za/v1 meta"), &index, &format!("meta:{blob_key}"));
    let mut blob = Vec::with_capacity(raw.len() + 128);
    blob.extend_from_slice(BLOB_MAGIC);
    blob.extend_from_slice(&(key.version as u32).to_be_bytes());
    blob.extend_from_slice(&(ek.len() as u16).to_be_bytes());
    blob.extend_from_slice(&ek);
    blob.extend(encrypt_file(&content_key, "original", raw));
    Ok(Sealed {
        row: format!("{ROW}{account_id}:{}:{}:{}", key.version, b64(&ek), b64(&sealed_index)),
        msgid: hash_msgid(account_id, &s.msgid),
        refs: s.refs.iter().map(|r| hash_msgid(account_id, r)).collect(),
        blob_key,
        blob,
    })
}

pub fn is_sealed_row(envelope: &str) -> bool {
    envelope.starts_with(ROW)
}

// ── Keys in memory (Open mode) ───────────────────────────────────────────────

struct Unlocked {
    /// version → private key
    keys: HashMap<u64, Zeroizing<[u8; 32]>>,
    /// App passwords that opened them (address, auth half), re-checked every minute.
    creds: Vec<(String, Zeroizing<String>)>,
    sessions: usize,
    last_used: Instant,
}

static UNLOCKED: LazyLock<Mutex<HashMap<i64, Unlocked>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// Opened rows, so a FETCH of many messages doesn't redo HPKE (dropped with the keys).
static OPENED: LazyLock<Mutex<HashMap<String, Arc<Index>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
const IDLE: Duration = Duration::from_secs(10 * 60);

fn keys_for(account_id: i64, version: u64) -> Option<Zeroizing<[u8; 32]>> {
    let mut map = UNLOCKED.lock();
    let u = map.get_mut(&account_id)?;
    u.last_used = Instant::now();
    u.keys.get(&version).cloned()
}

/// Whether this account's keys are open right now (an Open-mode session).
pub fn is_unlocked(account_id: i64) -> bool {
    UNLOCKED.lock().contains_key(&account_id)
}

/// Held by an IMAP session while it's connected: keeps the keys open.
pub struct SessionGuard(i64);
impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(u) = UNLOCKED.lock().get_mut(&self.0) {
            u.sessions = u.sessions.saturating_sub(1);
            u.last_used = Instant::now();
        }
    }
}
pub fn session(account_id: i64) -> Option<SessionGuard> {
    let mut map = UNLOCKED.lock();
    let u = map.get_mut(&account_id)?;
    u.sessions += 1;
    Some(SessionGuard(account_id))
}

/// Drops an account's keys now (app password deleted, mode changed, idle).
pub fn lock(state: &State, account_id: i64) {
    if UNLOCKED.lock().remove(&account_id).is_some() {
        let prefix = format!("{BLOB_PREFIX}{account_id}/");
        OPENED.lock().retain(|k, _| !k.starts_with(&prefix));
        state.blobs.forget_prefix(&prefix);
        tracing::info!(account_id, "zero-access keys dropped");
    }
}

// ── Opening rows and blobs (only with keys in memory) ────────────────────────

fn parse_row(envelope: &str) -> Option<(i64, u64, &str, &str)> {
    let mut it = envelope.strip_prefix(ROW)?.splitn(4, ':');
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?, it.next()?))
}

fn open_index(envelope: &str, blob: &str) -> Result<Arc<Index>> {
    if let Some(i) = OPENED.lock().get(blob) {
        return Ok(i.clone());
    }
    let (account, version, ek, idx) = parse_row(envelope).context("bad sealed row")?;
    let key = keys_for(account, version).context("locked")?;
    let content_key = open(&key, &unb64(ek)?, "pinal-za/v1 content-key", &format!("item:{blob}"))?;
    let json = unwrap(&hkdf(&content_key, "pinal-za/v1 meta"), &unb64(idx)?, &format!("meta:{blob}"))?;
    let index: Arc<Index> = Arc::new(serde_json::from_slice(&json)?);
    let mut cache = OPENED.lock();
    if cache.len() > 50_000 {
        cache.clear();
    }
    cache.insert(blob.to_owned(), index.clone());
    Ok(index)
}

/// Fills a sealed row's index from its sealed copy, if its account's keys
/// are open (an Open-mode session). Otherwise it stays sealed: an empty
/// envelope and body, which nothing serves (mail protocols refuse locked
/// zero-access accounts).
pub fn open_row(row: &mut MessageRow) {
    if !is_sealed_row(&row.envelope) {
        return;
    }
    match open_index(&row.envelope, &row.blob) {
        Ok(i) => {
            row.envelope = i.envelope.clone();
            row.bodystructure = i.bodystructure.clone();
            row.body = i.body.clone();
            row.meta = i.meta.clone();
            row.msgid = i.msgid.clone();
        }
        Err(_) => {
            row.envelope = "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)".into();
            row.bodystructure.clear();
            row.body.clear();
        }
    }
}

/// The plaintext of a sealed blob, with its account's keys open.
pub fn open_blob(key: &str, data: &[u8]) -> Result<Vec<u8>> {
    let account: i64 = key.strip_prefix(BLOB_PREFIX).and_then(|k| k.split('/').next()).and_then(|a| a.parse().ok()).context("bad sealed blob key")?;
    ensure!(data.len() > 10 && &data[..4] == BLOB_MAGIC, "not a sealed message");
    let version = u32::from_be_bytes(data[4..8].try_into()?) as u64;
    let ek_len = u16::from_be_bytes(data[8..10].try_into()?) as usize;
    ensure!(data.len() > 10 + ek_len, "truncated sealed message");
    let k = keys_for(account, version).ok_or_else(|| anyhow!("this mailbox is zero-access and locked"))?;
    let content_key = Zeroizing::new(array32(&open(&k, &data[10..10 + ek_len], "pinal-za/v1 content-key", &format!("item:{key}"))?)?);
    decrypt_file(&content_key, "original", &data[10 + ek_len..])
}

// ── Pinal Accounts ───────────────────────────────────────────────────────────

fn settings(state: &State) -> Option<(String, String)> {
    let cfg = &state.config.zero_access;
    let url = cfg.accounts_url.clone()?;
    let secret = match (&cfg.secret, &cfg.secret_file) {
        (Some(s), _) => s.clone(),
        (None, Some(f)) => std::fs::read_to_string(f).ok()?.trim().to_owned(),
        _ => return None,
    };
    Some((url.trim_end_matches('/').to_owned(), secret))
}

/// The Pinal user ID from an account's `issuer|sub` link.
fn pinal_user(account: &crate::db::Account) -> Option<&str> {
    let sub = account.oidc_sub.rsplit('|').next()?;
    (!sub.is_empty()).then_some(sub)
}

async fn internal(state: &State, path: &str, body: serde_json::Value) -> Result<Option<serde_json::Value>> {
    let (url, secret) = settings(state).context("zero-access is not configured")?;
    let res = reqwest::Client::new()
        .post(format!("{url}/api/internal/za/{path}"))
        .header("X-ZA-Internal", secret)
        .timeout(Duration::from_secs(10))
        .json(&body)
        .send()
        .await?;
    match res.status().as_u16() {
        200 => Ok(Some(res.json().await?)),
        401 | 404 => Ok(None),
        s => bail!("Pinal Accounts answered {s}"),
    }
}

static KEYS: LazyLock<Mutex<HashMap<i64, (Instant, Option<MailKey>)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// The account's mail public key if it is zero-access (cached a minute; the
/// last known key is kept in the database, so an outage at Pinal Accounts
/// never makes a zero-access account store plaintext).
pub async fn mail_key(state: &State, account: &crate::db::Account) -> Result<Option<MailKey>> {
    if let Some((at, k)) = KEYS.lock().get(&account.id).cloned() {
        if at.elapsed() < Duration::from_secs(60) {
            return Ok(k);
        }
    }
    let stored = stored_key(state, account.id).await?;
    let Some(user) = pinal_user(account).filter(|_| settings(state).is_some()) else {
        return Ok(stored);
    };
    let fetched = match internal(state, "service", serde_json::json!({ "userId": user, "service": "mail" })).await {
        Ok(Some(v)) => {
            let public = array32(&unb64(v["publicKey"].as_str().unwrap_or(""))?)?;
            Some(MailKey { version: v["version"].as_u64().unwrap_or(1), public, mode: v["mode"].as_str().unwrap_or("private").into() })
        }
        Ok(None) => {
            if stored.is_some() {
                // Was zero-access, now has no mail key (a fresh start): refuse
                // to store rather than fall back to plaintext.
                bail!("zero-access mail key missing for account {}; set Mail's mode again in the Privacy tab", account.id);
            }
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "Pinal Accounts unreachable; using the last known mail key");
            stored.clone()
        }
    };
    if let Some(k) = fetched.as_ref().filter(|k| stored.as_ref() != Some(*k)) {
        save_key(state, account.id, k).await?;
        if stored.is_none() {
            // Newly zero-access: seal what's already here.
            let st = state.clone();
            let acc = account.clone();
            tokio::spawn(async move {
                if let Err(e) = migrate(&st, &acc).await {
                    tracing::error!(account = acc.id, error = %e, "zero-access migration stopped");
                }
            });
        }
    }
    KEYS.lock().insert(account.id, (Instant::now(), fetched.clone()));
    Ok(fetched)
}

async fn stored_key(state: &State, account_id: i64) -> Result<Option<MailKey>> {
    use sqlx::Row;
    let row = sqlx::query("SELECT version, public_key, mode FROM za_accounts WHERE account_id = $1")
        .bind(account_id)
        .fetch_optional(&state.db.pool)
        .await?;
    Ok(match row {
        Some(r) => Some(MailKey {
            version: r.get::<i64, _>(0) as u64,
            public: array32(&unb64(&r.get::<String, _>(1))?)?,
            mode: r.get(2),
        }),
        None => None,
    })
}

async fn save_key(state: &State, account_id: i64, k: &MailKey) -> Result<()> {
    sqlx::query(
        "INSERT INTO za_accounts (account_id, version, public_key, mode, updated) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (account_id) DO UPDATE SET version = excluded.version, public_key = excluded.public_key, mode = excluded.mode, updated = excluded.updated",
    )
    .bind(account_id)
    .bind(k.version as i64)
    .bind(b64(&k.public))
    .bind(&k.mode)
    .bind(crate::util::now())
    .execute(&state.db.pool)
    .await?;
    Ok(())
}

/// Whether an account is zero-access (from this server's own record).
pub async fn is_zero_access(state: &State, account_id: i64) -> bool {
    stored_key(state, account_id).await.ok().flatten().is_some()
}

/// Looks like a Pinal app password (`xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx`).
pub fn looks_like_app_password(p: &str) -> bool {
    let parts: Vec<&str> = p.split('-').collect();
    parts.len() == 4 && parts.iter().all(|s| s.len() == 8 && s.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'9').contains(&b)))
}

/// Checks an app password with Pinal Accounts (Open mode only) and opens the
/// account's mail keys in memory. False when it isn't valid (or the account
/// is in Private mode).
pub async fn unlock_with_app_password(state: &State, account: &crate::db::Account, password: &str) -> Result<bool> {
    let secret = Zeroizing::new(password.as_bytes().to_vec());
    let auth = hkdf(&secret, "pinal-za/v1 app-pw-auth");
    let wrap_key = hkdf(&secret, "pinal-za/v1 app-pw-wrap");
    let user = pinal_user(account).context("account isn't linked to Pinal")?;
    let Some(v) = internal(state, "app-password", serde_json::json!({ "service": "mail", "userId": user, "auth": b64(auth.as_ref()) })).await? else {
        return Ok(false);
    };
    ensure!(pinal_user(account) == v["userId"].as_str(), "app password for another account");
    let mut keys = HashMap::new();
    for (version, wrapped) in v["wrapped"].as_object().into_iter().flatten() {
        let version: u64 = version.parse()?;
        let private = unwrap(&wrap_key, &unb64(wrapped.as_str().unwrap_or(""))?, &format!("pinal-za/v1 app-pw:mail:{version}"))?;
        keys.insert(version, Zeroizing::new(array32(&private)?));
    }
    ensure!(!keys.is_empty(), "no mail keys");
    let mut map = UNLOCKED.lock();
    let u = map.entry(account.id).or_insert_with(|| Unlocked { keys: HashMap::new(), creds: Vec::new(), sessions: 0, last_used: Instant::now() });
    u.keys.extend(keys);
    let auth_b64 = Zeroizing::new(b64(auth.as_ref()));
    if !u.creds.iter().any(|(_, a)| *a == auth_b64) {
        u.creds.push((user.to_owned(), auth_b64));
    }
    u.last_used = Instant::now();
    Ok(true)
}

/// Every minute: re-check the app passwords behind open keys (so deleting
/// one, or switching Mail to Private, cuts connected apps off), and drop keys
/// nobody has used for a while.
pub async fn keeper(state: State) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let entries: Vec<(i64, Vec<(String, Zeroizing<String>)>, bool)> = UNLOCKED
            .lock()
            .iter()
            .map(|(id, u)| (*id, u.creds.clone(), u.sessions == 0 && u.last_used.elapsed() > IDLE))
            .collect();
        for (account_id, creds, idle) in entries {
            if idle {
                lock(&state, account_id);
                continue;
            }
            let mut valid = Vec::new();
            let mut unreachable = false;
            for (user, auth) in creds {
                match internal(&state, "app-password", serde_json::json!({ "service": "mail", "userId": user, "auth": auth.as_str() })).await {
                    Ok(Some(_)) => valid.push((user, auth)),
                    Ok(None) => {}
                    Err(_) => unreachable = true,
                }
            }
            if valid.is_empty() && !unreachable {
                // Sessions still connected now see sealed rows and can't
                // fetch bodies: the app is effectively cut off.
                lock(&state, account_id);
            } else if let Some(u) = UNLOCKED.lock().get_mut(&account_id) {
                if !unreachable {
                    u.creds = valid;
                }
            }
        }
        KEYS.lock().retain(|_, (at, _)| at.elapsed() < Duration::from_secs(600));
    }
}

// ── Moving an existing mailbox over ──────────────────────────────────────────

/// Seals every message stored before the account became zero-access. The
/// one time the server reads old mail on purpose: it was readable here
/// before, and isn't afterwards.
pub async fn migrate(state: &State, account: &crate::db::Account) -> Result<()> {
    use sqlx::Row;
    let Some(key) = stored_key(state, account.id).await? else { return Ok(()) };
    let mut done = 0usize;
    loop {
        let rows = sqlx::query(
            "SELECT m.id, m.blob FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id
             WHERE b.account_id = $1 AND m.envelope NOT LIKE 'za1:%' ORDER BY m.id LIMIT 100",
        )
        .bind(account.id)
        .fetch_all(&state.db.pool)
        .await?;
        if rows.is_empty() {
            break;
        }
        for r in rows {
            let (id, old): (i64, String) = (r.get(0), r.get(1));
            let raw = state.blobs.get(&old).await?;
            let summary = crate::mime::summarize(&raw);
            let sealed = seal_message(account.id, &key, &raw, &summary)?;
            state.blobs.put_sealed(&sealed.blob_key, sealed.blob).await?;
            sqlx::query(
                "UPDATE messages SET blob = $1, envelope = $2, bodystructure = '', body = '', subject = '', from_addr = '', meta = '', msgid = $3 WHERE id = $4",
            )
            .bind(&sealed.blob_key)
            .bind(&sealed.row)
            .bind(&sealed.msgid)
            .bind(id)
            .execute(&state.db.pool)
            .await?;
            // Its plaintext search index goes too (sealed rows are never indexed).
            if state.db.fts.load(std::sync::atomic::Ordering::Relaxed) {
                let col = crate::dbx::fts_id_col(&state.db);
                let _ = sqlx::query(&format!("DELETE FROM message_fts WHERE {col} = $1")).bind(id).execute(&state.db.pool).await;
            }
            if state.db.release_blob(&old).await.unwrap_or(false) {
                let _ = state.blobs.delete(&old).await;
            }
            done += 1;
        }
    }
    if done > 0 {
        state.event("info", "zero-access", &format!("sealed {done} existing messages of {}", account.email));
    }
    Ok(())
}

/// Clears a zeroized key ring on shutdown.
pub fn forget_all() {
    for (_, mut u) in UNLOCKED.lock().drain() {
        for k in u.keys.values_mut() {
            k.zeroize();
        }
    }
    OPENED.lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_messages_open_only_with_the_private_key() {
        let ikm = random::<32>();
        let (sk, pk) = <Kem as hpke::Kem>::derive_keypair(&ikm);
        let private: [u8; 32] = sk.to_bytes().as_slice().try_into().unwrap();
        let key = MailKey { version: 3, public: pk.to_bytes().as_slice().try_into().unwrap(), mode: "open".into() };
        let raw = b"From: a@example.com\r\nSubject: Quarterly secret plans\r\nMessage-ID: <x@y>\r\n\r\nThe launch code is 1234.\r\n".repeat(2000);
        let summary = crate::mime::summarize(&raw);
        let s = seal_message(42, &key, &raw, &summary).unwrap();
        // No plaintext in what's stored.
        for needle in [&b"Quarterly"[..], b"launch code", b"a@example.com"] {
            assert!(!s.blob.windows(needle.len()).any(|w| w == needle));
            assert!(!s.row.as_bytes().windows(needle.len()).any(|w| w == needle));
        }
        assert!(s.msgid.starts_with("z:") && !s.msgid.contains("x@y"));
        // Locked: rows stay sealed, blobs don't open.
        let mut row = MessageRow { id: 1, uid: 1, blob: s.blob_key.clone(), size: 0, internal_date: 0, flags: String::new(), envelope: s.row.clone(), bodystructure: String::new(), body: String::new(), modseq: 1, meta: String::new(), msgid: String::new(), thread_id: 0, mailbox_id: 1 };
        open_row(&mut row);
        assert!(!row.envelope.contains("Quarterly"));
        assert!(open_blob(&s.blob_key, &s.blob).is_err());
        // Unlocked: both open.
        UNLOCKED.lock().insert(42, Unlocked { keys: HashMap::from([(3, Zeroizing::new(private))]), creds: vec![], sessions: 1, last_used: Instant::now() });
        let mut row2 = MessageRow { envelope: s.row.clone(), ..row };
        open_row(&mut row2);
        assert!(row2.envelope.contains("Quarterly secret plans"));
        assert_eq!(open_blob(&s.blob_key, &s.blob).unwrap(), raw);
        // Bound to its blob key.
        assert!(open_blob(&format!("{BLOB_PREFIX}42/other"), &s.blob).is_err());
        UNLOCKED.lock().remove(&42);
    }

    #[test]
    fn app_password_shape() {
        assert!(looks_like_app_password("9d2udtfz-kmvcmrvx-wgdfx779-m9k65kui"));
        assert!(!looks_like_app_password("hunter2"));
        assert!(!looks_like_app_password("pmk_abcdef"));
    }
}
