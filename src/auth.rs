//! Password hashing, login, brute-force protection and the setup access key.
use crate::db::Account;
use crate::state::State;
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use sha2::Sha256;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

fn argon() -> Argon2<'static> {
    // OWASP-recommended argon2id parameters: 19 MiB, 2 passes.
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(19 * 1024, 2, 1, None).unwrap())
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    argon()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hash: {e}"))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(h) => argon().verify_password(password.as_bytes(), &h).is_ok(),
        Err(_) => false,
    }
}

pub fn check_password_strength(pw: &str, min: usize) -> Result<(), String> {
    if pw.chars().count() < min {
        return Err(format!("Password must be at least {min} characters."));
    }
    if pw.len() > 1024 {
        return Err("Password is too long.".into());
    }
    let classes = [
        pw.chars().any(|c| c.is_lowercase()),
        pw.chars().any(|c| c.is_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    if classes < 2 && pw.chars().count() < 16 {
        return Err("Use a mix of letters, digits or symbols, or a longer passphrase.".into());
    }
    Ok(())
}

#[derive(Debug, PartialEq)]
pub enum AuthError {
    Banned,
    Invalid,
    Disabled,
    Internal,
    /// Account passwords are turned off for this service.
    PasswordDisabled,
    /// A zero-access account (src/za.rs) needs an app password from Pinal
    /// (Open mode) to read mail here.
    ZeroAccess,
}

/// What a credential may do on a service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Access {
    None,
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    Imap,
    Smtp,
    Jmap,
    /// ManageSieve (filters).
    Sieve,
    /// WebDAV, CalDAV, CardDAV.
    Dav,
    /// The account self-service API (/api/v1/me).
    Account,
}

/// Scopes: `imap`, `imap:read`, `smtp`, `jmap`, `jmap:read`, `sieve`,
/// `dav`, `dav:read` (every DAV section), `caldav`, `caldav:read`,
/// `carddav`, `carddav:read`, `account`, `account:read`, `admin`, and the
/// older `mail` (= imap + smtp). Tokens from the identity provider are
/// translated by `resource::map_scopes` and marked external.
pub fn access(scopes: &str, svc: Service) -> Access {
    let has = |x: &str| scopes.split([',', ' ']).any(|s| s == x);
    let external = has(crate::resource::EXTERNAL);
    match svc {
        Service::Imap if has("imap") || has("mail") => Access::Write,
        Service::Imap if has("imap:read") => Access::Read,
        Service::Smtp if has("smtp") || has("mail") => Access::Write,
        Service::Jmap if has("jmap") => Access::Write,
        Service::Jmap if has("jmap:read") => Access::Read,
        // Filters can forward mail, so outside apps need mail.settings for them.
        Service::Sieve if has("sieve") || has("account") || (!external && (has("mail") || has("imap"))) => Access::Write,
        Service::Dav => ["files", "calendars", "addressbooks"].iter().map(|s| dav_access(scopes, s)).max().unwrap_or(Access::None),
        Service::Account if has("account") => Access::Write,
        Service::Account if has("account:read") => Access::Read,
        _ => Access::None,
    }
}

/// Access to one DAV section (`files`, `calendars` or `addressbooks`).
pub fn dav_access(scopes: &str, section: &str) -> Access {
    let has = |x: &str| scopes.split([',', ' ']).any(|s| s == x);
    let (w, r) = match section {
        "calendars" => ("caldav", "caldav:read"),
        "addressbooks" => ("carddav", "carddav:read"),
        _ => ("", ""),
    };
    if has("dav") || (!w.is_empty() && has(w)) {
        Access::Write
    } else if has("dav:read") || (!r.is_empty() && has(r)) {
        Access::Read
    } else {
        Access::None
    }
}

pub const VALID_SCOPES: [&str; 12] = ["admin", "imap", "imap:read", "smtp", "jmap", "jmap:read", "mail", "sieve", "dav", "dav:read", "account", "account:read"];

/// A bearer credential: an API token / app password (`pmk_`) or an access
/// token from the identity provider (a JWT, see `resource`).
pub struct Principal {
    pub account: Account,
    pub scopes: String,
    /// Issued by the identity provider rather than created here.
    pub external: bool,
}

pub async fn bearer_principal(state: &State, token: &str) -> Option<Principal> {
    if token.starts_with(TOKEN_PREFIX) {
        if token.len() > 200 {
            return None;
        }
        let (account, t) = token_auth(state, token).await?;
        return Some(Principal { account, scopes: t.scopes, external: false });
    }
    crate::resource::principal(state, token).await
}

/// Whether a password field holds a token rather than a password.
pub fn is_token(password: &str) -> bool {
    password.starts_with(TOKEN_PREFIX) || crate::resource::looks_like_jwt(password)
}

/// Sign in to a mail service with a password, app password or OAuth token
/// or provider access token (as the password, or via SASL XOAUTH2/OAUTHBEARER).
pub async fn login_service(state: &State, email: &str, password: &str, ip: IpAddr, svc: Service) -> Result<(Account, Access), AuthError> {
    let found = state.db.account_by_email(email.trim()).await.map_err(|_| AuthError::Internal)?;
    if let Some(account) = found.filter(|a| a.active) {
        if crate::za::is_zero_access(state, account.id).await {
            return zero_access_login(state, account, password, ip, svc).await;
        }
    }
    if is_token(password) {
        let sec = state.settings().security.clone();
        let allowlisted = crate::util::ip_in_list(ip, &sec.allowlist);
        if !allowlisted && state.limiter.is_banned(ip) {
            return Err(AuthError::Banned);
        }
        if let Some(p) = bearer_principal(state, password).await {
            let lvl = access(&p.scopes, svc);
            if p.account.email.eq_ignore_ascii_case(email.trim()) && lvl > Access::None {
                state.limiter.success(ip);
                return Ok((p.account, lvl));
            }
        }
        crate::metrics::AUTH_FAILURES.inc();
        if !allowlisted && state.limiter.fail(ip, sec.max_auth_failures, sec.auth_failure_window_secs, sec.ban_secs) {
            state.event("warn", "security", &format!("banned {ip} for {}s after repeated failed logins", sec.ban_secs));
        }
        return Err(AuthError::Invalid);
    }
    if !state.settings().auth.mail_password_login {
        return Err(AuthError::PasswordDisabled);
    }
    login(state, email, password, ip).await.map(|a| (a, Access::Write))
}

/// Zero-access accounts sign in to mail services only with a Pinal app
/// password (Open mode), which also opens their mail keys in memory. Their
/// account password, API tokens and Pinal access tokens can't read mail here
/// (Private mode: Pinal's apps read ciphertext through the REST API instead).
/// Filters and calendars/contacts keep their usual sign-in.
async fn zero_access_login(state: &State, account: Account, password: &str, ip: IpAddr, svc: Service) -> Result<(Account, Access), AuthError> {
    let sec = state.settings().security.clone();
    let allowlisted = crate::util::ip_in_list(ip, &sec.allowlist);
    if !allowlisted && state.limiter.is_banned(ip) {
        return Err(AuthError::Banned);
    }
    if crate::za::looks_like_app_password(password.trim()) {
        match crate::za::unlock_with_app_password(state, &account, password.trim()).await {
            Ok(true) => {
                state.limiter.success(ip);
                return Ok((account, Access::Write));
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(error = %e, "zero-access app password check failed");
                return Err(AuthError::Internal);
            }
        }
        crate::metrics::AUTH_FAILURES.inc();
        if !allowlisted && state.limiter.fail(ip, sec.max_auth_failures, sec.auth_failure_window_secs, sec.ban_secs) {
            state.event("warn", "security", &format!("banned {ip} for {}s after repeated failed logins", sec.ban_secs));
        }
        return Err(AuthError::Invalid);
    }
    if matches!(svc, Service::Imap | Service::Jmap | Service::Smtp) {
        return Err(AuthError::ZeroAccess);
    }
    // Filters and DAV: the usual credentials.
    if is_token(password) {
        if let Some(p) = bearer_principal(state, password).await {
            let lvl = access(&p.scopes, svc);
            if p.account.id == account.id && lvl > Access::None {
                return Ok((p.account, lvl));
            }
        }
        return Err(AuthError::Invalid);
    }
    login(state, &account.email, password, ip).await.map(|a| (a, Access::Write))
}

/// Parse a SASL XOAUTH2 or OAUTHBEARER (RFC 7628) client response into (user, token).
pub fn parse_oauth_sasl(mech: &str, raw: &[u8]) -> Option<(String, String)> {
    let s = String::from_utf8_lossy(raw);
    let mut user = None;
    let mut token = None;
    let mut parts: Vec<&str> = s.split('\x01').collect();
    if mech.eq_ignore_ascii_case("OAUTHBEARER") {
        // gs2 header: n,a=user@example.com,
        let gs2 = parts.remove(0);
        for f in gs2.split(',') {
            if let Some(u) = f.strip_prefix("a=") {
                user = Some(u.replace("=2C", ",").replace("=3D", "="));
            }
        }
    }
    for p in parts {
        if let Some(u) = p.strip_prefix("user=") {
            user = Some(u.to_string());
        } else if let Some(a) = p.strip_prefix("auth=") {
            let a = a.trim();
            token = a.strip_prefix("Bearer ").or_else(|| a.strip_prefix("bearer ")).map(|t| t.trim().to_string());
        }
    }
    Some((user?, token?))
}

/// Whether email + password may sign in to the web console.
pub fn web_password_allowed(state: &State) -> bool {
    state.settings().auth.web_password_login || std::env::var("PICACHO_ALLOW_PASSWORD_LOGIN").is_ok_and(|v| v == "1")
}

struct Failures {
    count: u32,
    first: Instant,
}

/// Tracks failed logins per address and bans abusers across all protocols.
#[derive(Default)]
pub struct Limiter {
    failures: DashMap<IpAddr, Failures>,
    bans: DashMap<IpAddr, (Instant, String)>,
}

impl Limiter {
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        if let Some(b) = self.bans.get(&ip) {
            if b.0 > Instant::now() {
                return true;
            }
        }
        self.bans.remove_if(&ip, |_, b| b.0 <= Instant::now());
        false
    }

    pub fn ban(&self, ip: IpAddr, secs: u64, reason: &str) {
        self.bans.insert(ip, (Instant::now() + Duration::from_secs(secs), reason.into()));
    }

    pub fn unban(&self, ip: IpAddr) {
        self.bans.remove(&ip);
        self.failures.remove(&ip);
    }

    /// Returns true when this failure triggered a ban.
    pub fn fail(&self, ip: IpAddr, max: u32, window: u64, ban_secs: u64) -> bool {
        let mut e = self.failures.entry(ip).or_insert(Failures { count: 0, first: Instant::now() });
        if e.first.elapsed() > Duration::from_secs(window) {
            e.count = 0;
            e.first = Instant::now();
        }
        e.count += 1;
        if e.count >= max {
            drop(e);
            self.failures.remove(&ip);
            self.ban(ip, ban_secs, "too many failed logins");
            return true;
        }
        false
    }

    pub fn success(&self, ip: IpAddr) {
        self.failures.remove(&ip);
    }

    pub fn list_bans(&self) -> Vec<(String, u64, String)> {
        let now = Instant::now();
        self.bans
            .iter()
            .filter(|e| e.value().0 > now)
            .map(|e| (e.key().to_string(), (e.value().0 - now).as_secs(), e.value().1.clone()))
            .collect()
    }
}

/// Recently verified credentials, so clients that reconnect often (mobile
/// IMAP, imaptest) don't pay for argon2 each time. Keys are HMACs under a
/// per-process secret; the password itself is never stored.
pub struct CredCache {
    key: [u8; 32],
    entries: DashMap<[u8; 32], (i64, Instant)>,
}

impl Default for CredCache {
    fn default() -> Self {
        Self { key: crate::util::random_bytes(), entries: DashMap::new() }
    }
}

impl CredCache {
    const TTL: Duration = Duration::from_secs(300);

    fn tag(&self, email: &str, password: &str, hash: &str) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).unwrap();
        m.update(email.as_bytes());
        m.update(&[0]);
        m.update(password.as_bytes());
        m.update(&[0]);
        m.update(hash.as_bytes());
        m.finalize().into_bytes().into()
    }

    fn hit(&self, email: &str, password: &str, hash: &str, id: i64) -> bool {
        let t = self.tag(email, password, hash);
        matches!(self.entries.get(&t), Some(e) if e.0 == id && e.1.elapsed() < Self::TTL)
    }

    fn put(&self, email: &str, password: &str, hash: &str, id: i64) {
        if self.entries.len() > 10_000 {
            self.entries.retain(|_, v| v.1.elapsed() < Self::TTL);
        }
        self.entries.insert(self.tag(email, password, hash), (id, Instant::now()));
    }
}

pub const TOKEN_PREFIX: &str = "pmk_";

/// New API token: (secret shown once, sha256 hash stored, display prefix).
pub fn generate_token() -> (String, String, String) {
    let t = format!("{TOKEN_PREFIX}{}", crate::util::random_token());
    let h = crate::util::sha256_hex(t.as_bytes());
    let p = t.chars().take(12).collect();
    (t, h, p)
}

/// Look up an API token; the account must be active.
pub async fn token_auth(state: &State, token: &str) -> Option<(Account, crate::db::ApiToken)> {
    if !token.starts_with(TOKEN_PREFIX) || token.len() > 200 {
        return None;
    }
    let t = state.db.token_by_hash(&crate::util::sha256_hex(token.as_bytes())).await.ok()??;
    let a = state.db.get_account(t.account_id).await.ok()??;
    a.active.then_some((a, t))
}

/// A dummy hash so unknown users take as long as known ones.
static DUMMY_HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub async fn login(state: &State, email: &str, password: &str, ip: IpAddr) -> Result<Account, AuthError> {
    let sec = state.settings().security.clone();
    let allowlisted = crate::util::ip_in_list(ip, &sec.allowlist);
    if !allowlisted && state.limiter.is_banned(ip) {
        return Err(AuthError::Banned);
    }
    let email = email.trim().to_ascii_lowercase();
    let password = Zeroizing::new(password.to_string());
    let account = state.db.account_by_email(&email).await.map_err(|_| AuthError::Internal)?;

    let ok = match &account {
        Some(a) if state.creds.hit(&email, &password, &a.password_hash, a.id) => true,
        Some(a) => {
            let (h, p) = (a.password_hash.clone(), password.clone());
            let ok = tokio::task::spawn_blocking(move || verify_password(&p, &h)).await.unwrap_or(false);
            if ok {
                state.creds.put(&email, &password, &a.password_hash, a.id);
            }
            ok
        }
        None => {
            let p = password.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let h = DUMMY_HASH.get_or_init(|| hash_password("dummy-password-for-timing").unwrap());
                verify_password(&p, h)
            })
            .await;
            false
        }
    };
    if !ok {
        crate::metrics::AUTH_FAILURES.inc();
        if !allowlisted && state.limiter.fail(ip, sec.max_auth_failures, sec.auth_failure_window_secs, sec.ban_secs) {
            state.event("warn", "security", &format!("banned {ip} for {}s after repeated failed logins", sec.ban_secs));
        }
        return Err(AuthError::Invalid);
    }
    let account = account.unwrap();
    if !account.active {
        return Err(AuthError::Disabled);
    }
    state.limiter.success(ip);
    Ok(account)
}

/// One-time access key printed at startup until an admin exists.
pub struct SetupKey {
    key: Mutex<Option<Zeroizing<String>>>,
    attempts: Mutex<(u32, Option<Instant>)>,
}

impl SetupKey {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { key: Mutex::new(None), attempts: Mutex::new((0, None)) })
    }

    /// Generate a fresh key: 25 base32 characters (125 bits) in groups of five.
    pub fn generate(&self) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        let bytes = crate::util::random_bytes::<25>();
        let chars: String = bytes.iter().map(|b| ALPHABET[(*b as usize) % 32] as char).collect();
        let key = chars
            .as_bytes()
            .chunks(5)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("-");
        *self.key.lock() = Some(Zeroizing::new(key.clone()));
        key
    }

    /// Reuse a key handed over by a setup restart.
    pub fn set(&self, key: &str) {
        *self.key.lock() = Some(Zeroizing::new(key.to_string()));
    }

    pub fn active(&self) -> bool {
        self.key.lock().is_some()
    }

    pub fn clear(&self) {
        *self.key.lock() = None;
    }

    /// Constant-time check, with a lockout after repeated wrong guesses.
    pub fn check(&self, candidate: &str) -> Result<(), &'static str> {
        {
            let mut a = self.attempts.lock();
            if let Some(until) = a.1 {
                if until > Instant::now() {
                    return Err("Too many attempts. Wait a minute and try again.");
                }
                *a = (0, None);
            }
        }
        let normalized: String = candidate
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let ok = match &*self.key.lock() {
            Some(k) => {
                let k: String = k.chars().filter(|c| *c != '-').collect();
                k.as_bytes().ct_eq(normalized.as_bytes()).into()
            }
            None => false,
        };
        if ok {
            return Ok(());
        }
        let mut a = self.attempts.lock();
        a.0 += 1;
        if a.0 >= 5 {
            a.1 = Some(Instant::now() + Duration::from_secs(60));
        }
        Err("That access key is not valid.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash_roundtrip() {
        let h = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &h));
        assert!(!verify_password("wrong", &h));
    }
    #[test]
    fn setup_key() {
        let k = SetupKey::new();
        let key = k.generate();
        assert!(k.check("nope").is_err());
        assert!(k.check(&key.to_lowercase()).is_ok());
    }
    #[test]
    fn strength() {
        assert!(check_password_strength("short", 10).is_err());
        assert!(check_password_strength("alllowercaseletters", 10).is_ok());
        assert!(check_password_strength("abcdefghij", 10).is_err());
        assert!(check_password_strength("abcdefghi1", 10).is_ok());
    }
}
