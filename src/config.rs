//! Static configuration loaded from `config.toml`.
//!
//! Every field is optional. A missing file means "all defaults": SQLite and
//! local storage under `./data`, standard ports, web console on :8080.
//! Anything that can change at runtime (relays, limits, policies) lives in
//! live settings (`settings.rs`) and is edited from the web console.
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Public host name (EHLO, banners, certificates). Overridable later in
    /// the web console; defaults to the machine's host name.
    pub hostname: Option<String>,
    pub listen: Listen,
    pub tls: TlsConfig,
    pub storage: Storage,
    pub web: Web,
    pub log: Log,
    pub limits: Limits,
    pub dns: Dns,
    pub zero_access: ZeroAccess,
}

/// Pinal's zero-access mail (src/za.rs): where Pinal Accounts is and the
/// shared secret for its internal API (`ZA_INTERNAL_SECRET` there).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ZeroAccess {
    /// e.g. https://accounts.pinal.tech. Unset: no account is zero-access.
    pub accounts_url: Option<String>,
    pub secret: Option<String>,
    /// A file holding the secret (preferred over `secret`).
    pub secret_file: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listen {
    /// Inbound MX (port 25). Empty list disables.
    pub smtp: Vec<SocketAddr>,
    /// Submission with STARTTLS (587).
    pub submission: Vec<SocketAddr>,
    /// Submission over implicit TLS (465).
    pub submissions: Vec<SocketAddr>,
    /// IMAP with STARTTLS (143).
    pub imap: Vec<SocketAddr>,
    /// IMAP over implicit TLS (993).
    pub imaps: Vec<SocketAddr>,
    /// ManageSieve (RFC 5804) for editing filters from mail apps (4190).
    pub managesieve: Vec<SocketAddr>,
    /// Accept PROXY protocol v1/v2 headers from these load balancers.
    pub proxy_protocol_from: Vec<String>,
}

impl Default for Listen {
    fn default() -> Self {
        let a = |s: &str| s.parse().unwrap();
        Self {
            smtp: vec![a("0.0.0.0:25")],
            submission: vec![a("0.0.0.0:587")],
            submissions: vec![a("0.0.0.0:465")],
            imap: vec![a("0.0.0.0:143")],
            imaps: vec![a("0.0.0.0:993")],
            managesieve: vec![a("0.0.0.0:4190")],
            proxy_protocol_from: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain. Without one, a self-signed certificate is
    /// generated and stored in the data directory.
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    /// Minimum TLS version: "1.2" (default) or "1.3".
    pub min_version: Option<String>,
    /// Obtain and renew certificates automatically (ACME, e.g. Let's Encrypt).
    pub acme: Option<AcmeConfig>,
    /// Re-read `cert`/`key` when they change on disk (checked every minute).
    pub watch_files: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AcmeConfig {
    /// ACME directory URL. Default: Let's Encrypt production.
    pub directory: String,
    /// Contact addresses (mailto: is added when missing).
    pub contact: Vec<String>,
    /// Names on the certificate. Default: the host name plus
    /// mta-sts.<domain> and autoconfig.<domain> for every local domain.
    pub domains: Vec<String>,
    /// Plain-HTTP listeners that answer HTTP-01 challenges (port 80).
    pub http_listen: Vec<SocketAddr>,
    /// Renew this many days before expiry.
    pub renew_days: i64,
    /// Accept the ACME terms of service (required).
    pub accept_terms: bool,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            directory: "https://acme-v02.api.letsencrypt.org/directory".into(),
            contact: vec![],
            domains: vec![],
            http_listen: vec!["0.0.0.0:80".parse().unwrap()],
            renew_days: 30,
            accept_terms: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Storage {
    /// Base directory for everything stored locally (database, blobs,
    /// certificates, live settings file). Defaults to `./data`.
    pub data_dir: PathBuf,
    pub database: DatabaseConfig,
    /// Where raw messages go.
    pub messages: BlobConfig,
    /// Where large attachments go. Defaults to the message store.
    pub attachments: Option<AttachmentConfig>,
    /// Where live (web-editable) settings go.
    pub settings: SettingsStore,
    /// Path to a 32-byte key (raw, hex or base64) for AES-256-GCM encryption
    /// of all stored messages and attachments. Generated in the data
    /// directory when `encrypt = true` and no file is given.
    pub encryption_key_file: Option<PathBuf>,
    pub encrypt: bool,
    /// In-memory cache for recently read messages, in MiB.
    pub cache_mb: usize,
    /// Where WebDAV files, calendars and contacts go (each defaults to the message store).
    pub dav: DavStorage,
    /// Maintain a full-text index for SEARCH BODY/TEXT and JMAP text filters.
    pub full_text_index: bool,
}

/// Separate stores for DAV data. Any part left out uses the message store
/// (local, S3 or database, as configured there).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct DavStorage {
    pub files: Option<BlobConfig>,
    pub calendars: Option<BlobConfig>,
    pub contacts: Option<BlobConfig>,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("data"),
            database: DatabaseConfig::default(),
            messages: BlobConfig::default(),
            attachments: None,
            settings: SettingsStore::default(),
            encryption_key_file: None,
            encrypt: false,
            cache_mb: 64,
            dav: DavStorage::default(),
            full_text_index: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseKind {
    #[default]
    Sqlite,
    Postgres,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    pub kind: DatabaseKind,
    /// `postgres://user:pass@host/db` or `sqlite:///path/mail.db`. Defaults
    /// to `<data_dir>/mail.db` for SQLite.
    pub url: Option<String>,
    /// Read the URL from this file (keeps passwords out of config.toml).
    pub url_file: Option<PathBuf>,
    pub max_connections: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self { kind: DatabaseKind::Sqlite, url: None, url_file: None, max_connections: 16 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BlobKind {
    /// Files on disk.
    #[default]
    Local,
    /// Any S3-compatible object store (AWS, R2, MinIO, Backblaze, ...).
    S3,
    /// Inside the metadata database.
    Database,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct BlobConfig {
    pub kind: BlobKind,
    /// Local: directory (default `<data_dir>/messages`).
    pub path: Option<PathBuf>,
    pub s3: Option<S3Config>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AttachmentConfig {
    pub kind: BlobKind,
    pub path: Option<PathBuf>,
    pub s3: Option<S3Config>,
    /// Attachments at least this many bytes are stored separately and
    /// deduplicated. Default 64 KiB.
    pub threshold_bytes: usize,
}

impl Default for AttachmentConfig {
    fn default() -> Self {
        Self { kind: BlobKind::Local, path: None, s3: None, threshold_bytes: 64 * 1024 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct S3Config {
    pub bucket: String,
    pub region: Option<String>,
    /// Custom endpoint for non-AWS providers.
    pub endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    /// Read the secret from a file instead.
    pub secret_access_key_file: Option<PathBuf>,
    /// Key prefix inside the bucket.
    pub prefix: Option<String>,
    /// Use path-style URLs (MinIO and most self-hosted stores).
    pub path_style: bool,
    /// Permit plain-HTTP endpoints (local testing only).
    pub allow_http: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SettingsKind {
    #[default]
    Database,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct SettingsStore {
    pub kind: SettingsKind,
    /// For `file`: path to a TOML file (default `<data_dir>/live.toml`).
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Web {
    pub listen: Vec<SocketAddr>,
    /// Serve the console over HTTPS with the server certificate.
    pub tls: bool,
    /// Public URL of the console, used in the startup banner.
    pub public_url: Option<String>,
    /// Session lifetime in hours.
    pub session_hours: u64,
    /// Trust X-Forwarded-For from these addresses (reverse proxies).
    pub trusted_proxies: Vec<String>,
    /// Serve Prometheus metrics at /metrics.
    pub metrics: bool,
    /// Addresses allowed to read /metrics without a token (CIDR or IP).
    pub metrics_allow: Vec<String>,
    /// Bearer token that also grants access to /metrics.
    pub metrics_token_file: Option<PathBuf>,
}

impl Default for Web {
    fn default() -> Self {
        Self {
            listen: vec!["0.0.0.0:8080".parse().unwrap()],
            tls: false,
            public_url: None,
            session_hours: 12,
            trusted_proxies: vec![],
            metrics: true,
            metrics_allow: vec!["127.0.0.1".into(), "::1".into()],
            metrics_token_file: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Log {
    /// trace, debug, info, warn, error (or a tracing filter string).
    pub level: String,
    /// "text" or "json".
    pub format: String,
}

impl Default for Log {
    fn default() -> Self {
        Self { level: "info".into(), format: "text".into() }
    }
}

/// Hard ceilings that protect the process. Policy limits that admins tune
/// day to day live in live settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub imap_max_line: usize,
    pub smtp_max_line: usize,
    pub idle_timeout_secs: u64,
    pub auth_timeout_secs: u64,
    /// On SIGTERM, wait this long for open sessions and deliveries to finish.
    pub shutdown_grace_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 10_000,
            max_connections_per_ip: 64,
            imap_max_line: 64 * 1024,
            smtp_max_line: 4096,
            idle_timeout_secs: 30 * 60,
            auth_timeout_secs: 60,
            shutdown_grace_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    /// "system" (default), "cloudflare", "google", "quad9", "cloudflare-tls".
    pub resolver: Option<String>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("{}: {}", path.display(), e))?;
        Ok(cfg)
    }

    /// TOML holding only the values that differ from the defaults.
    pub fn to_minimal_toml(&self) -> anyhow::Result<String> {
        fn prune(v: &mut toml::Value, d: &toml::Value) -> bool {
            match (v, d) {
                (toml::Value::Table(t), toml::Value::Table(dt)) => {
                    t.retain(|k, val| match dt.get(k) {
                        Some(dv) => !prune(val, dv),
                        None => true,
                    });
                    t.is_empty()
                }
                (a, b) => a == b,
            }
        }
        let mut v = toml::Value::try_from(self)?;
        let d = toml::Value::try_from(Config::default())?;
        prune(&mut v, &d);
        Ok(toml::to_string_pretty(&v)?)
    }

    pub fn data_path(&self, rel: &str) -> PathBuf {
        self.storage.data_dir.join(rel)
    }

    pub fn database_url(&self) -> anyhow::Result<String> {
        if let Some(f) = &self.storage.database.url_file {
            return Ok(std::fs::read_to_string(f)?.trim().to_string());
        }
        if let Some(u) = &self.storage.database.url {
            return Ok(u.clone());
        }
        match self.storage.database.kind {
            DatabaseKind::Sqlite => {
                let p = self.data_path("mail.db");
                Ok(format!("sqlite://{}?mode=rwc", p.display()))
            }
            DatabaseKind::Postgres => {
                anyhow::bail!("storage.database.url is required for postgres")
            }
        }
    }

    pub fn default_hostname(&self) -> String {
        if let Some(h) = &self.hostname {
            return h.clone();
        }
        std::env::var("HOSTNAME")
            .ok()
            .filter(|h| !h.is_empty())
            .or_else(|| {
                std::process::Command::new("hostname")
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
            })
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "localhost".into())
    }
}
