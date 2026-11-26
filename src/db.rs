//! Metadata store over SQLite or PostgreSQL (sqlx `Any`). Every query is
//! written once with `$n` placeholders, which both engines accept.
use crate::config::{Config, DatabaseKind};
use crate::util::now;
use anyhow::{anyhow, Result};
use serde::Serialize;
use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::{AnyPool, Executor, Row};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

#[derive(Clone)]
pub struct Db {
    pub pool: AnyPool,
    pub kind: DatabaseKind,
    /// SQLite allows one writer; serializing write transactions in-process
    /// avoids lock-upgrade failures under concurrency.
    write_lock: Arc<Mutex<()>>,
    /// The full-text index exists and is maintained.
    pub fts: Arc<std::sync::atomic::AtomicBool>,
}

pub struct WriteTx<'a> {
    pub tx: sqlx::Transaction<'static, sqlx::Any>,
    _guard: Option<MutexGuard<'a, ()>>,
}

impl<'a> WriteTx<'a> {
    pub async fn commit(self) -> Result<()> {
        self.tx.commit().await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Account {
    pub id: i64,
    pub email: String,
    pub domain_id: i64,
    #[serde(skip)]
    pub password_hash: String,
    pub display_name: String,
    pub role: String,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub active: bool,
    pub can_send_external: bool,
    pub forward_to: String,
    pub keep_copy: bool,
    pub created_at: i64,
    pub last_login: Option<i64>,
    /// Linked OpenID Connect identity ("issuer|sub"), if any.
    pub oidc_sub: String,
}

impl Account {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Domain {
    pub id: i64,
    pub name: String,
    /// local | relay | webhook
    pub mode: String,
    /// Transport id for relay/webhook domains.
    pub transport: String,
    pub catch_all: String,
    pub dkim_selector: String,
    #[serde(skip)]
    pub dkim_private: String,
    pub dkim_public: String,
    pub active: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alias {
    pub id: i64,
    pub source: String,
    pub destination: String,
    pub active: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Mailbox {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    pub uidvalidity: i64,
    pub uidnext: i64,
    pub modseq: i64,
    pub recent_uid: i64,
    pub special_use: String,
    pub keywords: String,
}

#[derive(Debug, Clone)]
pub struct MessageRow {
    pub id: i64,
    pub uid: i64,
    pub blob: String,
    pub size: i64,
    pub internal_date: i64,
    pub flags: String,
    pub envelope: String,
    pub bodystructure: String,
    pub body: String,
    pub modseq: i64,
    /// JSON summary (see `mime::Meta`); empty for rows not yet backfilled.
    pub meta: String,
    pub msgid: String,
    pub thread_id: i64,
    pub mailbox_id: i64,
}

/// The per-message state an IMAP session keeps in its view.
#[derive(Debug, Clone, PartialEq)]
pub struct ViewRow {
    pub uid: i64,
    pub flags: String,
    pub size: i64,
    pub modseq: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueueItem {
    pub id: i64,
    pub sender: String,
    pub recipients: Vec<String>,
    pub blob: String,
    pub size: i64,
    pub attempts: i64,
    pub next_attempt: i64,
    pub last_error: String,
    pub status: String,
    pub route: String,
    pub created_at: i64,
    /// DSN parameters (JSON, see `outbound::Dsn`); empty when none.
    #[serde(skip)]
    pub dsn: String,
    pub requiretls: bool,
    #[serde(skip)]
    pub delay_notified: bool,
    /// Relay peer that will pick this message up (status 'held').
    pub peer: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub id: i64,
    pub ts: i64,
    pub level: String,
    pub kind: String,
    pub message: String,
}

pub struct NewMessage<'a> {
    pub blob: &'a str,
    pub size: i64,
    pub internal_date: i64,
    pub flags: &'a str,
    pub envelope: &'a str,
    pub bodystructure: &'a str,
    pub body: &'a str,
    pub subject: &'a str,
    pub from_addr: &'a str,
    pub meta: &'a str,
    pub msgid: &'a str,
    /// Message-IDs this message refers to (References + In-Reply-To).
    pub refs: &'a [String],
    /// Known thread (copies); 0 means look it up from `refs`.
    pub thread_id: i64,
}

/// An API token as listed in the console (never the secret).
#[derive(Debug, Clone, Serialize)]
pub struct ApiToken {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    pub prefix: String,
    pub scopes: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub expires_at: Option<i64>,
}

impl ApiToken {
    pub fn has_scope(&self, s: &str) -> bool {
        self.scopes.split([',', ' ']).any(|x| x == s)
    }
}

/// Result of a STORE.
pub struct FlagResult {
    /// (uid, flags, modseq) for every message that exists.
    pub rows: Vec<(i64, String, i64)>,
    /// UIDs not changed because of UNCHANGEDSINCE.
    pub modified: Vec<i64>,
}

fn b(v: i64) -> bool {
    v != 0
}

fn account_from(r: &AnyRow) -> Result<Account> {
    Ok(Account {
        id: r.try_get("id")?,
        email: r.try_get("email")?,
        domain_id: r.try_get("domain_id")?,
        password_hash: r.try_get("password_hash")?,
        display_name: r.try_get("display_name")?,
        role: r.try_get("role")?,
        quota_bytes: r.try_get("quota_bytes")?,
        used_bytes: r.try_get("used_bytes")?,
        active: b(r.try_get("active")?),
        can_send_external: b(r.try_get("can_send_external")?),
        forward_to: r.try_get("forward_to")?,
        keep_copy: b(r.try_get("keep_copy")?),
        created_at: r.try_get("created_at")?,
        last_login: r.try_get("last_login")?,
        oidc_sub: r.try_get("oidc_sub")?,
    })
}

fn domain_from(r: &AnyRow) -> Result<Domain> {
    Ok(Domain {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        mode: r.try_get("mode")?,
        transport: r.try_get("transport")?,
        catch_all: r.try_get("catch_all")?,
        dkim_selector: r.try_get("dkim_selector")?,
        dkim_private: r.try_get("dkim_private")?,
        dkim_public: r.try_get("dkim_public")?,
        active: b(r.try_get("active")?),
        created_at: r.try_get("created_at")?,
    })
}

fn alias_from(r: &AnyRow) -> Result<Alias> {
    Ok(Alias {
        id: r.try_get("id")?,
        source: r.try_get("source")?,
        destination: r.try_get("destination")?,
        active: b(r.try_get("active")?),
        created_at: r.try_get("created_at")?,
    })
}

fn mailbox_from(r: &AnyRow) -> Result<Mailbox> {
    Ok(Mailbox {
        id: r.try_get("id")?,
        account_id: r.try_get("account_id")?,
        name: r.try_get("name")?,
        uidvalidity: r.try_get("uidvalidity")?,
        uidnext: r.try_get("uidnext")?,
        modseq: r.try_get("modseq")?,
        recent_uid: r.try_get("recent_uid")?,
        special_use: r.try_get("special_use")?,
        keywords: r.try_get("keywords")?,
    })
}

fn message_from(r: &AnyRow) -> Result<MessageRow> {
    let mut row = message_plain(r)?;
    // Zero-access rows open only while their account's keys are in memory.
    crate::za::open_row(&mut row);
    Ok(row)
}

fn message_plain(r: &AnyRow) -> Result<MessageRow> {
    Ok(MessageRow {
        id: r.try_get("id")?,
        uid: r.try_get("uid")?,
        blob: r.try_get("blob")?,
        size: r.try_get("size")?,
        internal_date: r.try_get("internal_date")?,
        flags: r.try_get("flags")?,
        envelope: r.try_get("envelope")?,
        bodystructure: r.try_get("bodystructure")?,
        body: r.try_get("body")?,
        modseq: r.try_get("modseq")?,
        meta: r.try_get("meta")?,
        msgid: r.try_get("msgid")?,
        thread_id: r.try_get("thread_id")?,
        mailbox_id: r.try_get("mailbox_id")?,
    })
}

fn queue_from(r: &AnyRow) -> Result<QueueItem> {
    let rcpts: String = r.try_get("recipients")?;
    Ok(QueueItem {
        id: r.try_get("id")?,
        sender: r.try_get("sender")?,
        recipients: serde_json::from_str(&rcpts).unwrap_or_default(),
        blob: r.try_get("blob")?,
        size: r.try_get("size")?,
        attempts: r.try_get("attempts")?,
        next_attempt: r.try_get("next_attempt")?,
        last_error: r.try_get("last_error")?,
        status: r.try_get("status")?,
        route: r.try_get("route")?,
        created_at: r.try_get("created_at")?,
        dsn: r.try_get("dsn")?,
        requiretls: b(r.try_get("requiretls")?),
        delay_notified: b(r.try_get("delay_notified")?),
        peer: r.try_get("peer")?,
    })
}

const ACCOUNT_COLS: &str = "id, email, domain_id, password_hash, display_name, role, quota_bytes, used_bytes, active, can_send_external, forward_to, keep_copy, created_at, last_login, oidc_sub";
const DOMAIN_COLS: &str = "id, name, mode, transport, catch_all, dkim_selector, dkim_private, dkim_public, active, created_at";
const MAILBOX_COLS: &str = "id, account_id, name, uidvalidity, uidnext, modseq, recent_uid, special_use, keywords";
const MESSAGE_COLS: &str = "id, uid, blob, size, internal_date, flags, envelope, bodystructure, body, modseq, meta, msgid, thread_id, mailbox_id";
const QUEUE_COLS: &str = "id, sender, recipients, blob, size, attempts, next_attempt, last_error, status, route, created_at, dsn, requiretls, delay_notified, peer";

fn schema(kind: &DatabaseKind) -> Vec<String> {
    let (id, int, blob) = match kind {
        DatabaseKind::Sqlite => ("INTEGER PRIMARY KEY AUTOINCREMENT", "INTEGER", "BLOB"),
        DatabaseKind::Postgres => ("BIGSERIAL PRIMARY KEY", "BIGINT", "BYTEA"),
    };
    let s = |t: &str| t.replace("{id}", id).replace("{int}", int).replace("{blob}", blob);
    vec![
        s("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)"),
        s("CREATE TABLE IF NOT EXISTS domains (
            id {id}, name TEXT NOT NULL UNIQUE, mode TEXT NOT NULL DEFAULT 'local',
            transport TEXT NOT NULL DEFAULT '', catch_all TEXT NOT NULL DEFAULT '',
            dkim_selector TEXT NOT NULL DEFAULT '', dkim_private TEXT NOT NULL DEFAULT '',
            dkim_public TEXT NOT NULL DEFAULT '', active {int} NOT NULL DEFAULT 1,
            created_at {int} NOT NULL)"),
        s("CREATE TABLE IF NOT EXISTS accounts (
            id {id}, email TEXT NOT NULL UNIQUE, domain_id {int} NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
            password_hash TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT 'user', quota_bytes {int} NOT NULL DEFAULT 0,
            used_bytes {int} NOT NULL DEFAULT 0, active {int} NOT NULL DEFAULT 1,
            can_send_external {int} NOT NULL DEFAULT 1, forward_to TEXT NOT NULL DEFAULT '',
            keep_copy {int} NOT NULL DEFAULT 1, created_at {int} NOT NULL, last_login {int})"),
        s("CREATE TABLE IF NOT EXISTS aliases (
            id {id}, source TEXT NOT NULL UNIQUE, destination TEXT NOT NULL,
            active {int} NOT NULL DEFAULT 1, created_at {int} NOT NULL)"),
        s("CREATE TABLE IF NOT EXISTS mailboxes (
            id {id}, account_id {int} NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            name TEXT NOT NULL, uidvalidity {int} NOT NULL, uidnext {int} NOT NULL DEFAULT 1,
            modseq {int} NOT NULL DEFAULT 1, recent_uid {int} NOT NULL DEFAULT 0,
            special_use TEXT NOT NULL DEFAULT '', keywords TEXT NOT NULL DEFAULT '',
            UNIQUE (account_id, name))"),
        s("CREATE TABLE IF NOT EXISTS subscriptions (
            account_id {int} NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            name TEXT NOT NULL, PRIMARY KEY (account_id, name))"),
        s("CREATE TABLE IF NOT EXISTS messages (
            id {id}, mailbox_id {int} NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
            uid {int} NOT NULL, blob TEXT NOT NULL, size {int} NOT NULL,
            internal_date {int} NOT NULL, flags TEXT NOT NULL DEFAULT '', modseq {int} NOT NULL DEFAULT 1,
            envelope TEXT NOT NULL, bodystructure TEXT NOT NULL, body TEXT NOT NULL,
            subject TEXT NOT NULL DEFAULT '', from_addr TEXT NOT NULL DEFAULT '',
            UNIQUE (mailbox_id, uid))"),
        s("CREATE INDEX IF NOT EXISTS messages_blob ON messages (blob)"),
        s("CREATE TABLE IF NOT EXISTS blob_refs (key TEXT PRIMARY KEY, size {int} NOT NULL, refs {int} NOT NULL)"),
        s("CREATE TABLE IF NOT EXISTS blob_data (key TEXT PRIMARY KEY, data {blob} NOT NULL)"),
        s("CREATE TABLE IF NOT EXISTS queue (
            id {id}, sender TEXT NOT NULL, recipients TEXT NOT NULL, blob TEXT NOT NULL,
            size {int} NOT NULL, attempts {int} NOT NULL DEFAULT 0, next_attempt {int} NOT NULL,
            last_error TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'queued',
            route TEXT NOT NULL DEFAULT '', created_at {int} NOT NULL)"),
        s("CREATE INDEX IF NOT EXISTS queue_due ON queue (status, next_attempt)"),
        s("CREATE TABLE IF NOT EXISTS web_sessions (
            token_hash TEXT PRIMARY KEY, account_id {int} NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            created_at {int} NOT NULL, expires_at {int} NOT NULL, ip TEXT NOT NULL DEFAULT '')"),
        s("CREATE TABLE IF NOT EXISTS events (
            id {id}, ts {int} NOT NULL, level TEXT NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL)"),
        s("CREATE INDEX IF NOT EXISTS events_ts ON events (ts)"),
        s("CREATE TABLE IF NOT EXISTS send_log (account_id {int} NOT NULL, ts {int} NOT NULL)"),
        s("CREATE TABLE IF NOT EXISTS expunged (mailbox_id {int} NOT NULL, uid {int} NOT NULL, modseq {int} NOT NULL, PRIMARY KEY (mailbox_id, uid))"),
        s("CREATE TABLE IF NOT EXISTS changes (id {id}, account_id {int} NOT NULL, kind TEXT NOT NULL, obj_id {int} NOT NULL, op TEXT NOT NULL, ts {int} NOT NULL)"),
        s("CREATE INDEX IF NOT EXISTS changes_acc ON changes (account_id, id)"),
        s("CREATE TABLE IF NOT EXISTS api_tokens (
            id {id}, account_id {int} NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL, scopes TEXT NOT NULL,
            created_at {int} NOT NULL, last_used {int}, expires_at {int})"),
        // Picacho no longer issues OAuth tokens (the identity provider does).
        s("DROP TABLE IF EXISTS oauth_tokens"),
        s("DROP TABLE IF EXISTS oauth_clients"),
        s("CREATE TABLE IF NOT EXISTS uploads (
            id {id}, account_id {int} NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, blob TEXT NOT NULL,
            size {int} NOT NULL, ctype TEXT NOT NULL, created_at {int} NOT NULL)"),
        s("CREATE INDEX IF NOT EXISTS send_log_idx ON send_log (account_id, ts)"),
        // Zero-access accounts (src/za.rs): their mail public key only.
        s("CREATE TABLE IF NOT EXISTS za_accounts (
            account_id {int} PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
            version {int} NOT NULL, public_key TEXT NOT NULL, mode TEXT NOT NULL, updated {int} NOT NULL)"),
    ]
}

/// Flags plus one modseq bump, as returned by flag updates.
pub struct FlagUpdate {
    pub uid: i64,
    pub flags: String,
}

impl Db {
    pub async fn connect(cfg: &Config) -> Result<Self> {
        sqlx::any::install_default_drivers();
        let url = cfg.database_url()?;
        let kind = if url.starts_with("postgres") {
            DatabaseKind::Postgres
        } else {
            DatabaseKind::Sqlite
        };
        if kind == DatabaseKind::Sqlite {
            std::fs::create_dir_all(&cfg.storage.data_dir)?;
        }
        let is_sqlite = kind == DatabaseKind::Sqlite;
        let pool = AnyPoolOptions::new()
            .max_connections(cfg.storage.database.max_connections.max(2))
            .after_connect(move |conn, _| {
                Box::pin(async move {
                    if is_sqlite {
                        conn.execute("PRAGMA journal_mode=WAL").await?;
                        conn.execute("PRAGMA synchronous=NORMAL").await?;
                        conn.execute("PRAGMA foreign_keys=ON").await?;
                        conn.execute("PRAGMA busy_timeout=10000").await?;
                    }
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .map_err(|e| anyhow!("database connection failed: {e}"))?;
        let db = Db { pool, kind, write_lock: Arc::new(Mutex::new(())), fts: Default::default() };
        db.migrate().await?;
        crate::dbx::migrate(&db, cfg.storage.full_text_index).await?;
        if is_sqlite {
            let p = cfg.data_path("mail.db");
            crate::util::restrict_permissions(&p);
        }
        Ok(db)
    }

    async fn migrate(&self) -> Result<()> {
        for stmt in schema(&self.kind) {
            sqlx::query(&stmt).execute(&self.pool).await?;
        }
        // Columns added after the first release. ADD COLUMN fails when the
        // column exists (SQLite has no IF NOT EXISTS for it), which is fine.
        let int = if self.kind == DatabaseKind::Sqlite { "INTEGER" } else { "BIGINT" };
        let _ = sqlx::query("ALTER TABLE accounts ADD COLUMN oidc_sub TEXT NOT NULL DEFAULT ''").execute(&self.pool).await;
        for col in [
            "meta TEXT NOT NULL DEFAULT ''".to_string(),
            "msgid TEXT NOT NULL DEFAULT ''".to_string(),
            format!("thread_id {int} NOT NULL DEFAULT 0"),
        ] {
            let _ = sqlx::query(&format!("ALTER TABLE messages ADD COLUMN {col}")).execute(&self.pool).await;
        }
        for idx in [
            "CREATE INDEX IF NOT EXISTS messages_msgid ON messages (msgid)",
            "CREATE INDEX IF NOT EXISTS messages_thread ON messages (thread_id)",
        ] {
            sqlx::query(idx).execute(&self.pool).await?;
        }
        Ok(())
    }

    pub async fn begin(&self) -> Result<WriteTx<'_>> {
        let guard = if self.kind == DatabaseKind::Sqlite {
            Some(self.write_lock.lock().await)
        } else {
            None
        };
        let tx = self.pool.begin().await?;
        Ok(WriteTx { tx, _guard: guard })
    }

    /// Serialize a single statement on SQLite.
    pub async fn wl(&self) -> Option<MutexGuard<'_, ()>> {
        if self.kind == DatabaseKind::Sqlite {
            Some(self.write_lock.lock().await)
        } else {
            None
        }
    }

    // ---------- settings ----------
    pub async fn get_setting(&self, name: &str) -> Result<Option<String>> {
        let r = sqlx::query("SELECT value FROM settings WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(r.map(|r| r.get::<String, _>(0)))
    }

    pub async fn set_setting(&self, name: &str, value: &str) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query(
            "INSERT INTO settings (name, value) VALUES ($1, $2)
             ON CONFLICT (name) DO UPDATE SET value = excluded.value",
        )
        .bind(name)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ---------- domains ----------
    pub async fn list_domains(&self) -> Result<Vec<Domain>> {
        let rows = sqlx::query(&format!("SELECT {DOMAIN_COLS} FROM domains ORDER BY name"))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(domain_from).collect()
    }

    pub async fn get_domain(&self, id: i64) -> Result<Option<Domain>> {
        let r = sqlx::query(&format!("SELECT {DOMAIN_COLS} FROM domains WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(domain_from).transpose()
    }

    pub async fn domain_by_name(&self, name: &str) -> Result<Option<Domain>> {
        let r = sqlx::query(&format!("SELECT {DOMAIN_COLS} FROM domains WHERE name = $1"))
            .bind(name.to_ascii_lowercase())
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(domain_from).transpose()
    }

    pub async fn create_domain(&self, name: &str, mode: &str, transport: &str) -> Result<i64> {
        let _g = self.wl().await;
        let r = sqlx::query(
            "INSERT INTO domains (name, mode, transport, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(name.to_ascii_lowercase())
        .bind(mode)
        .bind(transport)
        .bind(now())
        .fetch_one(&self.pool)
        .await?;
        Ok(r.get::<i64, _>(0))
    }

    pub async fn update_domain(&self, d: &Domain) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query(
            "UPDATE domains SET mode=$1, transport=$2, catch_all=$3, dkim_selector=$4,
             dkim_private=$5, dkim_public=$6, active=$7 WHERE id=$8",
        )
        .bind(&d.mode)
        .bind(&d.transport)
        .bind(&d.catch_all)
        .bind(&d.dkim_selector)
        .bind(&d.dkim_private)
        .bind(&d.dkim_public)
        .bind(d.active as i64)
        .bind(d.id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_domain(&self, id: i64) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("DELETE FROM domains WHERE id = $1").bind(id).execute(&self.pool).await?;
        Ok(())
    }

    // ---------- accounts ----------
    pub async fn count_admins(&self) -> Result<i64> {
        let r = sqlx::query("SELECT COUNT(*) FROM accounts WHERE role = 'admin'")
            .fetch_one(&self.pool)
            .await?;
        Ok(r.get::<i64, _>(0))
    }

    pub async fn list_accounts(&self) -> Result<Vec<Account>> {
        let rows = sqlx::query(&format!("SELECT {ACCOUNT_COLS} FROM accounts ORDER BY email"))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(account_from).collect()
    }

    pub async fn get_account(&self, id: i64) -> Result<Option<Account>> {
        let r = sqlx::query(&format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(account_from).transpose()
    }

    pub async fn account_by_email(&self, email: &str) -> Result<Option<Account>> {
        let r = sqlx::query(&format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE email = $1"))
            .bind(email.to_ascii_lowercase())
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(account_from).transpose()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_account(
        &self,
        email: &str,
        domain_id: i64,
        password_hash: &str,
        display_name: &str,
        role: &str,
        quota_bytes: i64,
    ) -> Result<i64> {
        let id = {
            let _g = self.wl().await;
            let r = sqlx::query(
                "INSERT INTO accounts (email, domain_id, password_hash, display_name, role, quota_bytes, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
            )
            .bind(email.to_ascii_lowercase())
            .bind(domain_id)
            .bind(password_hash)
            .bind(display_name)
            .bind(role)
            .bind(quota_bytes)
            .bind(now())
            .fetch_one(&self.pool)
            .await?;
            r.get::<i64, _>(0)
        };
        for (name, special) in [
            ("INBOX", ""),
            ("Sent", "\\Sent"),
            ("Drafts", "\\Drafts"),
            ("Archive", "\\Archive"),
            ("Junk", "\\Junk"),
            ("Trash", "\\Trash"),
        ] {
            self.create_mailbox(id, name, special).await?;
            self.subscribe(id, name).await?;
        }
        Ok(id)
    }

    pub async fn update_account(&self, a: &Account) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query(
            "UPDATE accounts SET display_name=$1, role=$2, quota_bytes=$3, active=$4,
             can_send_external=$5, forward_to=$6, keep_copy=$7 WHERE id=$8",
        )
        .bind(&a.display_name)
        .bind(&a.role)
        .bind(a.quota_bytes)
        .bind(a.active as i64)
        .bind(a.can_send_external as i64)
        .bind(&a.forward_to)
        .bind(a.keep_copy as i64)
        .bind(a.id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_password(&self, id: i64, hash: &str) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("UPDATE accounts SET password_hash=$1 WHERE id=$2")
            .bind(hash)
            .bind(id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM web_sessions WHERE account_id=$1").bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn touch_login(&self, id: i64) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("UPDATE accounts SET last_login=$1 WHERE id=$2")
            .bind(now())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete the account; returns the blob keys whose references dropped.
    pub async fn delete_account(&self, id: i64) -> Result<Vec<String>> {
        let mut tx = self.begin().await?;
        let rows = sqlx::query(
            "SELECT m.blob FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id WHERE b.account_id = $1",
        )
        .bind(id)
        .fetch_all(&mut *tx.tx)
        .await?;
        let blobs: Vec<String> = rows.iter().map(|r| r.get::<String, _>(0)).collect();
        sqlx::query("DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE account_id = $1)")
            .bind(id)
            .execute(&mut *tx.tx)
            .await?;
        sqlx::query("DELETE FROM mailboxes WHERE account_id = $1").bind(id).execute(&mut *tx.tx).await?;
        sqlx::query("DELETE FROM subscriptions WHERE account_id = $1").bind(id).execute(&mut *tx.tx).await?;
        sqlx::query("DELETE FROM web_sessions WHERE account_id = $1").bind(id).execute(&mut *tx.tx).await?;
        sqlx::query("DELETE FROM accounts WHERE id = $1").bind(id).execute(&mut *tx.tx).await?;
        let dropped = Self::release_blobs(&mut tx, &blobs).await?;
        tx.commit().await?;
        Ok(dropped)
    }

    pub async fn add_usage(&self, account_id: i64, delta: i64) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("UPDATE accounts SET used_bytes = CASE WHEN used_bytes + $1 < 0 THEN 0 ELSE used_bytes + $1 END WHERE id = $2")
            .bind(delta)
            .bind(account_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn record_send(&self, account_id: i64) -> Result<i64> {
        let _g = self.wl().await;
        let t = now();
        sqlx::query("DELETE FROM send_log WHERE ts < $1").bind(t - 3600).execute(&self.pool).await?;
        sqlx::query("INSERT INTO send_log (account_id, ts) VALUES ($1, $2)")
            .bind(account_id)
            .bind(t)
            .execute(&self.pool)
            .await?;
        let r = sqlx::query("SELECT COUNT(*) FROM send_log WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(r.get::<i64, _>(0))
    }

    // ---------- aliases ----------
    pub async fn list_aliases(&self) -> Result<Vec<Alias>> {
        let rows = sqlx::query("SELECT id, source, destination, active, created_at FROM aliases ORDER BY source")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(alias_from).collect()
    }

    pub async fn alias_by_source(&self, source: &str) -> Result<Option<Alias>> {
        let r = sqlx::query("SELECT id, source, destination, active, created_at FROM aliases WHERE source = $1")
            .bind(source.to_ascii_lowercase())
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(alias_from).transpose()
    }

    pub async fn create_alias(&self, source: &str, destination: &str) -> Result<i64> {
        let _g = self.wl().await;
        let r = sqlx::query("INSERT INTO aliases (source, destination, created_at) VALUES ($1, $2, $3) RETURNING id")
            .bind(source.to_ascii_lowercase())
            .bind(destination)
            .bind(now())
            .fetch_one(&self.pool)
            .await?;
        Ok(r.get::<i64, _>(0))
    }

    pub async fn update_alias(&self, id: i64, destination: &str, active: bool) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("UPDATE aliases SET destination=$1, active=$2 WHERE id=$3")
            .bind(destination)
            .bind(active as i64)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_alias(&self, id: i64) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("DELETE FROM aliases WHERE id = $1").bind(id).execute(&self.pool).await?;
        Ok(())
    }

    // ---------- mailboxes ----------
    pub async fn list_mailboxes(&self, account_id: i64) -> Result<Vec<Mailbox>> {
        let rows = sqlx::query(&format!("SELECT {MAILBOX_COLS} FROM mailboxes WHERE account_id = $1 ORDER BY name"))
            .bind(account_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(mailbox_from).collect()
    }

    pub async fn mailbox(&self, account_id: i64, name: &str) -> Result<Option<Mailbox>> {
        let r = sqlx::query(&format!("SELECT {MAILBOX_COLS} FROM mailboxes WHERE account_id = $1 AND name = $2"))
            .bind(account_id)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(mailbox_from).transpose()
    }

    pub async fn mailbox_by_id(&self, id: i64) -> Result<Option<Mailbox>> {
        let r = sqlx::query(&format!("SELECT {MAILBOX_COLS} FROM mailboxes WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(mailbox_from).transpose()
    }

    pub async fn mailbox_by_special(&self, account_id: i64, special: &str) -> Result<Option<Mailbox>> {
        let r = sqlx::query(&format!(
            "SELECT {MAILBOX_COLS} FROM mailboxes WHERE account_id = $1 AND special_use = $2 ORDER BY id LIMIT 1"
        ))
        .bind(account_id)
        .bind(special)
        .fetch_optional(&self.pool)
        .await?;
        r.as_ref().map(mailbox_from).transpose()
    }

    pub async fn mailbox_modseq(&self, id: i64) -> Result<Option<i64>> {
        let r = sqlx::query("SELECT modseq FROM mailboxes WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(r.map(|r| r.get::<i64, _>(0)))
    }

    pub async fn create_mailbox(&self, account_id: i64, name: &str, special: &str) -> Result<i64> {
        let _g = self.wl().await;
        // UIDVALIDITY must never repeat for a name: seconds since 2020 plus a
        // per-process counter keeps it increasing and within 32 bits.
        let validity = crate::util::next_uidvalidity();
        let r = sqlx::query(
            "INSERT INTO mailboxes (account_id, name, uidvalidity, special_use) VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(account_id)
        .bind(name)
        .bind(validity)
        .bind(special)
        .fetch_one(&self.pool)
        .await?;
        let id = r.get::<i64, _>(0);
        Self::log_change_pool(&self.pool, account_id, "Mailbox", id, "c").await?;
        Ok(id)
    }

    /// Delete a mailbox and its messages; returns blob keys with no refs left
    /// and the bytes freed.
    pub async fn delete_mailbox(&self, id: i64) -> Result<(Vec<String>, i64)> {
        let mut tx = self.begin().await?;
        let rows = sqlx::query("SELECT blob, size FROM messages WHERE mailbox_id = $1")
            .bind(id)
            .fetch_all(&mut *tx.tx)
            .await?;
        let blobs: Vec<String> = rows.iter().map(|r| r.get::<String, _>(0)).collect();
        let freed: i64 = rows.iter().map(|r| r.get::<i64, _>(1)).sum();
        let acc = sqlx::query("SELECT account_id FROM mailboxes WHERE id = $1").bind(id).fetch_optional(&mut *tx.tx).await?;
        if let Some(acc) = acc {
            let acc: i64 = acc.get(0);
            let ids = sqlx::query("SELECT id FROM messages WHERE mailbox_id = $1").bind(id).fetch_all(&mut *tx.tx).await?;
            for r in ids {
                Self::log_change(&mut tx, acc, "Email", r.get(0), "d").await?;
            }
            Self::log_change(&mut tx, acc, "Mailbox", id, "d").await?;
        }
        sqlx::query("DELETE FROM messages WHERE mailbox_id = $1").bind(id).execute(&mut *tx.tx).await?;
        sqlx::query("DELETE FROM expunged WHERE mailbox_id = $1").bind(id).execute(&mut *tx.tx).await?;
        sqlx::query("DELETE FROM mailboxes WHERE id = $1").bind(id).execute(&mut *tx.tx).await?;
        let dropped = Self::release_blobs(&mut tx, &blobs).await?;
        tx.commit().await?;
        Ok((dropped, freed))
    }

    /// Rename a mailbox (and its children). Gives renamed mailboxes a new
    /// UIDVALIDITY as RFC 3501 requires for reused names.
    pub async fn rename_mailbox(&self, account_id: i64, from: &str, to: &str, delim: char) -> Result<()> {
        let mut tx = self.begin().await?;
        let prefix = format!("{from}{delim}");
        let rows = sqlx::query("SELECT id, name FROM mailboxes WHERE account_id = $1")
            .bind(account_id)
            .fetch_all(&mut *tx.tx)
            .await?;
        for r in rows {
            let id: i64 = r.get(0);
            let name: String = r.get(1);
            let new = if name == from {
                to.to_string()
            } else if let Some(rest) = name.strip_prefix(&prefix) {
                format!("{to}{delim}{rest}")
            } else {
                continue;
            };
            sqlx::query("UPDATE mailboxes SET name = $1 WHERE id = $2")
                .bind(&new)
                .bind(id)
                .execute(&mut *tx.tx)
                .await?;
            Self::log_change(&mut tx, account_id, "Mailbox", id, "u").await?;
        }
        tx.commit().await
    }

    pub async fn subscriptions(&self, account_id: i64) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT name FROM subscriptions WHERE account_id = $1 ORDER BY name")
            .bind(account_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(|r| r.get::<String, _>(0)).collect())
    }

    pub async fn subscribe(&self, account_id: i64, name: &str) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("INSERT INTO subscriptions (account_id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(account_id)
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn unsubscribe(&self, account_id: i64, name: &str) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("DELETE FROM subscriptions WHERE account_id = $1 AND name = $2")
            .bind(account_id)
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Mark messages above the current recent mark as recent for this
    /// session; returns the previous mark.
    pub async fn claim_recent(&self, mailbox_id: i64) -> Result<i64> {
        let mut tx = self.begin().await?;
        let r = sqlx::query("SELECT recent_uid, uidnext FROM mailboxes WHERE id = $1")
            .bind(mailbox_id)
            .fetch_one(&mut *tx.tx)
            .await?;
        let old: i64 = r.get(0);
        let next: i64 = r.get(1);
        if next - 1 > old {
            sqlx::query("UPDATE mailboxes SET recent_uid = $1 WHERE id = $2")
                .bind(next - 1)
                .bind(mailbox_id)
                .execute(&mut *tx.tx)
                .await?;
        }
        tx.commit().await?;
        Ok(old)
    }

    pub async fn add_keywords(&self, mailbox_id: i64, keywords: &str) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("UPDATE mailboxes SET keywords = $1 WHERE id = $2")
            .bind(keywords)
            .bind(mailbox_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---------- messages ----------
    pub async fn view(&self, mailbox_id: i64) -> Result<Vec<ViewRow>> {
        let rows = sqlx::query("SELECT uid, flags, size, modseq FROM messages WHERE mailbox_id = $1 ORDER BY uid")
            .bind(mailbox_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .iter()
            .map(|r| ViewRow { uid: r.get(0), flags: r.get(1), size: r.get(2), modseq: r.get(3) })
            .collect())
    }

    pub async fn messages_by_uids(&self, mailbox_id: i64, lo: i64, hi: i64) -> Result<Vec<MessageRow>> {
        let rows = sqlx::query(&format!(
            "SELECT {MESSAGE_COLS} FROM messages WHERE mailbox_id = $1 AND uid >= $2 AND uid <= $3 ORDER BY uid"
        ))
        .bind(mailbox_id)
        .bind(lo)
        .bind(hi)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(message_from).collect()
    }

    pub async fn mailbox_counts(&self, mailbox_id: i64) -> Result<(i64, i64, i64)> {
        let r = sqlx::query(
            "SELECT COUNT(*), CAST(COALESCE(SUM(CASE WHEN flags LIKE '%\\Seen%' THEN 0 ELSE 1 END), 0) AS BIGINT),
                    CAST(COALESCE(SUM(size), 0) AS BIGINT)
             FROM messages WHERE mailbox_id = $1",
        )
        .bind(mailbox_id)
        .fetch_one(&self.pool)
        .await?;
        Ok((r.get(0), r.get(1), r.get(2)))
    }

    /// Insert a message, allocating its UID atomically. Returns (uid, modseq, id).
    pub async fn insert_message(&self, mailbox_id: i64, m: &NewMessage<'_>) -> Result<(i64, i64, i64)> {
        let mut tx = self.begin().await?;
        // The blob reference was taken by BlobStore::put_message.
        let r = Self::insert_message_tx(&mut tx, mailbox_id, m).await?;
        tx.commit().await?;
        Ok(r)
    }

    async fn insert_message_tx(tx: &mut WriteTx<'_>, mailbox_id: i64, m: &NewMessage<'_>) -> Result<(i64, i64, i64)> {
        let r = sqlx::query(
            "UPDATE mailboxes SET uidnext = uidnext + 1, modseq = modseq + 1 WHERE id = $1 RETURNING uidnext - 1, modseq, account_id",
        )
        .bind(mailbox_id)
        .fetch_one(&mut *tx.tx)
        .await?;
        let uid: i64 = r.get(0);
        let modseq: i64 = r.get(1);
        let account_id: i64 = r.get(2);
        let mut thread = m.thread_id;
        if thread == 0 && !m.refs.is_empty() {
            // Join the thread of any message this one refers to.
            for chunk in m.refs.chunks(40) {
                let ph: Vec<String> = (0..chunk.len()).map(|i| format!("${}", i + 2)).collect();
                let q = format!(
                    "SELECT m.thread_id FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id
                     WHERE b.account_id = $1 AND m.msgid IN ({}) AND m.thread_id > 0 LIMIT 1",
                    ph.join(",")
                );
                let mut query = sqlx::query(&q).bind(account_id);
                for r in chunk {
                    query = query.bind(r);
                }
                if let Some(row) = query.fetch_optional(&mut *tx.tx).await? {
                    thread = row.get(0);
                    break;
                }
            }
        }
        let r = sqlx::query(
            "INSERT INTO messages (mailbox_id, uid, blob, size, internal_date, flags, modseq, envelope, bodystructure, body, subject, from_addr, meta, msgid, thread_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING id",
        )
        .bind(mailbox_id)
        .bind(uid)
        .bind(m.blob)
        .bind(m.size)
        .bind(m.internal_date)
        .bind(m.flags)
        .bind(modseq)
        .bind(m.envelope)
        .bind(m.bodystructure)
        .bind(m.body)
        .bind(m.subject)
        .bind(m.from_addr)
        .bind(m.meta)
        .bind(m.msgid)
        .bind(thread)
        .fetch_one(&mut *tx.tx)
        .await?;
        let id: i64 = r.get(0);
        let new_thread = thread == 0;
        if new_thread {
            thread = id;
            sqlx::query("UPDATE messages SET thread_id = $1 WHERE id = $1").bind(id).execute(&mut *tx.tx).await?;
        }
        Self::log_change(tx, account_id, "Email", id, "c").await?;
        Self::log_change(tx, account_id, "Mailbox", mailbox_id, "u").await?;
        Self::log_change(tx, account_id, "Thread", thread, if new_thread { "c" } else { "u" }).await?;
        Ok((uid, modseq, id))
    }

    async fn log_change(tx: &mut WriteTx<'_>, account_id: i64, kind: &str, obj: i64, op: &str) -> Result<()> {
        sqlx::query("INSERT INTO changes (account_id, kind, obj_id, op, ts) VALUES ($1, $2, $3, $4, $5)")
            .bind(account_id)
            .bind(kind)
            .bind(obj)
            .bind(op)
            .bind(now())
            .execute(&mut *tx.tx)
            .await?;
        Ok(())
    }

    async fn log_change_pool(pool: &AnyPool, account_id: i64, kind: &str, obj: i64, op: &str) -> Result<()> {
        sqlx::query("INSERT INTO changes (account_id, kind, obj_id, op, ts) VALUES ($1, $2, $3, $4, $5)")
            .bind(account_id)
            .bind(kind)
            .bind(obj)
            .bind(op)
            .bind(now())
            .execute(pool)
            .await?;
        Ok(())
    }

    /// Record an "updated" change for messages by UID (flag changes).
    async fn log_email_updates(tx: &mut WriteTx<'_>, mailbox_id: i64, uids: &[i64]) -> Result<()> {
        for chunk in uids.chunks(400) {
            let list = chunk.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");
            sqlx::query(&format!(
                "INSERT INTO changes (account_id, kind, obj_id, op, ts)
                 SELECT b.account_id, 'Email', m.id, 'u', $2 FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id
                 WHERE m.mailbox_id = $1 AND m.uid IN ({list})"
            ))
            .bind(mailbox_id)
            .bind(now())
            .execute(&mut *tx.tx)
            .await?;
        }
        sqlx::query(
            "INSERT INTO changes (account_id, kind, obj_id, op, ts) SELECT account_id, 'Mailbox', id, 'u', $2 FROM mailboxes WHERE id = $1",
        )
        .bind(mailbox_id)
        .bind(now())
        .execute(&mut *tx.tx)
        .await?;
        Ok(())
    }

    async fn ref_blob_tx(tx: &mut WriteTx<'_>, key: &str, size: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO blob_refs (key, size, refs) VALUES ($1, $2, 1)
             ON CONFLICT (key) DO UPDATE SET refs = blob_refs.refs + 1",
        )
        .bind(key)
        .bind(size)
        .execute(&mut *tx.tx)
        .await?;
        Ok(())
    }

    /// Take a reference on a blob; returns the reference count afterwards.
    pub async fn incr_blob(&self, key: &str, size: i64) -> Result<i64> {
        let _g = self.wl().await;
        let r = sqlx::query(
            "INSERT INTO blob_refs (key, size, refs) VALUES ($1, $2, 1)
             ON CONFLICT (key) DO UPDATE SET refs = blob_refs.refs + 1 RETURNING refs",
        )
        .bind(key)
        .bind(size)
        .fetch_one(&self.pool)
        .await?;
        Ok(r.get::<i64, _>(0))
    }

    /// Drop references; returns keys that reached zero (to delete from storage).
    async fn release_blobs(tx: &mut WriteTx<'_>, keys: &[String]) -> Result<Vec<String>> {
        let mut dropped = vec![];
        for k in keys {
            let r = sqlx::query("UPDATE blob_refs SET refs = refs - 1 WHERE key = $1 RETURNING refs")
                .bind(k)
                .fetch_optional(&mut *tx.tx)
                .await?;
            if let Some(r) = r {
                if r.get::<i64, _>(0) <= 0 {
                    sqlx::query("DELETE FROM blob_refs WHERE key = $1").bind(k).execute(&mut *tx.tx).await?;
                    dropped.push(k.clone());
                }
            }
        }
        Ok(dropped)
    }

    pub async fn release_blob(&self, key: &str) -> Result<bool> {
        let mut tx = self.begin().await?;
        let d = Self::release_blobs(&mut tx, &[key.to_string()]).await?;
        tx.commit().await?;
        Ok(!d.is_empty())
    }

    /// Apply a STORE atomically against the stored flags, so concurrent
    /// sessions never overwrite each other's changes. `mode` is '=', '+'
    /// or '-'. With `unchanged_since`, messages modified after that modseq
    /// are left alone and reported (CONDSTORE).
    pub async fn modify_flags(
        &self,
        mailbox_id: i64,
        uids: &[i64],
        mode: char,
        flags: &[String],
        unchanged_since: Option<i64>,
    ) -> Result<FlagResult> {
        let mut tx = self.begin().await?;
        let mut rows_out = vec![];
        let mut modified = vec![];
        let mut changed = vec![];
        for chunk in uids.chunks(500) {
            let list = chunk.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");
            let rows = sqlx::query(&format!("SELECT uid, flags, modseq FROM messages WHERE mailbox_id = $1 AND uid IN ({list})"))
                .bind(mailbox_id)
                .fetch_all(&mut *tx.tx)
                .await?;
            for r in rows {
                let uid: i64 = r.get(0);
                let old: String = r.get(1);
                let ms: i64 = r.get(2);
                if unchanged_since.is_some_and(|u| ms > u) {
                    modified.push(uid);
                    continue;
                }
                let mut cur: Vec<String> = old.split_whitespace().map(String::from).collect();
                match mode {
                    '=' => cur = flags.to_vec(),
                    '+' => {
                        for f in flags {
                            if !cur.iter().any(|x| x.eq_ignore_ascii_case(f)) {
                                cur.push(f.clone());
                            }
                        }
                    }
                    _ => cur.retain(|x| !flags.iter().any(|f| f.eq_ignore_ascii_case(x))),
                }
                let new = cur.join(" ");
                if crate::imap::seq::norm_flags(&new) != crate::imap::seq::norm_flags(&old) {
                    changed.push((uid, new.clone()));
                }
                rows_out.push((uid, new, ms));
            }
        }
        if !changed.is_empty() {
            let r = sqlx::query("UPDATE mailboxes SET modseq = modseq + 1 WHERE id = $1 RETURNING modseq")
                .bind(mailbox_id)
                .fetch_one(&mut *tx.tx)
                .await?;
            let modseq: i64 = r.get(0);
            for (uid, f) in &changed {
                sqlx::query("UPDATE messages SET flags = $1, modseq = $2 WHERE mailbox_id = $3 AND uid = $4")
                    .bind(f)
                    .bind(modseq)
                    .bind(mailbox_id)
                    .bind(uid)
                    .execute(&mut *tx.tx)
                    .await?;
            }
            for row in rows_out.iter_mut() {
                if changed.iter().any(|c| c.0 == row.0) {
                    row.2 = modseq;
                }
            }
            let uids: Vec<i64> = changed.iter().map(|c| c.0).collect();
            Self::log_email_updates(&mut tx, mailbox_id, &uids).await?;
        }
        tx.commit().await?;
        rows_out.sort_unstable();
        modified.sort_unstable();
        Ok(FlagResult { rows: rows_out, modified })
    }

    /// Replace flags on messages. Returns the new modseq.
    pub async fn set_flags(&self, mailbox_id: i64, updates: &[FlagUpdate]) -> Result<i64> {
        let mut tx = self.begin().await?;
        let r = sqlx::query("UPDATE mailboxes SET modseq = modseq + 1 WHERE id = $1 RETURNING modseq")
            .bind(mailbox_id)
            .fetch_one(&mut *tx.tx)
            .await?;
        let modseq: i64 = r.get(0);
        for u in updates {
            sqlx::query("UPDATE messages SET flags = $1, modseq = $2 WHERE mailbox_id = $3 AND uid = $4")
                .bind(&u.flags)
                .bind(modseq)
                .bind(mailbox_id)
                .bind(u.uid)
                .execute(&mut *tx.tx)
                .await?;
        }
        let uids: Vec<i64> = updates.iter().map(|u| u.uid).collect();
        Self::log_email_updates(&mut tx, mailbox_id, &uids).await?;
        tx.commit().await?;
        Ok(modseq)
    }

    /// Remove messages by UID. Returns (removed uids, blob keys to delete, bytes freed).
    pub async fn expunge(&self, mailbox_id: i64, uids: &[i64]) -> Result<(Vec<i64>, Vec<String>, i64)> {
        if uids.is_empty() {
            return Ok((vec![], vec![], 0));
        }
        let mut tx = self.begin().await?;
        let mut removed = vec![];
        let mut blobs = vec![];
        let mut ids = vec![];
        let mut freed = 0;
        for chunk in uids.chunks(200) {
            let list = chunk.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");
            let rows = sqlx::query(&format!(
                "DELETE FROM messages WHERE mailbox_id = $1 AND uid IN ({list}) RETURNING uid, blob, size, id"
            ))
            .bind(mailbox_id)
            .fetch_all(&mut *tx.tx)
            .await?;
            for r in rows {
                removed.push(r.get::<i64, _>(0));
                blobs.push(r.get::<String, _>(1));
                freed += r.get::<i64, _>(2);
                ids.push(r.get::<i64, _>(3));
            }
        }
        if !removed.is_empty() {
            let r = sqlx::query("UPDATE mailboxes SET modseq = modseq + 1 WHERE id = $1 RETURNING modseq, account_id")
                .bind(mailbox_id)
                .fetch_one(&mut *tx.tx)
                .await?;
            let modseq: i64 = r.get(0);
            let account_id: i64 = r.get(1);
            for uid in &removed {
                sqlx::query(
                    "INSERT INTO expunged (mailbox_id, uid, modseq) VALUES ($1, $2, $3)
                     ON CONFLICT (mailbox_id, uid) DO UPDATE SET modseq = excluded.modseq",
                )
                .bind(mailbox_id)
                .bind(uid)
                .bind(modseq)
                .execute(&mut *tx.tx)
                .await?;
            }
            for id in &ids {
                Self::log_change(&mut tx, account_id, "Email", *id, "d").await?;
            }
            Self::log_change(&mut tx, account_id, "Mailbox", mailbox_id, "u").await?;
        }
        let dropped = Self::release_blobs(&mut tx, &blobs).await?;
        tx.commit().await?;
        removed.sort_unstable();
        Ok((removed, dropped, freed))
    }

    /// Copy messages to another mailbox. Returns (src uid, dst uid) pairs and bytes added.
    pub async fn copy_messages(&self, src: i64, uids: &[i64], dst: i64) -> Result<(Vec<(i64, i64)>, i64)> {
        let mut tx = self.begin().await?;
        let mut pairs = vec![];
        let mut added = 0;
        for &uid in uids {
            let r = sqlx::query(
                "SELECT blob, size, internal_date, flags, envelope, bodystructure, body, subject, from_addr, meta, msgid, thread_id
                 FROM messages WHERE mailbox_id = $1 AND uid = $2",
            )
            .bind(src)
            .bind(uid)
            .fetch_optional(&mut *tx.tx)
            .await?;
            let Some(r) = r else { continue };
            let blob: String = r.get(0);
            let size: i64 = r.get(1);
            let flags: String = r.get(3);
            let flags = crate::imap::flags_without_recent(&flags);
            let envelope: String = r.get(4);
            let bs: String = r.get(5);
            let body: String = r.get(6);
            let subject: String = r.get(7);
            let from_addr: String = r.get(8);
            let meta: String = r.get(9);
            let msgid: String = r.get(10);
            let nm = NewMessage {
                meta: &meta,
                msgid: &msgid,
                refs: &[],
                thread_id: r.get(11),
                blob: &blob,
                size,
                internal_date: r.get(2),
                flags: &flags,
                envelope: &envelope,
                bodystructure: &bs,
                body: &body,
                subject: &subject,
                from_addr: &from_addr,
            };
            let (new_uid, _, _) = Self::insert_message_tx(&mut tx, dst, &nm).await?;
            Self::ref_blob_tx(&mut tx, &blob, size).await?;
            pairs.push((uid, new_uid));
            added += size;
        }
        tx.commit().await?;
        Ok((pairs, added))
    }

    pub async fn recent_messages(&self, account_id: i64, limit: i64) -> Result<Vec<serde_json::Value>> {
        let rows = sqlx::query(
            "SELECT m.uid, m.size, m.internal_date, m.flags, m.subject, m.from_addr, b.name
             FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id
             WHERE b.account_id = $1 ORDER BY m.internal_date DESC LIMIT $2",
        )
        .bind(account_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "uid": r.get::<i64,_>(0), "size": r.get::<i64,_>(1), "date": r.get::<i64,_>(2),
                    "flags": r.get::<String,_>(3), "subject": r.get::<String,_>(4),
                    "from": r.get::<String,_>(5), "mailbox": r.get::<String,_>(6),
                })
            })
            .collect())
    }

    // ---------- queue ----------
    pub async fn enqueue(&self, sender: &str, rcpts: &[String], blob: &str, size: i64, route: &str) -> Result<i64> {
        self.enqueue_ext(sender, rcpts, blob, size, route, "", false, "").await
    }

    /// Queue with DSN parameters, REQUIRETLS, or for pickup by a relay peer
    /// (`peer` non-empty: status 'held' until the peer fetches it).
    #[allow(clippy::too_many_arguments)]
    pub async fn enqueue_ext(&self, sender: &str, rcpts: &[String], blob: &str, size: i64, route: &str, dsn: &str, requiretls: bool, peer: &str) -> Result<i64> {
        let mut tx = self.begin().await?;
        let r = sqlx::query(
            "INSERT INTO queue (sender, recipients, blob, size, next_attempt, route, created_at, dsn, requiretls, peer, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id",
        )
        .bind(sender)
        .bind(serde_json::to_string(rcpts)?)
        .bind(blob)
        .bind(size)
        .bind(now())
        .bind(route)
        .bind(now())
        .bind(dsn)
        .bind(requiretls as i64)
        .bind(peer)
        .bind(if peer.is_empty() { "queued" } else { "held" })
        .fetch_one(&mut *tx.tx)
        .await?;
        // The blob reference was taken by BlobStore::put_message.
        let _ = size;
        tx.commit().await?;
        Ok(r.get::<i64, _>(0))
    }

    pub async fn due_queue(&self, limit: i64) -> Result<Vec<QueueItem>> {
        let rows = sqlx::query(&format!(
            "SELECT {QUEUE_COLS} FROM queue WHERE status IN ('queued','deferred') AND next_attempt <= $1
             ORDER BY next_attempt LIMIT $2"
        ))
        .bind(now())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(queue_from).collect()
    }

    /// Claim an item for delivery so concurrent workers (or nodes) skip it.
    pub async fn claim_queue(&self, id: i64, lease_secs: i64) -> Result<bool> {
        let _g = self.wl().await;
        let t = now();
        let r = sqlx::query(
            "UPDATE queue SET next_attempt = $1 WHERE id = $2 AND next_attempt <= $3 AND status IN ('queued','deferred')",
        )
        .bind(t + lease_secs)
        .bind(id)
        .bind(t)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn list_queue(&self) -> Result<Vec<QueueItem>> {
        let rows = sqlx::query(&format!("SELECT {QUEUE_COLS} FROM queue ORDER BY id DESC LIMIT 500"))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(queue_from).collect()
    }

    pub async fn get_queue(&self, id: i64) -> Result<Option<QueueItem>> {
        let r = sqlx::query(&format!("SELECT {QUEUE_COLS} FROM queue WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(queue_from).transpose()
    }

    pub async fn update_queue(&self, id: i64, rcpts: &[String], attempts: i64, next: i64, err: &str, status: &str) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query(
            "UPDATE queue SET recipients=$1, attempts=$2, next_attempt=$3, last_error=$4, status=$5 WHERE id=$6",
        )
        .bind(serde_json::to_string(rcpts)?)
        .bind(attempts)
        .bind(next)
        .bind(err)
        .bind(status)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_delay_notified(&self, id: i64) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("UPDATE queue SET delay_notified = 1 WHERE id = $1").bind(id).execute(&self.pool).await?;
        Ok(())
    }

    /// Remove a queue item; returns whether its blob lost its last reference.
    pub async fn delete_queue(&self, id: i64) -> Result<Option<String>> {
        let mut tx = self.begin().await?;
        let r = sqlx::query("DELETE FROM queue WHERE id = $1 RETURNING blob")
            .bind(id)
            .fetch_optional(&mut *tx.tx)
            .await?;
        let mut out = None;
        if let Some(r) = r {
            let blob: String = r.get(0);
            if !Self::release_blobs(&mut tx, std::slice::from_ref(&blob)).await?.is_empty() {
                out = Some(blob);
            }
        }
        tx.commit().await?;
        Ok(out)
    }

    pub async fn queue_stats(&self) -> Result<(i64, i64, i64)> {
        let r = sqlx::query(
            "SELECT CAST(COALESCE(SUM(CASE WHEN status='queued' THEN 1 ELSE 0 END),0) AS BIGINT),
                    CAST(COALESCE(SUM(CASE WHEN status='deferred' THEN 1 ELSE 0 END),0) AS BIGINT),
                    CAST(COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END),0) AS BIGINT) FROM queue",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok((r.get(0), r.get(1), r.get(2)))
    }

    // ---------- web sessions ----------
    pub async fn create_session(&self, token_hash: &str, account_id: i64, ttl: i64, ip: &str) -> Result<()> {
        let _g = self.wl().await;
        let t = now();
        sqlx::query("DELETE FROM web_sessions WHERE expires_at < $1").bind(t).execute(&self.pool).await?;
        sqlx::query("INSERT INTO web_sessions (token_hash, account_id, created_at, expires_at, ip) VALUES ($1,$2,$3,$4,$5)")
            .bind(token_hash)
            .bind(account_id)
            .bind(t)
            .bind(t + ttl)
            .bind(ip)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn session_account(&self, token_hash: &str) -> Result<Option<i64>> {
        let r = sqlx::query("SELECT account_id FROM web_sessions WHERE token_hash = $1 AND expires_at > $2")
            .bind(token_hash)
            .bind(now())
            .fetch_optional(&self.pool)
            .await?;
        Ok(r.map(|r| r.get::<i64, _>(0)))
    }

    pub async fn delete_session(&self, token_hash: &str) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("DELETE FROM web_sessions WHERE token_hash = $1").bind(token_hash).execute(&self.pool).await?;
        Ok(())
    }

    // ---------- events ----------
    pub async fn log_event(&self, level: &str, kind: &str, message: &str) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("INSERT INTO events (ts, level, kind, message) VALUES ($1, $2, $3, $4)")
            .bind(now())
            .bind(level)
            .bind(kind)
            .bind(message)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn prune_events(&self, keep_days: i64) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("DELETE FROM events WHERE ts < $1")
            .bind(now() - keep_days * 86400)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_events(&self, limit: i64, kind: Option<&str>) -> Result<Vec<Event>> {
        let rows = match kind {
            Some(k) => {
                sqlx::query("SELECT id, ts, level, kind, message FROM events WHERE kind = $1 ORDER BY id DESC LIMIT $2")
                    .bind(k)
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query("SELECT id, ts, level, kind, message FROM events ORDER BY id DESC LIMIT $1")
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows
            .iter()
            .map(|r| Event { id: r.get(0), ts: r.get(1), level: r.get(2), kind: r.get(3), message: r.get(4) })
            .collect())
    }

    // ---------- blob data (database blob backend) ----------
    pub async fn blob_put(&self, key: &str, data: &[u8]) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("INSERT INTO blob_data (key, data) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING")
            .bind(key)
            .bind(data.to_vec())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn blob_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let r = sqlx::query("SELECT data FROM blob_data WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(r.map(|r| r.get::<Vec<u8>, _>(0)))
    }

    pub async fn blob_delete(&self, key: &str) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("DELETE FROM blob_data WHERE key = $1").bind(key).execute(&self.pool).await?;
        Ok(())
    }

    // ---------- CONDSTORE / QRESYNC ----------
    /// UIDs expunged after `since` (QRESYNC VANISHED).
    pub async fn vanished_since(&self, mailbox_id: i64, since: i64) -> Result<Vec<i64>> {
        let rows = sqlx::query("SELECT uid FROM expunged WHERE mailbox_id = $1 AND modseq > $2 ORDER BY uid")
            .bind(mailbox_id)
            .bind(since)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(|r| r.get::<i64, _>(0)).collect())
    }

    // ---------- message metadata ----------
    pub async fn messages_by_ids(&self, account_id: i64, ids: &[i64]) -> Result<Vec<MessageRow>> {
        let mut out = vec![];
        for chunk in ids.chunks(400) {
            let list = chunk.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");
            let cols = MESSAGE_COLS.split(", ").map(|c| format!("m.{c}")).collect::<Vec<_>>().join(", ");
            let rows = sqlx::query(&format!(
                "SELECT {cols} FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id WHERE b.account_id = $1 AND m.id IN ({list})"
            ))
            .bind(account_id)
            .fetch_all(&self.pool)
            .await?;
            for r in &rows {
                out.push(message_from(r)?);
            }
        }
        Ok(out)
    }

    pub async fn account_messages(&self, account_id: i64) -> Result<Vec<MessageRow>> {
        let cols = MESSAGE_COLS.split(", ").map(|c| format!("m.{c}")).collect::<Vec<_>>().join(", ");
        let rows = sqlx::query(&format!(
            "SELECT {cols} FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id WHERE b.account_id = $1"
        ))
        .bind(account_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(message_from).collect()
    }

    pub async fn messages_missing_meta(&self, limit: i64) -> Result<Vec<(i64, String)>> {
        let rows = sqlx::query("SELECT id, blob FROM messages WHERE meta = '' AND envelope NOT LIKE 'za1:%' LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
    }

    pub async fn set_meta(&self, id: i64, meta: &str, msgid: &str) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("UPDATE messages SET meta = $1, msgid = $2, thread_id = CASE WHEN thread_id = 0 THEN id ELSE thread_id END WHERE id = $3")
            .bind(meta)
            .bind(msgid)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Move a message to another mailbox keeping its id (JMAP). Returns the new UID.
    pub async fn move_message(&self, id: i64, dst: i64) -> Result<Option<i64>> {
        let mut tx = self.begin().await?;
        let r = sqlx::query("SELECT mailbox_id, uid FROM messages WHERE id = $1").bind(id).fetch_optional(&mut *tx.tx).await?;
        let Some(r) = r else { return Ok(None) };
        let src: i64 = r.get(0);
        let old_uid: i64 = r.get(1);
        if src == dst {
            return Ok(Some(old_uid));
        }
        let d = sqlx::query(
            "UPDATE mailboxes SET uidnext = uidnext + 1, modseq = modseq + 1 WHERE id = $1 RETURNING uidnext - 1, modseq, account_id",
        )
        .bind(dst)
        .fetch_one(&mut *tx.tx)
        .await?;
        let (uid, modseq, acc): (i64, i64, i64) = (d.get(0), d.get(1), d.get(2));
        sqlx::query("UPDATE messages SET mailbox_id = $1, uid = $2, modseq = $3 WHERE id = $4")
            .bind(dst)
            .bind(uid)
            .bind(modseq)
            .bind(id)
            .execute(&mut *tx.tx)
            .await?;
        let s = sqlx::query("UPDATE mailboxes SET modseq = modseq + 1 WHERE id = $1 RETURNING modseq")
            .bind(src)
            .fetch_one(&mut *tx.tx)
            .await?;
        let sm: i64 = s.get(0);
        sqlx::query(
            "INSERT INTO expunged (mailbox_id, uid, modseq) VALUES ($1, $2, $3)
             ON CONFLICT (mailbox_id, uid) DO UPDATE SET modseq = excluded.modseq",
        )
        .bind(src)
        .bind(old_uid)
        .bind(sm)
        .execute(&mut *tx.tx)
        .await?;
        Self::log_change(&mut tx, acc, "Email", id, "u").await?;
        Self::log_change(&mut tx, acc, "Mailbox", src, "u").await?;
        Self::log_change(&mut tx, acc, "Mailbox", dst, "u").await?;
        tx.commit().await?;
        Ok(Some(uid))
    }

    pub async fn thread_counts(&self, mailbox_id: i64) -> Result<(i64, i64)> {
        let r = sqlx::query(
            "SELECT COUNT(DISTINCT thread_id),
                    COUNT(DISTINCT CASE WHEN flags LIKE '%\\Seen%' THEN NULL ELSE thread_id END)
             FROM messages WHERE mailbox_id = $1",
        )
        .bind(mailbox_id)
        .fetch_one(&self.pool)
        .await?;
        Ok((r.get(0), r.get(1)))
    }

    // ---------- JMAP change log ----------
    pub async fn jmap_state(&self, account_id: i64) -> Result<i64> {
        let r = sqlx::query("SELECT CAST(COALESCE(MAX(id), 0) AS BIGINT) FROM changes WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(r.get(0))
    }

    /// Changes of `kind` after `since`. Returns None when `since` is older
    /// than the retained log (client must resync).
    pub async fn changes_since(&self, account_id: i64, kind: &str, since: i64, limit: i64) -> Result<Option<(Vec<(i64, String)>, i64, bool)>> {
        let pruned: i64 = self.get_setting("changes_pruned_below").await?.and_then(|v| v.parse().ok()).unwrap_or(0);
        if since < pruned {
            return Ok(None);
        }
        let rows = sqlx::query(
            "SELECT id, obj_id, op FROM changes WHERE account_id = $1 AND kind = $2 AND id > $3 ORDER BY id LIMIT $4",
        )
        .bind(account_id)
        .bind(kind)
        .bind(since)
        .bind(limit + 1)
        .fetch_all(&self.pool)
        .await?;
        let more = rows.len() as i64 > limit;
        let rows = &rows[..rows.len().min(limit as usize)];
        let new_state = if more { rows.last().map(|r| r.get::<i64, _>(0)).unwrap_or(since) } else { self.jmap_state(account_id).await? };
        Ok(Some((rows.iter().map(|r| (r.get::<i64, _>(1), r.get::<String, _>(2))).collect(), new_state, more)))
    }

    pub async fn prune_changes(&self, keep_days: i64) -> Result<()> {
        let _g = self.wl().await;
        let cutoff = now() - keep_days * 86400;
        let r = sqlx::query("SELECT CAST(COALESCE(MAX(id), 0) AS BIGINT) FROM changes WHERE ts < $1")
            .bind(cutoff)
            .fetch_one(&self.pool)
            .await?;
        let below: i64 = r.get(0);
        if below > 0 {
            sqlx::query("DELETE FROM changes WHERE id <= $1").bind(below).execute(&self.pool).await?;
            sqlx::query(
                "INSERT INTO settings (name, value) VALUES ('changes_pruned_below', $1)
                 ON CONFLICT (name) DO UPDATE SET value = excluded.value",
            )
            .bind(below.to_string())
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    // ---------- API tokens ----------
    pub async fn create_token(&self, account_id: i64, name: &str, hash: &str, prefix: &str, scopes: &str, expires_at: Option<i64>) -> Result<i64> {
        let _g = self.wl().await;
        let r = sqlx::query(
            "INSERT INTO api_tokens (account_id, name, token_hash, prefix, scopes, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(account_id)
        .bind(name)
        .bind(hash)
        .bind(prefix)
        .bind(scopes)
        .bind(now())
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(r.get(0))
    }

    fn token_from(r: &AnyRow) -> Result<ApiToken> {
        Ok(ApiToken {
            id: r.try_get("id")?,
            account_id: r.try_get("account_id")?,
            name: r.try_get("name")?,
            prefix: r.try_get("prefix")?,
            scopes: r.try_get("scopes")?,
            created_at: r.try_get("created_at")?,
            last_used: r.try_get("last_used")?,
            expires_at: r.try_get("expires_at")?,
        })
    }

    pub async fn token_by_hash(&self, hash: &str) -> Result<Option<ApiToken>> {
        let r = sqlx::query(
            "SELECT id, account_id, name, prefix, scopes, created_at, last_used, expires_at FROM api_tokens WHERE token_hash = $1",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = r else { return Ok(None) };
        let t = Self::token_from(&r)?;
        if t.expires_at.is_some_and(|e| e < now()) {
            return Ok(None);
        }
        if t.last_used.is_none_or(|l| now() - l > 60) {
            let _g = self.wl().await;
            sqlx::query("UPDATE api_tokens SET last_used = $1 WHERE id = $2").bind(now()).bind(t.id).execute(&self.pool).await?;
        }
        Ok(Some(t))
    }

    pub async fn list_tokens(&self, account_id: Option<i64>) -> Result<Vec<ApiToken>> {
        let base = "SELECT id, account_id, name, prefix, scopes, created_at, last_used, expires_at FROM api_tokens";
        let rows = match account_id {
            Some(a) => sqlx::query(&format!("{base} WHERE account_id = $1 ORDER BY id DESC")).bind(a).fetch_all(&self.pool).await?,
            None => sqlx::query(&format!("{base} ORDER BY id DESC")).fetch_all(&self.pool).await?,
        };
        rows.iter().map(Self::token_from).collect()
    }

    pub async fn delete_token(&self, id: i64, account_id: Option<i64>) -> Result<bool> {
        let _g = self.wl().await;
        let r = match account_id {
            Some(a) => sqlx::query("DELETE FROM api_tokens WHERE id = $1 AND account_id = $2").bind(id).bind(a).execute(&self.pool).await?,
            None => sqlx::query("DELETE FROM api_tokens WHERE id = $1").bind(id).execute(&self.pool).await?,
        };
        Ok(r.rows_affected() > 0)
    }

    // ---------- uploads (JMAP) ----------
    pub async fn add_upload(&self, account_id: i64, blob: &str, size: i64, ctype: &str) -> Result<i64> {
        let _g = self.wl().await;
        let r = sqlx::query("INSERT INTO uploads (account_id, blob, size, ctype, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id")
            .bind(account_id)
            .bind(blob)
            .bind(size)
            .bind(ctype)
            .bind(now())
            .fetch_one(&self.pool)
            .await?;
        Ok(r.get(0))
    }

    pub async fn upload(&self, account_id: i64, id: i64) -> Result<Option<(String, i64, String)>> {
        let r = sqlx::query("SELECT blob, size, ctype FROM uploads WHERE id = $1 AND account_id = $2")
            .bind(id)
            .bind(account_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(r.map(|r| (r.get(0), r.get(1), r.get(2))))
    }

    /// Whether `blob` is readable by the account (one of its messages or uploads).
    pub async fn account_owns_blob(&self, account_id: i64, blob: &str) -> Result<bool> {
        let r = sqlx::query(
            "SELECT 1 FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id WHERE b.account_id = $1 AND m.blob = $2
             UNION SELECT 1 FROM uploads WHERE account_id = $1 AND blob = $2 LIMIT 1",
        )
        .bind(account_id)
        .bind(blob)
        .fetch_optional(&self.pool)
        .await?;
        Ok(r.is_some())
    }

    /// Remove uploads older than `secs`; returns their blob keys.
    pub async fn expire_uploads(&self, secs: i64) -> Result<Vec<String>> {
        let _g = self.wl().await;
        let rows = sqlx::query("DELETE FROM uploads WHERE created_at < $1 RETURNING blob")
            .bind(now() - secs)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(|r| r.get::<String, _>(0)).collect())
    }

    // ---------- OIDC links ----------
    pub async fn account_by_oidc(&self, sub: &str) -> Result<Option<Account>> {
        let r = sqlx::query(&format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE oidc_sub = $1 AND oidc_sub <> ''"))
            .bind(sub)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(account_from).transpose()
    }

    pub async fn set_oidc_sub(&self, id: i64, sub: &str) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("UPDATE accounts SET oidc_sub = $1 WHERE id = $2").bind(sub).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn set_role(&self, id: i64, role: &str) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("UPDATE accounts SET role = $1 WHERE id = $2").bind(role).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn stats(&self) -> Result<serde_json::Value> {
        let one = |q: &'static str| async move {
            let r = sqlx::query(q).fetch_one(&self.pool).await?;
            Ok::<i64, anyhow::Error>(r.get::<i64, _>(0))
        };
        Ok(serde_json::json!({
            "domains": one("SELECT COUNT(*) FROM domains").await?,
            "accounts": one("SELECT COUNT(*) FROM accounts").await?,
            "aliases": one("SELECT COUNT(*) FROM aliases").await?,
            "messages": one("SELECT COUNT(*) FROM messages").await?,
            "mailboxes": one("SELECT COUNT(*) FROM mailboxes").await?,
            "stored_bytes": one("SELECT CAST(COALESCE(SUM(size),0) AS BIGINT) FROM blob_refs").await?,
            "blobs": one("SELECT COUNT(*) FROM blob_refs").await?,
            "logical_bytes": one("SELECT CAST(COALESCE(SUM(used_bytes),0) AS BIGINT) FROM accounts").await?,
        }))
    }
}
