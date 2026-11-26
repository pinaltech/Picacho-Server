//! Schema for features added after the core mail store: delivery security
//! (MTA-STS cache, TLS and DMARC reporting), content filtering (Bayes,
//! greylisting), Sieve and vacation, IMAP ACL and METADATA, the relay link,
//! the audit log and WebDAV/CalDAV/CardDAV. Queries for each feature live
//! next to the feature (`impl Db` blocks in their modules); this file only
//! creates tables and indexes.
use crate::config::DatabaseKind;
use crate::db::Db;
use anyhow::Result;

fn tables(kind: &DatabaseKind) -> Vec<String> {
    let (id, int, blob) = match kind {
        DatabaseKind::Sqlite => ("INTEGER PRIMARY KEY AUTOINCREMENT", "INTEGER", "BLOB"),
        DatabaseKind::Postgres => ("BIGSERIAL PRIMARY KEY", "BIGINT", "BYTEA"),
    };
    let s = |t: &str| t.replace("{id}", id).replace("{int}", int).replace("{blob}", blob);
    vec![
        // ---- delivery security
        s("CREATE TABLE IF NOT EXISTS mta_sts_cache (domain TEXT PRIMARY KEY, policy_id TEXT NOT NULL, policy TEXT NOT NULL,
            fetched_at {int} NOT NULL, expires_at {int} NOT NULL)"),
        s("CREATE TABLE IF NOT EXISTS tls_results (day TEXT NOT NULL, domain TEXT NOT NULL, policy_type TEXT NOT NULL,
            policy TEXT NOT NULL DEFAULT '', mx TEXT NOT NULL, result TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',
            count {int} NOT NULL DEFAULT 0, PRIMARY KEY (day, domain, policy_type, mx, result))"),
        s("CREATE TABLE IF NOT EXISTS dmarc_records (day TEXT NOT NULL, domain TEXT NOT NULL, source_ip TEXT NOT NULL,
            header_from TEXT NOT NULL, disposition TEXT NOT NULL, dkim TEXT NOT NULL, spf TEXT NOT NULL,
            dkim_domain TEXT NOT NULL DEFAULT '', spf_domain TEXT NOT NULL DEFAULT '', policy TEXT NOT NULL DEFAULT '',
            rua TEXT NOT NULL DEFAULT '', count {int} NOT NULL DEFAULT 0,
            PRIMARY KEY (day, domain, source_ip, header_from, disposition, dkim, spf, dkim_domain, spf_domain))"),
        s("CREATE TABLE IF NOT EXISTS reports_in (id {id}, kind TEXT NOT NULL, org TEXT NOT NULL, report_id TEXT NOT NULL,
            domain TEXT NOT NULL, begin_ts {int} NOT NULL, end_ts {int} NOT NULL, summary TEXT NOT NULL, data TEXT NOT NULL,
            received_at {int} NOT NULL, UNIQUE (kind, org, report_id))"),
        s("CREATE TABLE IF NOT EXISTS reports_sent (kind TEXT NOT NULL, domain TEXT NOT NULL, day TEXT NOT NULL,
            sent_at {int} NOT NULL, PRIMARY KEY (kind, domain, day))"),
        // ---- filtering
        s("CREATE TABLE IF NOT EXISTS bayes_tokens (account_id {int} NOT NULL, token TEXT NOT NULL,
            spam {int} NOT NULL DEFAULT 0, ham {int} NOT NULL DEFAULT 0, updated_at {int} NOT NULL DEFAULT 0,
            PRIMARY KEY (account_id, token))"),
        s("CREATE TABLE IF NOT EXISTS bayes_totals (account_id {int} PRIMARY KEY, spam {int} NOT NULL DEFAULT 0, ham {int} NOT NULL DEFAULT 0)"),
        s("CREATE TABLE IF NOT EXISTS bayes_learned (account_id {int} NOT NULL, msg TEXT NOT NULL, class TEXT NOT NULL,
            PRIMARY KEY (account_id, msg))"),
        s("CREATE TABLE IF NOT EXISTS greylist (triplet TEXT PRIMARY KEY, first_seen {int} NOT NULL, last_seen {int} NOT NULL,
            passed {int} NOT NULL DEFAULT 0)"),
        // ---- sieve, vacation
        s("CREATE TABLE IF NOT EXISTS sieve_scripts (id {id}, account_id {int} NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            name TEXT NOT NULL, content TEXT NOT NULL, active {int} NOT NULL DEFAULT 0,
            created_at {int} NOT NULL, updated_at {int} NOT NULL, UNIQUE (account_id, name))"),
        s("CREATE TABLE IF NOT EXISTS vacation (account_id {int} PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
            enabled {int} NOT NULL DEFAULT 0, subject TEXT, text_body TEXT, html_body TEXT,
            from_date {int}, to_date {int}, days {int} NOT NULL DEFAULT 7)"),
        s("CREATE TABLE IF NOT EXISTS vacation_sent (account_id {int} NOT NULL, handle TEXT NOT NULL, sender TEXT NOT NULL,
            sent_at {int} NOT NULL, PRIMARY KEY (account_id, handle, sender))"),
        // ---- IMAP ACL and METADATA
        s("CREATE TABLE IF NOT EXISTS acl (mailbox_id {int} NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
            identifier TEXT NOT NULL, rights TEXT NOT NULL, PRIMARY KEY (mailbox_id, identifier))"),
        s("CREATE INDEX IF NOT EXISTS acl_ident ON acl (identifier)"),
        s("CREATE TABLE IF NOT EXISTS metadata (owner_id {int} NOT NULL, mailbox_id {int} NOT NULL, name TEXT NOT NULL,
            value {blob} NOT NULL, PRIMARY KEY (owner_id, mailbox_id, name))"),
        // ---- relay link
        s("CREATE TABLE IF NOT EXISTS relay_peers (id {id}, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE,
            prefix TEXT NOT NULL, domains TEXT NOT NULL DEFAULT '', active {int} NOT NULL DEFAULT 1,
            created_at {int} NOT NULL, last_seen {int})"),
        // ---- audit log
        s("CREATE TABLE IF NOT EXISTS audit (id {id}, ts {int} NOT NULL, actor TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '')"),
        s("CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts)"),
        // ---- WebDAV / CalDAV / CardDAV
        s("CREATE TABLE IF NOT EXISTS dav_principals (id {id}, username TEXT NOT NULL UNIQUE,
            account_id {int} UNIQUE REFERENCES accounts(id) ON DELETE CASCADE,
            password_hash TEXT NOT NULL DEFAULT '', display_name TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '',
            quota_bytes {int} NOT NULL DEFAULT 0, used_bytes {int} NOT NULL DEFAULT 0, active {int} NOT NULL DEFAULT 1,
            created_at {int} NOT NULL)"),
        s("CREATE TABLE IF NOT EXISTS dav_nodes (id {id}, principal_id {int} NOT NULL REFERENCES dav_principals(id) ON DELETE CASCADE,
            path TEXT NOT NULL, parent TEXT NOT NULL, collection {int} NOT NULL DEFAULT 0, kind TEXT NOT NULL DEFAULT '',
            blob TEXT NOT NULL DEFAULT '', size {int} NOT NULL DEFAULT 0, etag TEXT NOT NULL DEFAULT '',
            ctype TEXT NOT NULL DEFAULT '', props TEXT NOT NULL DEFAULT '{}', uid TEXT NOT NULL DEFAULT '',
            comp TEXT NOT NULL DEFAULT '', dtstart {int}, dtend {int}, created_at {int} NOT NULL, updated_at {int} NOT NULL,
            UNIQUE (principal_id, path))"),
        s("CREATE INDEX IF NOT EXISTS dav_nodes_parent ON dav_nodes (principal_id, parent)"),
        s("CREATE INDEX IF NOT EXISTS dav_nodes_uid ON dav_nodes (principal_id, parent, uid)"),
        s("CREATE TABLE IF NOT EXISTS dav_changes (id {id}, collection_id {int} NOT NULL, name TEXT NOT NULL,
            deleted {int} NOT NULL DEFAULT 0, ts {int} NOT NULL)"),
        s("CREATE INDEX IF NOT EXISTS dav_changes_coll ON dav_changes (collection_id, id)"),
        s("CREATE TABLE IF NOT EXISTS dav_locks (token TEXT PRIMARY KEY, principal_id {int} NOT NULL, path TEXT NOT NULL,
            depth TEXT NOT NULL, exclusive {int} NOT NULL, owner TEXT NOT NULL DEFAULT '', expires_at {int} NOT NULL)"),
        s("CREATE INDEX IF NOT EXISTS dav_locks_path ON dav_locks (principal_id, path)"),
        // ---- orphaned-object sweep bookmark
        s("CREATE TABLE IF NOT EXISTS gc_seen (key TEXT PRIMARY KEY, first_seen {int} NOT NULL)"),
    ]
}

/// Create the extra tables, add new columns to old ones, and set up the
/// full-text index. Safe to run on every start.
pub async fn migrate(db: &Db, full_text: bool) -> Result<()> {
    for stmt in tables(&db.kind) {
        sqlx::query(&stmt).execute(&db.pool).await?;
    }
    let int = if db.kind == DatabaseKind::Sqlite { "INTEGER" } else { "BIGINT" };
    // Queue: DSN parameters, REQUIRETLS, delay notices.
    for col in [
        "dsn TEXT NOT NULL DEFAULT ''".to_string(),
        "requiretls INTEGER NOT NULL DEFAULT 0".replace("INTEGER", int),
        format!("delay_notified {int} NOT NULL DEFAULT 0"),
        "peer TEXT NOT NULL DEFAULT ''".to_string(),
    ] {
        let _ = sqlx::query(&format!("ALTER TABLE queue ADD COLUMN {col}")).execute(&db.pool).await;
    }
    sqlx::query("CREATE INDEX IF NOT EXISTS queue_peer ON queue (peer, status)").execute(&db.pool).await?;
    // Accounts: spam preferences (JSON), DAV link mode.
    let _ = sqlx::query("ALTER TABLE accounts ADD COLUMN prefs TEXT NOT NULL DEFAULT '{}'").execute(&db.pool).await;
    // Mailboxes: per-folder retention override (days, 0 = server default).
    let _ = sqlx::query(&format!("ALTER TABLE mailboxes ADD COLUMN retention_days {int} NOT NULL DEFAULT 0")).execute(&db.pool).await;
    // Uploads: when the blob was created (sweep).
    let _ = sqlx::query(&format!("ALTER TABLE blob_refs ADD COLUMN created_at {int} NOT NULL DEFAULT 0")).execute(&db.pool).await;
    if full_text {
        if let Err(e) = full_text_index(db).await {
            tracing::warn!("full-text index unavailable, searches will scan: {e:#}");
        }
    }
    Ok(())
}

async fn full_text_index(db: &Db) -> Result<()> {
    match db.kind {
        DatabaseKind::Sqlite => {
            // An earlier build indexed the wrong column; drop it.
            for stmt in [
                "DROP TRIGGER IF EXISTS messages_fts_ai",
                "DROP TRIGGER IF EXISTS messages_fts_ad",
                "DROP TRIGGER IF EXISTS messages_fts_au",
                "DROP TABLE IF EXISTS messages_fts",
                // Trigram tokens answer substring queries (IMAP semantics).
                "CREATE VIRTUAL TABLE IF NOT EXISTS message_fts USING fts5(text, tokenize='trigram')",
                "CREATE TRIGGER IF NOT EXISTS message_fts_ad AFTER DELETE ON messages BEGIN DELETE FROM message_fts WHERE rowid = old.id; END",
            ] {
                sqlx::query(stmt).execute(&db.pool).await?;
            }
        }
        DatabaseKind::Postgres => {
            let _ = sqlx::query("CREATE EXTENSION IF NOT EXISTS pg_trgm").execute(&db.pool).await;
            sqlx::query("DROP INDEX IF EXISTS messages_body_trgm").execute(&db.pool).await?;
            sqlx::query("CREATE TABLE IF NOT EXISTS message_fts (id BIGINT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE, text TEXT NOT NULL)").execute(&db.pool).await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS message_fts_trgm ON message_fts USING gin (text gin_trgm_ops)").execute(&db.pool).await?;
        }
    }
    db.fts.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

pub fn fts_id_col(db: &Db) -> &'static str {
    if db.kind == DatabaseKind::Sqlite {
        "rowid"
    } else {
        "id"
    }
}

/// Index messages that aren't indexed yet (new, copied or from before the
/// index existed). Runs in the background; searches treat unindexed
/// messages as candidates, so results are never missing anything.
pub fn spawn_indexer(state: crate::state::State) {
    if !state.db.fts.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    tokio::spawn(async move {
        loop {
            let col = fts_id_col(&state.db);
            let rows = sqlx::query(&format!("SELECT id, blob FROM messages WHERE id NOT IN (SELECT {col} FROM message_fts) AND blob NOT LIKE 'z/%' ORDER BY id DESC LIMIT 200"))
                .fetch_all(&state.db.pool)
                .await
                .unwrap_or_default();
            if rows.is_empty() {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => continue,
                    _ = state.shutdown.cancelled() => return,
                }
            }
            for r in rows {
                use sqlx::Row;
                let id: i64 = r.get(0);
                let blob: String = r.get(1);
                let text = match state.blobs.get(&blob).await {
                    Ok(raw) => tokio::task::spawn_blocking(move || {
                        let c = crate::imap::search::Content::load(raw);
                        let mut t = String::new();
                        for (n, v) in &c.headers {
                            t.push_str(n);
                            t.push_str(": ");
                            t.push_str(&v.to_lowercase());
                            t.push('\n');
                        }
                        t.push('\n');
                        t.push_str(&c.body);
                        t
                    })
                    .await
                    .unwrap_or_default(),
                    Err(_) => String::new(),
                };
                let _g = state.db.wl().await;
                let q = if state.db.kind == DatabaseKind::Sqlite {
                    "INSERT OR REPLACE INTO message_fts (rowid, text) VALUES ($1, $2)"
                } else {
                    "INSERT INTO message_fts (id, text) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET text = excluded.text"
                };
                let _ = sqlx::query(q).bind(id).bind(text).execute(&state.db.pool).await;
                if state.shutdown.is_cancelled() {
                    return;
                }
            }
        }
    });
}

/// Terms that must all appear (top-level AND of BODY / HEADER keys).
fn fts_terms(k: &crate::imap::search::Key, out: &mut Vec<String>) {
    use crate::imap::search::Key;
    match k {
        Key::Body(t) | Key::Header(_, t) => {
            let s = String::from_utf8_lossy(t).to_lowercase();
            if s.chars().count() >= 3 {
                out.push(s);
            }
        }
        Key::And(v) => v.iter().for_each(|x| fts_terms(x, out)),
        _ => {}
    }
}

/// UIDs in a mailbox that might match `key`, or None when the index can't
/// narrow it down (no usable terms, index off).
pub async fn fts_candidates(db: &Db, mailbox_id: i64, key: &crate::imap::search::Key) -> Option<std::collections::HashSet<i64>> {
    use sqlx::Row;
    if !db.fts.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    let mut terms = vec![];
    fts_terms(key, &mut terms);
    let term = terms.into_iter().max_by_key(|t| t.len())?;
    let rows = match db.kind {
        DatabaseKind::Sqlite => {
            let phrase = format!("\"{}\"", term.replace('"', "\"\""));
            sqlx::query(
                "SELECT uid FROM messages WHERE mailbox_id = $1 AND (id IN (SELECT rowid FROM message_fts WHERE message_fts MATCH $2)
                 OR id NOT IN (SELECT rowid FROM message_fts))",
            )
            .bind(mailbox_id)
            .bind(phrase)
            .fetch_all(&db.pool)
            .await
        }
        DatabaseKind::Postgres => {
            let like = format!("%{}%", term.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
            sqlx::query(
                "SELECT m.uid FROM messages m LEFT JOIN message_fts f ON f.id = m.id WHERE m.mailbox_id = $1 AND (f.id IS NULL OR f.text ILIKE $2)",
            )
            .bind(mailbox_id)
            .bind(like)
            .fetch_all(&db.pool)
            .await
        }
    };
    match rows {
        Ok(r) => Some(r.iter().map(|x| x.get::<i64, _>(0)).collect()),
        Err(e) => {
            tracing::debug!("fts query: {e}");
            None
        }
    }
}
