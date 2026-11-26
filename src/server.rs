//! Listener setup and the shared "store a message in a mailbox" path.
use crate::db::{Mailbox, NewMessage};
use crate::net::Stream;
use crate::state::State;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;

#[derive(Debug)]
pub enum StoreError {
    OverQuota,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for StoreError {
    fn from(e: anyhow::Error) -> Self {
        StoreError::Other(e)
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::OverQuota => write!(f, "quota exceeded"),
            StoreError::Other(e) => write!(f, "{e:#}"),
        }
    }
}

/// Store a raw (CRLF-normalized) message in a mailbox. Returns its UID.
pub async fn store_message(
    state: &State,
    account_id: i64,
    mb: &Mailbox,
    raw: &[u8],
    flags: &str,
    internal_date: Option<i64>,
) -> Result<i64, StoreError> {
    let size = raw.len() as i64;
    let account = state.db.get_account(account_id).await?;
    if let Some(a) = &account {
        if a.quota_bytes > 0 && a.used_bytes + size > a.quota_bytes {
            return Err(StoreError::OverQuota);
        }
    }
    // Zero-access accounts (src/za.rs): sealed to the account's own key.
    let za_key = match &account {
        Some(a) => crate::za::mail_key(state, a).await?,
        None => None,
    };
    let summary = if raw.len() > 1 << 20 {
        let owned = raw.to_vec();
        tokio::task::spawn_blocking(move || crate::mime::summarize(&owned)).await.map_err(|e| anyhow::anyhow!(e))?
    } else {
        crate::mime::summarize(raw)
    };
    let sealed = match &za_key {
        Some(k) => Some(crate::za::seal_message(account_id, k, raw, &summary)?),
        None => None,
    };
    let key = match &sealed {
        Some(s) => {
            state.blobs.put_sealed(&s.blob_key, s.blob.clone()).await?;
            s.blob_key.clone()
        }
        None => state.blobs.put_message(raw).await?,
    };
    let message = match &sealed {
        // Only the sealed index and hashed Message-IDs (for threading) are stored.
        Some(s) => NewMessage {
            blob: &key,
            size,
            internal_date: internal_date.unwrap_or_else(crate::util::now),
            flags,
            envelope: &s.row,
            bodystructure: "",
            body: "",
            subject: "",
            from_addr: "",
            meta: "",
            msgid: &s.msgid,
            refs: &s.refs,
            thread_id: 0,
        },
        None => NewMessage {
            blob: &key,
            size,
            internal_date: internal_date.unwrap_or_else(crate::util::now),
            flags,
            envelope: &summary.envelope,
            bodystructure: &summary.bodystructure,
            body: &summary.body,
            subject: &summary.subject,
            from_addr: &summary.from,
            meta: &summary.meta,
            msgid: &summary.msgid,
            refs: &summary.refs,
            thread_id: 0,
        },
    };
    let inserted = state.db.insert_message(mb.id, &message).await;
    let (uid, _, _) = match inserted {
        Ok(v) => v,
        Err(e) => {
            // Give back the reference put_message took.
            if state.db.release_blob(&key).await.unwrap_or(false) {
                let _ = state.blobs.delete(&key).await;
            }
            return Err(e.into());
        }
    };
    state.db.add_usage(account_id, size).await?;
    state.hub.notify(mb.id);
    Ok(uid)
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Proto {
    Imap,
    Imaps,
    Smtp,
    Submission,
    Submissions,
    ManageSieve,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Imap => "IMAP",
            Proto::Imaps => "IMAPS",
            Proto::Smtp => "SMTP",
            Proto::Submission => "Submission",
            Proto::Submissions => "Submissions",
            Proto::ManageSieve => "ManageSieve",
        }
    }
    fn implicit_tls(self) -> bool {
        matches!(self, Proto::Imaps | Proto::Submissions)
    }
}

/// Bind a listener and serve it in the background. Returns an error string
/// when binding fails, so startup can report it without aborting.
pub async fn spawn_listener(state: State, addr: SocketAddr, proto: Proto) -> Result<SocketAddr, String> {
    let listener = TcpListener::bind(addr).await.map_err(|e| format!("{} on {addr}: {e}", proto.name()))?;
    let bound = listener.local_addr().unwrap_or(addr);
    state.listeners.lock().push(serde_json::json!({"protocol": proto.name(), "address": bound.to_string()}));
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                a = listener.accept() => a,
                _ = state.shutdown.cancelled() => break,
            };
            let (tcp, peer) = match accepted {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("accept on {addr}: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let _ = tcp.set_nodelay(true);
            let limits = &state.config.limits;
            let kind = if matches!(proto, Proto::Imap | Proto::Imaps) { "imap" } else { "smtp" };
            let Some(guard) = state.conns.acquire(peer.ip(), limits.max_connections, limits.max_connections_per_ip, kind) else {
                tracing::warn!("connection limit reached; refusing {peer} ({} open)", state.conns.total());
                drop(tcp);
                continue;
            };
            let state = state.clone();
            let tracker = state.tasks.clone();
            tracker.spawn(async move {
                let _guard = guard;
                let stream = if proto.implicit_tls() {
                    match tokio::time::timeout(Duration::from_secs(30), state.tls.acceptor.accept(tcp)).await {
                        Ok(Ok(s)) => Stream::Tls(Box::new(s)),
                        _ => return,
                    }
                } else {
                    Stream::Plain(tcp)
                };
                match proto {
                    Proto::Imap | Proto::Imaps => crate::imap::handle(state, stream, peer).await,
                    Proto::Smtp => crate::smtp::handle(state, stream, peer, crate::smtp::Mode::Mx).await,
                    Proto::Submission | Proto::Submissions => {
                        crate::smtp::handle(state, stream, peer, crate::smtp::Mode::Submission).await
                    }
                    Proto::ManageSieve => crate::sieve::managesieve::handle(state, stream, peer).await,
                }
            });
        }
    });
    Ok(bound)
}
