//! IMAP4rev1 server (RFC 3501) with LITERAL+, SASL-IR, IDLE, NAMESPACE,
//! UIDPLUS, MOVE, UNSELECT, CHILDREN, SPECIAL-USE, CREATE-SPECIAL-USE, ID,
//! ENABLE, CONDSTORE, QRESYNC, ESEARCH, ESORT, SORT, SORT=DISPLAY,
//! THREAD=ORDEREDSUBJECT, THREAD=REFERENCES, BINARY, MULTIAPPEND, CATENATE,
//! LIST-EXTENDED, LIST-STATUS, QUOTA, WITHIN and STATUS=SIZE.
pub mod acl;
pub mod fetch;
pub mod proto;
pub mod search;
pub mod seq;
pub mod sort;

use crate::db::{Account, FlagUpdate, Mailbox};
use crate::net::Stream;
use crate::state::State;
use base64::Engine;
use fetch::Att;
use proto::{Arg, Conn, Parser, ReadError};
use seq::{canonical_flag, has_flag, norm_flags, SeqSet, SYSTEM_FLAGS};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::sync::broadcast;

pub const DELIM: char = '/';
const MAX_LITERAL: usize = 64 * 1024;

pub fn flags_without_recent(f: &str) -> String {
    f.split_whitespace().filter(|x| !x.eq_ignore_ascii_case("\\Recent")).collect::<Vec<_>>().join(" ")
}

pub fn normalize_mailbox(name: &str) -> String {
    if name.eq_ignore_ascii_case("INBOX") {
        return "INBOX".into();
    }
    if name.len() > 6 && name[..6].eq_ignore_ascii_case("INBOX/") {
        return format!("INBOX/{}", &name[6..]);
    }
    name.to_string()
}

fn valid_mailbox_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with(DELIM)
        && !name.contains("//")
        && name.split(DELIM).count() <= 32
        && name.chars().all(|c| !c.is_control() && c != '*' && c != '%' && c.is_ascii())
}

/// LIST wildcard matching: `*` matches anything, `%` anything but the delimiter.
pub fn list_match(pattern: &[u8], name: &[u8]) -> bool {
    fn go(p: &[u8], n: &[u8], budget: &mut u32) -> bool {
        *budget = budget.saturating_sub(1);
        if *budget == 0 {
            return false;
        }
        match p.first() {
            None => n.is_empty(),
            Some(b'*') => (0..=n.len()).any(|i| go(&p[1..], &n[i..], budget)),
            Some(b'%') => {
                let mut i = 0;
                loop {
                    if go(&p[1..], &n[i..], budget) {
                        return true;
                    }
                    if i >= n.len() || n[i] == DELIM as u8 {
                        return false;
                    }
                    i += 1;
                }
            }
            Some(&c) => n.first() == Some(&c) && go(&p[1..], &n[1..], budget),
        }
    }
    let mut budget = 100_000;
    go(pattern, name, &mut budget)
}

/// Compress numbers into ranges, keeping their order (ESORT ALL).
fn compress_ordered(nums: &[i64]) -> String {
    let mut out: Vec<String> = vec![];
    let mut i = 0;
    while i < nums.len() {
        let start = nums[i];
        let mut end = start;
        while i + 1 < nums.len() && nums[i + 1] == end + 1 {
            i += 1;
            end = nums[i];
        }
        out.push(if start == end { start.to_string() } else { format!("{start}:{end}") });
        i += 1;
    }
    out.join(",")
}

/// Percent-decoding for IMAP URLs.
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

struct Entry {
    uid: i64,
    flags: String,
    expunged: bool,
    modseq: i64,
}

struct Selected {
    mb: Mailbox,
    read_only: bool,
    view: Vec<Entry>,
    modseq: i64,
    rx: broadcast::Receiver<()>,
    recent: HashSet<i64>,
    keywords: Vec<String>,
    /// ACL rights on this mailbox (all of them for one's own).
    rights: String,
}

enum Resp {
    Ok(String),
    No(String),
    Bad(String),
}

struct Session {
    state: State,
    conn: Conn,
    peer: IpAddr,
    account: Option<Account>,
    sel: Option<Selected>,
    logout: bool,
    counted: Option<i64>,
    pending_tls: bool,
    pending_compress: bool,
    compressed: bool,
    condstore: bool,
    qresync: bool,
    /// Read-only for `imap:read` tokens.
    access: crate::auth::Access,
    /// Tag of the command being executed (for ESEARCH).
    tag: String,
    /// Keeps a zero-access account's keys open while connected (src/za.rs).
    za: Option<crate::za::SessionGuard>,
}

pub async fn handle(state: State, stream: Stream, peer: SocketAddr) {
    let mut s = Session {
        state,
        conn: Conn::new(stream),
        peer: peer.ip(),
        account: None,
        sel: None,
        logout: false,
        counted: None,
        pending_tls: false,
        pending_compress: false,
        compressed: false,
        condstore: false,
        qresync: false,
        access: crate::auth::Access::Write,
        tag: String::new(),
        za: None,
    };
    if s.state.limiter.is_banned(s.peer) && !crate::util::ip_in_list(s.peer, &s.state.settings().security.allowlist) {
        s.conn.push("* BYE Too many failed logins. Try again later.\r\n");
        let _ = s.conn.flush().await;
        return;
    }
    let caps = s.capabilities();
    s.conn.push(&format!("* OK [CAPABILITY {caps}] Picacho Server ready.\r\n"));
    if let Err(e) = s.run().await {
        tracing::debug!("imap session {}: {e}", s.peer);
    }
    let _ = s.conn.flush().await;
    if let Some(id) = s.counted {
        if let Some(mut c) = s.state.imap_sessions.get_mut(&id) {
            *c = c.saturating_sub(1);
        }
    }
}

impl Session {
    fn tls(&mut self) -> bool {
        self.conn.stream().is_tls()
    }

    fn plaintext_ok(&mut self) -> bool {
        let sec = self.state.settings().security.clone();
        self.tls()
            || !sec.require_tls_for_auth
            || (sec.allow_plaintext_localhost && crate::util::is_loopback(self.peer))
    }

    fn capabilities(&mut self) -> String {
        let mut c = String::from(
            "IMAP4rev1 SASL-IR LITERAL+ ID ENABLE IDLE NAMESPACE UNSELECT CHILDREN UIDPLUS MOVE SPECIAL-USE CREATE-SPECIAL-USE \
             CONDSTORE QRESYNC ESEARCH ESORT SORT SORT=DISPLAY THREAD=ORDEREDSUBJECT THREAD=REFERENCES BINARY MULTIAPPEND \
             CATENATE LIST-EXTENDED LIST-STATUS QUOTA QUOTA=RES-STORAGE WITHIN STATUS=SIZE ACL RIGHTS=texk METADATA",
        );
        if !self.compressed {
            c.push_str(" COMPRESS=DEFLATE");
        }
        if self.account.is_none() {
            if !self.tls() {
                c.push_str(" STARTTLS");
            }
            if self.plaintext_ok() {
                c.push_str(" AUTH=PLAIN AUTH=LOGIN AUTH=XOAUTH2 AUTH=OAUTHBEARER");
            } else {
                c.push_str(" LOGINDISABLED");
            }
        }
        c
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        let limits = self.state.config.limits.clone();
        loop {
            self.conn.flush().await?;
            if self.logout {
                return Ok(());
            }
            let timeout = if self.account.is_some() { limits.idle_timeout_secs } else { limits.auth_timeout_secs };
            let big = self.state.settings().limits.max_message_bytes as usize;
            let shutdown = self.state.shutdown.clone();
            let read = tokio::select! {
                r = tokio::time::timeout(
                    Duration::from_secs(timeout),
                    self.conn.read_command(limits.imap_max_line, MAX_LITERAL, big),
                ) => r,
                _ = shutdown.cancelled() => {
                    self.conn.push("* BYE [UNAVAILABLE] Server shutting down, please reconnect shortly.\r\n");
                    return Ok(());
                }
            };
            let cmd = match read {
                Err(_) => {
                    self.conn.push("* BYE Disconnected for inactivity.\r\n");
                    return Ok(());
                }
                Ok(Err(ReadError::Eof)) => return Ok(()),
                Ok(Err(ReadError::Io(e))) => return Err(e.into()),
                Ok(Err(ReadError::LineTooLong)) => {
                    self.conn.push("* BAD Command line too long.\r\n");
                    continue;
                }
                Ok(Err(ReadError::LiteralTooBig(tag))) => {
                    if tag.is_empty() {
                        self.conn.push("* BYE Literal too large.\r\n");
                        return Ok(());
                    }
                    self.conn.push(&format!("{tag} NO [TOOBIG] Message too large.\r\n"));
                    continue;
                }
                Ok(Err(ReadError::Timeout)) => return Ok(()),
                Ok(Ok(c)) => c,
            };
            let Some((tag, name, off)) = proto::split_command(&cmd) else {
                self.conn.push("* BAD Error in IMAP command received by server.\r\n");
                continue;
            };
            let mut parser = Parser::new(&cmd[off..]);
            let started = std::time::Instant::now();
            let peer = self.peer;
            let resp = {
                let fut = self.dispatch(&tag, &name, &mut parser);
                tokio::pin!(fut);
                match tokio::time::timeout(Duration::from_secs(10), &mut fut).await {
                    Ok(r) => r,
                    Err(_) => {
                        tracing::warn!("imap {name} from {peer} still running after 10s");
                        fut.await
                    }
                }
            };
            if started.elapsed() > Duration::from_secs(2) {
                tracing::warn!("imap {name} took {:?}", started.elapsed());
            }
            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("imap {name} failed: {e:#}");
                    Resp::No("[SERVERBUG] Internal error occurred. Refer to server log for more information.".into())
                }
            };
            match resp {
                Resp::Ok(t) => self.conn.push(&format!("{tag} OK {t}\r\n")),
                Resp::No(t) => self.conn.push(&format!("{tag} NO {t}\r\n")),
                Resp::Bad(t) => self.conn.push(&format!("{tag} BAD {t}\r\n")),
            }
            if self.pending_tls {
                self.pending_tls = false;
                self.upgrade_tls().await?;
            }
            if self.pending_compress {
                self.pending_compress = false;
                self.conn.flush().await?;
                let old = std::mem::replace(&mut self.conn, Conn::new(Stream::Duplex(tokio::io::duplex(1).0)));
                self.conn = Conn::new(old.reader.into_inner().compress());
                self.compressed = true;
            }
        }
    }

    async fn dispatch(&mut self, tag: &str, name: &str, p: &mut Parser<'_>) -> anyhow::Result<Resp> {
        // Commands parsed specially (they read further lines).
        match name {
            "AUTHENTICATE" => return self.authenticate(p).await,
            "IDLE" => {
                if self.account.is_none() {
                    return Ok(Resp::Bad("Not authenticated.".into()));
                }
                return self.idle().await;
            }
            "STARTTLS" => return self.starttls().await,
            _ => {}
        }
        let args = match p.args() {
            Ok(a) => a,
            Err(e) => return Ok(Resp::Bad(format!("Error in IMAP command {name}: {}", e.0))),
        };
        self.tag = tag.to_string();
        if self.access == crate::auth::Access::Read {
            let sub = args.first().and_then(|a| a.as_atom()).map(|a| a.to_ascii_uppercase()).unwrap_or_default();
            let writes = matches!(name, "APPEND" | "CREATE" | "DELETE" | "RENAME" | "SUBSCRIBE" | "UNSUBSCRIBE" | "STORE" | "EXPUNGE" | "COPY" | "MOVE")
                || (name == "UID" && matches!(sub.as_str(), "STORE" | "EXPUNGE" | "COPY" | "MOVE"));
            if writes {
                return Ok(Resp::No("[NOPERM] This sign-in has read-only access.".into()));
            }
        }
        let authed = self.account.is_some();
        let selected = self.sel.is_some();
        let r = match name {
            "CAPABILITY" => {
                let c = self.capabilities();
                self.conn.push(&format!("* CAPABILITY {c}\r\n"));
                Resp::Ok("Capability completed.".into())
            }
            "NOOP" => Resp::Ok("NOOP completed.".into()),
            "LOGOUT" => {
                self.conn.push("* BYE Logging out\r\n");
                self.logout = true;
                return Ok(Resp::Ok("Logout completed.".into()));
            }
            "ID" => {
                self.conn.push("* ID (\"name\" \"Picacho Server\")\r\n");
                Resp::Ok("ID completed.".into())
            }
            "LOGIN" if !authed => self.login(&args).await?,
            "LOGIN" => Resp::Bad("Already logged in.".into()),
            _ if !authed => Resp::Bad("Please log in first.".into()),
            "ENABLE" => {
                let mut en = vec![];
                for a in &args {
                    match a.as_atom().map(|x| x.to_ascii_uppercase()).as_deref() {
                        Some("CONDSTORE") => {
                            self.enable_condstore();
                            en.push("CONDSTORE");
                        }
                        Some("QRESYNC") => {
                            self.enable_condstore();
                            self.qresync = true;
                            en.push("QRESYNC");
                        }
                        _ => {}
                    }
                }
                self.conn.push(&format!("* ENABLED {}\r\n", en.join(" ")).replace(" \r", "\r"));
                Resp::Ok("Enabled.".into())
            }
            "GETQUOTAROOT" | "GETQUOTA" | "SETQUOTA" => self.quota(name, &args).await?,
            "NAMESPACE" => {
                self.conn.push("* NAMESPACE ((\"\" \"/\")) ((\"Shared/\" \"/\")) NIL\r\n");
                Resp::Ok("Namespace completed.".into())
            }
            "SETACL" | "DELETEACL" | "GETACL" | "LISTRIGHTS" | "MYRIGHTS" => self.acl_cmd(name, &args).await?,
            "GETMETADATA" => self.getmetadata(&args).await?,
            "SETMETADATA" => self.setmetadata(&args).await?,
            "COMPRESS" => {
                if self.compressed {
                    Resp::No("[COMPRESSIONACTIVE] Already compressing.".into())
                } else if !args.first().and_then(|a| a.as_atom()).is_some_and(|a| a.eq_ignore_ascii_case("DEFLATE")) {
                    Resp::Bad("Unknown compression algorithm.".into())
                } else if self.conn.buffered() > 0 {
                    Resp::Bad("Unexpected data after COMPRESS.".into())
                } else {
                    self.pending_compress = true;
                    Resp::Ok("DEFLATE active.".into())
                }
            }
            "SELECT" | "EXAMINE" => {
                let ro = name == "EXAMINE" || self.access == crate::auth::Access::Read;
                self.select(&args, ro).await?
            }
            "CREATE" => self.create(&args).await?,
            "DELETE" => self.delete(&args).await?,
            "RENAME" => self.rename(&args).await?,
            "SUBSCRIBE" | "UNSUBSCRIBE" => self.subscribe(&args, name == "SUBSCRIBE").await?,
            "LIST" => self.list(&args, false).await?,
            "LSUB" => self.list(&args, true).await?,
            "STATUS" => self.status(&args).await?,
            "APPEND" => self.append(&args).await?,
            "CHECK" | "CLOSE" | "UNSELECT" | "EXPUNGE" | "SEARCH" | "FETCH" | "STORE" | "COPY" | "MOVE" | "UID" | "SORT"
            | "THREAD"
                if !selected =>
            {
                Resp::Bad("No mailbox selected.".into())
            }
            "CHECK" => Resp::Ok("Check completed.".into()),
            "CLOSE" => {
                let s = self.sel.take().unwrap();
                if !s.read_only {
                    let del: Vec<i64> =
                        s.view.iter().filter(|e| !e.expunged && has_flag(&e.flags, "\\Deleted")).map(|e| e.uid).collect();
                    self.expunge_uids(s.mb.id, s.mb.account_id, &del).await?;
                }
                return Ok(Resp::Ok("Close completed.".into()));
            }
            "UNSELECT" => {
                self.sel = None;
                return Ok(Resp::Ok("Unselect completed.".into()));
            }
            "EXPUNGE" => self.expunge(None).await?,
            "SEARCH" => self.search(&args, false).await?,
            "SORT" => self.sort(&args, false).await?,
            "THREAD" => self.thread(&args, false).await?,
            "FETCH" => self.fetch(&args, false).await?,
            "STORE" => self.store(&args, false).await?,
            "COPY" => self.copy(&args, false, false).await?,
            "MOVE" => self.copy(&args, false, true).await?,
            "UID" => {
                let sub = args.first().and_then(|a| a.as_atom()).map(|a| a.to_ascii_uppercase()).unwrap_or_default();
                let rest = args.get(1..).unwrap_or(&[]);
                match sub.as_str() {
                    "FETCH" => self.fetch(rest, true).await?,
                    "SEARCH" => self.search(rest, true).await?,
                    "SORT" => self.sort(rest, true).await?,
                    "THREAD" => self.thread(rest, true).await?,
                    "STORE" => self.store(rest, true).await?,
                    "COPY" => self.copy(rest, true, false).await?,
                    "MOVE" => self.copy(rest, true, true).await?,
                    "EXPUNGE" => match rest.first().and_then(|a| a.as_atom()).and_then(SeqSet::parse) {
                        Some(set) => self.expunge(Some(set)).await?,
                        None => Resp::Bad("Invalid UID set.".into()),
                    },
                    _ => Resp::Bad("Unknown UID command.".into()),
                }
            }
            _ => Resp::Bad(format!("Unknown command {name}.")),
        };
        // Report changes. Expunges may not be sent during FETCH, STORE or
        // SEARCH (sequence numbers would shift under the client).
        if self.sel.is_some() {
            let allow_expunge = !matches!(name, "FETCH" | "STORE" | "SEARCH" | "SORT" | "THREAD");
            self.sync(allow_expunge).await?;
        }
        Ok(r)
    }

    // ---------------------------------------------------------------- auth

    async fn finish_login(&mut self, account: Account) -> anyhow::Result<Resp> {
        let max = self.state.settings().limits.max_imap_sessions_per_user;
        {
            let mut c = self.state.imap_sessions.entry(account.id).or_insert(0);
            if *c >= max {
                return Ok(Resp::No("[LIMIT] Too many open sessions for this account.".into()));
            }
            *c += 1;
        }
        self.counted = Some(account.id);
        self.za = crate::za::session(account.id);
        let _ = self.state.db.touch_login(account.id).await;
        self.account = Some(account);
        let caps = self.capabilities();
        Ok(Resp::Ok(format!("[CAPABILITY {caps}] Logged in")))
    }

    async fn check_login(&mut self, user: &str, pass: &str) -> anyhow::Result<Resp> {
        if !self.plaintext_ok() {
            return Ok(Resp::No("[PRIVACYREQUIRED] Plaintext authentication disallowed on non-secure connections.".into()));
        }
        match crate::auth::login_service(&self.state, user, pass, self.peer, crate::auth::Service::Imap).await {
            Ok((a, access)) => {
                self.access = access;
                self.finish_login(a).await
            }
            Err(crate::auth::AuthError::PasswordDisabled) => {
                Ok(Resp::No("[AUTHENTICATIONFAILED] Account passwords are turned off; use an app password or OAuth.".into()))
            }
            Err(crate::auth::AuthError::Banned) => {
                self.conn.push("* BYE Too many failed logins.\r\n");
                self.logout = true;
                Ok(Resp::No("[UNAVAILABLE] Try again later.".into()))
            }
            Err(crate::auth::AuthError::Disabled) => Ok(Resp::No("[AUTHORIZATIONFAILED] Account disabled.".into())),
            Err(crate::auth::AuthError::ZeroAccess) => Ok(Resp::No("[AUTHORIZATIONFAILED] Pinal Mail is zero-access: use an app password from accounts.pinal.tech/account#privacy (Open mode), or the Picacho app.".into())),
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(300)).await;
                Ok(Resp::No("[AUTHENTICATIONFAILED] Authentication failed.".into()))
            }
        }
    }

    async fn login(&mut self, args: &[Arg]) -> anyhow::Result<Resp> {
        if args.len() != 2 {
            return Ok(Resp::Bad("LOGIN expects user and password.".into()));
        }
        let (Some(u), Some(p)) = (args[0].string(), args[1].string()) else {
            return Ok(Resp::Bad("Invalid credentials syntax.".into()));
        };
        self.check_login(&u, &p).await
    }

    async fn authenticate(&mut self, p: &mut Parser<'_>) -> anyhow::Result<Resp> {
        if self.account.is_some() {
            return Ok(Resp::Bad("Already logged in.".into()));
        }
        let args = match p.args() {
            Ok(a) => a,
            Err(_) => return Ok(Resp::Bad("Invalid AUTHENTICATE arguments.".into())),
        };
        let mech = args.first().and_then(|a| a.as_atom()).map(|m| m.to_ascii_uppercase()).unwrap_or_default();
        let initial = args.get(1).and_then(|a| a.string());
        if !self.plaintext_ok() {
            return Ok(Resp::No("[PRIVACYREQUIRED] Plaintext authentication disallowed on non-secure connections.".into()));
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        match mech.as_str() {
            "PLAIN" => {
                let data = match initial {
                    Some(i) if i == "=" => String::new(),
                    Some(i) => i,
                    None => match self.continuation("").await? {
                        Some(l) => l,
                        None => return Ok(Resp::Bad("Authentication aborted.".into())),
                    },
                };
                let Ok(raw) = b64.decode(data.trim()) else {
                    return Ok(Resp::Bad("Invalid base64.".into()));
                };
                let parts: Vec<&[u8]> = raw.split(|c| *c == 0).collect();
                if parts.len() != 3 {
                    return Ok(Resp::Bad("Invalid PLAIN response.".into()));
                }
                let (authz, user, pass) = (
                    String::from_utf8_lossy(parts[0]).to_string(),
                    String::from_utf8_lossy(parts[1]).to_string(),
                    String::from_utf8_lossy(parts[2]).to_string(),
                );
                if !authz.is_empty() && !authz.eq_ignore_ascii_case(&user) {
                    return Ok(Resp::No("[AUTHORIZATIONFAILED] Authorization identity not permitted.".into()));
                }
                self.check_login(&user, &pass).await
            }
            "LOGIN" => {
                let user = match initial {
                    Some(i) => i,
                    None => match self.continuation("VXNlcm5hbWU6").await? {
                        Some(l) => l,
                        None => return Ok(Resp::Bad("Authentication aborted.".into())),
                    },
                };
                let Some(pass) = self.continuation("UGFzc3dvcmQ6").await? else {
                    return Ok(Resp::Bad("Authentication aborted.".into()));
                };
                let (Ok(u), Ok(p)) = (b64.decode(user.trim()), b64.decode(pass.trim())) else {
                    return Ok(Resp::Bad("Invalid base64.".into()));
                };
                self.check_login(&String::from_utf8_lossy(&u), &String::from_utf8_lossy(&p)).await
            }
            "XOAUTH2" | "OAUTHBEARER" => {
                let data = match initial {
                    Some(i) => i,
                    None => match self.continuation("").await? {
                        Some(l) => l,
                        None => return Ok(Resp::Bad("Authentication aborted.".into())),
                    },
                };
                let Ok(raw) = b64.decode(data.trim()) else {
                    return Ok(Resp::Bad("Invalid base64.".into()));
                };
                let Some((user, token)) = crate::auth::parse_oauth_sasl(&mech, &raw) else {
                    return Ok(Resp::Bad("Invalid OAuth response.".into()));
                };
                let r = self.check_login(&user, &token).await?;
                if matches!(r, Resp::No(_)) {
                    // RFC 7628: send the error as a challenge; the client answers with an empty line.
                    let err = base64::engine::general_purpose::STANDARD.encode(br#"{"status":"invalid_token","scope":"imap"}"#);
                    let _ = self.continuation(&err).await?;
                }
                Ok(r)
            }
            _ => Ok(Resp::No("Unsupported authentication mechanism.".into())),
        }
    }

    async fn continuation(&mut self, prompt: &str) -> anyhow::Result<Option<String>> {
        self.conn.push(&format!("+ {prompt}\r\n"));
        self.conn.flush().await?;
        let line = match self.conn.read_line(16 * 1024).await {
            Ok(l) => l,
            Err(ReadError::Io(e)) => return Err(e.into()),
            Err(_) => return Ok(None),
        };
        let s = String::from_utf8_lossy(&line).to_string();
        if s.trim() == "*" {
            return Ok(None);
        }
        Ok(Some(s))
    }

    async fn starttls(&mut self) -> anyhow::Result<Resp> {
        if self.tls() {
            return Ok(Resp::Bad("TLS is already active.".into()));
        }
        if self.account.is_some() {
            return Ok(Resp::Bad("STARTTLS not allowed after login.".into()));
        }
        if self.conn.buffered() > 0 {
            // Pipelined plaintext after STARTTLS would be an injection vector.
            self.logout = true;
            return Ok(Resp::Bad("Unexpected data after STARTTLS.".into()));
        }
        // The handshake starts after the tagged OK is written (see `run`).
        self.pending_tls = true;
        Ok(Resp::Ok("Begin TLS negotiation now.".into()))
    }

    async fn upgrade_tls(&mut self) -> anyhow::Result<()> {
        self.conn.flush().await?;
        let old = std::mem::replace(&mut self.conn, Conn::new(Stream::Duplex(tokio::io::duplex(1).0)));
        let stream = old.reader.into_inner();
        let tls = tokio::time::timeout(Duration::from_secs(30), stream.upgrade(&self.state.tls.acceptor)).await??;
        self.conn = Conn::new(tls);
        Ok(())
    }

    // ------------------------------------------------------------- mailbox
    // ------------------------------------------------------------- mailbox

    fn account_id(&self) -> i64 {
        self.account.as_ref().map(|a| a.id).unwrap_or(0)
    }

    fn mailbox_arg(arg: Option<&Arg>) -> Option<String> {
        let raw = arg?.string()?;
        Some(normalize_mailbox(raw.trim_end_matches(DELIM)))
    }

    fn enable_condstore(&mut self) {
        if !self.condstore {
            self.condstore = true;
            if let Some(sel) = &self.sel {
                self.conn.push(&format!("* OK [HIGHESTMODSEQ {}] Highest\r\n", sel.modseq));
            }
        }
    }

    async fn select(&mut self, args: &[Arg], read_only: bool) -> anyhow::Result<Resp> {
        let had = self.sel.take().is_some();
        if had && self.qresync {
            self.conn.push("* OK [CLOSED] Previous mailbox closed.\r\n");
        }
        let Some(name) = Self::mailbox_arg(args.first()) else {
            return Ok(Resp::Bad("Invalid mailbox name.".into()));
        };
        let mut qr: Option<(i64, i64, Option<SeqSet>)> = None;
        match args.get(1) {
            None => {}
            Some(Arg::List(params)) => {
                let mut i = 0;
                while i < params.len() {
                    match params[i].as_atom().map(|a| a.to_ascii_uppercase()).as_deref() {
                        Some("CONDSTORE") => self.condstore = true,
                        Some("QRESYNC") => {
                            if !self.qresync {
                                return Ok(Resp::Bad("QRESYNC isn't enabled.".into()));
                            }
                            let Some(Arg::List(q)) = params.get(i + 1) else {
                                return Ok(Resp::Bad("Invalid QRESYNC parameters.".into()));
                            };
                            i += 1;
                            let num = |a: Option<&Arg>| a.and_then(|x| x.as_atom()).and_then(|x| x.parse::<i64>().ok());
                            let (Some(v), Some(m)) = (num(q.first()), num(q.get(1))) else {
                                return Ok(Resp::Bad("Invalid QRESYNC parameters.".into()));
                            };
                            let known = q.get(2).and_then(|a| a.as_atom()).and_then(SeqSet::parse);
                            qr = Some((v, m, known));
                        }
                        _ => return Ok(Resp::Bad("Unknown SELECT parameter.".into())),
                    }
                    i += 1;
                }
            }
            Some(_) => return Ok(Resp::Bad("Invalid SELECT parameters.".into())),
        }
        let Some((mb, rights)) = self.resolve_mb(&name).await? else {
            return Ok(Resp::No("[NONEXISTENT] Mailbox doesn't exist.".into()));
        };
        if !rights.contains('r') {
            return Ok(Resp::No("[NOPERM] You may not read this mailbox.".into()));
        }
        let read_only = read_only || !rights.chars().any(|c| "wsite".contains(c));
        let shown_name = mb.name.clone();
        let rx = self.state.hub.subscribe(mb.id);
        let modseq = self.state.db.mailbox_modseq(mb.id).await?.unwrap_or(0);
        let rows = self.state.db.view(mb.id).await?;
        let mark = if read_only { mb.recent_uid } else { self.state.db.claim_recent(mb.id).await? };
        let recent: HashSet<i64> = rows.iter().filter(|r| r.uid > mark).map(|r| r.uid).collect();
        let mut mb = self.state.db.mailbox_by_id(mb.id).await?.unwrap_or(mb);
        mb.name = shown_name;
        let keywords = Self::merge_keywords(mb.keywords.split_whitespace().map(String::from).collect(), &rows);
        let view: Vec<Entry> =
            rows.into_iter().map(|r| Entry { uid: r.uid, flags: r.flags, expunged: false, modseq: r.modseq }).collect();
        let first_unseen = view.iter().position(|e| !has_flag(&e.flags, "\\Seen"));
        let flags = Self::flag_list(&keywords);
        self.conn.push(&format!("* FLAGS ({flags})\r\n"));
        if read_only {
            self.conn.push("* OK [PERMANENTFLAGS ()] Read-only mailbox.\r\n");
        } else {
            self.conn.push(&format!("* OK [PERMANENTFLAGS ({flags} \\*)] Flags permitted.\r\n"));
        }
        self.conn.push(&format!("* {} EXISTS\r\n* {} RECENT\r\n", view.len(), recent.len()));
        if let Some(i) = first_unseen {
            self.conn.push(&format!("* OK [UNSEEN {}] First unseen.\r\n", i + 1));
        }
        self.conn.push(&format!("* OK [UIDVALIDITY {}] UIDs valid\r\n", mb.uidvalidity));
        self.conn.push(&format!("* OK [UIDNEXT {}] Predicted next UID\r\n", mb.uidnext));
        self.conn.push(&format!("* OK [HIGHESTMODSEQ {modseq}] Highest\r\n"));
        let (validity, uidnext) = (mb.uidvalidity, mb.uidnext);
        let mb_id = mb.id;
        self.sel = Some(Selected { mb, read_only, view, modseq, rx, recent, keywords, rights });
        if let Some((v, m, known)) = qr {
            if v == validity {
                let mut vanished = self.state.db.vanished_since(mb_id, m).await?;
                if let Some(k) = &known {
                    vanished.retain(|u| k.contains(*u, uidnext - 1));
                }
                if !vanished.is_empty() {
                    self.conn.push(&format!("* VANISHED (EARLIER) {}\r\n", seq::compress(&vanished)));
                }
                let sel = self.sel.as_ref().unwrap();
                let mut lines = vec![];
                for (i, e) in sel.view.iter().enumerate() {
                    if e.modseq > m {
                        let f = Self::fmt_flags(&e.flags, sel.recent.contains(&e.uid));
                        lines.push(format!("* {} FETCH (UID {} FLAGS ({f}) MODSEQ ({}))\r\n", i + 1, e.uid, e.modseq));
                    }
                }
                for l in lines {
                    self.conn.push(&l);
                }
            }
        }
        Ok(Resp::Ok(if read_only {
            "[READ-ONLY] Examine completed.".into()
        } else {
            "[READ-WRITE] Select completed.".into()
        }))
    }

    /// Mailbox keywords plus any keyword present on a message, so FLAGS is
    /// always announced before a FETCH that uses a new keyword.
    fn merge_keywords(mut kws: Vec<String>, rows: &[crate::db::ViewRow]) -> Vec<String> {
        for r in rows {
            for f in r.flags.split_whitespace() {
                if !f.starts_with('\\') && !kws.iter().any(|k| k.eq_ignore_ascii_case(f)) {
                    kws.push(f.to_string());
                }
            }
        }
        kws
    }

    fn flag_list(keywords: &[String]) -> String {
        let mut v: Vec<String> = SYSTEM_FLAGS.iter().map(|s| s.to_string()).collect();
        v.extend(keywords.iter().cloned());
        v.join(" ")
    }

    async fn create(&mut self, args: &[Arg]) -> anyhow::Result<Resp> {
        if Self::mailbox_arg(args.first()).is_some_and(|n| n == acl::SHARED || n.starts_with("Shared/")) {
            return Ok(Resp::No("[NOPERM] You can't create folders in the shared namespace.".into()));
        }
        let Some(name) = Self::mailbox_arg(args.first()) else {
            return Ok(Resp::Bad("Invalid mailbox name.".into()));
        };
        if !valid_mailbox_name(&name) {
            return Ok(Resp::No("Invalid mailbox name.".into()));
        }
        let mut special = String::new();
        if let Some(Arg::List(opts)) = args.get(1) {
            if opts.first().and_then(|a| a.as_atom()).is_some_and(|a| a.eq_ignore_ascii_case("USE")) {
                if let Some(Arg::List(uses)) = opts.get(1) {
                    const ALLOWED: [&str; 7] = ["\\All", "\\Archive", "\\Drafts", "\\Flagged", "\\Junk", "\\Sent", "\\Trash"];
                    for u in uses {
                        let u = u.as_atom().unwrap_or("");
                        match ALLOWED.iter().find(|a| a.eq_ignore_ascii_case(u)) {
                            Some(a) if special.is_empty() => special = a.to_string(),
                            Some(_) => return Ok(Resp::No("[USEATTR] Only one special use per mailbox.".into())),
                            None => return Ok(Resp::No("[USEATTR] Unsupported special use.".into())),
                        }
                    }
                }
            } else {
                return Ok(Resp::Bad("Unknown CREATE parameter.".into()));
            }
        }
        let acc = self.account_id();
        if self.state.db.mailbox(acc, &name).await?.is_some() {
            return Ok(Resp::No("[ALREADYEXISTS] Mailbox already exists.".into()));
        }
        let parts: Vec<&str> = name.split(DELIM).collect();
        for i in 1..parts.len() {
            let parent = parts[..i].join(&DELIM.to_string());
            if self.state.db.mailbox(acc, &parent).await?.is_none() {
                self.state.db.create_mailbox(acc, &parent, "").await?;
            }
        }
        self.state.db.create_mailbox(acc, &name, &special).await?;
        Ok(Resp::Ok("Create completed.".into()))
    }

    async fn delete(&mut self, args: &[Arg]) -> anyhow::Result<Resp> {
        let Some(name) = Self::mailbox_arg(args.first()) else {
            return Ok(Resp::Bad("Invalid mailbox name.".into()));
        };
        if name == "INBOX" {
            return Ok(Resp::No("INBOX can't be deleted.".into()));
        }
        let acc = self.account_id();
        let Some(mb) = self.state.db.mailbox(acc, &name).await? else {
            return Ok(Resp::No("[NONEXISTENT] Mailbox doesn't exist.".into()));
        };
        let prefix = format!("{name}{DELIM}");
        if self.state.db.list_mailboxes(acc).await?.iter().any(|m| m.name.starts_with(&prefix)) {
            return Ok(Resp::No("[INUSE] Mailbox has children, delete them first.".into()));
        }
        if self.sel.as_ref().is_some_and(|s| s.mb.id == mb.id) {
            self.sel = None;
        }
        let (blobs, freed) = self.state.db.delete_mailbox(mb.id).await?;
        self.state.db.add_usage(acc, -freed).await?;
        self.state.hub.notify(mb.id);
        self.state.blobs.delete_all(&blobs).await;
        Ok(Resp::Ok("Delete completed.".into()))
    }

    async fn rename(&mut self, args: &[Arg]) -> anyhow::Result<Resp> {
        let (Some(from), Some(to)) = (Self::mailbox_arg(args.first()), Self::mailbox_arg(args.get(1))) else {
            return Ok(Resp::Bad("Invalid mailbox name.".into()));
        };
        if !valid_mailbox_name(&to) {
            return Ok(Resp::No("Invalid mailbox name.".into()));
        }
        let acc = self.account_id();
        let Some(src) = self.state.db.mailbox(acc, &from).await? else {
            return Ok(Resp::No("[NONEXISTENT] Mailbox doesn't exist.".into()));
        };
        if self.state.db.mailbox(acc, &to).await?.is_some() {
            return Ok(Resp::No("[ALREADYEXISTS] Target mailbox already exists.".into()));
        }
        if to.starts_with(&format!("{from}{DELIM}")) {
            return Ok(Resp::No("Can't move a mailbox under itself.".into()));
        }
        let parts: Vec<&str> = to.split(DELIM).collect();
        for i in 1..parts.len() {
            let parent = parts[..i].join(&DELIM.to_string());
            if self.state.db.mailbox(acc, &parent).await?.is_none() {
                self.state.db.create_mailbox(acc, &parent, "").await?;
            }
        }
        if from == "INBOX" {
            // Moving INBOX moves its messages and leaves INBOX empty.
            let dst = self.state.db.create_mailbox(acc, &to, "").await?;
            let uids: Vec<i64> = self.state.db.view(src.id).await?.iter().map(|r| r.uid).collect();
            self.state.db.copy_messages(src.id, &uids, dst).await?;
            let (_, blobs, _) = self.state.db.expunge(src.id, &uids).await?;
            self.state.blobs.delete_all(&blobs).await;
            self.state.hub.notify(src.id);
        } else {
            self.state.db.rename_mailbox(acc, &from, &to, DELIM).await?;
            self.state.hub.notify(src.id);
        }
        Ok(Resp::Ok("Rename completed.".into()))
    }

    async fn subscribe(&mut self, args: &[Arg], sub: bool) -> anyhow::Result<Resp> {
        let Some(name) = Self::mailbox_arg(args.first()) else {
            return Ok(Resp::Bad("Invalid mailbox name.".into()));
        };
        let acc = self.account_id();
        if sub {
            if !valid_mailbox_name(&name) {
                return Ok(Resp::No("Invalid mailbox name.".into()));
            }
            self.state.db.subscribe(acc, &name).await?;
            Ok(Resp::Ok("Subscribe completed.".into()))
        } else {
            self.state.db.unsubscribe(acc, &name).await?;
            Ok(Resp::Ok("Unsubscribe completed.".into()))
        }
    }

    async fn list(&mut self, args: &[Arg], lsub: bool) -> anyhow::Result<Resp> {
        let mut i = 0;
        let (mut sel_subscribed, mut recursive, mut sel_special, mut any_sel) = (lsub, false, false, false);
        if !lsub {
            if let Some(Arg::List(opts)) = args.first() {
                i = 1;
                for o in opts {
                    match o.as_atom().map(|a| a.to_ascii_uppercase()).as_deref() {
                        Some("SUBSCRIBED") => {
                            sel_subscribed = true;
                            any_sel = true;
                        }
                        Some("SPECIAL-USE") => {
                            sel_special = true;
                            any_sel = true;
                        }
                        Some("REMOTE") => {}
                        Some("RECURSIVEMATCH") => recursive = true,
                        _ => return Ok(Resp::Bad("Unknown LIST selection option.".into())),
                    }
                }
                if recursive && !any_sel {
                    return Ok(Resp::Bad("RECURSIVEMATCH needs another selection option.".into()));
                }
            }
        }
        let (Some(reference), Some(pat_arg)) = (args.get(i).and_then(|a| a.string()), args.get(i + 1)) else {
            return Ok(Resp::Bad("LIST expects reference and pattern.".into()));
        };
        let patterns: Vec<String> = match pat_arg {
            Arg::List(l) => l.iter().filter_map(|a| a.string()).collect(),
            a => a.string().into_iter().collect(),
        };
        i += 2;
        let (mut ret_subscribed, mut ret_children, mut ret_status) = (false, false, None::<Vec<String>>);
        if let Some(a) = args.get(i) {
            if lsub || !a.as_atom().is_some_and(|x| x.eq_ignore_ascii_case("RETURN")) {
                return Ok(Resp::Bad("Unexpected LIST arguments.".into()));
            }
            let Some(Arg::List(opts)) = args.get(i + 1) else {
                return Ok(Resp::Bad("RETURN needs a list.".into()));
            };
            let mut j = 0;
            while j < opts.len() {
                match opts[j].as_atom().map(|x| x.to_ascii_uppercase()).as_deref() {
                    Some("SUBSCRIBED") => ret_subscribed = true,
                    Some("CHILDREN") => ret_children = true,
                    Some("SPECIAL-USE") => {}
                    Some("STATUS") => {
                        let Some(Arg::List(items)) = opts.get(j + 1) else {
                            return Ok(Resp::Bad("STATUS needs items.".into()));
                        };
                        ret_status = Some(items.iter().filter_map(|x| x.as_atom().map(|s| s.to_ascii_uppercase())).collect());
                        j += 1;
                    }
                    _ => return Ok(Resp::Bad("Unknown LIST return option.".into())),
                }
                j += 1;
            }
            if args.len() > i + 2 {
                return Ok(Resp::Bad("Unexpected LIST arguments.".into()));
            }
        }
        let cmd = if lsub { "LSUB" } else { "LIST" };
        if !lsub && !any_sel && patterns.len() == 1 && patterns[0].is_empty() {
            self.conn.push("* LIST (\\Noselect) \"/\" \"\"\r\n");
            return Ok(Resp::Ok("List completed.".into()));
        }
        let full: Vec<String> = patterns
            .iter()
            .filter(|p| !p.is_empty())
            .map(|pattern| {
                let f = if pattern.starts_with(DELIM) || reference.is_empty() {
                    pattern.clone()
                } else if reference.ends_with(DELIM) {
                    format!("{reference}{pattern}")
                } else {
                    format!("{reference}{DELIM}{pattern}")
                };
                normalize_mailbox(&f)
            })
            .collect();
        let matches = |n: &str| -> bool {
            full.iter().any(|f| {
                if n == "INBOX" || n.starts_with("INBOX/") {
                    let up = f.to_ascii_uppercase();
                    let np = if up.starts_with("INBOX") { format!("INBOX{}", &f[5..]) } else { f.clone() };
                    list_match(np.as_bytes(), n.as_bytes())
                } else {
                    list_match(f.as_bytes(), n.as_bytes())
                }
            })
        };
        let acc = self.account_id();
        let mut mailboxes = self.state.db.list_mailboxes(acc).await?;
        let me = self.account.as_ref().map(|a| a.email.clone()).unwrap_or_default();
        for (owner, mut mb, _) in self.state.db.shared_with(&me, acc).await? {
            mb.name = format!("{}/{owner}/{}", acl::SHARED, mb.name);
            mailboxes.push(mb);
        }
        let names: HashSet<&str> = mailboxes.iter().map(|m| m.name.as_str()).collect();
        let subs: HashSet<String> = self.state.db.subscriptions(acc).await?.into_iter().collect();
        let parents_of = |n: &str| -> Vec<String> {
            let parts: Vec<&str> = n.split(DELIM).collect();
            (1..parts.len()).map(|k| parts[..k].join("/")).collect()
        };
        let mut candidates: Vec<String> = vec![];
        if sel_subscribed {
            for s in &subs {
                candidates.push(s.clone());
                if recursive || lsub {
                    candidates.extend(parents_of(s));
                }
            }
        } else {
            for n in &names {
                candidates.push(n.to_string());
                candidates.extend(parents_of(n));
            }
        }
        candidates.sort();
        candidates.dedup();
        candidates.sort_by(|a, b| (a != "INBOX").cmp(&(b != "INBOX")).then(a.cmp(b)));
        let has_children = |n: &str| {
            let p = format!("{n}{DELIM}");
            names.iter().any(|x| x.starts_with(&p))
        };
        let mut lines = vec![];
        for n in candidates {
            if !matches(&n) {
                continue;
            }
            let exists = names.contains(n.as_str());
            let subscribed = subs.contains(&n);
            let prefix = format!("{n}{DELIM}");
            let childinfo = recursive && sel_subscribed && subs.iter().any(|s| s.starts_with(&prefix) && !matches(s));
            if lsub {
                if !subscribed {
                    // LSUB lists unsubscribed parents of subscribed names only for '%'.
                    if !(full.iter().any(|f| f.ends_with('%')) && subs.iter().any(|s| s.starts_with(&prefix))) {
                        continue;
                    }
                }
            } else if sel_subscribed && !subscribed && !childinfo {
                continue;
            }
            let mb = mailboxes.iter().find(|m| m.name == n);
            if sel_special && mb.is_none_or(|m| m.special_use.is_empty()) {
                continue;
            }
            if !exists && !lsub && !sel_subscribed && !full.iter().any(|f| f.ends_with('%')) {
                continue;
            }
            let mut attrs: Vec<String> = vec![];
            if lsub && !subscribed {
                attrs.push("\\Noselect".into());
            } else if !exists {
                if subscribed && sel_subscribed && !lsub {
                    attrs.push("\\NonExistent".into());
                } else {
                    attrs.push("\\Noselect".into());
                }
            }
            if !lsub && (!sel_subscribed || ret_children) && (exists || !subscribed) {
                attrs.push(if has_children(&n) { "\\HasChildren" } else { "\\HasNoChildren" }.into());
            }
            if let Some(m) = mb {
                if !m.special_use.is_empty() && !lsub {
                    attrs.push(m.special_use.clone());
                }
            }
            if !lsub && subscribed && (sel_subscribed || ret_subscribed) {
                attrs.push("\\Subscribed".into());
            }
            let mut line = format!("* {cmd} ({}) \"/\" ", attrs.join(" "));
            crate::mime::imap_string(&mut line, n.as_bytes());
            if childinfo {
                line.push_str(" (\"CHILDINFO\" (\"SUBSCRIBED\"))");
            }
            line.push_str("\r\n");
            lines.push((line, mb.map(|m| (m.id, m.name.clone()))));
        }
        for (line, id) in lines {
            self.conn.push(&line);
            if let (Some(items), Some((id, shown))) = (&ret_status, id) {
                if let Some(mut mb) = self.state.db.mailbox_by_id(id).await? {
                    mb.name = shown;
                    let st = self.status_line(&mb, items).await?;
                    match st {
                        Ok(l) => self.conn.push(&l),
                        Err(e) => return Ok(Resp::Bad(e)),
                    }
                }
            }
        }
        Ok(Resp::Ok(format!("{} completed.", if lsub { "Lsub" } else { "List" })))
    }

    async fn status(&mut self, args: &[Arg]) -> anyhow::Result<Resp> {
        let Some(name) = Self::mailbox_arg(args.first()) else {
            return Ok(Resp::Bad("Invalid mailbox name.".into()));
        };
        let Some(Arg::List(items)) = args.get(1) else {
            return Ok(Resp::Bad("STATUS expects a list of items.".into()));
        };
        let Some((mb, _)) = self.resolve_mb(&name).await? else {
            return Ok(Resp::No("[NONEXISTENT] Mailbox doesn't exist.".into()));
        };
        let items: Vec<String> = items.iter().map(|i| i.as_atom().unwrap_or("").to_ascii_uppercase()).collect();
        match self.status_line(&mb, &items).await? {
            Ok(l) => {
                self.conn.push(&l);
                Ok(Resp::Ok("Status completed.".into()))
            }
            Err(e) => Ok(Resp::Bad(e)),
        }
    }

    async fn status_line(&mut self, mb: &Mailbox, items: &[String]) -> anyhow::Result<Result<String, String>> {
        let (count, unseen, size) = self.state.db.mailbox_counts(mb.id).await?;
        let mut out = vec![];
        for it in items {
            let v = match it.as_str() {
                "MESSAGES" => count,
                "UNSEEN" => unseen,
                "UIDNEXT" => mb.uidnext,
                "UIDVALIDITY" => mb.uidvalidity,
                "SIZE" => size,
                "HIGHESTMODSEQ" => {
                    self.condstore = true;
                    self.state.db.mailbox_modseq(mb.id).await?.unwrap_or(mb.modseq)
                }
                "RECENT" => {
                    if self.sel.as_ref().is_some_and(|s| s.mb.id == mb.id) {
                        self.sel.as_ref().unwrap().recent.len() as i64
                    } else {
                        self.state.db.view(mb.id).await?.iter().filter(|r| r.uid > mb.recent_uid).count() as i64
                    }
                }
                _ => return Ok(Err(format!("Unknown STATUS item {it}."))),
            };
            out.push(format!("{it} {v}"));
        }
        let mut s = String::from("* STATUS ");
        crate::mime::imap_string(&mut s, mb.name.as_bytes());
        s.push_str(&format!(" ({})\r\n", out.join(" ")));
        Ok(Ok(s))
    }

    async fn quota(&mut self, cmd: &str, args: &[Arg]) -> anyhow::Result<Resp> {
        let Some(acc) = self.state.db.get_account(self.account_id()).await? else {
            return Ok(Resp::No("Account not found.".into()));
        };
        let line = if acc.quota_bytes > 0 {
            format!("* QUOTA \"\" (STORAGE {} {})\r\n", acc.used_bytes / 1024, acc.quota_bytes / 1024)
        } else {
            "* QUOTA \"\" ()\r\n".to_string()
        };
        match cmd {
            "GETQUOTAROOT" => {
                let Some(name) = Self::mailbox_arg(args.first()) else {
                    return Ok(Resp::Bad("Invalid mailbox name.".into()));
                };
                if self.state.db.mailbox(acc.id, &name).await?.is_none() {
                    return Ok(Resp::No("[NONEXISTENT] Mailbox doesn't exist.".into()));
                }
                let mut s = String::from("* QUOTAROOT ");
                crate::mime::imap_string(&mut s, name.as_bytes());
                s.push_str(" \"\"\r\n");
                self.conn.push(&s);
                self.conn.push(&line);
                Ok(Resp::Ok("Getquotaroot completed.".into()))
            }
            "GETQUOTA" => {
                if args.first().and_then(|a| a.string()).as_deref() != Some("") {
                    return Ok(Resp::No("[NONEXISTENT] No such quota root.".into()));
                }
                self.conn.push(&line);
                Ok(Resp::Ok("Getquota completed.".into()))
            }
            _ => Ok(Resp::No("[NOPERM] Quotas are set by the administrator.".into())),
        }
    }

    async fn append(&mut self, args: &[Arg]) -> anyhow::Result<Resp> {
        if args.len() < 2 {
            return Ok(Resp::Bad("APPEND expects a mailbox and a message.".into()));
        }
        let Some(name) = Self::mailbox_arg(args.first()) else {
            return Ok(Resp::Bad("Invalid mailbox name.".into()));
        };
        let Some((mb, rights)) = self.resolve_mb(&name).await? else {
            return Ok(Resp::No("[TRYCREATE] Mailbox doesn't exist.".into()));
        };
        if !rights.contains('i') {
            return Ok(Resp::No("[NOPERM] You may not add messages to this mailbox.".into()));
        }
        let acc = mb.account_id;
        let max = self.state.settings().limits.max_message_bytes as usize;
        // Parse every message first: MULTIAPPEND is all or nothing.
        let mut msgs: Vec<(Vec<String>, Option<i64>, Vec<u8>)> = vec![];
        let mut i = 1;
        while i < args.len() {
            let mut flags: Vec<String> = vec![];
            let mut date = None;
            if let Some(Arg::List(l)) = args.get(i) {
                for f in l {
                    let Some(s) = f.as_atom() else { return Ok(Resp::Bad("Invalid flag.".into())) };
                    if s.eq_ignore_ascii_case("\\Recent") {
                        continue;
                    }
                    match canonical_flag(s) {
                        Some(c) if !flags.iter().any(|x| x.eq_ignore_ascii_case(&c)) => flags.push(c),
                        Some(_) => {}
                        None => return Ok(Resp::Bad(format!("Invalid flag {s}."))),
                    }
                }
                i += 1;
            }
            if let Some(Arg::Str(d)) = args.get(i) {
                match fetch::parse_internal_date(&String::from_utf8_lossy(d)) {
                    Some(t) => date = Some(t),
                    None => return Ok(Resp::Bad("Invalid date-time.".into())),
                }
                i += 1;
            }
            let data = match args.get(i) {
                Some(Arg::Lit(m)) => crate::util::normalize_crlf(m),
                Some(Arg::Lit8(m)) => crate::mime::encode_binary_parts(m),
                Some(Arg::Atom(a)) if a.eq_ignore_ascii_case("CATENATE") => {
                    let Some(Arg::List(parts)) = args.get(i + 1) else {
                        return Ok(Resp::Bad("CATENATE needs a list.".into()));
                    };
                    i += 1;
                    let mut out = vec![];
                    let mut j = 0;
                    while j < parts.len() {
                        let kind = parts[j].as_atom().unwrap_or("").to_ascii_uppercase();
                        let Some(val) = parts.get(j + 1).and_then(|v| v.bytes()) else {
                            return Ok(Resp::Bad("Invalid CATENATE part.".into()));
                        };
                        match kind.as_str() {
                            "TEXT" => out.extend_from_slice(&crate::util::normalize_crlf(&val)),
                            "URL" => {
                                let url = String::from_utf8_lossy(&val).to_string();
                                match self.resolve_url(&url).await? {
                                    Some(d) => out.extend_from_slice(&d),
                                    None => {
                                        let mut q = String::new();
                                        crate::mime::imap_string(&mut q, url.as_bytes());
                                        return Ok(Resp::No(format!("[BADURL {q}] Unable to resolve URL.")));
                                    }
                                }
                            }
                            _ => return Ok(Resp::Bad("Invalid CATENATE part.".into())),
                        }
                        if out.len() > max {
                            return Ok(Resp::No("[TOOBIG] Message too large.".into()));
                        }
                        j += 2;
                    }
                    out
                }
                _ => return Ok(Resp::Bad("Missing message literal.".into())),
            };
            i += 1;
            if data.len() > max {
                return Ok(Resp::No("[TOOBIG] Message too large.".into()));
            }
            msgs.push((flags, date, data));
        }
        let mut uids = vec![];
        for (flags, date, raw) in msgs {
            match crate::server::store_message(&self.state, acc, &mb, &raw, &flags.join(" "), date).await {
                Ok(uid) => {
                    self.add_keywords(mb.id, &flags).await?;
                    uids.push(uid);
                }
                Err(crate::server::StoreError::OverQuota) => return Ok(Resp::No("[OVERQUOTA] Quota exceeded.".into())),
                Err(crate::server::StoreError::Other(e)) => return Err(e),
            }
        }
        Ok(Resp::Ok(format!("[APPENDUID {} {}] Append completed.", mb.uidvalidity, seq::compress(&uids))))
    }

    /// Resolve a relative IMAP URL (`/mailbox;uidvalidity=n/;uid=n/;section=x/;partial=o.l`)
    /// against the current account (CATENATE).
    async fn resolve_url(&mut self, url: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let Some(path) = url.strip_prefix('/') else { return Ok(None) };
        let mut parts = path.split("/;");
        let mbpart = parts.next().unwrap_or("");
        let (mbname, validity) = match mbpart.split_once(";uidvalidity=") {
            Some((n, v)) => (n, v.parse::<i64>().ok()),
            None => (mbpart, None),
        };
        let name = normalize_mailbox(&pct_decode(mbname));
        let (mut uid, mut section, mut partial) = (None, String::new(), None);
        for p in parts {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            match k.to_ascii_lowercase().as_str() {
                "uid" => uid = v.parse::<i64>().ok(),
                "section" => section = pct_decode(v),
                "partial" => {
                    let (o, l) = v.split_once('.').unwrap_or((v, ""));
                    partial = Some((o.parse::<usize>().unwrap_or(0), l.parse::<usize>().ok()));
                }
                _ => return Ok(None),
            }
        }
        let Some(uid) = uid else { return Ok(None) };
        let Some((mb, rights)) = self.resolve_mb(&name).await? else { return Ok(None) };
        if !rights.contains('r') {
            return Ok(None);
        }
        if validity.is_some_and(|v| v != mb.uidvalidity) {
            return Ok(None);
        }
        let rows = self.state.db.messages_by_uids(mb.id, uid, uid).await?;
        let Some(row) = rows.first() else { return Ok(None) };
        let raw = self.state.blobs.get(&row.blob).await?;
        let data = if section.is_empty() {
            raw.to_vec()
        } else {
            let Ok((p, spec)) = fetch::parse_section_spec(&section.to_ascii_uppercase()) else { return Ok(None) };
            let root = crate::mime::parse(&raw);
            match fetch::section_bytes(&raw, &root, &p, &spec) {
                Some(d) => d,
                None => return Ok(None),
            }
        };
        Ok(Some(match partial {
            Some((o, l)) => {
                let s = o.min(data.len());
                let e = match l {
                    Some(l) => o.saturating_add(l).min(data.len()),
                    None => data.len(),
                };
                data[s..e].to_vec()
            }
            None => data,
        }))
    }

    /// Record new keywords on the mailbox (and announce them when selected).
    async fn add_keywords(&mut self, mailbox_id: i64, flags: &[String]) -> anyhow::Result<()> {
        let new: Vec<String> = flags.iter().filter(|f| !f.starts_with('\\')).cloned().collect();
        if new.is_empty() {
            return Ok(());
        }
        let mb = self.state.db.mailbox_by_id(mailbox_id).await?;
        let Some(mb) = mb else { return Ok(()) };
        let mut kws: Vec<String> = mb.keywords.split_whitespace().map(String::from).collect();
        let mut changed = false;
        for k in new {
            if !kws.iter().any(|x| x.eq_ignore_ascii_case(&k)) {
                kws.push(k);
                changed = true;
            }
        }
        if changed {
            self.state.db.add_keywords(mailbox_id, &kws.join(" ")).await?;
        }
        Ok(())
    }

    // ------------------------------------------------------------ selected

    /// Bring the session view up to date and report changes.
    async fn sync(&mut self, allow_expunge: bool) -> anyhow::Result<()> {
        let (condstore, qresync) = (self.condstore, self.qresync);
        let Some(sel) = self.sel.as_mut() else { return Ok(()) };
        while sel.rx.try_recv().is_ok() {}
        let modseq = match self.state.db.mailbox_modseq(sel.mb.id).await? {
            Some(m) => m,
            None => {
                self.conn.push("* BYE Selected mailbox was deleted.\r\n");
                self.sel = None;
                self.logout = true;
                return Ok(());
            }
        };
        let pending_ghosts = sel.view.iter().any(|e| e.expunged);
        if modseq == sel.modseq && !(allow_expunge && pending_ghosts) {
            return Ok(());
        }
        let rows = self.state.db.view(sel.mb.id).await?;
        let current: HashMap<i64, &crate::db::ViewRow> = rows.iter().map(|r| (r.uid, r)).collect();
        for e in sel.view.iter_mut() {
            if !current.contains_key(&e.uid) {
                e.expunged = true;
            }
        }
        if allow_expunge {
            if qresync {
                let gone: Vec<i64> = sel.view.iter().filter(|e| e.expunged).map(|e| e.uid).collect();
                if !gone.is_empty() {
                    self.conn.push(&format!("* VANISHED {}\r\n", seq::compress(&gone)));
                    for u in &gone {
                        sel.recent.remove(u);
                    }
                    sel.view.retain(|e| !e.expunged);
                }
            } else {
                let mut i = sel.view.len();
                while i > 0 {
                    i -= 1;
                    if sel.view[i].expunged {
                        self.conn.push(&format!("* {} EXPUNGE\r\n", i + 1));
                        let uid = sel.view[i].uid;
                        sel.recent.remove(&uid);
                        sel.view.remove(i);
                    }
                }
            }
        }
        if let Some(mb) = self.state.db.mailbox_by_id(sel.mb.id).await? {
            let mut kws = sel.keywords.clone();
            for k in Self::merge_keywords(mb.keywords.split_whitespace().map(String::from).collect(), &rows) {
                if !kws.iter().any(|x| x.eq_ignore_ascii_case(&k)) {
                    kws.push(k);
                }
            }
            if kws != sel.keywords {
                sel.keywords = kws;
                let fl = Self::flag_list(&sel.keywords);
                self.conn.push(&format!("* FLAGS ({fl})\r\n"));
                if !sel.read_only {
                    self.conn.push(&format!("* OK [PERMANENTFLAGS ({fl} \\*)] Flags permitted.\r\n"));
                }
            }
            sel.mb.uidnext = mb.uidnext;
        }
        for (i, e) in sel.view.iter_mut().enumerate() {
            if e.expunged {
                continue;
            }
            if let Some(r) = current.get(&e.uid) {
                let flags_changed = norm_flags(&r.flags) != norm_flags(&e.flags);
                if flags_changed || r.modseq != e.modseq {
                    e.flags = r.flags.clone();
                    e.modseq = r.modseq;
                    if flags_changed || condstore {
                        let f = Self::fmt_flags(&e.flags, sel.recent.contains(&e.uid));
                        let ms = if condstore { format!(" MODSEQ ({})", e.modseq) } else { String::new() };
                        self.conn.push(&format!("* {} FETCH (UID {} FLAGS ({f}){ms})\r\n", i + 1, e.uid));
                    }
                }
            }
        }
        let last = sel.view.last().map(|e| e.uid).unwrap_or(0);
        let new: Vec<&crate::db::ViewRow> = rows.iter().filter(|r| r.uid > last).collect();
        if !new.is_empty() {
            let mark = if sel.read_only { i64::MAX } else { self.state.db.claim_recent(sel.mb.id).await? };
            for r in new {
                if r.uid > mark {
                    sel.recent.insert(r.uid);
                }
                sel.view.push(Entry { uid: r.uid, flags: r.flags.clone(), expunged: false, modseq: r.modseq });
            }
            self.conn.push(&format!("* {} EXISTS\r\n* {} RECENT\r\n", sel.view.len(), sel.recent.len()));
        }
        sel.modseq = modseq;
        Ok(())
    }

    fn fmt_flags(flags: &str, recent: bool) -> String {
        let mut f = flags.to_string();
        if recent {
            if !f.is_empty() {
                f.push(' ');
            }
            f.push_str("\\Recent");
        }
        f
    }

    /// View indices for a sequence set argument.
    fn targets(&self, arg: Option<&Arg>, uid: bool) -> Result<Vec<usize>, Resp> {
        let sel = self.sel.as_ref().unwrap();
        let set = arg
            .and_then(|a| a.as_atom())
            .and_then(SeqSet::parse)
            .ok_or_else(|| Resp::Bad("Invalid message set.".into()))?;
        if uid {
            let uids: Vec<i64> = sel.view.iter().map(|e| e.uid).collect();
            Ok(set.uid_indices(&uids))
        } else {
            set.msns(sel.view.len())
                .map(|v| v.into_iter().map(|n| n - 1).collect())
                .ok_or_else(|| Resp::Bad("Invalid messageset.".into()))
        }
    }

    async fn expunge(&mut self, uidset: Option<SeqSet>) -> anyhow::Result<Resp> {
        let sel = self.sel.as_ref().unwrap();
        if sel.read_only || !sel.rights.contains('e') {
            return Ok(Resp::No("[READ-ONLY] Mailbox is read-only.".into()));
        }
        let uids: Vec<i64> = sel.view.iter().map(|e| e.uid).collect();
        let max = uids.last().copied().unwrap_or(0);
        let del: Vec<i64> = sel
            .view
            .iter()
            .filter(|e| !e.expunged && has_flag(&e.flags, "\\Deleted"))
            .filter(|e| uidset.as_ref().map(|s| s.contains(e.uid, max)).unwrap_or(true))
            .map(|e| e.uid)
            .collect();
        let (id, acc) = (sel.mb.id, sel.mb.account_id);
        self.expunge_uids(id, acc, &del).await?;
        Ok(Resp::Ok("Expunge completed.".into()))
    }

    async fn expunge_uids(&mut self, mailbox_id: i64, account_id: i64, uids: &[i64]) -> anyhow::Result<()> {
        if uids.is_empty() {
            return Ok(());
        }
        let (_, blobs, freed) = self.state.db.expunge(mailbox_id, uids).await?;
        self.state.db.add_usage(account_id, -freed).await?;
        self.state.hub.notify(mailbox_id);
        self.state.blobs.delete_all(&blobs).await;
        Ok(())
    }

    /// `RETURN (opts)` at the start of SEARCH/SORT arguments.
    fn parse_return(args: &[Arg]) -> Result<(Option<Vec<String>>, &[Arg]), Resp> {
        if args.first().and_then(|a| a.as_atom()).is_some_and(|a| a.eq_ignore_ascii_case("RETURN")) {
            let Some(Arg::List(opts)) = args.get(1) else {
                return Err(Resp::Bad("RETURN needs a list.".into()));
            };
            let mut out = vec![];
            for o in opts {
                let o = o.as_atom().unwrap_or("").to_ascii_uppercase();
                if !matches!(o.as_str(), "MIN" | "MAX" | "ALL" | "COUNT") {
                    return Err(Resp::Bad(format!("Unsupported RETURN option {o}.")));
                }
                out.push(o);
            }
            return Ok((Some(out), &args[2..]));
        }
        Ok((None, args))
    }

    /// Parse `[CHARSET x] keys`.
    fn parse_criteria(args: &[Arg], charset_required: bool) -> Result<search::Key, Resp> {
        let mut args = args;
        let has_charset = args.first().and_then(|a| a.as_atom()).is_some_and(|a| a.eq_ignore_ascii_case("CHARSET"));
        if has_charset || charset_required {
            let idx = usize::from(has_charset);
            let cs = args.get(idx).and_then(|a| a.string()).unwrap_or_default().to_ascii_uppercase();
            if cs != "UTF-8" && cs != "US-ASCII" {
                return Err(Resp::No("[BADCHARSET (US-ASCII UTF-8)] Unsupported charset.".into()));
            }
            args = &args[idx + 1..];
        }
        search::KeyParser::new(args).parse_all().map_err(|e| Resp::Bad(format!("Error in search criteria: {e}.")))
    }

    /// View indices matching `key`, with the message rows used.
    async fn matching(&mut self, key: &search::Key) -> anyhow::Result<(Vec<usize>, HashMap<i64, crate::db::MessageRow>)> {
        let sel = self.sel.as_ref().unwrap();
        let needs = key.needs_content();
        let lo = sel.view.first().map(|e| e.uid).unwrap_or(0);
        let hi = sel.view.last().map(|e| e.uid).unwrap_or(0);
        let rows: HashMap<i64, crate::db::MessageRow> =
            self.state.db.messages_by_uids(sel.mb.id, lo, hi).await?.into_iter().map(|r| (r.uid, r)).collect();
        let max_uid = sel.view.last().map(|e| e.uid).unwrap_or(0);
        let max_msn = sel.view.len() as i64;
        let candidates = crate::dbx::fts_candidates(&self.state.db, sel.mb.id, key).await;
        let mut hits = vec![];
        for (i, e) in sel.view.iter().enumerate() {
            if candidates.as_ref().is_some_and(|c| !c.contains(&e.uid)) {
                continue;
            }
            let Some(row) = rows.get(&e.uid) else { continue };
            let content = if needs {
                match self.state.blobs.get(&row.blob).await {
                    Ok(raw) => Some(search::Content::load(raw)),
                    Err(_) => None,
                }
            } else {
                None
            };
            let ctx = search::Ctx {
                msn: i as i64 + 1,
                max_msn,
                uid: e.uid,
                max_uid,
                flags: &e.flags,
                recent: sel.recent.contains(&e.uid),
                size: row.size,
                internal_date: row.internal_date,
                modseq: e.modseq,
                content: content.as_ref(),
            };
            if search::eval(key, &ctx) {
                hits.push(i);
            }
        }
        Ok((hits, rows))
    }

    /// `* ESEARCH (TAG "t") [UID] MIN.. MAX.. ALL.. COUNT.. [MODSEQ ..]`.
    /// `ids` are in result order; `ordered` keeps that order for ALL (ESORT).
    fn esearch(&mut self, opts: &[String], uid: bool, ids: &[(i64, i64)], ordered: bool, with_modseq: bool) {
        let all_opts = vec!["ALL".to_string()];
        let opts = if opts.is_empty() { &all_opts } else { opts };
        let mut s = format!("* ESEARCH (TAG \"{}\")", self.tag);
        if uid {
            s.push_str(" UID");
        }
        let mut returned: Vec<i64> = vec![];
        if !ids.is_empty() {
            let (min, max) = if ordered {
                (ids[0], ids[ids.len() - 1])
            } else {
                (*ids.iter().min_by_key(|x| x.0).unwrap(), *ids.iter().max_by_key(|x| x.0).unwrap())
            };
            if opts.iter().any(|o| o == "MIN") {
                s.push_str(&format!(" MIN {}", min.0));
                returned.push(min.1);
            }
            if opts.iter().any(|o| o == "MAX") {
                s.push_str(&format!(" MAX {}", max.0));
                returned.push(max.1);
            }
            if opts.iter().any(|o| o == "ALL") {
                let list: Vec<i64> = ids.iter().map(|x| x.0).collect();
                let set = if ordered { compress_ordered(&list) } else {
                    let mut l = list.clone();
                    l.sort_unstable();
                    seq::compress(&l)
                };
                s.push_str(&format!(" ALL {set}"));
                returned.extend(ids.iter().map(|x| x.1));
            }
        }
        if opts.iter().any(|o| o == "COUNT") {
            s.push_str(&format!(" COUNT {}", ids.len()));
            returned.extend(ids.iter().map(|x| x.1));
        }
        if with_modseq {
            if let Some(m) = returned.iter().max() {
                s.push_str(&format!(" MODSEQ {m}"));
            }
        }
        s.push_str("\r\n");
        self.conn.push(&s);
    }

    async fn search(&mut self, args: &[Arg], uid: bool) -> anyhow::Result<Resp> {
        let (ret, args) = match Self::parse_return(args) {
            Ok(x) => x,
            Err(r) => return Ok(r),
        };
        let key = match Self::parse_criteria(args, false) {
            Ok(k) => k,
            Err(r) => return Ok(r),
        };
        let with_modseq = key.uses_modseq();
        if with_modseq {
            self.enable_condstore();
        }
        let (hits, _) = self.matching(&key).await?;
        let sel = self.sel.as_ref().unwrap();
        let ids: Vec<(i64, i64)> =
            hits.iter().map(|&i| (if uid { sel.view[i].uid } else { i as i64 + 1 }, sel.view[i].modseq)).collect();
        match ret {
            Some(opts) => self.esearch(&opts, uid, &ids, false, with_modseq),
            None => {
                let mut line = String::from("* SEARCH");
                for (id, _) in &ids {
                    line.push_str(&format!(" {id}"));
                }
                if with_modseq {
                    if let Some(m) = ids.iter().map(|x| x.1).max() {
                        line.push_str(&format!(" (MODSEQ {m})"));
                    }
                }
                line.push_str("\r\n");
                self.conn.push(&line);
            }
        }
        Ok(Resp::Ok("Search completed.".into()))
    }

    /// Sort/thread items for view indices (decoded headers, computed if missing).
    async fn items_for(&mut self, idx: &[usize], rows: &HashMap<i64, crate::db::MessageRow>) -> Vec<sort::Item> {
        let sel = self.sel.as_ref().unwrap();
        let mut out = Vec::with_capacity(idx.len());
        for &i in idx {
            let e = &sel.view[i];
            let Some(row) = rows.get(&e.uid) else { continue };
            let meta = match serde_json::from_str::<crate::mime::Meta>(&row.meta) {
                Ok(m) if !row.meta.is_empty() => m,
                _ => match self.state.blobs.get(&row.blob).await {
                    Ok(raw) => crate::mime::meta_of(&raw, &crate::mime::parse(&raw)),
                    Err(_) => Default::default(),
                },
            };
            out.push(sort::Item { msn: i as i64 + 1, uid: e.uid, size: row.size, internal: row.internal_date, meta });
        }
        out
    }

    async fn sort(&mut self, args: &[Arg], uid: bool) -> anyhow::Result<Resp> {
        let (ret, args) = match Self::parse_return(args) {
            Ok(x) => x,
            Err(r) => return Ok(r),
        };
        let Some(Arg::List(crit)) = args.first() else {
            return Ok(Resp::Bad("SORT expects sort criteria.".into()));
        };
        let atoms: Vec<String> = crit.iter().filter_map(|a| a.as_atom().map(String::from)).collect();
        let crits = match sort::parse_criteria(&atoms) {
            Ok(c) => c,
            Err(e) => return Ok(Resp::Bad(format!("{e}."))),
        };
        let key = match Self::parse_criteria(&args[1..], true) {
            Ok(k) => k,
            Err(r) => return Ok(r),
        };
        let with_modseq = key.uses_modseq();
        if with_modseq {
            self.enable_condstore();
        }
        let (hits, rows) = self.matching(&key).await?;
        let mut items = self.items_for(&hits, &rows).await;
        sort::sort(&mut items, &crits);
        let sel = self.sel.as_ref().unwrap();
        let ids: Vec<(i64, i64)> = items
            .iter()
            .map(|it| (it.id(uid), sel.view[(it.msn - 1) as usize].modseq))
            .collect();
        match ret {
            Some(opts) => self.esearch(&opts, uid, &ids, true, with_modseq),
            None => {
                let mut line = String::from("* SORT");
                for (id, _) in &ids {
                    line.push_str(&format!(" {id}"));
                }
                line.push_str("\r\n");
                self.conn.push(&line);
            }
        }
        Ok(Resp::Ok("Sort completed.".into()))
    }

    async fn thread(&mut self, args: &[Arg], uid: bool) -> anyhow::Result<Resp> {
        let alg = args.first().and_then(|a| a.as_atom()).unwrap_or("").to_ascii_uppercase();
        if alg != "REFERENCES" && alg != "ORDEREDSUBJECT" {
            return Ok(Resp::Bad("Unsupported threading algorithm.".into()));
        }
        let key = match Self::parse_criteria(args.get(1..).unwrap_or(&[]), true) {
            Ok(k) => k,
            Err(r) => return Ok(r),
        };
        let (hits, rows) = self.matching(&key).await?;
        let items = self.items_for(&hits, &rows).await;
        let t = if alg == "REFERENCES" { sort::thread_references(&items, uid) } else { sort::thread_orderedsubject(&items, uid) };
        if t.is_empty() {
            self.conn.push("* THREAD\r\n");
        } else {
            self.conn.push(&format!("* THREAD {t}\r\n"));
        }
        Ok(Resp::Ok("Thread completed.".into()))
    }

    async fn fetch(&mut self, args: &[Arg], uid: bool) -> anyhow::Result<Resp> {
        if args.len() < 2 {
            return Ok(Resp::Bad("FETCH expects a message set and items.".into()));
        }
        let mut idx = match self.targets(args.first(), uid) {
            Ok(v) => v,
            Err(r) => return Ok(r),
        };
        let mut atts = match fetch::parse_atts(&args[1]) {
            Ok(a) => a,
            Err(e) => return Ok(Resp::Bad(format!("Error in IMAP command FETCH: {e}."))),
        };
        let (mut changed_since, mut vanished) = (None::<i64>, false);
        if let Some(m) = args.get(2) {
            let Arg::List(mods) = m else { return Ok(Resp::Bad("Invalid FETCH modifiers.".into())) };
            let mut i = 0;
            while i < mods.len() {
                match mods[i].as_atom().map(|a| a.to_ascii_uppercase()).as_deref() {
                    Some("CHANGEDSINCE") => {
                        let Some(n) = mods.get(i + 1).and_then(|a| a.as_atom()).and_then(|a| a.parse::<i64>().ok()) else {
                            return Ok(Resp::Bad("CHANGEDSINCE needs a number.".into()));
                        };
                        changed_since = Some(n);
                        i += 1;
                    }
                    Some("VANISHED") => vanished = true,
                    _ => return Ok(Resp::Bad("Unknown FETCH modifier.".into())),
                }
                i += 1;
            }
            if args.len() > 3 || (vanished && (!uid || !self.qresync || changed_since.is_none())) {
                return Ok(Resp::Bad("Invalid FETCH modifiers.".into()));
            }
        }
        if changed_since.is_some() || atts.contains(&Att::ModSeq) {
            self.enable_condstore();
        }
        if uid && !atts.contains(&Att::Uid) {
            atts.insert(0, Att::Uid);
        }
        if (changed_since.is_some() || (self.condstore && atts.contains(&Att::Flags))) && !atts.contains(&Att::ModSeq) {
            atts.push(Att::ModSeq);
        }
        if let Some(cs) = changed_since {
            let sel = self.sel.as_ref().unwrap();
            idx.retain(|&i| sel.view[i].modseq > cs);
            if vanished {
                let set = args[0].as_atom().and_then(SeqSet::parse);
                let max = sel.mb.uidnext - 1;
                let mut v = self.state.db.vanished_since(sel.mb.id, cs).await?;
                if let Some(set) = set {
                    v.retain(|u| set.contains(*u, max));
                }
                if !v.is_empty() {
                    self.conn.push(&format!("* VANISHED (EARLIER) {}\r\n", seq::compress(&v)));
                }
            }
        }
        if idx.is_empty() {
            return Ok(Resp::Ok("Fetch completed.".into()));
        }
        let needs_content = atts.iter().any(|a| a.needs_content());
        let needs_parse = atts.iter().any(|a| a.needs_parse());
        let sets_seen = atts.iter().any(|a| a.sets_seen());
        let (mb_id, read_only) = {
            let sel = self.sel.as_ref().unwrap();
            (sel.mb.id, sel.read_only)
        };
        let (lo, hi) = {
            let sel = self.sel.as_ref().unwrap();
            (sel.view[idx[0]].uid, sel.view[*idx.last().unwrap()].uid)
        };
        let rows: HashMap<i64, crate::db::MessageRow> =
            self.state.db.messages_by_uids(mb_id, lo, hi).await?.into_iter().map(|r| (r.uid, r)).collect();
        let mut missing = false;
        let mut seen_updates = vec![];
        for i in idx {
            let (euid, eflags, recent, emodseq) = {
                let sel = self.sel.as_ref().unwrap();
                let e = &sel.view[i];
                (e.uid, e.flags.clone(), sel.recent.contains(&e.uid), e.modseq)
            };
            let Some(row) = rows.get(&euid) else {
                missing = true;
                continue;
            };
            let mut flags = eflags;
            let mut add_flags = false;
            if sets_seen && !read_only && !has_flag(&flags, "\\Seen") {
                flags = if flags.is_empty() { "\\Seen".into() } else { format!("{flags} \\Seen") };
                seen_updates.push(FlagUpdate { uid: euid, flags: flags.clone() });
                if let Some(e) = self.sel.as_mut().unwrap().view.get_mut(i) {
                    e.flags = flags.clone();
                }
                add_flags = !atts.contains(&Att::Flags);
            }
            let raw = if needs_content {
                match self.state.blobs.get(&row.blob).await {
                    Ok(r) => Some(r),
                    Err(e) => {
                        tracing::error!("message {} unreadable: {e:#}", row.blob);
                        missing = true;
                        continue;
                    }
                }
            } else {
                None
            };
            let parsed = raw.as_ref().filter(|_| needs_parse).map(|r| crate::mime::parse(r));
            let mut buf: Vec<u8> = format!("* {} FETCH (", i + 1).into_bytes();
            let mut items: Vec<&Att> = atts.iter().collect();
            let flags_att = Att::Flags;
            if add_flags {
                items.push(&flags_att);
            }
            let literal = |buf: &mut Vec<u8>, key: &str, data: &[u8], binary: bool| {
                let tilde = if binary && data.contains(&0) { "~" } else { "" };
                buf.extend_from_slice(format!("{key} {tilde}{{{}}}\r\n", data.len()).as_bytes());
                buf.extend_from_slice(data);
            };
            let slice = |d: &[u8], partial: &Option<(usize, usize)>| -> Vec<u8> {
                match partial {
                    Some((o, c)) => {
                        let s = (*o).min(d.len());
                        let e = o.saturating_add(*c).min(d.len());
                        d[s..e].to_vec()
                    }
                    None => d.to_vec(),
                }
            };
            for (n, a) in items.into_iter().enumerate() {
                if n > 0 {
                    buf.push(b' ');
                }
                let push = |buf: &mut Vec<u8>, s: String| buf.extend_from_slice(s.as_bytes());
                match a {
                    Att::Uid => push(&mut buf, format!("UID {euid}")),
                    Att::Flags => push(&mut buf, format!("FLAGS ({})", Self::fmt_flags(&flags, recent))),
                    Att::InternalDate => push(&mut buf, format!("INTERNALDATE \"{}\"", fetch::format_internal_date(row.internal_date))),
                    Att::Size => push(&mut buf, format!("RFC822.SIZE {}", row.size)),
                    Att::Envelope => push(&mut buf, format!("ENVELOPE {}", row.envelope)),
                    Att::Body => push(&mut buf, format!("BODY {}", row.body)),
                    Att::BodyStructure => push(&mut buf, format!("BODYSTRUCTURE {}", row.bodystructure)),
                    Att::ModSeq => push(&mut buf, format!("MODSEQ ({emodseq})")),
                    Att::Rfc822 => literal(&mut buf, "RFC822", raw.as_ref().unwrap(), false),
                    Att::Rfc822Header | Att::Rfc822Text => {
                        let r = raw.as_ref().unwrap();
                        let root = crate::mime::parse(r);
                        if matches!(a, Att::Rfc822Header) {
                            literal(&mut buf, "RFC822.HEADER", root.header_bytes(r), false);
                        } else {
                            literal(&mut buf, "RFC822.TEXT", root.body_bytes(r), false);
                        }
                    }
                    Att::Section { path, spec, partial, label, .. } => {
                        let r = raw.as_ref().unwrap();
                        let mut key = format!("BODY[{label}]");
                        match fetch::section_bytes(r, parsed.as_ref().unwrap(), path, spec) {
                            None => push(&mut buf, format!("{key} NIL")),
                            Some(d) => {
                                if let Some((o, _)) = partial {
                                    key.push_str(&format!("<{o}>"));
                                }
                                literal(&mut buf, &key, &slice(&d, partial), false);
                            }
                        }
                    }
                    Att::Binary { path, partial, label, .. } => {
                        let r = raw.as_ref().unwrap();
                        let mut key = format!("BINARY[{label}]");
                        match fetch::binary_bytes(r, parsed.as_ref().unwrap(), path) {
                            None => push(&mut buf, format!("{key} NIL")),
                            Some(Err(())) => return Ok(Resp::No("[UNKNOWN-CTE] Unknown Content-Transfer-Encoding.".into())),
                            Some(Ok(d)) => {
                                if let Some((o, _)) = partial {
                                    key.push_str(&format!("<{o}>"));
                                }
                                literal(&mut buf, &key, &slice(&d, partial), true);
                            }
                        }
                    }
                    Att::BinarySize { path, label } => {
                        let r = raw.as_ref().unwrap();
                        match fetch::binary_bytes(r, parsed.as_ref().unwrap(), path) {
                            None => push(&mut buf, format!("BINARY.SIZE[{label}] NIL")),
                            Some(Err(())) => return Ok(Resp::No("[UNKNOWN-CTE] Unknown Content-Transfer-Encoding.".into())),
                            Some(Ok(d)) => push(&mut buf, format!("BINARY.SIZE[{label}] {}", d.len())),
                        }
                    }
                }
            }
            buf.extend_from_slice(b")\r\n");
            self.conn.push_bytes(&buf);
            if self.conn.out.len() > 512 * 1024 {
                self.conn.flush().await?;
            }
        }
        if !seen_updates.is_empty() {
            self.state.db.set_flags(mb_id, &seen_updates).await?;
            self.state.hub.notify(mb_id);
        }
        if missing {
            return Ok(Resp::No("[EXPUNGEISSUED] Some of the requested messages no longer exist.".into()));
        }
        Ok(Resp::Ok("Fetch completed.".into()))
    }



    async fn store(&mut self, args: &[Arg], uid: bool) -> anyhow::Result<Resp> {
        let mut a = 1;
        let mut unchanged_since = None;
        if let Some(Arg::List(m)) = args.get(1) {
            if m.len() != 2 || !m[0].as_atom().is_some_and(|x| x.eq_ignore_ascii_case("UNCHANGEDSINCE")) {
                return Ok(Resp::Bad("Unknown STORE modifier.".into()));
            }
            let Some(n) = m[1].as_atom().and_then(|x| x.parse::<i64>().ok()) else {
                return Ok(Resp::Bad("UNCHANGEDSINCE needs a number.".into()));
            };
            unchanged_since = Some(n);
            a = 2;
            self.enable_condstore();
        }
        if args.len() < a + 2 {
            return Ok(Resp::Bad("STORE expects a message set, an item and flags.".into()));
        }
        let idx = match self.targets(args.first(), uid) {
            Ok(v) => v,
            Err(r) => return Ok(r),
        };
        let item = args[a].as_atom().unwrap_or("").to_ascii_uppercase();
        let (mode, silent) = match item.as_str() {
            "FLAGS" => ('=', false),
            "FLAGS.SILENT" => ('=', true),
            "+FLAGS" => ('+', false),
            "+FLAGS.SILENT" => ('+', true),
            "-FLAGS" => ('-', false),
            "-FLAGS.SILENT" => ('-', true),
            _ => return Ok(Resp::Bad(format!("Invalid STORE item {item}."))),
        };
        let raw_flags: Vec<&Arg> = match &args[a + 1] {
            Arg::List(l) => l.iter().collect(),
            _ => args[a + 1..].iter().collect(),
        };
        let mut flags: Vec<String> = vec![];
        for f in raw_flags {
            let Some(s) = f.as_atom() else { return Ok(Resp::Bad("Invalid flag.".into())) };
            if s.eq_ignore_ascii_case("\\Recent") {
                return Ok(Resp::Bad("Error in IMAP command STORE: Invalid system flag \\Recent.".into()));
            }
            match canonical_flag(s) {
                Some(c) => {
                    if !flags.iter().any(|x| x.eq_ignore_ascii_case(&c)) {
                        flags.push(c)
                    }
                }
                None => return Ok(Resp::Bad(format!("Error in IMAP command STORE: Invalid flag {s}."))),
            }
        }
        let sel = self.sel.as_ref().unwrap();
        if sel.read_only {
            return Ok(Resp::No("[READ-ONLY] Mailbox is read-only.".into()));
        }
        let mb_id = sel.mb.id;
        let targets: Vec<(usize, i64)> = idx.iter().filter(|&&i| !sel.view[i].expunged).map(|&i| (i, sel.view[i].uid)).collect();
        let uids: Vec<i64> = targets.iter().map(|t| t.1).collect();
        if !flags.is_empty() && mode != '-' {
            self.add_keywords(mb_id, &flags).await?;
        }
        let res = self.state.db.modify_flags(mb_id, &uids, mode, &flags, unchanged_since).await?;
        let result: HashMap<i64, (String, i64)> = res.rows.into_iter().map(|(u, f, m)| (u, (f, m))).collect();
        self.state.hub.notify(mb_id);
        self.sync_keywords().await?;
        let condstore = self.condstore;
        let sel = self.sel.as_mut().unwrap();
        for &(i, uid_) in &targets {
            let Some((f, m)) = result.get(&uid_) else { continue };
            let changed = sel.view[i].modseq != *m;
            sel.view[i].flags = f.clone();
            sel.view[i].modseq = *m;
            let uid_part = if uid { format!("UID {uid_} ") } else { String::new() };
            if !silent {
                let fl = Self::fmt_flags(f, sel.recent.contains(&uid_));
                let ms = if condstore { format!(" MODSEQ ({m})") } else { String::new() };
                self.conn.push(&format!("* {} FETCH ({uid_part}FLAGS ({fl}){ms})\r\n", i + 1));
            } else if condstore && changed {
                self.conn.push(&format!("* {} FETCH ({uid_part}MODSEQ ({m}))\r\n", i + 1));
            }
        }
        if !res.modified.is_empty() {
            let ids: Vec<i64> = if uid {
                res.modified.clone()
            } else {
                let mut v: Vec<i64> = res
                    .modified
                    .iter()
                    .filter_map(|u| sel.view.iter().position(|e| e.uid == *u).map(|p| p as i64 + 1))
                    .collect();
                v.sort_unstable();
                v
            };
            return Ok(Resp::Ok(format!("[MODIFIED {}] Conditional STORE failed.", seq::compress(&ids))));
        }
        Ok(Resp::Ok("Store completed.".into()))
    }

    async fn sync_keywords(&mut self) -> anyhow::Result<()> {
        let Some(sel) = self.sel.as_mut() else { return Ok(()) };
        if let Some(mb) = self.state.db.mailbox_by_id(sel.mb.id).await? {
            let mut kws = sel.keywords.clone();
            for k in mb.keywords.split_whitespace() {
                if !kws.iter().any(|x| x.eq_ignore_ascii_case(k)) {
                    kws.push(k.to_string());
                }
            }
            if kws != sel.keywords {
                sel.keywords = kws;
                let fl = Self::flag_list(&sel.keywords);
                self.conn.push(&format!("* FLAGS ({fl})\r\n"));
                self.conn.push(&format!("* OK [PERMANENTFLAGS ({fl} \\*)] Flags permitted.\r\n"));
            }
        }
        Ok(())
    }

    async fn copy(&mut self, args: &[Arg], uid: bool, mv: bool) -> anyhow::Result<Resp> {
        if args.len() != 2 {
            return Ok(Resp::Bad("Expected a message set and a mailbox.".into()));
        }
        let idx = match self.targets(args.first(), uid) {
            Ok(v) => v,
            Err(r) => return Ok(r),
        };
        let Some(name) = Self::mailbox_arg(args.get(1)) else {
            return Ok(Resp::Bad("Invalid mailbox name.".into()));
        };
        let Some((dst, dst_rights)) = self.resolve_mb(&name).await? else {
            return Ok(Resp::No("[TRYCREATE] Mailbox doesn't exist.".into()));
        };
        if !dst_rights.contains('i') {
            return Ok(Resp::No("[NOPERM] You may not add messages to that mailbox.".into()));
        }
        let acc = dst.account_id;
        let sel = self.sel.as_ref().unwrap();
        if mv && (sel.read_only || !sel.rights.contains('t') || !sel.rights.contains('e')) {
            return Ok(Resp::No("[READ-ONLY] Mailbox is read-only.".into()));
        }
        let src_owner = sel.mb.account_id;
        let src_junk = sel.mb.special_use.contains("\\Junk");
        let src_id = sel.mb.id;
        let uids: Vec<i64> = idx.iter().filter(|&&i| !sel.view[i].expunged).map(|&i| sel.view[i].uid).collect();
        if uids.is_empty() {
            return Ok(Resp::Ok(if mv { "No messages moved." } else { "No messages copied." }.into()));
        }
        // Quota: copies count against the account.
        if let Some(a) = self.state.db.get_account(acc).await? {
            if a.quota_bytes > 0 && !mv {
                let rows = self.state.db.messages_by_uids(src_id, uids[0], *uids.last().unwrap()).await?;
                let add: i64 = rows.iter().filter(|r| uids.contains(&r.uid)).map(|r| r.size).sum();
                if a.used_bytes + add > a.quota_bytes {
                    return Ok(Resp::No("[OVERQUOTA] Quota exceeded.".into()));
                }
            }
        }
        let (pairs, added) = self.state.db.copy_messages(src_id, &uids, dst.id).await?;
        if !mv || src_owner != acc {
            self.state.db.add_usage(acc, added).await?;
        }
        // Train the spam filter from the user's own corrections.
        let dst_junk = dst.special_use.contains("\\Junk");
        let dst_trash = dst.special_use.contains("\\Trash");
        if dst_junk != src_junk && !(src_junk && dst_trash) {
            if let Ok(rows) = self.state.db.messages_by_uids(src_id, uids[0], *uids.last().unwrap()).await {
                for r in rows.into_iter().filter(|r| uids.contains(&r.uid)) {
                    crate::filter::bayes::learn_blob(&self.state, self.account_id(), r.blob, dst_junk);
                }
            }
        }
        self.state.hub.notify(dst.id);
        let dst = self.state.db.mailbox_by_id(dst.id).await?.unwrap_or(dst);
        let src_uids: Vec<i64> = pairs.iter().map(|p| p.0).collect();
        let dst_uids: Vec<i64> = pairs.iter().map(|p| p.1).collect();
        let code = if pairs.is_empty() {
            String::new()
        } else {
            format!("[COPYUID {} {} {}] ", dst.uidvalidity, seq::compress(&src_uids), seq::compress(&dst_uids))
        };
        if mv {
            self.conn.push(&format!("* OK {code}Moved UIDs.\r\n"));
            let (_, blobs, freed) = self.state.db.expunge(src_id, &src_uids).await?;
            if src_owner != acc {
                self.state.db.add_usage(src_owner, -freed).await?;
            }
            self.state.hub.notify(src_id);
            self.state.blobs.delete_all(&blobs).await;
            return Ok(Resp::Ok("Move completed.".into()));
        }
        Ok(Resp::Ok(format!("{code}Copy completed.")))
    }

    /// Resolve a mailbox name, including `Shared/<owner>/<folder>`.
    /// Returns the mailbox (named as the client sees it) and our rights.
    async fn resolve_mb(&self, name: &str) -> anyhow::Result<Option<(Mailbox, String)>> {
        let acc = self.account_id();
        if let Some(rest) = name.strip_prefix("Shared/") {
            let Some((owner, folder)) = rest.split_once('/') else { return Ok(None) };
            let Some(o) = self.state.db.account_by_email(owner).await? else { return Ok(None) };
            let folder = normalize_mailbox(folder);
            if o.id == acc {
                return Ok(self.state.db.mailbox(acc, &folder).await?.map(|m| (m, acl::ALL_RIGHTS.to_string())));
            }
            let Some(mut mb) = self.state.db.mailbox(o.id, &folder).await? else { return Ok(None) };
            let me = self.account.as_ref().map(|a| a.email.clone()).unwrap_or_default();
            let rights = self.state.db.rights_for(mb.id, &me).await?;
            if !rights.contains('l') && !rights.contains('r') {
                return Ok(None);
            }
            mb.name = name.to_string();
            return Ok(Some((mb, rights)));
        }
        Ok(self.state.db.mailbox(acc, name).await?.map(|m| (m, acl::ALL_RIGHTS.to_string())))
    }

    /// SETACL, DELETEACL, GETACL, LISTRIGHTS, MYRIGHTS (RFC 4314).
    async fn acl_cmd(&mut self, cmd: &str, args: &[Arg]) -> anyhow::Result<Resp> {
        let Some(name) = Self::mailbox_arg(args.first()) else {
            return Ok(Resp::Bad("Invalid mailbox name.".into()));
        };
        let Some((mb, rights)) = self.resolve_mb(&name).await? else {
            return Ok(Resp::No("[NONEXISTENT] Mailbox doesn't exist.".into()));
        };
        let owner = mb.account_id == self.account_id();
        let mut quoted = String::new();
        crate::mime::imap_string(&mut quoted, name.as_bytes());
        match cmd {
            "MYRIGHTS" => {
                self.conn.push(&format!("* MYRIGHTS {quoted} {rights}\r\n"));
                return Ok(Resp::Ok("Myrights completed.".into()));
            }
            _ if !owner && !rights.contains('a') => return Ok(Resp::No("[NOPERM] You may not administer this mailbox.".into())),
            "GETACL" => {
                let mut line = format!("* ACL {quoted}");
                if let Some(o) = self.state.db.get_account(mb.account_id).await? {
                    line.push_str(&format!(" \"{}\" {}", o.email, acl::ALL_RIGHTS));
                }
                for (id, r) in self.state.db.acl(mb.id).await? {
                    line.push(' ');
                    crate::mime::imap_string(&mut line, id.as_bytes());
                    line.push_str(&format!(" {r}"));
                }
                self.conn.push(&format!("{line}\r\n"));
                return Ok(Resp::Ok("Getacl completed.".into()));
            }
            _ => {}
        }
        let Some(ident) = args.get(1).and_then(|a| a.string()).map(|s| s.to_ascii_lowercase()) else {
            return Ok(Resp::Bad("Missing identifier.".into()));
        };
        if ident.starts_with('-') {
            return Ok(Resp::No("Negative rights are not supported.".into()));
        }
        let valid_ident = ident == "anyone" || ident == "authenticated" || self.state.db.account_by_email(&ident).await?.is_some();
        match cmd {
            "LISTRIGHTS" => {
                let mut line = format!("* LISTRIGHTS {quoted} ");
                crate::mime::imap_string(&mut line, ident.as_bytes());
                let is_owner = self.state.db.get_account(mb.account_id).await?.is_some_and(|o| o.email == ident);
                if is_owner {
                    line.push_str(&format!(" {}", acl::ALL_RIGHTS));
                } else {
                    line.push_str(" \"\" l r s w i p k x t e a");
                }
                self.conn.push(&format!("{line}\r\n"));
                Ok(Resp::Ok("Listrights completed.".into()))
            }
            "DELETEACL" => {
                self.state.db.set_acl(mb.id, &ident, "").await?;
                Ok(Resp::Ok("Deleteacl completed.".into()))
            }
            _ => {
                // SETACL mailbox identifier [+|-]rights
                if !valid_ident {
                    return Ok(Resp::No("No such user.".into()));
                }
                let Some(spec) = args.get(2).and_then(|a| a.string()) else {
                    return Ok(Resp::Bad("Missing rights.".into()));
                };
                let current = self.state.db.acl(mb.id).await?.into_iter().find(|(i, _)| *i == ident).map(|(_, r)| r).unwrap_or_default();
                let new = if let Some(add) = spec.strip_prefix('+') {
                    acl::normalize(&format!("{current}{add}"))
                } else if let Some(del) = spec.strip_prefix('-') {
                    acl::normalize(del).map(|d| current.chars().filter(|c| !d.contains(*c)).collect())
                } else {
                    acl::normalize(&spec)
                };
                let Some(new) = new else { return Ok(Resp::Bad("Invalid rights.".into())) };
                self.state.db.set_acl(mb.id, &ident, &new).await?;
                self.state.event("info", "imap", &format!("{} set ACL on {} for {ident}: {new}", self.account.as_ref().map(|a| a.email.as_str()).unwrap_or(""), name));
                Ok(Resp::Ok("Setacl completed.".into()))
            }
        }
    }

    /// Mailbox id for METADATA ("" = server = 0) and whether we may write shared entries.
    async fn metadata_target(&self, name: &str) -> anyhow::Result<Option<(i64, i64, String)>> {
        if name.is_empty() {
            let admin = self.account.as_ref().is_some_and(|a| a.is_admin());
            return Ok(Some((0, 0, if admin { acl::ALL_RIGHTS.to_string() } else { "lr".to_string() })));
        }
        Ok(self.resolve_mb(name).await?.map(|(m, r)| (m.id, m.account_id, r)))
    }

    async fn getmetadata(&mut self, args: &[Arg]) -> anyhow::Result<Resp> {
        let mut i = 0;
        let mut maxsize: Option<usize> = None;
        let mut depth = "0".to_string();
        if let Some(Arg::List(opts)) = args.first() {
            let mut j = 0;
            while j < opts.len() {
                match opts[j].as_atom().map(|a| a.to_ascii_uppercase()).as_deref() {
                    Some("MAXSIZE") => {
                        maxsize = opts.get(j + 1).and_then(|a| a.as_atom()).and_then(|a| a.parse().ok());
                        j += 1;
                    }
                    Some("DEPTH") => {
                        depth = opts.get(j + 1).and_then(|a| a.as_atom()).unwrap_or("0").to_ascii_lowercase();
                        j += 1;
                    }
                    _ => return Ok(Resp::Bad("Unknown GETMETADATA option.".into())),
                }
                j += 1;
            }
            i = 1;
        }
        let Some(name) = args.get(i).and_then(|a| a.string()) else { return Ok(Resp::Bad("Missing mailbox.".into())) };
        let name = if name.is_empty() { String::new() } else { normalize_mailbox(name.trim_end_matches(DELIM)) };
        let entries: Vec<String> = match args.get(i + 1) {
            Some(Arg::List(l)) => l.iter().filter_map(|a| a.string()).collect(),
            Some(a) => a.string().into_iter().collect(),
            None => return Ok(Resp::Bad("Missing entries.".into())),
        };
        let Some((mbid, owner, rights)) = self.metadata_target(&name).await? else {
            return Ok(Resp::No("[NONEXISTENT] Mailbox doesn't exist.".into()));
        };
        if !rights.contains('r') && !rights.contains('l') {
            return Ok(Resp::No("[NOPERM] Permission denied.".into()));
        }
        let me = self.account_id();
        let shared_owner = if mbid == 0 { 0 } else { -owner.max(1) };
        let all = self.state.db.metadata(mbid, &[me, shared_owner]).await?;
        let mut out: Vec<(String, Vec<u8>)> = vec![];
        let mut longest = 0usize;
        for e in &entries {
            let lower = e.to_ascii_lowercase();
            let (scope_owner, rel) = if let Some(r) = lower.strip_prefix("/private") { (me, r.to_string()) } else if let Some(r) = lower.strip_prefix("/shared") { (shared_owner, r.to_string()) } else { continue };
            for (o, n, v) in &all {
                if *o != scope_owner {
                    continue;
                }
                let nl = n.to_ascii_lowercase();
                let prefix = if lower.starts_with("/private") { "/private" } else { "/shared" };
                let matched = nl == rel
                    || (depth == "1" && nl.strip_prefix(&format!("{rel}/")).is_some_and(|x| !x.contains('/')))
                    || (depth == "infinity" && nl.starts_with(&format!("{rel}/")));
                if matched {
                    if maxsize.is_some_and(|m| v.len() > m) {
                        longest = longest.max(v.len());
                        continue;
                    }
                    out.push((format!("{prefix}{n}"), v.clone()));
                }
            }
        }
        if !out.is_empty() {
            let mut line = String::from("* METADATA ");
            crate::mime::imap_string(&mut line, name.as_bytes());
            line.push_str(" (");
            for (k, (n, v)) in out.iter().enumerate() {
                if k > 0 {
                    line.push(' ');
                }
                crate::mime::imap_string(&mut line, n.as_bytes());
                line.push(' ');
                if v.iter().any(|b| *b == b'\r' || *b == b'\n' || *b == b'"' || *b == b'\\' || *b >= 0x80 || *b == 0) {
                    line.push_str(&format!("{{{}}}\r\n", v.len()));
                    self.conn.push(&line);
                    self.conn.push_bytes(v);
                    line = String::new();
                } else {
                    line.push('"');
                    line.push_str(&String::from_utf8_lossy(v));
                    line.push('"');
                }
            }
            line.push_str(")\r\n");
            self.conn.push(&line);
        }
        if longest > 0 {
            return Ok(Resp::Ok(format!("[METADATA LONGENTRIES {longest}] Getmetadata completed.")));
        }
        Ok(Resp::Ok("Getmetadata completed.".into()))
    }

    async fn setmetadata(&mut self, args: &[Arg]) -> anyhow::Result<Resp> {
        let Some(name) = args.first().and_then(|a| a.string()) else { return Ok(Resp::Bad("Missing mailbox.".into())) };
        let name = if name.is_empty() { String::new() } else { normalize_mailbox(name.trim_end_matches(DELIM)) };
        let Some(Arg::List(pairs)) = args.get(1) else { return Ok(Resp::Bad("Expected a list of entries and values.".into())) };
        let Some((mbid, owner, rights)) = self.metadata_target(&name).await? else {
            return Ok(Resp::No("[NONEXISTENT] Mailbox doesn't exist.".into()));
        };
        let me = self.account_id();
        let shared_owner = if mbid == 0 { 0 } else { -owner.max(1) };
        if pairs.len() % 2 != 0 {
            return Ok(Resp::Bad("Entries and values must come in pairs.".into()));
        }
        for pair in pairs.chunks(2) {
            let Some(entry) = pair[0].string() else { return Ok(Resp::Bad("Invalid entry.".into())) };
            if !acl::valid_entry(&entry) {
                return Ok(Resp::Bad("Invalid entry name.".into()));
            }
            let lower = entry.to_ascii_lowercase();
            let private = lower.starts_with("/private");
            if !private && !rights.contains('w') && !(mbid != 0 && owner == me) {
                return Ok(Resp::No("[NOPERM] You may not set shared entries here.".into()));
            }
            let value = if pair[1].is_nil() { None } else { pair[1].bytes() };
            if let Some(v) = &value {
                if v.len() > 64 * 1024 {
                    return Ok(Resp::No(format!("[METADATA MAXSIZE {}] Value too large.", 64 * 1024)));
                }
            }
            let o = if private { me } else { shared_owner };
            if value.is_some() && self.state.db.metadata_count(mbid, o).await? >= 200 {
                return Ok(Resp::No("[METADATA TOOMANY] Too many entries.".into()));
            }
            let rel = if private { &entry[8..] } else { &entry[7..] };
            self.state.db.set_metadata(o, mbid, rel, value.as_deref()).await?;
        }
        Ok(Resp::Ok("Setmetadata completed.".into()))
    }

    async fn idle(&mut self) -> anyhow::Result<Resp> {
        self.conn.push("+ idling\r\n");
        self.sync(true).await?;
        self.conn.flush().await?;
        let timeout = Duration::from_secs(self.state.config.limits.idle_timeout_secs);
        let deadline = tokio::time::Instant::now() + timeout;
        let mut poll = tokio::time::interval(Duration::from_secs(30));
        poll.tick().await;
        loop {
            enum Ev {
                Data(std::io::Result<usize>),
                Change,
                Poll,
                Timeout,
                Shutdown,
            }
            let shutdown = self.state.shutdown.clone();
            let ev = {
                let reader = &mut self.conn.reader;
                let rx = self.sel.as_mut().map(|s| &mut s.rx);
                tokio::select! {
                    r = tokio::io::AsyncBufReadExt::fill_buf(reader) => Ev::Data(r.map(|b| b.len())),
                    _ = async {
                        match rx {
                            Some(rx) => { let _ = rx.recv().await; }
                            None => std::future::pending::<()>().await,
                        }
                    } => Ev::Change,
                    _ = poll.tick() => Ev::Poll,
                    _ = tokio::time::sleep_until(deadline) => Ev::Timeout,
                    _ = shutdown.cancelled() => Ev::Shutdown,
                }
            };
            match ev {
                Ev::Data(Ok(0)) | Ev::Data(Err(_)) => {
                    self.logout = true;
                    return Ok(Resp::Ok("Idle ended.".into()));
                }
                Ev::Data(Ok(_)) => {
                    let line = match self.conn.read_line(1024).await {
                        Ok(l) => l,
                        Err(_) => {
                            self.logout = true;
                            return Ok(Resp::Bad("Idle aborted.".into()));
                        }
                    };
                    if line.eq_ignore_ascii_case(b"DONE") {
                        return Ok(Resp::Ok("Idle completed.".into()));
                    }
                    return Ok(Resp::Bad("Expected DONE.".into()));
                }
                Ev::Change | Ev::Poll => {
                    self.sync(true).await?;
                    self.conn.flush().await?;
                    if self.logout {
                        return Ok(Resp::Ok("Idle ended.".into()));
                    }
                }
                Ev::Shutdown => {
                    self.conn.push("* BYE [UNAVAILABLE] Server shutting down, please reconnect shortly.\r\n");
                    self.logout = true;
                    return Ok(Resp::Ok("Idle ended.".into()));
                }
                Ev::Timeout => {
                    self.conn.push("* BYE Idle timeout.\r\n");
                    self.logout = true;
                    return Ok(Resp::Ok("Idle ended.".into()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matching() {
        assert!(list_match(b"*", b"a/b/c"));
        assert!(list_match(b"%", b"a"));
        assert!(!list_match(b"%", b"a/b"));
        assert!(list_match(b"a/%", b"a/b"));
        assert!(list_match(b"a*c", b"a/b/c"));
        assert!(!list_match(b"a%c", b"a/b/c"));
    }
}
