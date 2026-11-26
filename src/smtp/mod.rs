//! SMTP server: inbound MX (port 25) and authenticated submission (587/465).
pub mod delivery;

use crate::db::Account;
use crate::imap::proto::{Conn, ReadError};
use crate::net::Stream;
use crate::state::State;
use base64::Engine;
use delivery::{RcptError, Target};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    /// Accepts mail for local domains from anyone; AUTH optional.
    Mx,
    /// Requires AUTH before MAIL.
    Submission,
}

struct Session {
    state: State,
    conn: Conn,
    peer: IpAddr,
    mode: Mode,
    helo: Option<String>,
    esmtp: bool,
    account: Option<Account>,
    from: Option<String>,
    rcpts: Vec<(String, Vec<Target>)>,
    rdns: Option<String>,
    quit: bool,
    pending_tls: bool,
    bad_commands: u32,
    hostname: String,
    /// DSN parameters from MAIL/RCPT (RFC 3461).
    dsn: crate::outbound::Dsn,
    /// REQUIRETLS on MAIL FROM (RFC 8689).
    requiretls: bool,
    /// BDAT chunks received so far (RFC 3030).
    bdat: Option<Vec<u8>>,
    bdat_too_big: bool,
    /// Listed on a score-only DNSBL.
    dnsbl_hit: Option<String>,
}

pub async fn handle(state: State, stream: Stream, peer: SocketAddr, mode: Mode) {
    let hostname = state.hostname();
    let mut s = Session {
        state,
        conn: Conn::new(stream),
        peer: peer.ip(),
        mode,
        helo: None,
        esmtp: false,
        account: None,
        from: None,
        rcpts: vec![],
        rdns: None,
        quit: false,
        pending_tls: false,
        bad_commands: 0,
        hostname,
        dsn: Default::default(),
        requiretls: false,
        bdat: None,
        bdat_too_big: false,
        dnsbl_hit: None,
    };
    if let Err(e) = s.run().await {
        tracing::debug!("smtp session {}: {e:#}", s.peer);
    }
    let _ = s.conn.flush().await;
}

impl Session {
    fn reply(&mut self, code: u16, text: &str) {
        let lines: Vec<&str> = text.split('\n').collect();
        for (i, l) in lines.iter().enumerate() {
            let sep = if i + 1 < lines.len() { '-' } else { ' ' };
            self.conn.push(&format!("{code}{sep}{l}\r\n"));
        }
    }

    fn tls(&mut self) -> bool {
        self.conn.stream().is_tls()
    }

    fn auth_allowed(&mut self) -> bool {
        let sec = self.state.settings().security.clone();
        self.tls() || !sec.require_tls_for_auth || (sec.allow_plaintext_localhost && crate::util::is_loopback(self.peer))
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        let sec = self.state.settings().security.clone();
        let allowlisted = crate::util::ip_in_list(self.peer, &sec.allowlist);
        if !allowlisted && self.state.limiter.is_banned(self.peer) {
            self.reply(421, "4.7.0 Too many failed attempts, try again later");
            return Ok(());
        }
        if self.mode == Mode::Mx && !allowlisted && !crate::util::is_loopback(self.peer) {
            if let Some(list) = self.dnsbl_listed(&sec.dnsbl).await {
                self.state.event("info", "smtp", &format!("rejected {} listed on {list}", self.peer));
                self.reply(554, &format!("5.7.1 Service unavailable; client host [{}] blocked using {list}", self.peer));
                return Ok(());
            }
            if let Some(list) = self.dnsbl_listed(&self.state.settings().filter.dnsbl.clone()).await {
                self.dnsbl_hit = Some(list);
            }
            self.rdns = self.reverse_dns().await;
            if sec.require_rdns && self.rdns.is_none() {
                self.reply(550, "5.7.25 Client host has no reverse DNS");
                return Ok(());
            }
        }
        let greeting = self.state.settings().server.greeting.clone().unwrap_or_else(|| "ESMTP Picacho Server".into());
        self.reply(220, &format!("{} {greeting}", self.hostname));
        let max_line = self.state.config.limits.smtp_max_line;
        loop {
            self.conn.flush().await?;
            if self.quit {
                return Ok(());
            }
            if self.state.shutdown.is_cancelled() && self.from.is_none() && self.bdat.is_none() {
                self.reply(421, &format!("4.3.2 {} shutting down, try again later", self.hostname));
                self.conn.flush().await?;
                return Ok(());
            }
            if self.pending_tls {
                self.pending_tls = false;
                self.conn.flush().await?;
                let old = std::mem::replace(&mut self.conn, Conn::new(Stream::Duplex(tokio::io::duplex(1).0)));
                let tls = tokio::time::timeout(
                    Duration::from_secs(30),
                    old.reader.into_inner().upgrade(&self.state.tls.acceptor),
                )
                .await??;
                self.conn = Conn::new(tls);
                // RFC 3207: forget everything learned before TLS.
                self.helo = None;
                self.from = None;
                self.rcpts.clear();
                continue;
            }
            let read = async {
                tokio::select! {
                    r = tokio::time::timeout(Duration::from_secs(300), self.conn.read_line(max_line)) => Some(r),
                    _ = self.state.shutdown.cancelled() => None,
                }
            };
            let Some(read) = read.await else {
                // Woken by shutdown while idle: loop to send 421.
                if self.from.is_none() {
                    continue;
                }
                // Mid-transaction: let the client finish.
                self.state.shutdown.cancelled().await;
                continue;
            };
            let line = match read {
                Err(_) => {
                    self.reply(421, "4.4.2 Idle timeout, closing connection");
                    return Ok(());
                }
                Ok(Err(ReadError::LineTooLong)) => {
                    self.reply(500, "5.5.2 Line too long");
                    continue;
                }
                Ok(Err(ReadError::Io(e))) => return Err(e.into()),
                Ok(Err(_)) => return Ok(()),
                Ok(Ok(l)) => l,
            };
            let line = String::from_utf8_lossy(&line).to_string();
            let (verb, arg) = match line.split_once(' ') {
                Some((v, a)) => (v.to_ascii_uppercase(), a.trim().to_string()),
                None => (line.trim().to_ascii_uppercase(), String::new()),
            };
            match verb.as_str() {
                "EHLO" | "HELO" => self.ehlo(&arg, verb == "EHLO"),
                "STARTTLS" => {
                    if self.tls() {
                        self.reply(503, "5.5.1 TLS already active");
                    } else if self.conn.buffered() > 0 {
                        self.reply(503, "5.5.1 Pipelining not allowed before STARTTLS");
                        self.quit = true;
                    } else {
                        self.reply(220, "2.0.0 Ready to start TLS");
                        self.pending_tls = true;
                    }
                }
                "AUTH" => self.auth(&arg).await?,
                "MAIL" => self.mail(&arg).await,
                "RCPT" => self.rcpt(&arg).await,
                "DATA" => self.data().await?,
                "BDAT" => self.bdat(&arg).await?,
                "RSET" => {
                    self.reset();
                    self.reply(250, "2.0.0 OK");
                }
                "NOOP" => self.reply(250, "2.0.0 OK"),
                "VRFY" => self.reply(252, "2.5.0 Cannot verify user, but will accept message"),
                "HELP" => self.reply(214, "2.0.0 https://www.rfc-editor.org/rfc/rfc5321"),
                "QUIT" => {
                    self.reply(221, &format!("2.0.0 {} closing connection", self.hostname));
                    self.quit = true;
                }
                "GET" | "POST" | "HEAD" | "CONNECT" => {
                    // HTTP to an SMTP port: drop it.
                    self.quit = true;
                }
                _ => {
                    self.bad_commands += 1;
                    self.reply(500, "5.5.2 Command not recognized");
                    if self.bad_commands > 10 {
                        self.reply(421, "4.7.0 Too many errors");
                        self.quit = true;
                    }
                }
            }
        }
    }

    fn ehlo(&mut self, arg: &str, esmtp: bool) {
        if arg.is_empty() {
            self.reply(501, "5.5.4 Syntax: EHLO hostname");
            return;
        }
        self.helo = Some(arg.chars().take(255).collect());
        self.esmtp = esmtp;
        self.reset();
        if !esmtp {
            self.reply(250, &self.hostname.clone());
            return;
        }
        let max = self.state.settings().limits.max_message_bytes;
        let mut lines = vec![
            format!("{} Hello {}", self.hostname, arg),
            "PIPELINING".into(),
            format!("SIZE {max}"),
            "8BITMIME".into(),
            "ENHANCEDSTATUSCODES".into(),
            "SMTPUTF8".into(),
            "DSN".into(),
            "CHUNKING".into(),
        ];
        if !self.tls() {
            lines.push("STARTTLS".into());
        } else {
            lines.push("REQUIRETLS".into());
        }
        if self.account.is_none() && self.auth_allowed() {
            lines.push("AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER".into());
        }
        self.reply(250, &lines.join("\n"));
    }

    async fn auth(&mut self, arg: &str) -> anyhow::Result<()> {
        if self.helo.is_none() {
            self.reply(503, "5.5.1 EHLO first");
            return Ok(());
        }
        if self.account.is_some() {
            self.reply(503, "5.5.1 Already authenticated");
            return Ok(());
        }
        if self.from.is_some() {
            self.reply(503, "5.5.1 AUTH not permitted during a transaction");
            return Ok(());
        }
        if !self.auth_allowed() {
            self.reply(538, "5.7.11 Encryption required for requested authentication mechanism");
            return Ok(());
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut it = arg.split_whitespace();
        let mech = it.next().unwrap_or("").to_ascii_uppercase();
        let initial = it.next().map(|s| s.to_string());
        let (user, pass) = match mech.as_str() {
            "PLAIN" => {
                let data = match initial {
                    Some(d) if d == "=" => String::new(),
                    Some(d) => d,
                    None => match self.challenge("").await? {
                        Some(d) => d,
                        None => return Ok(()),
                    },
                };
                let Ok(raw) = b64.decode(data.trim()) else {
                    self.reply(501, "5.5.2 Invalid base64");
                    return Ok(());
                };
                let parts: Vec<&[u8]> = raw.split(|c| *c == 0).collect();
                if parts.len() != 3 {
                    self.reply(501, "5.5.2 Invalid PLAIN response");
                    return Ok(());
                }
                let authz = String::from_utf8_lossy(parts[0]).to_string();
                let user = String::from_utf8_lossy(parts[1]).to_string();
                if !authz.is_empty() && !authz.eq_ignore_ascii_case(&user) {
                    self.reply(535, "5.7.8 Authorization identity not permitted");
                    return Ok(());
                }
                (user, String::from_utf8_lossy(parts[2]).to_string())
            }
            "LOGIN" => {
                let u = match initial {
                    Some(u) => u,
                    None => match self.challenge("VXNlcm5hbWU6").await? {
                        Some(u) => u,
                        None => return Ok(()),
                    },
                };
                let Some(p) = self.challenge("UGFzc3dvcmQ6").await? else { return Ok(()) };
                let (Ok(u), Ok(p)) = (b64.decode(u.trim()), b64.decode(p.trim())) else {
                    self.reply(501, "5.5.2 Invalid base64");
                    return Ok(());
                };
                (String::from_utf8_lossy(&u).to_string(), String::from_utf8_lossy(&p).to_string())
            }
            "XOAUTH2" | "OAUTHBEARER" => {
                let data = match initial {
                    Some(d) => d,
                    None => match self.challenge("").await? {
                        Some(d) => d,
                        None => return Ok(()),
                    },
                };
                let parsed = b64.decode(data.trim()).ok().and_then(|raw| crate::auth::parse_oauth_sasl(&mech, &raw));
                let Some((u, t)) = parsed else {
                    self.reply(501, "5.5.2 Invalid OAuth response");
                    return Ok(());
                };
                (u, t)
            }
            _ => {
                self.reply(504, "5.5.4 Unrecognized authentication mechanism");
                return Ok(());
            }
        };
        match crate::auth::login_service(&self.state, &user, &pass, self.peer, crate::auth::Service::Smtp).await.map(|x| x.0) {
            Err(crate::auth::AuthError::PasswordDisabled) => {
                self.reply(535, "5.7.8 Account passwords are turned off; use an app password or OAuth");
            }
            Err(crate::auth::AuthError::ZeroAccess) => {
                self.reply(535, "5.7.8 Pinal Mail is zero-access: use an app password from accounts.pinal.tech/account#privacy (Open mode), or the Picacho app");
            }
            Ok(a) => {
                self.state.event("info", "auth", &format!("smtp login {} from {}", a.email, self.peer));
                self.account = Some(a);
                self.reply(235, "2.7.0 Authentication successful");
            }
            Err(crate::auth::AuthError::Banned) => {
                self.reply(421, "4.7.0 Too many failed attempts");
                self.quit = true;
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
                self.reply(535, "5.7.8 Authentication credentials invalid");
            }
        }
        Ok(())
    }

    async fn challenge(&mut self, prompt: &str) -> anyhow::Result<Option<String>> {
        self.conn.push(&format!("334 {prompt}\r\n"));
        self.conn.flush().await?;
        let line = match self.conn.read_line(16 * 1024).await {
            Ok(l) => String::from_utf8_lossy(&l).to_string(),
            Err(ReadError::Io(e)) => return Err(e.into()),
            Err(_) => return Ok(None),
        };
        if line.trim() == "*" {
            self.reply(501, "5.0.0 Authentication cancelled");
            return Ok(None);
        }
        Ok(Some(line))
    }

    /// Parse `FROM:<addr> PARAMS` / `TO:<addr> PARAMS`.
    fn path_arg(arg: &str, prefix: &str) -> Option<(String, Vec<(String, String)>)> {
        let rest = arg.get(..prefix.len()).filter(|p| p.eq_ignore_ascii_case(prefix)).map(|_| &arg[prefix.len()..])?;
        let rest = rest.trim_start();
        let (path, params) = if let Some(r) = rest.strip_prefix('<') {
            let end = r.find('>')?;
            (&r[..end], &r[end + 1..])
        } else {
            let end = rest.find(' ').unwrap_or(rest.len());
            (&rest[..end], &rest[end..])
        };
        // Strip source routes (@a,@b:user@host).
        let path = path.rsplit(':').next().unwrap_or(path).trim();
        let params = params
            .split_whitespace()
            .map(|p| match p.split_once('=') {
                Some((k, v)) => (k.to_ascii_uppercase(), v.to_string()),
                None => (p.to_ascii_uppercase(), String::new()),
            })
            .collect();
        Some((path.to_string(), params))
    }

    async fn mail(&mut self, arg: &str) {
        if self.helo.is_none() {
            self.reply(503, "5.5.1 EHLO/HELO first");
            return;
        }
        if self.from.is_some() {
            self.reply(503, "5.5.1 Nested MAIL command");
            return;
        }
        if self.mode == Mode::Submission && self.account.is_none() {
            self.reply(530, "5.7.0 Authentication required");
            return;
        }
        let Some((addr, params)) = Self::path_arg(arg, "FROM:") else {
            self.reply(501, "5.5.4 Syntax: MAIL FROM:<address>");
            return;
        };
        self.dsn = Default::default();
        self.requiretls = false;
        let max = self.state.settings().limits.max_message_bytes;
        for (k, v) in &params {
            match k.as_str() {
                "SIZE" => {
                    if v.parse::<u64>().map(|s| s > max).unwrap_or(true) {
                        self.reply(552, "5.3.4 Message size exceeds fixed maximum message size");
                        return;
                    }
                }
                "BODY" => {
                    if !matches!(v.to_ascii_uppercase().as_str(), "7BIT" | "8BITMIME") {
                        self.reply(555, "5.5.4 Unsupported BODY type");
                        return;
                    }
                }
                "SMTPUTF8" | "AUTH" => {}
                "RET" => {
                    let r = v.to_ascii_uppercase();
                    if r != "FULL" && r != "HDRS" {
                        self.reply(501, "5.5.4 RET must be FULL or HDRS");
                        return;
                    }
                    self.dsn.ret = r;
                }
                "ENVID" => {
                    let e = crate::outbound::xtext_decode(v);
                    if e.len() > 100 || e.chars().any(|c| c.is_control()) {
                        self.reply(501, "5.5.4 Invalid ENVID");
                        return;
                    }
                    self.dsn.envid = e;
                }
                "REQUIRETLS" => {
                    if !self.tls() {
                        self.reply(530, "5.7.10 REQUIRETLS needs a TLS connection");
                        return;
                    }
                    self.requiretls = true;
                }
                _ => {
                    self.reply(555, &format!("5.5.4 Unsupported parameter {k}"));
                    return;
                }
            }
        }
        let sender = if addr.is_empty() {
            String::new()
        } else {
            match crate::util::normalize_address(&addr) {
                Some(a) => a,
                None => {
                    self.reply(553, "5.1.7 Invalid sender address");
                    return;
                }
            }
        };
        if let Some(acc) = self.account.clone() {
            let sec = self.state.settings().security.clone();
            if sec.enforce_sender_ownership && !acc.is_admin() && !self.owns_address(&acc, &sender).await {
                self.reply(553, &format!("5.7.1 Sender address not owned by {}", acc.email));
                return;
            }
            let limit = self.state.settings().limits.send_rate_per_hour;
            if limit > 0 {
                if let Ok(n) = self.state.db.record_send(acc.id).await {
                    if n > limit as i64 {
                        self.reply(450, "4.7.1 Hourly sending limit reached, try again later");
                        return;
                    }
                }
            }
        }
        self.from = Some(sender);
        self.rcpts.clear();
        self.reply(250, "2.1.0 OK");
    }

    /// Forget the current transaction (RSET, EHLO, after a message).
    fn reset(&mut self) {
        self.from = None;
        self.rcpts.clear();
        self.dsn = Default::default();
        self.requiretls = false;
        self.bdat = None;
        self.bdat_too_big = false;
    }

    async fn owns_address(&self, acc: &Account, sender: &str) -> bool {
        if sender.is_empty() || sender == acc.email {
            return true;
        }
        if let Some((l, d)) = sender.rsplit_once('@') {
            if let Some((base, _)) = l.split_once('+') {
                if format!("{base}@{d}") == acc.email {
                    return true;
                }
            }
        }
        match self.state.db.alias_by_source(sender).await {
            Ok(Some(a)) => a.destination.split([',', ' ']).any(|d| d.trim().eq_ignore_ascii_case(&acc.email)),
            _ => false,
        }
    }

    async fn rcpt(&mut self, arg: &str) {
        if self.from.is_none() {
            self.reply(503, "5.5.1 MAIL first");
            return;
        }
        let max = self.state.settings().limits.max_recipients;
        if self.rcpts.len() >= max {
            self.reply(452, "4.5.3 Too many recipients");
            return;
        }
        let Some((addr, params)) = Self::path_arg(arg, "TO:") else {
            self.reply(501, "5.5.4 Syntax: RCPT TO:<address>");
            return;
        };
        let mut rdsn = crate::outbound::RcptDsn::default();
        for (k, v) in &params {
            match k.as_str() {
                "NOTIFY" => {
                    let parts: Vec<String> = v.split(',').map(|p| p.trim().to_ascii_uppercase()).collect();
                    let ok = parts.iter().all(|p| matches!(p.as_str(), "NEVER" | "SUCCESS" | "FAILURE" | "DELAY"))
                        && (!parts.contains(&"NEVER".to_string()) || parts.len() == 1);
                    if !ok {
                        self.reply(501, "5.5.4 Invalid NOTIFY");
                        return;
                    }
                    rdsn.notify = parts.join(",");
                }
                "ORCPT" => {
                    let Some((t, a)) = v.split_once(';') else {
                        self.reply(501, "5.5.4 Invalid ORCPT");
                        return;
                    };
                    rdsn.orcpt = format!("{t};{}", crate::outbound::xtext_decode(a));
                }
                _ => {
                    self.reply(555, &format!("5.5.4 Unsupported parameter {k}"));
                    return;
                }
            }
        }
        let relay_ok = self.account.as_ref().is_some_and(|a| a.can_send_external);
        match delivery::resolve(&self.state, &addr, relay_ok).await {
            Ok(targets) => {
                // Refuse up front when a local mailbox is full, so the
                // sender retries or bounces instead of losing the message.
                for t in &targets {
                    if let Target::Local(id) = t {
                        if let Ok(Some(a)) = self.state.db.get_account(*id).await {
                            if a.quota_bytes > 0 && a.used_bytes >= a.quota_bytes {
                                self.reply(452, "4.2.2 Mailbox full, try again later");
                                return;
                            }
                        }
                    }
                }
                let norm = crate::util::normalize_address(&addr).unwrap_or(addr);
                if rdsn != crate::outbound::RcptDsn::default() {
                    self.dsn.rcpts.insert(norm.clone(), rdsn);
                }
                self.rcpts.push((norm, targets));
                self.reply(250, "2.1.5 OK");
            }
            Err(RcptError::NoSuchUser) => self.reply(550, "5.1.1 Recipient address rejected: user unknown"),
            Err(RcptError::Disabled) => self.reply(550, "5.2.1 Mailbox disabled"),
            Err(RcptError::RelayDenied) => {
                if self.account.is_some() {
                    self.reply(550, "5.7.1 This account may not send to external recipients")
                } else {
                    self.reply(554, "5.7.1 Relay access denied")
                }
            }
            Err(RcptError::Temporary) => self.reply(451, "4.3.0 Temporary lookup failure"),
        }
    }

    async fn data(&mut self) -> anyhow::Result<()> {
        if self.from.is_none() {
            self.reply(503, "5.5.1 MAIL first");
            return Ok(());
        }
        if self.rcpts.is_empty() {
            self.reply(554, "5.5.1 No valid recipients");
            return Ok(());
        }
        self.reply(354, "Start mail input; end with <CRLF>.<CRLF>");
        self.conn.flush().await?;
        let max = self.state.settings().limits.max_message_bytes as usize;
        let mut body = Vec::with_capacity(16 * 1024);
        let mut too_big = false;
        loop {
            let mut line = Vec::new();
            let n = tokio::time::timeout(Duration::from_secs(600), self.conn.reader.read_until(b'\n', &mut line)).await??;
            if n == 0 {
                anyhow::bail!("connection closed during DATA");
            }
            let content = line.strip_suffix(b"\n").unwrap_or(&line);
            let content = content.strip_suffix(b"\r").unwrap_or(content);
            if content == b"." {
                break;
            }
            let content = content.strip_prefix(b".").unwrap_or(content);
            if body.len() + content.len() + 2 > max {
                too_big = true;
                continue;
            }
            body.extend_from_slice(content);
            body.extend_from_slice(b"\r\n");
        }
        if too_big {
            self.reply(552, "5.3.4 Message size exceeds fixed maximum message size");
            self.from = None;
            self.rcpts.clear();
            return Ok(());
        }
        let result = self.accept_message(body).await;
        self.reset();
        self.finish(result);
        Ok(())
    }

    fn finish(&mut self, result: Result<String, DataError>) {
        match result {
            Ok(id) => {
                crate::metrics::SMTP_ACCEPTED.inc();
                self.reply(250, &format!("2.0.0 OK queued as {id}"))
            }
            Err(DataError::Reject(code, msg)) => {
                crate::metrics::SMTP_REJECTED.inc();
                self.reply(code, &msg)
            }
            Err(DataError::Internal(e)) => {
                tracing::error!("delivery failed: {e:#}");
                self.reply(451, "4.3.0 Local error in processing, try again later");
            }
        }
    }

    /// BDAT <size> [LAST] (RFC 3030). The chunk is always read, even when
    /// the command is refused, to stay in sync with the client.
    async fn bdat(&mut self, arg: &str) -> anyhow::Result<()> {
        use tokio::io::AsyncReadExt;
        let mut it = arg.split_whitespace();
        let Some(size) = it.next().and_then(|n| n.parse::<u64>().ok()) else {
            self.reply(501, "5.5.4 Syntax: BDAT <size> [LAST]");
            self.quit = true;
            return Ok(());
        };
        let last = it.next().is_some_and(|l| l.eq_ignore_ascii_case("LAST"));
        let max = self.state.settings().limits.max_message_bytes;
        // Read (or discard) the chunk.
        let mut chunk = Vec::new();
        let keep = self.from.is_some() && !self.rcpts.is_empty() && !self.bdat_too_big;
        let current = self.bdat.as_ref().map(|b| b.len() as u64).unwrap_or(0);
        let fits = current + size <= max;
        let mut remaining = size;
        let mut buf = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let n = remaining.min(buf.len() as u64) as usize;
            let got = tokio::time::timeout(Duration::from_secs(600), self.conn.reader.read(&mut buf[..n])).await??;
            if got == 0 {
                anyhow::bail!("connection closed during BDAT");
            }
            if keep && fits {
                chunk.extend_from_slice(&buf[..got]);
            }
            remaining -= got as u64;
        }
        if self.from.is_none() {
            self.reply(503, "5.5.1 MAIL first");
            return Ok(());
        }
        if self.rcpts.is_empty() {
            self.reply(554, "5.5.1 No valid recipients");
            return Ok(());
        }
        if !fits {
            self.bdat_too_big = true;
        }
        if !self.bdat_too_big {
            self.bdat.get_or_insert_with(Vec::new).extend_from_slice(&chunk);
        }
        if !last {
            self.reply(250, &format!("2.0.0 {size} octets received"));
            return Ok(());
        }
        if self.bdat_too_big {
            self.reset();
            self.reply(552, "5.3.4 Message size exceeds fixed maximum message size");
            return Ok(());
        }
        let body = crate::util::normalize_crlf(&self.bdat.take().unwrap_or_default());
        let result = self.accept_message(body).await;
        self.reset();
        self.finish(result);
        Ok(())
    }

    async fn dnsbl_listed(&self, lists: &[String]) -> Option<String> {
        let IpAddr::V4(v4) = self.peer else { return None };
        let resolver = self.state.resolver.as_ref()?.resolver();
        let o = v4.octets();
        for zone in lists {
            let name = format!("{}.{}.{}.{}.{}.", o[3], o[2], o[1], o[0], zone.trim_end_matches('.'));
            if let Ok(Ok(r)) = tokio::time::timeout(Duration::from_secs(3), resolver.ipv4_lookup(name)).await {
                if !r.answers().is_empty() {
                    return Some(zone.clone());
                }
            }
        }
        None
    }

    async fn reverse_dns(&self) -> Option<String> {
        let resolver = self.state.resolver.as_ref()?.resolver();
        let r = tokio::time::timeout(Duration::from_secs(3), resolver.reverse_lookup(self.peer)).await.ok()?.ok()?;
        r.answers().iter().find_map(|rec| match &rec.data {
            mail_auth::hickory_resolver::proto::rr::RData::PTR(p) => Some(p.0.to_string().trim_end_matches('.').to_string()),
            _ => None,
        })
    }

    async fn accept_message(&mut self, body: Vec<u8>) -> Result<String, DataError> {
        let id = uuid::Uuid::new_v4().simple().to_string()[..16].to_string();
        let sender = self.from.clone().unwrap_or_default();
        let authed = self.account.is_some();
        let tls = self.conn.stream().tls_info();
        let with = match (tls.is_some(), authed) {
            (true, true) => "ESMTPSA",
            (true, false) => "ESMTPS",
            (false, true) => "ESMTPA",
            (false, false) => "ESMTP",
        };
        let helo = self.helo.clone().unwrap_or_default();
        let rdns = self.rdns.clone().unwrap_or_else(|| "unknown".into());
        let date = chrono::Utc::now().to_rfc2822();
        let mut received = format!(
            "Received: from {helo} ({rdns} [{}])\r\n\tby {} (Picacho Server) with {with} id {id}",
            self.peer, self.hostname
        );
        if let Some(t) = &tls {
            received.push_str(&format!("\r\n\t(using {t})"));
        }
        if self.rcpts.len() == 1 {
            received.push_str(&format!("\r\n\tfor <{}>", self.rcpts[0].0));
        }
        received.push_str(&format!(";\r\n\t{date}\r\n"));

        // Group targets.
        let mut local: BTreeSet<i64> = BTreeSet::new();
        let mut remote: BTreeSet<String> = BTreeSet::new();
        let mut transports: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut peers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut forwarded = false;
        let mut local_rcpt: BTreeMap<i64, String> = BTreeMap::new();
        for (orig, targets) in &self.rcpts {
            for t in targets {
                match t {
                    Target::Local(a) => {
                        local.insert(*a);
                        local_rcpt.entry(*a).or_insert_with(|| orig.clone());
                    }
                    Target::Remote(r) => {
                        if r != orig {
                            forwarded = true;
                        }
                        remote.insert(r.clone());
                    }
                    Target::Transport(addr, tr) => transports.entry(tr.clone()).or_default().push(addr.clone()),
                    Target::Peer(addr, p) => peers.entry(p.clone()).or_default().push(addr.clone()),
                }
            }
        }

        // Inbound authentication checks for unauthenticated (MX) mail.
        let mut junk = false;
        let mut auth_header = String::new();
        let mut arc_header = String::new();
        let mut summary = None;
        let settings = self.state.settings();
        if !authed && settings.security.verify_inbound {
            if let Some(r) = self.state.resolver.as_ref() {
                let seal = forwarded && !authed && settings.delivery.arc_seal;
                match check_inbound(r, &self.state, &body, self.peer, &helo, &sender, &self.hostname, seal).await {
                    Verdict::Reject(msg) => {
                        self.state.event("info", "smtp", &format!("rejected mail from {sender} ({}): {msg}", self.peer));
                        return Err(DataError::Reject(550, format!("5.7.1 {msg}")));
                    }
                    Verdict::Accept { header, quarantine, arc, auth } => {
                        auth_header = header;
                        arc_header = arc;
                        junk = quarantine;
                        summary = Some(auth);
                    }
                }
            }
        }
        // Content filter.
        let ctx = crate::filter::Context {
            ip: Some(self.peer),
            helo: helo.clone(),
            rdns: self.rdns.clone(),
            sender: sender.clone(),
            rcpts: self.rcpts.iter().map(|r| r.0.clone()).collect(),
            accounts: local.iter().copied().collect(),
            authenticated: authed,
            auth: summary,
            dnsbl: self.dnsbl_hit.clone(),
            relayed: false,
        };
        let verdict = crate::filter::scan(&self.state, &ctx, &body).await;
        if let Some(msg) = &verdict.tempfail {
            return Err(DataError::Reject(451, msg.clone()));
        }
        if let Some(msg) = &verdict.reject {
            self.state.event("info", "filter", &format!("rejected mail from <{sender}> ({}): {msg} [{:.1}]", self.peer, verdict.score));
            return Err(DataError::Reject(if verdict.virus.is_some() { 554 } else { 550 }, msg.clone()));
        }
        junk |= verdict.junk;
        let spam_headers = crate::filter::apply_headers(&verdict, Vec::new());

        let mut message = Vec::with_capacity(body.len() + received.len() + auth_header.len() + 256);
        message.extend_from_slice(format!("Return-Path: <{sender}>\r\n").as_bytes());
        message.extend_from_slice(&spam_headers);
        message.extend_from_slice(arc_header.as_bytes());
        message.extend_from_slice(auth_header.as_bytes());
        message.extend_from_slice(received.as_bytes());
        message.extend_from_slice(&body);

        let mut delivered_local = vec![];
        for acc in local {
            deliver_local_from(&self.state, acc, &sender, local_rcpt.get(&acc).map(|s| s.as_str()).unwrap_or(""), &message, junk)
                .await
                .map_err(DataError::Internal)?;
            delivered_local.push(acc);
        }
        crate::reports::maybe_ingest(&self.state, &self.rcpts.iter().map(|r| r.0.clone()).collect::<Vec<_>>(), &body).await;
        if !remote.is_empty() {
            let rcpts: Vec<String> = remote.into_iter().collect();
            let (env_from, payload) = if authed {
                let signed = delivery::dkim_sign(&self.state, crate::util::domain_of(&sender), body.clone()).await;
                let mut m = received.clone().into_bytes();
                m.extend_from_slice(&signed);
                (sender.clone(), m)
            } else {
                // Forwarded inbound mail: rewrite the envelope sender (SRS).
                let s = if forwarded { delivery::srs_forward(&self.state, &sender).await } else { sender.clone() };
                (s, message.clone())
            };
            crate::queue::enqueue_ext(&self.state, &env_from, &rcpts, &payload, "", &self.dsn, self.requiretls).await.map_err(DataError::Internal)?;
        }
        for (tr, rcpts) in transports {
            crate::queue::enqueue_ext(&self.state, &sender, &rcpts, &message, &format!("transport:{tr}"), &self.dsn, self.requiretls)
                .await
                .map_err(DataError::Internal)?;
        }
        for (p, rcpts) in peers {
            crate::relay::hold_for_peer(&self.state, &p, &sender, &rcpts, &message).await.map_err(DataError::Internal)?;
        }
        // "delivered" notifications for local recipients that asked for them.
        if !sender.is_empty() {
            let notes: Vec<crate::queue::Notice> = self
                .rcpts
                .iter()
                .filter(|(r, t)| t.iter().any(|x| matches!(x, Target::Local(_))) && self.dsn.rcpt(r).notify.contains("SUCCESS"))
                .map(|(r, _)| crate::queue::Notice { rcpt: r.clone(), action: "delivered", status: "2.0.0".into(), diag: String::new() })
                .collect();
            if !notes.is_empty() {
                let d = crate::queue::build_dsn(&self.state, &sender, &body, &self.dsn, &notes);
                let _ = crate::queue::send_report(&self.state, &sender, &d).await;
            }
        }
        let who = self.account.as_ref().map(|a| a.email.clone()).unwrap_or_else(|| self.peer.to_string());
        self.state.event(
            "info",
            "smtp",
            &format!(
                "accepted {id} from <{sender}> ({who}) for {} recipient(s), {} bytes{}",
                self.rcpts.len(),
                message.len(),
                if verdict.scanned { format!(", spam score {:.1}{}", verdict.score, if junk { " (junk)" } else { "" }) } else { String::new() }
            ),
        );
        Ok(id)
    }
}

enum DataError {
    Reject(u16, String),
    Internal(anyhow::Error),
}

enum Verdict {
    Accept { header: String, quarantine: bool, arc: String, auth: crate::filter::AuthSummary },
    Reject(String),
}

#[allow(clippy::too_many_arguments)]
async fn check_inbound(
    auth: &mail_auth::MessageAuthenticator,
    state: &State,
    body: &[u8],
    ip: IpAddr,
    helo: &str,
    sender: &str,
    hostname: &str,
    seal: bool,
) -> Verdict {
    use mail_auth::{AuthenticatedMessage, AuthenticationResults, DkimResult, DmarcResult, SpfResult};
    let empty = || Verdict::Accept { header: String::new(), quarantine: false, arc: String::new(), auth: Default::default() };
    let Some(msg) = AuthenticatedMessage::parse(body) else {
        return empty();
    };
    let timeout = Duration::from_secs(10);
    let mail_from_domain = if sender.is_empty() { helo.to_string() } else { crate::util::domain_of(sender).to_string() };
    let spf_params = if sender.is_empty() {
        mail_auth::spf::verify::SpfParameters::helo(ip, helo, hostname)
    } else {
        mail_auth::spf::verify::SpfParameters::mail_from(ip, helo, hostname, sender)
    };
    let spf = tokio::time::timeout(timeout, auth.verify_spf(spf_params)).await;
    let dkim = tokio::time::timeout(timeout, auth.verify_dkim(&msg)).await;
    let arc = tokio::time::timeout(timeout, auth.verify_arc(&msg)).await;
    let (Ok(spf), Ok(dkim)) = (spf, dkim) else {
        return empty();
    };
    let dmarc = tokio::time::timeout(
        timeout,
        auth.verify_dmarc(mail_auth::dmarc::verify::DmarcParameters::new(&msg, &dkim, &mail_from_domain, &spf)),
    )
    .await;
    let header_from = msg.from_addresses().first().map(|s| s.as_str()).unwrap_or("");
    let mut ar = AuthenticationResults::new(hostname).with_dkim_results(&dkim, header_from).with_spf_result(&spf, &spf_params);
    if let Ok(a) = &arc {
        ar = ar.with_arc_result(a, ip);
    }
    let mut summary = crate::filter::AuthSummary {
        spf: match spf.result() {
            SpfResult::Pass => "pass",
            SpfResult::Fail => "fail",
            SpfResult::SoftFail => "softfail",
            SpfResult::Neutral => "neutral",
            SpfResult::None => "none",
            _ => "error",
        }
        .into(),
        dkim: if dkim.iter().any(|d| d.result() == &DkimResult::Pass) {
            "pass"
        } else if dkim.is_empty() {
            "none"
        } else {
            "fail"
        }
        .into(),
        dmarc: "none".into(),
        arc: match &arc {
            Ok(a) => match a.result() {
                DkimResult::Pass => "pass",
                DkimResult::None => "none",
                _ => "fail",
            }
            .into(),
            Err(_) => "none".into(),
        },
    };
    let mut quarantine = false;
    let mut disposition = "none";
    if let Ok(dmarc) = &dmarc {
        ar = ar.with_dmarc_result(dmarc);
        let failed = dmarc.dkim_result() != &DmarcResult::Pass && dmarc.spf_result() != &DmarcResult::Pass;
        summary.dmarc = if failed { if matches!(dmarc.result(), DmarcResult::None) { "none" } else { "fail" } } else { "pass" }.into();
        // A valid ARC chain from a trusted forwarder could override this; we
        // record it but still apply the sender's policy.
        if failed {
            let sec = state.settings().security.clone();
            match dmarc.policy() {
                mail_auth::dmarc::Policy::Reject if sec.honor_dmarc_reject => {
                    crate::reports::record_dmarc(state, dmarc.domain(), ip, header_from, "reject", &dkim, &spf, &mail_from_domain).await;
                    return Verdict::Reject("Message rejected due to DMARC policy".into());
                }
                mail_auth::dmarc::Policy::Reject | mail_auth::dmarc::Policy::Quarantine => {
                    quarantine = sec.quarantine_to_junk;
                    if quarantine {
                        disposition = "quarantine";
                    }
                }
                _ => {}
            }
        }
        if !dmarc.domain().is_empty() && !matches!(dmarc.result(), DmarcResult::None) {
            crate::reports::record_dmarc(state, dmarc.domain(), ip, header_from, disposition, &dkim, &spf, &mail_from_domain).await;
        }
    }
    let _ = spf.result() == SpfResult::Pass;
    let header = mail_auth::headers::HeaderWriter::to_header(&ar);
    // ARC-seal mail we are about to forward, so the next hop can trust our results.
    let mut arc_out = String::new();
    if seal {
        if let Ok(a) = &arc {
            if a.can_be_sealed() {
                if let Some((key, d, sel)) = delivery::signing_key(state, None).await {
                    let sealer = mail_auth::arc::ArcSealer::from_key(key)
                        .domain(d)
                        .selector(sel)
                        .headers(["From", "To", "Cc", "Subject", "Date", "Message-ID", "Reply-To", "In-Reply-To", "References", "MIME-Version", "Content-Type", "DKIM-Signature"]);
                    match sealer.seal(&msg, &ar, a) {
                        Ok(set) => arc_out = mail_auth::headers::HeaderWriter::to_header(&set),
                        Err(e) => tracing::debug!("arc seal: {e}"),
                    }
                }
            }
        }
    }
    Verdict::Accept { header, quarantine, arc: arc_out, auth: summary }
}

/// Deliver to an account's INBOX (or Junk), without a known envelope.
pub async fn deliver_local(state: &State, account_id: i64, message: &[u8], junk: bool) -> anyhow::Result<()> {
    deliver_local_from(state, account_id, "", "", message, junk).await
}

/// Local delivery with the envelope: runs the account's Sieve script (and
/// vacation responder), then stores the message where it says.
pub async fn deliver_local_from(state: &State, account_id: i64, sender: &str, rcpt: &str, message: &[u8], junk: bool) -> anyhow::Result<()> {
    let plan = crate::sieve::deliver::plan(state, account_id, sender, rcpt, message, junk).await;
    crate::sieve::deliver::execute(state, account_id, sender, message, plan).await
}

/// Store in a named folder (created when missing), falling back to INBOX.
pub async fn store_in(state: &State, account_id: i64, folder: &str, message: &[u8], flags: &str) -> anyhow::Result<()> {
    let mb = match state.db.mailbox(account_id, folder).await? {
        Some(m) => Some(m),
        None if folder.eq_ignore_ascii_case("INBOX") => None,
        None => {
            // "Junk" may exist under another name with the \Junk special use.
            let special = match folder {
                "Junk" => state.db.mailbox_by_special(account_id, "\\Junk").await?,
                _ => None,
            };
            match special {
                Some(m) => Some(m),
                None => match state.db.create_mailbox(account_id, folder, "").await {
                    Ok(id) => state.db.mailbox_by_id(id).await?,
                    Err(_) => None,
                },
            }
        }
    };
    let mb = match mb {
        Some(m) => m,
        None => match state.db.mailbox(account_id, "INBOX").await? {
            Some(m) => m,
            None => {
                let id = state.db.create_mailbox(account_id, "INBOX", "").await?;
                state.db.mailbox_by_id(id).await?.unwrap()
            }
        },
    };
    match crate::server::store_message(state, account_id, &mb, message, flags, None).await {
        Ok(_) => {
            crate::metrics::LOCAL_DELIVERIES.inc();
            Ok(())
        }
        Err(crate::server::StoreError::OverQuota) => {
            state.event("warn", "delivery", &format!("account {account_id} is over quota; message dropped to bounce"));
            anyhow::bail!("recipient over quota")
        }
        Err(crate::server::StoreError::Other(e)) => Err(e),
    }
}

/// Deliver a message to one resolved target (relay link, reports).
pub async fn deliver_target(state: &State, sender: &str, raw: &[u8], t: Target, junk: bool) -> anyhow::Result<()> {
    match t {
        Target::Local(acc) => deliver_local_from(state, acc, sender, "", raw, junk).await,
        Target::Remote(r) => crate::queue::enqueue(state, sender, &[r], raw, "").await.map(|_| ()),
        Target::Transport(r, tr) => crate::queue::enqueue(state, sender, &[r], raw, &format!("transport:{tr}")).await.map(|_| ()),
        Target::Peer(r, p) => crate::relay::hold_for_peer(state, &p, sender, &[r], raw).await,
    }
}
