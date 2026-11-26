use clap::{Parser, Subcommand};
use picacho_server::{config::Config, server, state::AppState};
use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "picacho-server", version, about = "Picacho Server server")]
struct Cli {
    /// Path to config.toml (optional; every setting has a default).
    #[arg(short, long, env = "PICACHO_CONFIG", default_value = "config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server (default).
    Serve,
    /// Validate config.toml and print the effective configuration.
    CheckConfig,
    /// Set an account's password (reads the new password from stdin).
    Passwd { email: String },
    /// Back up the database and every stored object into a directory.
    Backup { dir: PathBuf },
    /// Restore a backup into an empty database and stores.
    Restore { dir: PathBuf },
    /// Export one account (mail, filters, vacation, calendars, contacts, files) as a zip.
    Export { email: String, out: PathBuf },
    /// Import a Picacho export zip, a zipped Maildir or an mbox file into an account.
    Import {
        email: String,
        file: PathBuf,
        /// Folder for mbox imports.
        #[arg(long, default_value = "Imported")]
        folder: String,
    },
    /// Request or renew the ACME certificate now.
    RenewCert,
}

fn init_logging(cfg: &Config) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("PICACHO_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(format!("{},sqlx=warn,hickory=warn,lettre=warn", cfg.log.level)));
    let b = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    if cfg.log.format == "json" {
        b.json().init();
    } else {
        b.init();
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;
    match cli.command.unwrap_or(Command::Serve) {
        Command::CheckConfig => {
            println!("{cfg:#?}");
            println!("database: {}", redact_url(&cfg.database_url()?));
            Ok(())
        }
        Command::Passwd { email } => {
            init_logging(&cfg);
            let state = AppState::with_path(cfg, cli.config.clone()).await?;
            let acc = state.db.account_by_email(&email).await?.ok_or_else(|| anyhow::anyhow!("no account {email}"))?;
            eprint!("New password for {email}: ");
            let _ = std::io::stderr().flush();
            let mut pw = String::new();
            std::io::stdin().read_line(&mut pw)?;
            let pw = pw.trim_end_matches(['\r', '\n']);
            picacho_server::auth::check_password_strength(pw, state.settings().security.password_min_length)
                .map_err(|e| anyhow::anyhow!(e))?;
            state.db.set_password(acc.id, &picacho_server::auth::hash_password(pw)?).await?;
            eprintln!("Password updated.");
            Ok(())
        }
        Command::Backup { dir } => {
            init_logging(&cfg);
            let state = AppState::with_path(cfg, cli.config.clone()).await?;
            let m = picacho_server::ops::backup(&state, &dir).await?;
            println!("{}", serde_json::to_string_pretty(&m)?);
            Ok(())
        }
        Command::Restore { dir } => {
            init_logging(&cfg);
            let state = AppState::with_path(cfg, cli.config.clone()).await?;
            let m = picacho_server::ops::restore(&state, &dir).await?;
            println!("{}", serde_json::to_string_pretty(&m)?);
            Ok(())
        }
        Command::Export { email, out } => {
            init_logging(&cfg);
            let state = AppState::with_path(cfg, cli.config.clone()).await?;
            let acc = state.db.account_by_email(&email).await?.ok_or_else(|| anyhow::anyhow!("no account {email}"))?;
            picacho_server::ops::export_account(&state, acc.id, &out).await?;
            eprintln!("Exported {email} to {}", out.display());
            Ok(())
        }
        Command::Import { email, file, folder } => {
            init_logging(&cfg);
            let state = AppState::with_path(cfg, cli.config.clone()).await?;
            let acc = state.db.account_by_email(&email).await?.ok_or_else(|| anyhow::anyhow!("no account {email}"))?;
            let data = std::fs::read(&file)?;
            let stats = picacho_server::ops::import_account(&state, acc.id, data, &folder).await?;
            println!("{}", serde_json::to_string_pretty(&stats)?);
            Ok(())
        }
        Command::RenewCert => {
            init_logging(&cfg);
            let state = AppState::with_path(cfg.clone(), cli.config.clone()).await?;
            // Answer HTTP-01 challenges while the request runs.
            if let Some(a) = &cfg.tls.acme {
                for addr in &a.http_listen {
                    if let Err(e) = picacho_server::web::wellknown::serve_http(state.clone(), *addr).await {
                        eprintln!("{e}");
                    }
                }
            }
            for addr in state.config.web.listen.clone() {
                let _ = picacho_server::web::serve(state.clone(), addr).await;
            }
            println!("{}", picacho_server::acme::issue(&state).await?);
            Ok(())
        }
        Command::Serve => serve(cfg, cli.config).await,
    }
}

fn redact_url(u: &str) -> String {
    match (u.find("://"), u.find('@')) {
        (Some(s), Some(at)) if at > s => format!("{}://***{}", &u[..s], &u[at..]),
        _ => u.to_string(),
    }
}

async fn serve(cfg: Config, path: PathBuf) -> anyhow::Result<()> {
    init_logging(&cfg);
    let state = AppState::with_path(cfg, path).await?;
    let mut failures = vec![];
    for addr in state.config.web.listen.clone() {
        if let Err(e) = picacho_server::web::serve(state.clone(), addr).await.map(|_| ()) {
            failures.push(e);
        }
    }
    let l = state.config.listen.clone();
    let groups = [
        (l.smtp, server::Proto::Smtp),
        (l.submission, server::Proto::Submission),
        (l.submissions, server::Proto::Submissions),
        (l.imap, server::Proto::Imap),
        (l.imaps, server::Proto::Imaps),
        (l.managesieve, server::Proto::ManageSieve),
    ];
    for (addrs, proto) in groups {
        for a in addrs {
            if let Err(e) = server::spawn_listener(state.clone(), a, proto).await.map(|_| ()) {
                failures.push(e);
            }
        }
    }
    if let Some(a) = &state.config.tls.acme {
        for addr in a.http_listen.clone() {
            if let Err(e) = picacho_server::web::wellknown::serve_http(state.clone(), addr).await {
                failures.push(e);
            }
        }
    }
    for f in &failures {
        tracing::error!("could not listen: {f}");
    }
    if state.listeners.lock().is_empty() {
        anyhow::bail!("no listeners could be started");
    }
    picacho_server::queue::spawn_worker(state.clone());
    picacho_server::relay::spawn_puller(state.clone());
    picacho_server::ops::spawn_maintenance(state.clone());
    picacho_server::acme::spawn(state.clone());
    picacho_server::dbx::spawn_indexer(state.clone());
    // Zero-access mail: re-check app passwords, drop idle keys (src/za.rs).
    tokio::spawn(picacho_server::za::keeper(state.clone()));
    {
        // Compute header metadata (SORT/THREAD/JMAP) for messages stored by older versions.
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok(rows) = st.db.messages_missing_meta(200).await else { break };
                if rows.is_empty() {
                    break;
                }
                for (id, blob) in rows {
                    let (meta, msgid) = match st.blobs.get(&blob).await {
                        Ok(raw) => {
                            let s = picacho_server::mime::summarize(&raw);
                            (s.meta, s.msgid)
                        }
                        Err(_) => ("{}".to_string(), String::new()),
                    };
                    let _ = st.db.set_meta(id, &meta, &msgid).await;
                }
            }
        });
    }
    {
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                let _ = st.db.prune_events(30).await;
                let _ = st.db.prune_changes(30).await;
                if let Ok(blobs) = st.db.expire_uploads(24 * 3600).await {
                    for b in blobs {
                        if st.db.release_blob(&b).await.unwrap_or(false) {
                            let _ = st.blobs.delete(&b).await;
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        });
    }

    let listening: Vec<String> = state
        .listeners
        .lock()
        .iter()
        .map(|v| format!("{} {}", v["protocol"].as_str().unwrap_or(""), v["address"].as_str().unwrap_or("")))
        .collect();
    tracing::info!("Picacho Server {} listening: {}", env!("CARGO_PKG_VERSION"), listening.join(", "));

    if state.setup_required() {
        // A restart during setup (storage step) keeps the same key.
        let handed = std::env::var("PICACHO_SETUP_KEY").ok().filter(|k| k.len() == 29);
        let key = match handed {
            Some(k) => {
                state.setup_key.set(&k);
                k
            }
            None => state.setup_key.generate(),
        };
        print_setup_banner(&state.config, &key);
        state.event("info", "setup", "server is waiting for setup; a new access key was printed to the console");
    } else {
        let urls = console_urls(&state.config);
        tracing::info!("web console: {}", urls.join("  "));
    }

    shutdown_signal().await;
    let grace = state.config.limits.shutdown_grace_secs;
    tracing::info!("shutting down: no new connections; waiting up to {grace}s for open sessions and deliveries");
    state.shutdown.cancel();
    state.tasks.close();
    let drained = tokio::select! {
        _ = state.tasks.wait() => true,
        _ = tokio::time::sleep(std::time::Duration::from_secs(grace)) => false,
        _ = shutdown_signal() => false,
    };
    if drained {
        tracing::info!("all sessions closed");
    } else {
        tracing::warn!("{} task(s) still running after {grace}s; exiting anyway (queued mail is retried on start)", state.tasks.len());
    }
    // Let the activity log writes finish.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    state.db.pool.close().await;
    Ok(())
}

fn local_ip() -> Option<std::net::IpAddr> {
    // No packets are sent; this only asks the OS which interface would route.
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

fn console_urls(cfg: &Config) -> Vec<String> {
    if let Some(u) = &cfg.web.public_url {
        return vec![u.trim_end_matches('/').to_string()];
    }
    let scheme = if cfg.web.tls { "https" } else { "http" };
    let mut out = vec![];
    for a in &cfg.web.listen {
        let port = a.port();
        if a.ip().is_unspecified() {
            out.push(format!("{scheme}://localhost:{port}"));
            if let Some(ip) = local_ip() {
                out.push(format!("{scheme}://{}", SocketAddr::new(ip, port)));
            }
        } else {
            out.push(format!("{scheme}://{a}"));
        }
    }
    out
}

fn print_setup_banner(cfg: &Config, key: &str) {
    let urls = console_urls(cfg);
    let color = std::io::stderr().is_terminal();
    let (b, g, d, r) = if color { ("\x1b[1m", "\x1b[32m", "\x1b[2m", "\x1b[0m") } else { ("", "", "", "") };
    let mut out = String::new();
    out.push_str(&format!("\n{g}  ▲{r} {b}Picacho Server is not set up yet{r}\n\n"));
    out.push_str("  Open the web console to create the admin account:\n");
    for u in &urls {
        out.push_str(&format!("    {b}{u}/setup{r}\n"));
    }
    out.push_str(&format!("\n  Access key:  {b}{g}{key}{r}\n"));
    out.push_str(&format!("  {d}A new key is printed on every start until setup is complete.{r}\n\n"));
    eprint!("{out}");
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
