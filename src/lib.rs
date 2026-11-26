//! Picacho Server: an IMAP4rev1/SMTP mail server with a web postmaster console.
//!
//! Layout:
//! - `config`   static configuration (config.toml), every field optional
//! - `settings` live settings edited from the web console (database or file)
//! - `db`       metadata store (SQLite or PostgreSQL)
//! - `blob`     message/attachment store (local disk, S3, or the database)
//! - `mime`     MIME structure, ENVELOPE and BODYSTRUCTURE
//! - `imap`     IMAP server
//! - `smtp`     SMTP server (MX, submission) and local delivery
//! - `queue`    outbound queue: direct MX, smarthosts and webhooks
//! - `web`      postmaster console and JSON API
pub mod acme;
pub mod auth;
pub mod blob;
pub mod config;
pub mod dav;
pub mod db;
pub mod dbx;
pub mod events;
pub mod filter;
pub mod imap;
pub mod jmap;
pub mod metrics;
pub mod mime;
pub mod net;
pub mod oidc;
pub mod ops;
pub mod outbound;
pub mod queue;
pub mod relay;
pub mod reports;
pub mod resource;
pub mod server;
pub mod settings;
pub mod sieve;
pub mod smtp;
pub mod state;
pub mod tls;
pub mod util;
pub mod web;
pub mod xml;
pub mod za;
