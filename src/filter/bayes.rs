//! Bayesian spam classifier (Robinson/Fisher combining), trained per
//! account and server-wide. People train it by moving mail into and out of
//! Junk (IMAP COPY/MOVE, JMAP mailbox changes or $junk/$notjunk keywords).
use crate::db::Db;
use crate::state::State;
use anyhow::Result;
use sqlx::Row;
use std::collections::{BTreeSet, HashMap};

/// Global statistics live under account 0.
pub const GLOBAL: i64 = 0;
const MAX_TOKENS: usize = 1500;

/// Tokens of a message: subject words, body words, sender domain, link
/// domains and a few structural markers.
pub fn tokenize(raw: &[u8]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(msg) = mail_parser::MessageParser::default().parse(raw) else { return out };
    let words = |prefix: &str, text: &str, out: &mut BTreeSet<String>| {
        for w in text.split(|c: char| !(c.is_alphanumeric() || c == '\'' || c == '$' || c == '-')) {
            let w = w.trim_matches(|c: char| c == '\'' || c == '-');
            let n = w.chars().count();
            if (3..=24).contains(&n) && !w.chars().all(|c| c.is_ascii_digit()) {
                out.insert(format!("{prefix}{}", w.to_lowercase()));
                if out.len() >= MAX_TOKENS {
                    return;
                }
            }
        }
    };
    if let Some(s) = msg.subject() {
        words("s:", s, &mut out);
    }
    for i in 0..msg.text_body().len() {
        if let Some(t) = msg.body_text(i) {
            words("", &t, &mut out);
        }
    }
    if msg.text_body().len() == 0 {
        for i in 0..msg.html_body().len() {
            if let Some(h) = msg.body_html(i) {
                words("", &strip_html(&h), &mut out);
            }
        }
    }
    if let Some(from) = msg.from().and_then(|f| f.first()).and_then(|a| a.address().map(|s| s.to_string())) {
        let from = from.as_str();
        out.insert(format!("f:{}", crate::util::domain_of(from).to_ascii_lowercase()));
    }
    for d in super::link_domains(raw).into_iter().take(50) {
        out.insert(format!("u:{d}"));
    }
    if msg.has_attachments() {
        out.insert("x:has-attachment".into());
    }
    if !(msg.html_body().len() == 0) && (msg.text_body().len() == 0) {
        out.insert("x:html-only".into());
    }
    if let Some(x) = msg.headers().get("X-Mailer").map(|h| String::from_utf8_lossy(h.raw_value()).to_string()) {
        out.insert(format!("m:{}", x.trim().to_ascii_lowercase().chars().take(40).collect::<String>()));
    }
    out
}

pub fn strip_html(h: &str) -> String {
    let mut out = String::with_capacity(h.len() / 2);
    let mut in_tag = false;
    for c in h.chars() {
        match c {
            '<' => {
                in_tag = true;
                out.push(' ');
            }
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&nbsp;", " ").replace("&amp;", "&")
}

impl Db {
    async fn bayes_totals(&self, accounts: &[i64]) -> Result<(i64, i64)> {
        let mut spam = 0;
        let mut ham = 0;
        for a in accounts {
            if let Some(r) = sqlx::query("SELECT spam, ham FROM bayes_totals WHERE account_id = $1").bind(a).fetch_optional(&self.pool).await? {
                spam += r.get::<i64, _>(0);
                ham += r.get::<i64, _>(1);
            }
        }
        Ok((spam, ham))
    }

    async fn bayes_counts(&self, accounts: &[i64], tokens: &[String]) -> Result<HashMap<String, (i64, i64)>> {
        let mut out: HashMap<String, (i64, i64)> = HashMap::new();
        for chunk in tokens.chunks(200) {
            for a in accounts {
                let placeholders: Vec<String> = (0..chunk.len()).map(|i| format!("${}", i + 2)).collect();
                let q = format!("SELECT token, spam, ham FROM bayes_tokens WHERE account_id = $1 AND token IN ({})", placeholders.join(","));
                let mut query = sqlx::query(&q).bind(a);
                for t in chunk {
                    query = query.bind(t);
                }
                for r in query.fetch_all(&self.pool).await? {
                    let e = out.entry(r.get::<String, _>(0)).or_default();
                    e.0 += r.get::<i64, _>(1);
                    e.1 += r.get::<i64, _>(2);
                }
            }
        }
        Ok(out)
    }

    /// Add (sign = 1) or remove (sign = -1) a message's tokens from a class.
    async fn bayes_apply(&self, account: i64, tokens: &[String], spam: bool, sign: i64) -> Result<()> {
        let mut tx = self.begin().await?;
        let col = if spam { "spam" } else { "ham" };
        for t in tokens {
            sqlx::query(&format!(
                "INSERT INTO bayes_tokens (account_id, token, {col}, updated_at) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (account_id, token) DO UPDATE SET {col} = CASE WHEN bayes_tokens.{col} + $3 < 0 THEN 0 ELSE bayes_tokens.{col} + $3 END,
                 updated_at = $4"
            ))
            .bind(account)
            .bind(t)
            .bind(sign.max(0))
            .bind(crate::util::now())
            .execute(&mut *tx.tx)
            .await?;
            if sign < 0 {
                sqlx::query(&format!("UPDATE bayes_tokens SET {col} = CASE WHEN {col} > 0 THEN {col} - 1 ELSE 0 END WHERE account_id = $1 AND token = $2"))
                    .bind(account)
                    .bind(t)
                    .execute(&mut *tx.tx)
                    .await?;
            }
        }
        sqlx::query(&format!(
            "INSERT INTO bayes_totals (account_id, {col}) VALUES ($1, $2)
             ON CONFLICT (account_id) DO UPDATE SET {col} = CASE WHEN bayes_totals.{col} + $2 < 0 THEN 0 ELSE bayes_totals.{col} + $2 END"
        ))
        .bind(account)
        .bind(sign)
        .execute(&mut *tx.tx)
        .await?;
        tx.commit().await
    }

    async fn bayes_learned(&self, account: i64, msg: &str) -> Result<Option<String>> {
        let r = sqlx::query("SELECT class FROM bayes_learned WHERE account_id = $1 AND msg = $2").bind(account).bind(msg).fetch_optional(&self.pool).await?;
        Ok(r.map(|r| r.get(0)))
    }

    async fn bayes_mark(&self, account: i64, msg: &str, class: &str) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("INSERT INTO bayes_learned (account_id, msg, class) VALUES ($1, $2, $3) ON CONFLICT (account_id, msg) DO UPDATE SET class = excluded.class")
            .bind(account)
            .bind(msg)
            .bind(class)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn bayes_stats(&self) -> Result<serde_json::Value> {
        let (s, h) = self.bayes_totals(&[GLOBAL]).await?;
        let t: i64 = sqlx::query("SELECT COUNT(*) FROM bayes_tokens WHERE account_id = 0").fetch_one(&self.pool).await?.get(0);
        Ok(serde_json::json!({"spam_learned": s, "ham_learned": h, "tokens": t}))
    }
}

/// Spam probability (0..1) of a message for these recipients, or None when
/// the classifier hasn't seen enough mail of both kinds yet.
pub async fn classify(state: &State, accounts: &[i64], raw: &[u8]) -> Option<f64> {
    let s = state.settings();
    let mut scopes = vec![GLOBAL];
    scopes.extend(accounts.iter().copied());
    let (nspam, nham) = state.db.bayes_totals(&scopes).await.ok()?;
    if nspam < s.filter.bayes_min_learns || nham < s.filter.bayes_min_learns {
        return None;
    }
    let raw = raw.to_vec();
    let tokens: Vec<String> = tokio::task::spawn_blocking(move || tokenize(&raw).into_iter().collect()).await.ok()?;
    let counts = state.db.bayes_counts(&scopes, &tokens).await.ok()?;
    // Robinson's f(w) with strength s=1, x=0.5, then Fisher's chi-square combining
    // over the 150 most significant tokens.
    let mut probs: Vec<f64> = counts
        .values()
        .map(|(sp, hm)| {
            let ps = *sp as f64 / nspam.max(1) as f64;
            let ph = *hm as f64 / nham.max(1) as f64;
            let p = if ps + ph == 0.0 { 0.5 } else { ps / (ps + ph) };
            let n = (*sp + *hm) as f64;
            (0.5 + n * p) / (1.0 + n)
        })
        .filter(|p| (p - 0.5).abs() > 0.1)
        .collect();
    if probs.len() < 5 {
        return Some(0.5);
    }
    probs.sort_by(|a, b| (b - 0.5).abs().partial_cmp(&(a - 0.5).abs()).unwrap_or(std::cmp::Ordering::Equal));
    probs.truncate(150);
    let n = probs.len() as f64;
    let h = chi2q(-2.0 * probs.iter().map(|p| p.max(1e-200).ln()).sum::<f64>(), 2.0 * n);
    let sp = chi2q(-2.0 * probs.iter().map(|p| (1.0 - p).max(1e-200).ln()).sum::<f64>(), 2.0 * n);
    Some((1.0 + h - sp) / 2.0)
}

/// Inverse chi-square (upper tail) for even degrees of freedom.
fn chi2q(x2: f64, v: f64) -> f64 {
    let m = x2 / 2.0;
    let mut term = (-m).exp();
    let mut sum = term;
    let mut i = 1.0;
    while i < v / 2.0 {
        term *= m / i;
        sum += term;
        i += 1.0;
    }
    sum.min(1.0)
}

/// Train on a message for an account (and the global model). Learning the
/// same message again in the other class moves it.
pub async fn learn(state: &State, account: i64, raw: &[u8], spam: bool) -> Result<()> {
    if !state.settings().filter.bayes {
        return Ok(());
    }
    let key = crate::util::sha256_hex(raw);
    let class = if spam { "spam" } else { "ham" };
    let prev = state.db.bayes_learned(account, &key).await?;
    if prev.as_deref() == Some(class) {
        return Ok(());
    }
    let r = raw.to_vec();
    let tokens: Vec<String> = tokio::task::spawn_blocking(move || tokenize(&r).into_iter().collect()).await?;
    if let Some(p) = &prev {
        let was_spam = p == "spam";
        state.db.bayes_apply(account, &tokens, was_spam, -1).await?;
        state.db.bayes_apply(GLOBAL, &tokens, was_spam, -1).await?;
    }
    state.db.bayes_apply(account, &tokens, spam, 1).await?;
    state.db.bayes_apply(GLOBAL, &tokens, spam, 1).await?;
    state.db.bayes_mark(account, &key, class).await?;
    Ok(())
}

/// Learn from a stored message (by blob) in the background.
pub fn learn_blob(state: &State, account: i64, blob: String, spam: bool) {
    // Zero-access messages: their words must not end up in the token tables.
    if blob.starts_with(crate::za::BLOB_PREFIX) {
        return;
    }
    let st = state.clone();
    tokio::spawn(async move {
        if let Ok(raw) = st.blobs.get(&blob).await {
            if let Err(e) = learn(&st, account, &raw, spam).await {
                tracing::debug!("bayes learn: {e:#}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokens() {
        let t = tokenize(b"From: a@spam.example\r\nSubject: Cheap pills now\r\n\r\nBuy cheap pills at http://pills.example/x today\r\n");
        assert!(t.contains("s:cheap"));
        assert!(t.contains("pills"));
        assert!(t.contains("f:spam.example"));
        assert!(t.contains("u:pills.example"));
    }
    #[test]
    fn chi() {
        assert!((chi2q(0.0, 4.0) - 1.0).abs() < 1e-9);
        assert!(chi2q(100.0, 4.0) < 1e-10);
    }
}
