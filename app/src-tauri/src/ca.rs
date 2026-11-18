//! The CA certificate of the server as it is *now*, and the fingerprint this computer knows.
//!
//! The launcher ships a copy of the CA (see build.rs), but the server owner can regenerate the
//! certificates with `scripts/gen-certs.sh` after the launcher was built. The game client then aborts the
//! TLS handshake to the bnet port and cannot connect, even though the launcher itself still works (it
//! carries its own copy). So every start asks the server's website for its current CA and, when it differs
//! from the one installed here, that one is installed instead.
//!
//! The website is the server's own, on the LAN, over plain HTTP: the certificate is public material and no
//! secret is sent. If the website cannot be reached, the built-in copy stays in use (a website that is down
//! must not stop the game from starting).

use crate::config::{Server, CA_PEM};
use base64::Engine;
use sha1::{Digest, Sha1};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// PEM the launcher uses right now: the built-in one until the server offers a different one.
static ACTIVE: Mutex<Option<String>> = Mutex::new(None);
/// When the server was last asked (the UI asks for the checks more than once per start).
static LAST: Mutex<Option<Instant>> = Mutex::new(None);
const FRESH: Duration = Duration::from_secs(60);

pub fn pem() -> String {
    ACTIVE.lock().unwrap().clone().unwrap_or_else(|| CA_PEM.to_string())
}

/// DER bytes of that CA.
pub fn der() -> Vec<u8> {
    let b64: String = pem().lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(b64).expect("the CA is a PEM certificate")
}

/// SHA-1 of that CA (the fingerprint the Windows store, the Wine prefix and `security -Z` use).
pub fn sha1() -> [u8; 20] {
    Sha1::digest(der()).into()
}

pub fn sha1_hex() -> String {
    hex::encode_upper(sha1())
}

fn sha1_of(pem: &str) -> Option<String> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    Some(hex::encode_upper(Sha1::digest(der)))
}

/// A single PEM certificate, as the website serves it.
fn valid(pem: &str) -> bool {
    pem.starts_with("-----BEGIN CERTIFICATE-----")
        && pem.ends_with("-----END CERTIFICATE-----")
        && pem.matches("-----BEGIN CERTIFICATE-----").count() == 1
}

/// Takes over the CA the server offers now. true: the server's CA differs from the one used so far.
/// Any network or format problem keeps the built-in CA and answers false.
pub async fn refresh(server: &Server) -> bool {
    if LAST.lock().unwrap().is_some_and(|t| t.elapsed() < FRESH) {
        return false;
    }
    let changed = fetch(server).await;
    *LAST.lock().unwrap() = Some(Instant::now());
    changed
}

async fn fetch(server: &Server) -> bool {
    let website = server.website.trim().trim_end_matches('/');
    if website.is_empty() {
        return false;
    }
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let Ok(res) = client.get(format!("{website}/forever_root_ca.crt")).send().await else { return false };
    if !res.status().is_success() {
        return false;
    }
    let Ok(body) = res.text().await else { return false };
    let body = body.trim();
    if !valid(body) {
        return false;
    }
    let current = sha1_hex();
    match sha1_of(body) {
        Some(server_ca) if server_ca != current => {
            *ACTIVE.lock().unwrap() = Some(body.to_string());
            true
        }
        _ => false,
    }
}
