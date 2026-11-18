//! Update check: asks the GitHub releases of the launcher repository for the newest build.
//!
//! Only the version and a download link are fetched; installing stays with the player's system
//! (the link points at the release asset for this platform).

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Repository carrying the launcher releases (FOREVER_UPDATE_REPO at build time).
const DEFAULT_REPO: &str = "myjumperlp-byte/forever-launcher";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    /// Version of the running launcher.
    pub current: &'static str,
    /// Newest published version, without the leading "v".
    pub latest: String,
    /// Download of the asset for this platform (or the release page).
    pub url: String,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

fn repo() -> &'static str {
    option_env!("FOREVER_UPDATE_REPO")
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .unwrap_or(DEFAULT_REPO)
}

/// The file ending of this platform's launcher build.
fn platform_suffix() -> &'static str {
    if cfg!(windows) {
        ".exe"
    } else if cfg!(target_os = "macos") {
        ".dmg"
    } else {
        ".appimage"
    }
}

/// 1.2.0, v1.2.0 and 1.2.0-beta.1 all compare as (1, 2, 0); unparsable parts count as 0.
fn version(v: &str) -> (u64, u64, u64) {
    let core = v.trim().trim_start_matches(['v', 'V']).split(['-', '+']).next().unwrap_or("");
    let mut parts = core.split('.').map(|p| p.trim().parse::<u64>().unwrap_or(0));
    (parts.next().unwrap_or(0), parts.next().unwrap_or(0), parts.next().unwrap_or(0))
}

/// The download for this platform, or the release page when the release has no such asset.
fn download_url(release: &Release) -> String {
    let suffix = platform_suffix();
    release
        .assets
        .iter()
        .find(|a| a.name.to_ascii_lowercase().ends_with(suffix))
        .map(|a| a.browser_download_url.clone())
        .unwrap_or_else(|| release.html_url.clone())
}

/// The newest release when it is newer than this build; Ok(None) when the launcher is up to date.
pub async fn check() -> Result<Option<UpdateInfo>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent(concat!("ForeverLauncher/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("https://api.github.com/repos/{}/releases/latest", repo());
    let res = client
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("HTTP {}", res.status().as_u16()));
    }
    let release: Release = res.json().await.map_err(|e| e.to_string())?;
    let current = env!("CARGO_PKG_VERSION");
    // "latest" never includes drafts or pre-releases, so the tag is safe to compare as a version
    let latest = release.tag_name.trim().trim_start_matches(['v', 'V']).to_string();
    if version(&latest) <= version(current) {
        return Ok(None);
    }
    let url = download_url(&release);
    if !url.starts_with("https://") {
        return Err("unexpected download address".into());
    }
    Ok(Some(UpdateInfo { current, latest, url }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions() {
        assert!(version("v1.3.0") > version("1.2.0"));
        assert_eq!(version("v1.2.0"), version("1.2.0"));
        assert!(version("1.2.1") > version("1.2.0"));
        assert!(version("2.0.0") > version("1.99.99"));
        assert_eq!(version("1.2"), (1, 2, 0));
        assert_eq!(version("1.2.0-beta.1"), (1, 2, 0));
    }

    #[test]
    fn picks_the_build_of_this_platform() {
        let release = Release {
            tag_name: "v9.9.9".into(),
            html_url: "https://github.com/x/y/releases/tag/v9.9.9".into(),
            assets: vec![
                Asset { name: "Legacy.of.Azeroth_9.9.9_amd64.AppImage".into(), browser_download_url: "https://example.test/linux".into() },
                Asset { name: "Legacy.of.Azeroth_9.9.9_universal.dmg".into(), browser_download_url: "https://example.test/mac".into() },
                Asset { name: "forever-launcher.exe".into(), browser_download_url: "https://example.test/windows".into() },
            ],
        };
        let expected = if cfg!(windows) {
            "https://example.test/windows"
        } else if cfg!(target_os = "macos") {
            "https://example.test/mac"
        } else {
            "https://example.test/linux"
        };
        assert_eq!(download_url(&release), expected);
        // a release without an asset for this platform falls back to the release page
        let empty = Release { assets: Vec::new(), ..release };
        assert_eq!(download_url(&empty), "https://github.com/x/y/releases/tag/v9.9.9");
    }
}
