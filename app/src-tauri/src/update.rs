//! Update: asks the GitHub releases of the launcher repository for the newest build, downloads it and swaps it in
//! at the next start. Nothing has to be installed by hand.
//!
//! The running program cannot be overwritten (Windows keeps the image locked, the mount of a Linux AppImage is
//! read-only), but it can be renamed. So a download waits in the launcher's folder and is put in place right at the
//! start of the next launch, before the window opens: rename the current file (or .app) aside, move the new one in,
//! start it again. The old file is removed at the following start.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
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

// ---------------------------------------------------------------------------------------------- installing

/// A download that waits for the next start.
#[derive(Serialize, Deserialize)]
struct Pending {
    version: String,
    /// "file" (the exe, or the AppImage) or "app" (an unpacked macOS bundle).
    kind: String,
    path: String,
}

fn pending_dir() -> PathBuf {
    crate::config::config_dir().join("update")
}

fn pending_file() -> PathBuf {
    pending_dir().join("pending.json")
}

/// The file to replace and to start again: the AppImage itself, not the read-only mount of it.
fn launch_target() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    if let Some(appimage) = std::env::var_os("APPIMAGE") {
        return Some(PathBuf::from(appimage));
    }
    std::env::current_exe().ok()
}

/// .../Legacy of Azeroth.app/Contents/MacOS/legacy-of-azeroth -> .../Legacy of Azeroth.app
#[cfg(target_os = "macos")]
fn bundle_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.parent()?.parent()?.to_path_buf())
}

/// First bytes of the download: a PE binary (Windows), an ELF (the AppImage) or a UDIF image (the .dmg, its
/// trailer starts with "koly"). Stops an HTML error page saved as .exe from being installed.
fn looks_like_build(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
        || bytes.starts_with(b"\x7fELF")
        || (bytes.len() > 512 && bytes[bytes.len() - 512..].starts_with(b"koly"))
}

async fn fetch(url: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(300)).build().map_err(|e| e.to_string())?;
    let res = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("HTTP {}", res.status().as_u16()));
    }
    let bytes = res.bytes().await.map_err(|e| e.to_string())?;
    if !looks_like_build(&bytes) {
        return Err(crate::i18n::t("update_bad_file").into());
    }
    Ok(bytes.to_vec())
}

/// Downloads the newest build and leaves it waiting for `apply_pending`; the caller restarts the launcher.
/// Returns the version that was downloaded.
pub async fn install() -> Result<String, String> {
    let Some(info) = check().await? else {
        return Err(crate::i18n::t("no_update").into());
    };
    let dir = pending_dir();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{} : {e}", dir.display()))?;
    let name = info.url.rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or("update.bin").to_string();
    let file = dir.join(name);
    std::fs::write(&file, fetch(&info.url).await?).map_err(|e| format!("{} : {e}", file.display()))?;
    let version = info.latest.clone();
    tokio::task::spawn_blocking(move || prepare(&version, &file, &dir)).await.map_err(|e| e.to_string())?
}

/// Puts the download into the shape the next start expects and records it.
fn prepare(version: &str, file: &Path, dir: &Path) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    let (kind, path) = ("app", unpack_app(file, dir)?);
    #[cfg(not(target_os = "macos"))]
    let (kind, path) = ("file", file.to_path_buf());
    let pending = Pending { version: version.to_string(), kind: kind.to_string(), path: path.to_string_lossy().into_owned() };
    let json = serde_json::to_vec(&pending).map_err(|e| e.to_string())?;
    std::fs::write(pending_file(), json).map_err(|e| format!("{} : {e}", pending_file().display()))?;
    crate::config::log_line(format!("update: {version} downloaded ({})", pending.path));
    Ok(version.to_string())
}

/// Runs before the window opens: a waiting download is swapped in and the new build started.
pub fn apply_pending() {
    let Ok(text) = std::fs::read_to_string(pending_file()) else { return };
    // read once: a broken download must not keep the launcher from starting
    let _ = std::fs::remove_file(pending_file());
    let Ok(pending) = serde_json::from_str::<Pending>(&text) else {
        let _ = std::fs::remove_dir_all(pending_dir());
        return;
    };
    let new = PathBuf::from(&pending.path);
    #[cfg(target_os = "macos")]
    let result = if pending.kind == "app" { swap_app(&new) } else { swap_file(&new) };
    #[cfg(not(target_os = "macos"))]
    let result = swap_file(&new);
    match result {
        Ok(()) => {
            crate::config::log_line(format!("update: {} installed, starting the new build", pending.version));
            let _ = std::fs::remove_dir_all(pending_dir());
            restart();
        }
        Err(e) => crate::config::log_line(format!("update: {} could not be installed: {e}", pending.version)),
    }
}

/// Renames the current file aside and moves the download into its place.
fn swap_file(new: &Path) -> Result<(), String> {
    let target = launch_target().ok_or_else(|| "no program to replace".to_string())?;
    let name = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let old = target.with_file_name(format!("{name}.old"));
    let _ = std::fs::remove_file(&old);
    std::fs::rename(&target, &old).map_err(|e| format!("{} : {e}", target.display()))?;
    let placed = std::fs::rename(new, &target).or_else(|_| std::fs::copy(new, &target).map(|_| ()));
    if let Err(e) = placed {
        let _ = std::fs::rename(&old, &target);
        return Err(format!("{} : {e}", target.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755));
    }
    // Windows keeps the renamed image locked: the next start removes it
    let _ = std::fs::remove_file(&old);
    Ok(())
}

/// Same for a macOS app bundle: the running bundle is renamed, the unpacked one moved in.
#[cfg(target_os = "macos")]
fn swap_app(new: &Path) -> Result<(), String> {
    let bundle = bundle_path().ok_or_else(|| "not inside an app bundle".to_string())?;
    if !new.is_dir() {
        return Err(format!("{} : not a bundle", new.display()));
    }
    let name = bundle.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let old = bundle.with_file_name(format!("{name}.old"));
    let _ = std::fs::remove_dir_all(&old);
    std::fs::rename(&bundle, &old).map_err(|e| format!("{} : {e}", bundle.display()))?;
    if let Err(e) = std::fs::rename(new, &bundle) {
        let _ = std::fs::rename(&old, &bundle);
        return Err(format!("{} : {e}", bundle.display()));
    }
    let _ = std::fs::remove_dir_all(&old);
    Ok(())
}

/// The downloaded .dmg, mounted and copied out as an .app.
#[cfg(target_os = "macos")]
fn unpack_app(dmg: &Path, dir: &Path) -> Result<PathBuf, String> {
    let mount = dir.join("mnt");
    std::fs::create_dir_all(&mount).map_err(|e| e.to_string())?;
    let attach = std::process::Command::new("hdiutil")
        .args(["attach", "-nobrowse", "-readonly", "-noverify", "-mountpoint"])
        .arg(&mount)
        .arg(dmg)
        .output()
        .map_err(|e| format!("hdiutil : {e}"))?;
    if !attach.status.success() {
        return Err(format!("hdiutil : {}", String::from_utf8_lossy(&attach.stderr).trim()));
    }
    let result = (|| {
        let app = std::fs::read_dir(&mount)
            .map_err(|e| e.to_string())?
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "app"))
            .ok_or_else(|| "no .app in the disk image".to_string())?;
        let dest = dir.join(app.file_name().ok_or_else(|| "nameless .app".to_string())?);
        let _ = std::fs::remove_dir_all(&dest);
        let copied = std::process::Command::new("ditto").arg(&app).arg(&dest).status().map_err(|e| e.to_string())?;
        if !copied.success() {
            return Err(format!("ditto failed for {}", app.display()));
        }
        // a downloaded bundle would otherwise be refused by Gatekeeper on the next start
        let _ = std::process::Command::new("xattr").args(["-dr", "com.apple.quarantine"]).arg(&dest).status();
        Ok(dest)
    })();
    let _ = std::process::Command::new("hdiutil").args(["detach", "-quiet"]).arg(&mount).status();
    result
}

/// Starts this build again and ends the current process.
pub fn restart() -> ! {
    #[cfg(target_os = "macos")]
    {
        match bundle_path() {
            Some(bundle) => {
                let _ = std::process::Command::new("open").arg("-n").arg(&bundle).spawn();
            }
            None => {
                if let Ok(exe) = std::env::current_exe() {
                    let _ = std::process::Command::new(exe).args(std::env::args().skip(1)).spawn();
                }
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(target) = launch_target() {
            let _ = std::process::Command::new(target).args(std::env::args().skip(1)).spawn();
        }
    }
    std::process::exit(0);
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
    fn only_accepts_a_real_build() {
        assert!(looks_like_build(b"MZ\x90\x00\x03"));
        assert!(looks_like_build(b"\x7fELF\x02\x01\x01"));
        let mut dmg = vec![0u8; 1024];
        dmg[512..516].copy_from_slice(b"koly");
        assert!(looks_like_build(&dmg));
        assert!(!looks_like_build(b"<!DOCTYPE html><html>404</html>"));
        assert!(!looks_like_build(b""));
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
