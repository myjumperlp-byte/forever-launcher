//! Game preparation and start: WTF config, Launch Options\WoW (auto-login), WowB.exe -launcherlogin.
//! macOS starts a copy of the game app instead: see macos.rs.

use crate::config::Settings;
use crate::i18n::tf;
use std::path::Path;
#[cfg(not(target_os = "macos"))]
use std::process::{Child, Command};
#[cfg(target_os = "linux")]
use std::process::Stdio;

pub const WTF_NAME: &str = "ForeverLauncher.wtf";
/// The client's own settings file, next to the one it is started with.
const BASE_WTF: &str = "Config.wtf";
/// Where the client reads the login ticket. The live client is the Battle.net product `wowf`, the Classic beta was
/// `WoW`; both are written because each client only reads its own one.
#[cfg(not(target_os = "macos"))]
const LAUNCH_OPTIONS: [&str; 2] = [
    r"Software\Blizzard Entertainment\Battle.net\Launch Options\WoW",
    r"Software\Blizzard Entertainment\Battle.net\Launch Options\WoWF",
];

/// WTF/Config.wtf and WTF/ForeverLauncher.wtf: the portal and the language, forced before every start.
///
/// The client saves its settings when it closes and writes `SET portal "EU"` back, so both files are set again on
/// every start. The file the client is started with is left read-only: otherwise the next start would talk to
/// Blizzard instead of this server, which only shows up as "you have been disconnected".
pub fn write_wtf(settings: &Settings) -> Result<(), String> {
    let dir = Path::new(&settings.game_dir).join("WTF");
    std::fs::create_dir_all(&dir).map_err(|e| tf("wtf_folder", &[&e]))?;
    // Config.wtf stays writable (the client saves its video settings there), the -config file is locked
    write_portal(&dir, settings, BASE_WTF, false)?;
    write_portal(&dir, settings, WTF_NAME, true)
}

fn write_portal(dir: &Path, settings: &Settings, name: &str, lock: bool) -> Result<(), String> {
    let path = dir.join(name);
    let shown = path.display().to_string();
    // an earlier start may have left the file read-only
    set_mode(&path, 0o644);
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let wanted = [
        ("portal", settings.server.portal.clone()),
        ("textLocale", settings.locale.clone()),
        ("audioLocale", settings.locale.clone()),
    ];
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l| !wanted.iter().any(|(k, _)| l.starts_with(&format!("SET {k} "))))
        .map(str::to_string)
        .collect();
    for (k, v) in wanted {
        lines.push(format!("SET {k} \"{v}\""));
    }
    std::fs::write(&path, lines.join("\r\n") + "\r\n").map_err(|e| format!("{shown} : {e}"))?;
    // read back: a portal that did not make it into the file must not be discovered by the game
    let back = std::fs::read_to_string(&path).map_err(|e| format!("{shown} : {e}"))?;
    let want_line = format!("SET portal \"{}\"", settings.server.portal);
    if !back.lines().any(|l| l.trim() == want_line) {
        return Err(tf("wtf_not_written", &[&shown]));
    }
    if lock {
        set_mode(&path, 0o444);
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) {}

/// Stores the login ticket where the client reads it with -launcherlogin.
#[cfg(windows)]
pub fn write_launch_options(_settings: &Settings, portal: &str, ticket: &str, game_account: &str) -> Result<(), String> {
    use windows::core::HSTRING;
    use windows::Win32::System::Registry::*;
    let blob = crate::dpapi::protect(ticket.as_bytes())?;
    for path in LAUNCH_OPTIONS {
        unsafe {
            let mut key = HKEY::default();
            RegCreateKeyExW(HKEY_CURRENT_USER, &HSTRING::from(path), 0, None, REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut key, None)
                .ok()
                .map_err(|e| tf("registry", &[&e]))?;
            let set_str = |name: &str, value: &str| {
                let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
                let bytes = std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2);
                RegSetValueExW(key, &HSTRING::from(name), 0, REG_SZ, Some(bytes)).ok()
            };
            let r = set_str("CONNECTION_STRING", portal)
                .and_then(|_| set_str("GAME_ACCOUNT", game_account))
                .and_then(|_| RegSetValueExW(key, &HSTRING::from("WEB_TOKEN"), 0, REG_BINARY, Some(&blob)).ok());
            let _ = RegCloseKey(key);
            r.map_err(|e| tf("registry", &[&e]))?;
        }
    }
    Ok(())
}

/// The registry file body: the launch options of both products, and Wine's crash dialog switched off. A crashed
/// client then exits instead of leaving a winedbg process that waits for a click it will never get.
#[cfg(target_os = "linux")]
fn launch_options_reg(portal: &str, ticket: &str, game_account: &str) -> Vec<u8> {
    use crate::dpapi::{wine, WEB_TOKEN_ENTROPY};
    let blob = wine::protect(ticket.as_bytes(), wine::PROTON_USER, &WEB_TOKEN_ENTROPY);
    let hexdata: Vec<String> = blob.iter().map(|b| format!("{b:02x}")).collect();
    let section = |path: &str| {
        format!(
            "[HKEY_CURRENT_USER\\{path}]\r\n\"WEB_TOKEN\"=hex:{}\r\n\"GAME_ACCOUNT\"=\"{game_account}\"\r\n\"CONNECTION_STRING\"=\"{portal}\"\r\n",
            hexdata.join(",")
        )
    };
    // Wine's crash dialog is switched off in the same file: a crashed client must exit, not leave a winedbg
    // waiting for a click it will never get - that is what filled players' memory
    let content = format!(
        "Windows Registry Editor Version 5.00\r\n\r\n{}\r\n{}\r\n[HKEY_CURRENT_USER\\Software\\Wine\\WineDbg]\r\n\"ShowCrashDialog\"=dword:00000000\r\n",
        section(LAUNCH_OPTIONS[0]),
        section(LAUNCH_OPTIONS[1])
    );
    // regedit files are UTF-16 LE with a BOM; Wine sees the Linux file system as Z:
    let mut bytes = vec![0xFF, 0xFE];
    for u in content.encode_utf16() {
        bytes.extend(u.to_le_bytes());
    }
    bytes
}

/// Linux: the same values in the prefix registry, through `reg import` (the Wine DPAPI blob is built here).
#[cfg(target_os = "linux")]
pub fn write_launch_options(settings: &Settings, portal: &str, ticket: &str, game_account: &str) -> Result<(), String> {
    let bytes = launch_options_reg(portal, ticket, game_account);
    // the same ticket as last time needs no second Wine session: its own start is expensive enough
    use sha1::{Digest, Sha1};
    let digest = hex::encode(Sha1::digest(&bytes));
    let stamp = crate::config::config_dir().join("launch-options.sha1");
    if std::fs::read_to_string(&stamp).map(|s| s.trim() == digest.as_str()).unwrap_or(false) {
        return Ok(());
    }
    let dir = crate::config::config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let file = dir.join("launch-options.reg");
    std::fs::write(&file, bytes).map_err(|e| e.to_string())?;
    let wine_path = format!("Z:{}", file.to_string_lossy().replace('/', "\\"));
    let res = crate::system::run_in_prefix(settings, &["reg", "import", &wine_path]);
    let _ = std::fs::remove_file(&file);
    if res.is_ok() {
        let _ = std::fs::write(&stamp, digest);
    }
    res
}

#[cfg(windows)]
pub fn spawn(settings: &Settings) -> Result<Child, String> {
    Command::new(settings.exe())
        .args(["-launcherlogin", "-config", WTF_NAME])
        .current_dir(&settings.game_dir)
        .spawn()
        .map_err(|e| tf("launch_failed", &[&crate::config::LIVE_EXE, &e]))
}

#[cfg(target_os = "linux")]
pub fn spawn(settings: &Settings) -> Result<Child, String> {
    // the folder exists and is marked with the runner that creates it, before Wine is asked to look at it
    crate::system::prepare_prefix(settings)?;
    let (runner, mut env) = crate::system::runner(settings)?;
    // no debug output (it costs memory and floods game.log), and a 64-bit prefix when one is created now;
    // Wine's crash dialog is switched off with the launch options
    env.push(("WINEDEBUG".into(), "-all".into()));
    env.push(("WINEARCH".into(), "win64".into()));
    let mut cmd: Vec<String> = runner;
    cmd.push(settings.exe().to_string_lossy().into_owned());
    cmd.extend(["-launcherlogin", "-config", WTF_NAME].map(String::from));
    let l = &settings.linux;
    if l.gamescope && crate::system::which("gamescope") {
        // gamescope starts its own Xwayland with a US keyboard unless told otherwise
        let (layout, variant) = l.keyboard.split_once('+').unwrap_or((l.keyboard.as_str(), ""));
        if !layout.is_empty() {
            env.push(("XKB_DEFAULT_LAYOUT".into(), layout.into()));
        }
        if !variant.is_empty() {
            env.push(("XKB_DEFAULT_VARIANT".into(), variant.into()));
        }
        let mut wrapped = vec!["gamescope".to_string()];
        wrapped.extend(l.gamescope_args.split_whitespace().map(String::from));
        wrapped.push("--".into());
        wrapped.extend(cmd);
        cmd = wrapped;
    }
    let mut command = Command::new(&cmd[0]);
    command.args(&cmd[1..]).envs(env).current_dir(&settings.game_dir);
    // its own process group: when the game ends or crashes, the whole Wine tree goes with it instead of leaving
    // a wineserver, conhost.exe and winedbg behind (see end_session in lib.rs)
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    // started from the desktop there is no terminal: every message umu or Proton prints would be lost, so the
    // output of this start goes to game.log next to settings.json (fresh file per start)
    if let Some(log) = crate::config::log_file("game.log", true) {
        crate::config::log_line(format!("game: {} (output in game.log)", cmd.join(" ")));
        if let Ok(also) = log.try_clone() {
            command.stdout(Stdio::from(also)).stderr(Stdio::from(log));
        }
    }
    crate::system::clean_env(&mut command)
        .spawn()
        .map_err(|e| tf("launch_failed", &[&cmd[0], &e]))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// UTF-16 LE with the regedit BOM back to text.
    fn decode(bytes: &[u8]) -> String {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }

    #[test]
    fn launch_options_reg_has_both_products_and_no_crash_dialog() {
        let bytes = launch_options_reg("trinity.actual.battle.net:48989", "ticket", "WoW1");
        let text = decode(&bytes);
        assert!(text.starts_with("Windows Registry Editor Version 5.00"));
        assert!(text.contains(r"Launch Options\WoW"));
        assert!(text.contains(r"Launch Options\WoWF"));
        assert!(text.contains("CONNECTION_STRING\"=\"trinity.actual.battle.net:48989\""));
        assert!(text.contains("GAME_ACCOUNT\"=\"WoW1\""));
        // a crashed client must exit instead of waiting in a winedbg dialog
        assert!(text.contains("ShowCrashDialog\"=dword:00000000"));
    }
}
