//! Settings (game folder, language, Linux runner...), server definition and the saved login session.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Public half of the Ed25519 key built into stock TrinityCore (used by the forever branch too).
pub const STOCK_PUBLIC_KEY: &str = "02596F0D0C061A8B30745988FD72C59E29EC367FB0F341F28E0F08D037BAFC69";
/// Public certificate of the server's private CA (never the key).
pub const CA_PEM: &str = include_str!(concat!(env!("OUT_DIR"), "/forever_root_ca.crt"));

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Server {
    pub name: String,
    /// Host name the client and the certificate use.
    pub portal: String,
    /// Where that host name really is (IP or DNS name of the server).
    pub address: String,
    pub bnet_port: u16,
    pub rest_port: u16,
    pub world_port: u16,
    pub public_key: String,
    pub region_group: u32,
    pub website: String,
}

/// A build-time setting (FOREVER_SERVER_ADDRESS...), set by GitHub Actions from the repository variables.
fn built_in(value: Option<&'static str>, default: &str) -> String {
    value.filter(|v| !v.trim().is_empty()).unwrap_or(default).trim().to_string()
}

/// A build-time port (FOREVER_BNET_PORT...), for servers published through a tunnel with its own ports.
fn built_in_port(value: Option<&'static str>, default: u16) -> u16 {
    value.and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

/// Your server, from the FOREVER_SERVER_NAME / FOREVER_SERVER_ADDRESS / FOREVER_WEBSITE variables at build time.
/// Players can still change them in Settings > Server (advanced).
impl Default for Server {
    fn default() -> Self {
        Self {
            name: built_in(option_env!("FOREVER_SERVER_NAME"), "Forever"),
            portal: "trinity.actual.battle.net".into(),
            address: built_in(option_env!("FOREVER_SERVER_ADDRESS"), "127.0.0.1"),
            // one playit tunnel, three consecutive ports (48989 bnet, 48990 login REST, 48991 world)
            bnet_port: built_in_port(option_env!("FOREVER_BNET_PORT"), 48989),
            rest_port: built_in_port(option_env!("FOREVER_REST_PORT"), 48990),
            world_port: built_in_port(option_env!("FOREVER_WORLD_PORT"), 48991),
            public_key: STOCK_PUBLIC_KEY.into(),
            region_group: 8,
            website: built_in(option_env!("FOREVER_WEBSITE"), ""),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct LinuxSettings {
    /// Proton folder (run through umu-run) or "wine".
    pub runner: String,
    pub prefix: String,
    pub gamescope: bool,
    pub gamescope_args: String,
    pub keyboard: String,
}

impl Default for LinuxSettings {
    fn default() -> Self {
        Self {
            runner: String::new(),
            prefix: home().join("Games/forever-wow").to_string_lossy().into_owned(),
            gamescope: false,
            gamescope_args: "-f".into(),
            keyboard: String::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    pub server: Server,
    /// The client's channel folder: `_forever_` (Wow.exe) or `_classic_beta_` (WowB.exe); the game .app on macOS.
    pub game_dir: String,
    /// textLocale / audioLocale, e.g. frFR.
    pub locale: String,
    /// Launcher language: fr, en, es, pt, or empty for the system language.
    pub language: String,
    pub linux: LinuxSettings,
}

/// Login kept between launches: the 30-day launcher token of the bnetserver, never the password.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Session {
    pub email: String,
    pub token: String,
    pub expires: u64,
}

pub const LOCALES: &[&str] = &["frFR", "enUS", "enGB", "deDE", "esES", "esMX", "itIT", "ptBR", "ruRU", "koKR", "zhCN", "zhTW"];

pub fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

pub fn config_dir() -> PathBuf {
    dirs::config_dir().unwrap_or_else(home).join("forever-launcher-app")
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// A log file in the launcher's folder (`fresh`: truncated first), or None when it cannot be opened.
pub fn log_file(name: &str, fresh: bool) -> Option<std::fs::File> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir).ok()?;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true);
    if fresh {
        opts.truncate(true);
    } else {
        opts.append(true);
    }
    opts.open(dir.join(name)).ok()
}

/// One line in launcher.log (what was written where and how the start went), so a wrong portal or a failing
/// umu can be read without a terminal.
pub fn log_line(message: impl AsRef<str>) {
    use std::io::Write;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let stamp = format!("{:02}:{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    if let Some(mut file) = log_file("launcher.log", false) {
        let _ = writeln!(file, "{stamp} {}", message.as_ref());
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension("tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(data)?;
    }
    #[cfg(not(unix))]
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, path)
}

/// Addresses the builds up to 1.0.0 shipped with: the LAN machine on the old ports.
const OLD_ADDRESSES: [&str; 2] = ["127.0.0.1", "192.168.178.42"];
/// bnet, login REST and world port before the playit tunnel (8081 and 8085 are not published any more).
const OLD_PORTS: (u16, u16, u16) = (1119, 8081, 8085);
/// Realm name 1.0.0 wrote into settings.json (there is no field for it, so it stayed forever).
const OLD_NAMES: [&str; 1] = ["Forever"];
/// Website of the LAN machine before the real site was published.
const OLD_WEBSITE: &str = "http://192.168.178.42:8088";

/// Replaces exactly those dead values with `built_in` (the server this build was compiled with), so a
/// settings.json written by an old launcher does not keep sending players to an address that no longer answers.
/// Anything the player typed in himself stays untouched. true: something changed.
fn migrate_server_to(server: &mut Server, built_in: &Server) -> bool {
    // a launcher built without FOREVER_SERVER_ADDRESS has the same address as its default: nothing to gain
    if OLD_ADDRESSES.contains(&built_in.address.as_str()) {
        return false;
    }
    let dead_address = OLD_ADDRESSES.contains(&server.address.trim());
    let old_ports = (server.bnet_port, server.rest_port, server.world_port) == OLD_PORTS;
    let mut changed = false;
    // the untouched 1.0.0 file: the LAN address together with the old ports
    if dead_address && old_ports {
        server.address = built_in.address.clone();
        changed = true;
    }
    // everything else is decided on its own. The address may already have been corrected by hand while the old
    // ports, the old realm name and the old website stayed in the file - before 1.3.0 there was no field for them.
    if !(dead_address || server.address.trim() == built_in.address.trim()) {
        return changed; // a third-party server stays exactly as its player set it up
    }
    if old_ports {
        server.bnet_port = built_in.bnet_port;
        server.rest_port = built_in.rest_port;
        server.world_port = built_in.world_port;
        changed = true;
    }
    if OLD_NAMES.contains(&server.name.trim()) && !OLD_NAMES.contains(&built_in.name.as_str()) {
        server.name = built_in.name.clone();
        changed = true;
    }
    if (server.website.trim().is_empty() || server.website.trim() == OLD_WEBSITE)
        && !built_in.website.is_empty()
        && server.website.trim() != built_in.website.trim()
    {
        server.website = built_in.website.clone();
        changed = true;
    }
    changed
}

/// The migration as it runs on load: to the server compiled into this build.
fn migrate_server(server: &mut Server) -> bool {
    migrate_server_to(server, &Server::default())
}

/// Client build the realm runs (FOREVER_CLIENT_BUILD at build time, e.g. 1.60.1.70938), when the build knows it.
pub fn expected_version() -> Option<&'static str> {
    option_env!("FOREVER_CLIENT_BUILD").map(str::trim).filter(|v| !v.is_empty())
}

/// Compares the build number, the last part of the version: 1.60.1.70938 against 1.60.1.70938.
pub fn build_matches(installed: &str, expected: &str) -> bool {
    fn number(v: &str) -> Option<u64> {
        v.trim().rsplit('.').next()?.trim().parse().ok()
    }
    match (number(installed), number(expected)) {
        (Some(a), Some(b)) => a == b,
        _ => installed.trim() == expected.trim(),
    }
}

impl Settings {
    pub fn load() -> Self {
        let mut s: Settings = read_json(&config_dir().join("settings.json")).unwrap_or_default();
        if migrate_server(&mut s.server) {
            let _ = s.save();
        }
        if s.game_dir.is_empty() {
            s.game_dir = detect_game_dir().unwrap_or_default();
        }
        // a player who picked the install root: keep the channel folder that holds the game
        let channel = game_dir(Path::new(&s.game_dir));
        if !s.game_dir.is_empty() && channel != Path::new(&s.game_dir) {
            s.game_dir = channel.to_string_lossy().into_owned();
            let _ = s.save();
        }
        if s.locale.is_empty() {
            s.locale = installed_locale(Path::new(&s.game_dir)).unwrap_or_else(|| "enUS".into());
        }
        #[cfg(target_os = "linux")]
        {
            if s.linux.runner.is_empty() {
                s.linux.runner = crate::system::default_runner();
            }
            if s.linux.keyboard.is_empty() {
                s.linux.keyboard = crate::system::keyboard_layout();
            }
        }
        s
    }

    pub fn save(&self) -> std::io::Result<()> {
        write_private(&config_dir().join("settings.json"), &serde_json::to_vec_pretty(self).unwrap())
    }

    /// Wow.exe / WowB.exe (Windows, Linux/Wine) or the game .app (macOS), in the channel folder of the install.
    pub fn exe(&self) -> PathBuf {
        game_binary(&self.resolved_game_dir())
    }

    /// `game_dir` with the channel folder resolved (`…\World of Warcraft` → `…\World of Warcraft\_forever_`).
    pub fn resolved_game_dir(&self) -> PathBuf {
        game_dir(Path::new(&self.game_dir))
    }

    pub fn game_found(&self) -> bool {
        !self.game_dir.is_empty() && self.exe().exists()
    }

    /// The installed client build and the newest one the realm runs, when the installed build is not one of the
    /// builds the realm accepts (see `realm::accepted`). The server answers a build it does not know with a bare
    /// "you have been disconnected" right after the character login, so the launcher says which one to update to.
    pub fn client_build_mismatch(&self, accepted: &[String]) -> Option<(String, String)> {
        let expected = accepted.first()?;
        // without .build.info there is nothing to compare, and a missing file must not raise the banner
        let installed = installed_version(&self.resolved_game_dir())?;
        if accepted.iter().any(|build| build_matches(&installed, build)) {
            return None;
        }
        Some((installed, expected.clone()))
    }
}

impl Session {
    pub fn load() -> Option<Self> {
        read_json::<Session>(&config_dir().join("session.json")).filter(|s| !s.token.is_empty())
    }

    pub fn save(&self) -> std::io::Result<()> {
        write_private(&config_dir().join("session.json"), &serde_json::to_vec(self).unwrap())
    }

    pub fn clear() {
        let _ = std::fs::remove_file(config_dir().join("session.json"));
    }
}

/// Battle.net product of the live Forever client: `_forever_\Wow.exe` (since build 1.60.1.70790).
pub const PRODUCT_LIVE: &str = "wowf";
/// Battle.net product of the Classic beta client: `_classic_beta_\WowB.exe` (builds up to 1.60.1.70450).
pub const PRODUCT_BETA: &str = "wow_classic_beta";
pub const LIVE_DIR: &str = "_forever_";
pub const BETA_DIR: &str = "_classic_beta_";
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub const LIVE_EXE: &str = "Wow.exe";
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub const BETA_EXE: &str = "WowB.exe";

/// Product of the channel folder the player picked (`_forever_` = live client, anything else = the old beta).
pub fn product_for(game_dir: &Path) -> &'static str {
    match game_dir.file_name().map(|n| n.to_string_lossy().to_lowercase()) {
        Some(name) if name == BETA_DIR => PRODUCT_BETA,
        _ => PRODUCT_LIVE,
    }
}

/// `.build.info` next to the channel folder: its header and one row per installed product.
struct BuildInfo {
    header: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl BuildInfo {
    fn read(game_dir: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(game_dir.parent()?.join(".build.info")).ok()?;
        let mut lines = text.lines();
        let header = cells(lines.next()?);
        Some(Self { header, rows: lines.map(cells).collect() })
    }

    fn column(&self, name: &str) -> Option<usize> {
        self.header.iter().position(|c| c == name)
    }

    /// The row of the picked channel, else the row of any Forever product (the beta and the live client can be
    /// installed next to each other).
    fn row(&self, game_dir: &Path) -> Option<&Vec<String>> {
        let product = self.column("Product")?;
        let wanted = product_for(game_dir);
        self.rows.iter().find(|r| r.get(product).map(String::as_str) == Some(wanted)).or_else(|| {
            self.rows.iter().find(|r| r.get(product).is_some_and(|p| p == PRODUCT_LIVE || p == PRODUCT_BETA))
        })
    }
}

fn cells(line: &str) -> Vec<String> {
    line.split('|').map(|c| c.split('!').next().unwrap_or("").to_string()).collect()
}

/// Language installed with the client in that folder (to preselect it).
pub fn installed_locale(game_dir: &Path) -> Option<String> {
    let info = BuildInfo::read(game_dir)?;
    let row = info.row(game_dir)?;
    let tags = row.get(info.column("Tags")?)?;
    LOCALES.iter().find(|l| tags.contains(&format!("{l} text"))).map(|l| l.to_string())
}

/// Full client version (e.g. 1.60.1.70938), from the Version column of .build.info next to the game folder.
pub fn installed_version(game_dir: &Path) -> Option<String> {
    let info = BuildInfo::read(game_dir)?;
    let row = info.row(game_dir)?;
    let version = row.get(info.column("Version")?)?.clone();
    (!version.is_empty()).then_some(version)
}

#[cfg(not(target_os = "macos"))]
fn game_binary(dir: &Path) -> PathBuf {
    // the live client since build 70790; an old beta install keeps working as a fallback
    let live = dir.join(LIVE_EXE);
    if live.is_file() {
        return live;
    }
    dir.join(BETA_EXE)
}

/// Re-signed copy of the game app that the launcher starts on macOS (see macos.rs), next to the original.
#[cfg(target_os = "macos")]
pub const MAC_COPY_NAME: &str = "World of Warcraft Forever.app";

/// The first .app in the folder (the Classic beta app name is not fixed), other than the launcher's copy.
#[cfg(target_os = "macos")]
fn game_binary(dir: &Path) -> PathBuf {
    std::fs::read_dir(dir)
        .ok()
        .and_then(|d| {
            let mut apps: Vec<PathBuf> = d
                .flatten()
                .filter(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    !name.starts_with('.') && name != MAC_COPY_NAME
                })
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "app"))
                .collect();
            apps.sort();
            apps.into_iter().next()
        })
        .unwrap_or_else(|| dir.join("World of Warcraft.app"))
}

/// Both channel folders of an install (`_forever_` first).
fn channel_dirs(parent: &Path) -> [PathBuf; 2] {
    [parent.join(LIVE_DIR), parent.join(BETA_DIR)]
}

/// The folder the game is started from: the picked one, or the channel folder inside it. A player who picks the
/// "World of Warcraft" folder gets `_forever_` (or the old `_classic_beta_`) instead of a folder without Wow.exe.
pub fn game_dir(dir: &Path) -> PathBuf {
    // exists(), not is_file(): on macOS the game is an .app folder
    if game_binary(dir).exists() {
        return dir.to_path_buf();
    }
    channel_dirs(dir).into_iter().find(|p| game_binary(p).exists()).unwrap_or_else(|| dir.to_path_buf())
}

fn detect_game_dir() -> Option<String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    #[cfg(windows)]
    for root in ["C:\\Program Files (x86)", "C:\\Program Files", "D:\\", "D:\\Games", "E:\\", "E:\\Games"] {
        candidates.extend(channel_dirs(&Path::new(root).join("World of Warcraft")));
    }
    #[cfg(target_os = "macos")]
    for root in ["/Applications/World of Warcraft".to_string(),
                 home().join("Applications/World of Warcraft").to_string_lossy().into_owned()] {
        candidates.extend(channel_dirs(Path::new(&root)));
    }
    #[cfg(target_os = "linux")]
    {
        // a Lutris entry that already points at the game binary
        if let Ok(dir) = std::fs::read_dir(home().join(".local/share/lutris/games")) {
            for entry in dir.flatten() {
                if let Ok(text) = std::fs::read_to_string(entry.path()) {
                    for line in text.lines() {
                        if let Some(exe) = line.trim().strip_prefix("exe:") {
                            let exe = exe.trim().trim_matches(|c| c == '\'' || c == '"');
                            let name = exe.to_ascii_lowercase();
                            if name.ends_with("wow.exe") || name.ends_with("wowb.exe") {
                                if let Some(parent) = Path::new(exe).parent() {
                                    candidates.push(parent.to_path_buf());
                                }
                            }
                        }
                    }
                }
            }
        }
        for p in ["Games/battlenet/drive_c/Program Files (x86)/World of Warcraft",
                  "Games/battlenet/drive_c/Program Files/World of Warcraft",
                  "Games/World of Warcraft"] {
            candidates.extend(channel_dirs(&home().join(p)));
        }
    }
    candidates.into_iter().find(|p| game_binary(p).exists()).map(|p| p.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server the released builds get from the GitHub repository variables.
    fn tunnel() -> Server {
        Server {
            name: "Legacy of Azeroth".into(),
            portal: "trinity.actual.battle.net".into(),
            address: "play.legacy-of-azeroth.com".into(),
            bnet_port: 48989,
            rest_port: 48990,
            world_port: 48991,
            public_key: STOCK_PUBLIC_KEY.into(),
            region_group: 8,
            website: "https://legacy-of-azeroth.com".into(),
        }
    }

    /// What 1.0.0 wrote into settings.json: the LAN machine on the old ports.
    fn release_1_0_0() -> Server {
        Server { address: "192.168.178.42".into(), bnet_port: 1119, rest_port: 8081, world_port: 8085, ..tunnel() }
    }

    #[test]
    fn lifts_a_1_0_0_settings_file_to_the_tunnel() {
        let mut server = release_1_0_0();
        assert!(migrate_server_to(&mut server, &tunnel()));
        assert_eq!(server.address, "play.legacy-of-azeroth.com");
        assert_eq!((server.bnet_port, server.rest_port, server.world_port), (48989, 48990, 48991));
        // the rest of the file stays what it was
        assert_eq!(server.portal, "trinity.actual.battle.net");
        assert_eq!(server.name, "Legacy of Azeroth");
        assert_eq!(server.website, "https://legacy-of-azeroth.com");
    }

    #[test]
    fn lifts_the_loopback_default_too() {
        let mut server = Server { address: "127.0.0.1".into(), ..release_1_0_0() };
        assert!(migrate_server_to(&mut server, &tunnel()));
        assert_eq!(server.address, "play.legacy-of-azeroth.com");
        assert_eq!(server.world_port, 48991);
    }

    #[test]
    fn leaves_a_server_a_player_entered_alone() {
        // his own address, even on the old ports
        let mut own = Server { address: "wow.example.test".into(), ..release_1_0_0() };
        assert!(!migrate_server_to(&mut own, &tunnel()));
        assert_eq!(own.address, "wow.example.test");
        assert_eq!((own.bnet_port, own.rest_port, own.world_port), (1119, 8081, 8085));

        // the old address with ports he changed himself is his setup too
        let mut ports = Server { bnet_port: 49000, ..release_1_0_0() };
        assert!(!migrate_server_to(&mut ports, &tunnel()));
        assert_eq!(ports.address, "192.168.178.42");
        assert_eq!(ports.bnet_port, 49000);
    }

    #[test]
    fn does_not_rewrite_onto_a_build_without_an_address() {
        // a local build: Server::default() is 127.0.0.1, so "migrating" to it would gain nothing
        let mut server = release_1_0_0();
        let dev = Server { address: "127.0.0.1".into(), ..tunnel() };
        assert!(!migrate_server_to(&mut server, &dev));
        assert_eq!(server.address, "192.168.178.42");
    }

    /// The file after the player corrected the address by hand: the old ports, the old realm name and the old
    /// website are still in it, because there was no field for any of them before 1.3.0.
    fn corrected_by_hand() -> Server {
        Server {
            address: "play.legacy-of-azeroth.com".into(),
            bnet_port: 1119,
            rest_port: 8081,
            world_port: 8085,
            name: "Forever".into(),
            website: "http://192.168.178.42:8088".into(),
            ..tunnel()
        }
    }

    #[test]
    fn lifts_the_old_ports_when_only_the_address_was_corrected() {
        let mut server = corrected_by_hand();
        assert!(migrate_server_to(&mut server, &tunnel()));
        assert_eq!((server.bnet_port, server.rest_port, server.world_port), (48989, 48990, 48991));
        // the address he typed in stays
        assert_eq!(server.address, "play.legacy-of-azeroth.com");
    }

    #[test]
    fn lifts_the_old_realm_name_and_website() {
        let mut server = corrected_by_hand();
        migrate_server_to(&mut server, &tunnel());
        assert_eq!(server.name, "Legacy of Azeroth");
        assert_eq!(server.website, "https://legacy-of-azeroth.com");
    }

    #[test]
    fn keeps_a_third_party_server_as_its_player_set_it_up() {
        let mut own = Server {
            address: "wow.example.test".into(),
            name: "Forever".into(),
            website: String::new(),
            ..corrected_by_hand()
        };
        assert!(!migrate_server_to(&mut own, &tunnel()));
        assert_eq!(own.name, "Forever");
        assert_eq!(own.website, "");
        assert_eq!((own.bnet_port, own.rest_port, own.world_port), (1119, 8081, 8085));
    }

    #[test]
    fn keeps_a_realm_name_the_player_chose() {
        let mut server = Server { name: "My Realm".into(), ..corrected_by_hand() };
        migrate_server_to(&mut server, &tunnel());
        assert_eq!(server.name, "My Realm");
    }

    /// A game in `dir`: Wow.exe, or the .app a mac install carries.
    fn game_in(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        #[cfg(target_os = "macos")]
        std::fs::create_dir_all(dir.join("World of Warcraft.app")).unwrap();
        #[cfg(not(target_os = "macos"))]
        std::fs::write(dir.join(LIVE_EXE), b"MZ").unwrap();
    }

    #[test]
    fn takes_the_channel_folder_inside_the_install_root() {
        let root = std::env::temp_dir().join(format!("forever-launcher-game-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let live = root.join(LIVE_DIR);
        game_in(&live);
        std::fs::create_dir_all(root.join("Data")).unwrap();
        // the install root is not the folder to start from, `_forever_` is
        assert_eq!(game_dir(&root), live);
        // a folder that already holds the game is kept as it is
        assert_eq!(game_dir(&live), live);
        // nothing found: the picked folder stays, so the message names what the player chose
        let empty = root.join("Data");
        assert_eq!(game_dir(&empty), empty);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compares_the_client_build_number() {
        assert!(build_matches("1.60.1.70938", "1.60.1.70938"));
        assert!(build_matches("70938", "1.60.1.70938"));
        assert!(!build_matches("1.60.1.70450", "1.60.1.70938"));
        assert!(!build_matches("", "1.60.1.70938"));
    }

    /// The release workflow passes FOREVER_CLIENT_BUILD as well, otherwise a released launcher cannot tell an
    /// outdated client from a current one.
    #[test]
    fn the_ci_build_knows_the_client_build() {
        if option_env!("CI").is_none() {
            return;
        }
        let expected = expected_version().expect("FOREVER_CLIENT_BUILD did not reach the build");
        // a full client version, e.g. 1.60.1.70959: the build number is what is compared
        let build = expected.rsplit('.').next().unwrap_or_default();
        assert!(build.parse::<u32>().is_ok(), "FOREVER_CLIENT_BUILD is not a version: {expected}");
    }

    /// The release workflow passes FOREVER_SERVER_ADDRESS and the three port variables into the build, so a build
    /// made in CI must carry the tunnel and never the dead 1.0.0 values as its default.
    #[test]
    fn the_ci_build_carries_the_tunnel() {
        if option_env!("CI").is_none() {
            return; // a local build without the repository variables
        }
        // the workflow must actually hand the variable to the compiler: this is what makes option_env! see it
        assert!(option_env!("FOREVER_SERVER_ADDRESS").is_some(), "FOREVER_SERVER_ADDRESS did not reach the build");
        assert!(option_env!("FOREVER_BNET_PORT").is_some(), "FOREVER_BNET_PORT did not reach the build");
        assert!(option_env!("FOREVER_REST_PORT").is_some(), "FOREVER_REST_PORT did not reach the build");
        assert!(option_env!("FOREVER_WORLD_PORT").is_some(), "FOREVER_WORLD_PORT did not reach the build");
        let built_in = Server::default();
        assert_eq!(built_in.address, "play.legacy-of-azeroth.com");
        assert_eq!((built_in.bnet_port, built_in.rest_port, built_in.world_port), (48989, 48990, 48991));
        assert!(!OLD_ADDRESSES.contains(&built_in.address.as_str()));
        assert_ne!((built_in.bnet_port, built_in.rest_port, built_in.world_port), OLD_PORTS);
    }
}
