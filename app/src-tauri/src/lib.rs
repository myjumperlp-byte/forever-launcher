mod api;
mod ca;
mod config;
// macOS: only the entropy is used (see macos.rs); the rest is kept for its tests
#[cfg_attr(target_os = "macos", allow(dead_code))]
mod dpapi;
mod game;
mod i18n;
#[cfg(target_os = "macos")]
mod macos;
// macOS: the game may not reach private addresses, so it is pointed at loopback and relayed from there
#[cfg(target_os = "macos")]
mod relay;
// macOS: no external memory patch (see macos.rs); kept for its tests
#[cfg_attr(target_os = "macos", allow(dead_code))]
mod patcher;
mod realm;
mod system;
mod update;

use config::{Session, Settings};
use i18n::{t, tf};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
#[cfg(not(target_os = "macos"))]
use std::time::Duration;
use tauri::{AppHandle, Emitter, State};

#[cfg(windows)]
pub use system::admin_setup;

struct AppState {
    settings: Mutex<Settings>,
    playing: AtomicBool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    settings: Settings,
    email: Option<String>,
    platform: &'static str,
    version: &'static str,
    locales: &'static [&'static str],
    runners: Vec<(String, String)>,
    game_found: bool,
    game_version: Option<String>,
    playing: bool,
    /// The client build and the one the realm runs, when they differ: shown above the Play button, not enforced.
    build_mismatch: Option<BuildMismatch>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BuildMismatch {
    installed: String,
    expected: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GameEvent {
    kind: &'static str,
    message: String,
}

fn emit(app: &AppHandle, kind: &'static str, message: impl Into<String>) {
    let _ = app.emit("game", GameEvent { kind, message: message.into() });
}

/// One line in launcher.log (same folder as settings.json): what was written where and how the start went,
/// so a wrong portal or a missing macOS permission can be read without a terminal.
fn log_line(message: impl AsRef<str>) {
    config::log_line(message);
}

fn runners() -> Vec<(String, String)> {
    #[cfg(target_os = "linux")]
    {
        let mut r = system::list_protons();
        r.push((t("wine_system").into(), "wine".into()));
        r
    }
    #[cfg(not(target_os = "linux"))]
    Vec::new()
}

#[tauri::command]
fn get_state(state: State<AppState>) -> Snapshot {
    let settings = state.settings.lock().unwrap().clone();
    Snapshot {
        game_found: settings.game_found(),
        game_version: config::installed_version(std::path::Path::new(&settings.game_dir)),
        email: Session::load().map(|s| s.email),
        platform: if cfg!(windows) { "windows" } else if cfg!(target_os = "macos") { "macos" } else { "linux" },
        version: env!("CARGO_PKG_VERSION"),
        locales: config::LOCALES,
        runners: runners(),
        playing: state.playing.load(Ordering::SeqCst),
        build_mismatch: settings
            .client_build_mismatch(&realm::accepted())
            .map(|(installed, expected)| BuildMismatch { installed, expected }),
        settings,
    }
}

#[tauri::command]
fn save_settings(state: State<AppState>, settings: Settings) -> Result<(), String> {
    let mut settings = settings;
    if settings.server.portal.is_empty() {
        settings.server = Default::default();
    }
    settings.save().map_err(|e| e.to_string())?;
    *state.settings.lock().unwrap() = settings;
    Ok(())
}

/// Language of the messages sent by the Rust side (the UI resolves "system language" itself).
#[tauri::command]
fn set_language(language: String) {
    i18n::set(&language);
}

/// Language installed with the client in that folder (to preselect it).
#[tauri::command]
fn detect_locale(game_dir: String) -> Option<String> {
    config::installed_locale(std::path::Path::new(&game_dir))
}

#[tauri::command]
async fn login(state: State<'_, AppState>, email: String, password: String) -> Result<String, String> {
    let server = state.settings.lock().unwrap().server.clone();
    ca::refresh(&server).await;
    let api = api::Api::new(&server).await?;
    let ticket = api.login(email.trim(), &password).await?;
    let token = api.remember(&ticket).await?;
    let check = api.launcher_login(&token.token).await?;
    Session { email: check.email.clone(), token: token.token, expires: token.expires }
        .save()
        .map_err(|e| tf("session_save", &[&e]))?;
    Ok(check.email.to_lowercase())
}

#[tauri::command]
async fn logout(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(s) = Session::load() {
        let server = state.settings.lock().unwrap().server.clone();
        if let Ok(api) = api::Api::new(&server).await {
            api.forget(&s.token).await;
        }
    }
    Session::clear();
    Ok(())
}

#[derive(Serialize)]
struct Status {
    online: bool,
}

#[tauri::command]
async fn server_status(state: State<'_, AppState>) -> Result<Status, String> {
    let s = state.settings.lock().unwrap().server.clone();
    // Only the bnetserver is probed, and over TLS: a bare TCP connect to the world port would take one of the
    // server's Network.ConnectionsPerIp slots, and a login that just failed leaves its sockets open - the retry
    // players then make is refused because of the check that was meant to help them.
    Ok(Status { online: api::login_open(&s).await })
}

/// Newest published launcher build, when it is newer than this one.
#[tauri::command]
async fn check_update() -> Result<Option<update::UpdateInfo>, String> {
    update::check().await
}

/// Reads the client builds the realm accepts (see `realm`), then the UI asks `get_state` again: the banner above
/// the Play button follows that list, so it does not stay up for a client the realm runs.
#[tauri::command]
async fn check_client() -> Vec<String> {
    realm::refresh().await
}

/// Downloads the newest build so that the restart puts it in place. Returns the version.
#[tauri::command]
async fn install_update() -> Result<String, String> {
    update::install().await
}

/// Starts the launcher again; a just downloaded update is swapped in on the way (one restart, not two).
#[tauri::command]
fn relaunch() {
    update::apply_pending();
    update::restart();
}

#[tauri::command]
async fn news(state: State<'_, AppState>) -> Result<Vec<api::NewsItem>, String> {
    let website = state.settings.lock().unwrap().server.website.clone();
    if website.is_empty() {
        return Ok(Vec::new());
    }
    api::news(&website).await
}

#[tauri::command]
async fn checks(state: State<'_, AppState>) -> Result<system::Checks, String> {
    let settings = state.settings.lock().unwrap().clone();
    ca::refresh(&settings.server).await;
    tokio::task::spawn_blocking(move || system::check(&settings)).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn repair(state: State<'_, AppState>) -> Result<system::Checks, String> {
    let settings = state.settings.lock().unwrap().clone();
    ca::refresh(&settings.server).await;
    tokio::task::spawn_blocking(move || {
        system::repair(&settings)?;
        Ok(system::check(&settings))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Linux: ends the Wine session of the prefix right now. Returns the number of processes that were attached,
/// so the player sees that something actually happened.
#[tauri::command]
fn cleanup_wine(state: State<AppState>) -> Result<usize, String> {
    #[cfg(target_os = "linux")]
    {
        let prefix = state.settings.lock().unwrap().linux.prefix.clone();
        let (before, kb) = system::wine_processes(&prefix);
        system::wineserver_kill(&prefix);
        let (after, _) = system::wine_processes(&prefix);
        log_line(format!("wine: cleanup, {before} processes ({} MiB) before, {after} after", kb / 1024));
        Ok(before)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = state;
        Err(t("linux_only").into())
    }
}

/// Linux: moves the prefix aside (nothing deleted) so the next start creates a fresh one.
#[tauri::command]
fn reset_prefix(state: State<AppState>) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        if state.playing.load(Ordering::SeqCst) {
            return Err(t("already_running").into());
        }
        let settings = state.settings.lock().unwrap().clone();
        let backup = system::reset_prefix(&settings)?;
        log_line(format!("prefix: reset, old prefix kept at {backup}"));
        Ok(backup)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = state;
        Err(t("linux_only").into())
    }
}

#[tauri::command]
async fn play(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    if state.playing.swap(true, Ordering::SeqCst) {
        return Err(t("already_running").into());
    }
    let settings = state.settings.lock().unwrap().clone();
    let result = start(&app, settings).await;
    if result.is_err() {
        state.playing.store(false, Ordering::SeqCst);
    }
    result
}

async fn start(app: &AppHandle, settings: Settings) -> Result<(), String> {
    if !settings.game_found() {
        return Err(t("game_not_found").into());
    }
    // A different build is only noted, never a refusal: the realm also accepts slightly newer clients
    // (Realm.AlsoAcceptBuilds), and after an automatic Battle.net update the player cannot go back anyway.
    if let Some((installed, expected)) = settings.client_build_mismatch(&realm::accepted()) {
        log_line(format!("client: build {installed}, the realm runs {expected} (starting anyway)"));
    }
    let session = Session::load().ok_or(t("login_first"))?;
    emit(app, "step", t("step_connecting"));
    // the server may have regenerated its certificates since this launcher was built
    ca::refresh(&settings.server).await;
    let api = api::Api::new(&settings.server).await?;
    let login = match api.launcher_login(&session.token).await {
        Err(e) if e == "expired" => {
            Session::clear();
            return Err(t("session_expired").into());
        }
        other => other?,
    };

    emit(app, "step", t("step_preparing"));
    let s = settings.clone();
    let renewed = tokio::task::spawn_blocking(move || -> Result<bool, String> {
        // the game account the login answer names: "WoW1" only when the server does not list one
        let account = login
            .game_accounts
            .first()
            .map(|a| a.name.clone())
            .unwrap_or_else(|| "WoW1".into());
        // macOS blocks the game's connections to the server's private address (Local Network privacy, no packet
        // leaves the machine); loopback is always allowed, so the client connects there and the launcher relays
        #[cfg(target_os = "macos")]
        let portal = format!("127.0.0.1:{}", s.server.bnet_port);
        #[cfg(not(target_os = "macos"))]
        let portal = format!("{}:{}", s.server.portal, s.server.bnet_port);
        log_line(format!("play: portal {portal}, game account {account}, ticket {} characters", login.login_ticket.len()));
        game::write_wtf(&s)?;
        log_line("wtf: portal set in Config.wtf and ForeverLauncher.wtf");
        // the game client only gets through if this computer trusts the CA the server uses right now
        let renewed = system::ensure_ca(&s)?;
        log_line(if renewed { "ca: trust renewed" } else { "ca: already trusted" });
        #[cfg(not(target_os = "macos"))]
        game::write_launch_options(&s, &portal, &login.login_ticket, &account)?;
        #[cfg(target_os = "macos")]
        macos::write_launch_options(&portal, &login.login_ticket, &account)?;
        log_line("launch options: written and read back");
        Ok(renewed)
    })
    .await
    .map_err(|e| e.to_string())??;
    if renewed {
        emit(app, "log", t("cert_renewed"));
    }
    launch(app, settings).await
}

/// macOS: re-signed copy of the game with keypatch.dylib, followed through the library's log.
#[cfg(target_os = "macos")]
async fn launch(app: &AppHandle, settings: Settings) -> Result<(), String> {
    let (a, s) = (app.clone(), settings.clone());
    let copy = tokio::task::spawn_blocking(move || macos::prepare_copy(&s, |m| emit(&a, "step", m)))
        .await
        .map_err(|e| e.to_string())??;
    // the login and the world port are relayed from 127.0.0.1, so the game never talks to the private address
    let relay = relay::Relay::start(&settings.server.address, &[settings.server.bnet_port, settings.server.world_port])?;
    log_line(format!(
        "relay: {:?} -> {}",
        relay.ports(),
        settings.server.address
    ));
    emit(app, "step", t("step_launching"));
    log_line(format!("start: {}", copy.display()));
    let (child, log) = macos::spawn(&settings, &copy)?;
    let app = app.clone();
    std::thread::spawn(move || {
        // the relay has to live as long as the game: dropped when this thread ends, i.e. when the game closed
        emit(&app, "running", t("running"));
        match macos::watch(child, &log, |kind, m| emit(&app, kind, m)) {
            Ok(()) => emit(&app, "closed", t("closed")),
            Err(e) => emit(&app, "error", e),
        }
        drop(relay);
        log_line("relay: stopped");
        app.state::<AppState>().playing.store(false, Ordering::SeqCst);
    });
    Ok(())
}

/// Windows, Linux: the game is started, then the patcher writes the key into its memory.
#[cfg(not(target_os = "macos"))]
async fn launch(app: &AppHandle, settings: Settings) -> Result<(), String> {
    emit(app, "step", t("step_launching"));
    #[cfg(target_os = "linux")]
    {
        // nothing is playing at this point, so a Wine session still in the prefix is a leftover
        let prefix = settings.linux.prefix.clone();
        let (left, kb) = system::wine_processes(&prefix);
        if left > 0 {
            log_line(format!("wine: {left} leftover processes ({} MiB) in the prefix, ending them first", kb / 1024));
            system::wineserver_kill(&prefix);
        }
    }
    let patcher = patcher::Patcher::new(&settings.server.public_key, settings.server.region_group)?;
    let mut child = game::spawn(&settings)?;
    #[cfg(target_os = "linux")]
    let session = settings.clone();
    let app = app.clone();
    std::thread::spawn(move || {
        // reap the started process (on Linux it is umu-run / gamescope, which may exit early)
        let child_pid = child.id();
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        let first = wait_for_client(child_pid);
        match first {
            Some(mem) => {
                emit(&app, "running", t("running"));
                patcher.watch(
                    Box::new(mem),
                    |cur| {
                        let other = patcher::find_client()?;
                        let better = !cur.alive() || other.rss() > (current_rss(cur) * 2).max(50 * 1024);
                        (other_pid(&other) != cur.pid() && better).then(|| Box::new(other) as Box<dyn patcher::Memory>)
                    },
                    |ev| match ev {
                        patcher::Event::Log(m) => emit(&app, "log", m),
                        patcher::Event::Ready => emit(&app, "ready", t("ready")),
                        patcher::Event::Closed => {}
                    },
                );
                emit(&app, "closed", t("closed"));
            }
            None => emit(&app, "error", t("not_started")),
        }
        #[cfg(target_os = "linux")]
        end_session(&session, child_pid);
        app.state::<AppState>().playing.store(false, Ordering::SeqCst);
    });
    Ok(())
}

use tauri::Manager;

/// Linux: the game is gone. End the process group it was started in and the Wine session of the prefix, so a
/// closed (or crashed) client leaves nothing behind. Only that group and that prefix - never a pattern kill.
#[cfg(target_os = "linux")]
fn end_session(settings: &Settings, pgid: u32) {
    let group = format!("-{pgid}");
    let _ = std::process::Command::new("kill").args(["-TERM", &group]).status();
    std::thread::sleep(Duration::from_millis(500));
    let _ = std::process::Command::new("kill").args(["-KILL", &group]).status();
    system::wineserver_kill(&settings.linux.prefix);
}

#[cfg(not(target_os = "macos"))]
fn other_pid(m: &patcher::ProcessMemory) -> u32 {
    use patcher::Memory;
    m.pid()
}

#[cfg(not(target_os = "macos"))]
fn current_rss(m: &dyn patcher::Memory) -> u64 {
    patcher::ProcessMemory::open(m.pid()).map(|p| p.rss()).unwrap_or(0)
}

#[cfg(not(target_os = "macos"))]
fn wait_for_client(child_pid: u32) -> Option<patcher::ProcessMemory> {
    #[cfg(windows)]
    if let Some(m) = patcher::ProcessMemory::open(child_pid) {
        return Some(m);
    }
    let _ = child_pid;
    for _ in 0..180 {
        if let Some(m) = patcher::find_client() {
            return Some(m);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    None
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // before the window: a downloaded update is swapped in and the new build takes over
    update::apply_pending();
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState { settings: Mutex::new(Settings::load()), playing: AtomicBool::new(false) })
        .invoke_handler(tauri::generate_handler![
            get_state, save_settings, set_language, detect_locale, login, logout, server_status, news, checks, repair, play,
            check_update, install_update, relaunch, check_client, cleanup_wine, reset_prefix
        ])
        .build(tauri::generate_context!())
        .expect("error while running Forever Launcher");
    app.run(|handle, event| {
        // the window is closing for good: a Wine session the game left behind would stay until the reboot
        if let tauri::RunEvent::Exit = event {
            #[cfg(target_os = "linux")]
            {
                let prefix = handle.state::<AppState>().settings.lock().unwrap().linux.prefix.clone();
                system::wineserver_kill(&prefix);
            }
            let _ = handle;
        }
    });
}
