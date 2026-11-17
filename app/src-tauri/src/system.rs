//! PC preparation: hosts entry for the portal, trust in the server CA, and (Linux) the Wine/Proton runner.

use crate::ca;
use crate::config::{Server, Settings};
use crate::i18n::{t, tf};
use serde::Serialize;
use std::net::{IpAddr, ToSocketAddrs};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Checks {
    pub hosts: bool,
    pub hosts_detail: String,
    pub certificate: bool,
    pub certificate_detail: String,
}

/// IPv4 address the server address resolves to (it may be a DNS name).
pub fn server_ip(server: &Server) -> Result<IpAddr, String> {
    if let Ok(ip) = server.address.parse::<IpAddr>() {
        return Ok(ip);
    }
    (server.address.as_str(), 0)
        .to_socket_addrs()
        .map_err(|e| format!("{} : {e}", server.address))?
        .map(|a| a.ip())
        .find(|ip| ip.is_ipv4())
        .ok_or_else(|| tf("no_resolve", &[&server.address]))
}

fn portal_resolves_to(portal: &str) -> Option<IpAddr> {
    (portal, 0).to_socket_addrs().ok()?.map(|a| a.ip()).find(|ip| ip.is_ipv4())
}

pub fn check(settings: &Settings) -> Checks {
    let server = &settings.server;
    let (hosts, hosts_detail) = match (server_ip(server), portal_resolves_to(&server.portal)) {
        (Ok(want), Some(got)) if want == got => (true, format!("{} → {got}", server.portal)),
        (Ok(want), Some(got)) => (false, tf("hosts_wrong", &[&server.portal, &got, &want])),
        (Ok(_), None) => (false, tf("hosts_missing", &[&server.portal])),
        (Err(e), _) => (false, e),
    };
    let (certificate, certificate_detail) = certificate_status(settings);
    Checks { hosts, hosts_detail, certificate, certificate_detail }
}

fn valid_portal(p: &str) -> bool {
    !p.is_empty() && p.len() < 254 && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

// ------------------------------------------------------------------------------------------------- Windows
#[cfg(windows)]
mod imp {
    use super::*;
    use windows::core::{w, HSTRING, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::Security::Cryptography::*;
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    const HOSTS: &str = r"C:\Windows\System32\drivers\etc\hosts";

    pub fn certificate_status(_: &Settings) -> (bool, String) {
        unsafe {
            let Ok(store) = CertOpenSystemStoreW(None, w!("ROOT")) else {
                return (false, t("cert_store_unreadable").into());
            };
            let hash = ca::sha1();
            let blob = CRYPT_INTEGER_BLOB { cbData: 20, pbData: hash.as_ptr() as *mut u8 };
            let found = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                                   CERT_FIND_SHA1_HASH, Some(&blob as *const _ as _), None);
            let ok = !found.is_null();
            if ok {
                let _ = CertFreeCertificateContext(Some(found));
            }
            let _ = CertCloseStore(store, 0);
            (ok, if ok { t("cert_ok_windows").into() } else { t("cert_missing").into() })
        }
    }

    /// Relaunches this executable elevated (one UAC prompt) to write the hosts file and install the CA.
    pub fn repair(settings: &Settings) -> Result<(), String> {
        let ip = server_ip(&settings.server)?;
        if !valid_portal(&settings.server.portal) {
            return Err(t("bad_portal").into());
        }
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let params = HSTRING::from(format!("--admin-setup {ip} {}", settings.server.portal));
        let file = HSTRING::from(exe.as_os_str());
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: w!("runas"),
            lpFile: PCWSTR(file.as_ptr()),
            lpParameters: PCWSTR(params.as_ptr()),
            nShow: SW_HIDE.0,
            ..Default::default()
        };
        unsafe {
            ShellExecuteExW(&mut info).map_err(|_| t("admin_refused").to_string())?;
            if WaitForSingleObject(info.hProcess, INFINITE) != WAIT_OBJECT_0 {
                return Err(t("install_wait").into());
            }
            let mut code = 1u32;
            let _ = GetExitCodeProcess(info.hProcess, &mut code);
            let _ = CloseHandle(info.hProcess);
            if code != 0 {
                return Err(tf("install_failed", &[&code]));
            }
        }
        Ok(())
    }

    /// Runs in the elevated copy: `--admin-setup <ip> <portal>`. Returns the process exit code.
    pub fn admin_setup(ip: &str, portal: &str) -> i32 {
        let Ok(ip) = ip.parse::<IpAddr>() else { return 2 };
        if !valid_portal(portal) {
            return 2;
        }
        let mut code = 0;
        // hosts: drop old lines for the portal, add ours
        match std::fs::read_to_string(HOSTS) {
            Ok(text) => {
                let mut lines: Vec<&str> = text
                    .lines()
                    .filter(|l| !l.split('#').next().unwrap_or("").split_whitespace().skip(1).any(|h| h.eq_ignore_ascii_case(portal)))
                    .collect();
                let entry = format!("{ip} {portal}  # Forever Launcher");
                lines.push(&entry);
                if std::fs::write(HOSTS, lines.join("\r\n") + "\r\n").is_err() {
                    code = 3;
                }
            }
            Err(_) => code = 3,
        }
        // CA in the machine root store
        unsafe {
            let der = ca::der();
            match CertOpenStore(CERT_STORE_PROV_SYSTEM_W, CERT_QUERY_ENCODING_TYPE(0), None,
                                CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT),
                                Some(w!("ROOT").as_ptr() as _)) {
                Ok(store) => {
                    if CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &der,
                                                        CERT_STORE_ADD_REPLACE_EXISTING, None).is_err() {
                        code = 4;
                    }
                    let _ = CertCloseStore(store, 0);
                }
                Err(_) => code = 4,
            }
        }
        code
    }

    /// Makes this PC trust the server's current CA (one UAC prompt). Ok(true): it had to be installed.
    pub fn ensure_ca(settings: &Settings) -> Result<bool, String> {
        if certificate_status(settings).0 {
            return Ok(false);
        }
        repair(settings)?;
        Ok(true)
    }
}

// ------------------------------------------------------------------------------------------------- macOS
#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use crate::config::config_dir;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// Rewrites /etc/hosts (run as root by osascript, arguments passed separately).
    const HOSTS_SCRIPT: &str = r#"set -e
t=$(mktemp)
awk -v h="$2" '{ line=$0; sub(/#.*/, "", line); n=split(line, f, /[ \t]+/); keep=1; for (i=2; i<=n; i++) if (f[i]==h) keep=0; if (keep) print $0 }' /etc/hosts > "$t"
printf '%s %s  # Forever Launcher\n' "$1" "$2" >> "$t"
cat "$t" > /etc/hosts
rm -f "$t"
dscacheutil -flushcache
killall -HUP mDNSResponder || true
"#;

    fn write_file(name: &str, data: &str) -> Result<PathBuf, String> {
        let path = config_dir().join(name);
        std::fs::create_dir_all(config_dir()).map_err(|e| e.to_string())?;
        std::fs::write(&path, data).map_err(|e| format!("{} : {e}", path.display()))?;
        Ok(path)
    }

    /// The CA in use, written to disk (the process `security` reads it from there).
    fn ca_file() -> Result<PathBuf, String> {
        write_file("forever_root_ca.crt", &ca::pem())
    }

    /// Common name of the CA: the name the certificate is stored under in the keychain.
    fn common_name(ca: &Path) -> Option<String> {
        let out = Command::new("openssl")
            .args(["x509", "-in"])
            .arg(ca)
            .args(["-noout", "-subject", "-nameopt", "RFC2253"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let name = text.split("CN=").nth(1)?.trim().trim_matches('"').to_string();
        (!name.is_empty()).then_some(name)
    }

    /// Fingerprint of every certificate with that name in the keychain search list (upper case, no spaces).
    fn installed_fingerprints(cn: &str) -> Vec<String> {
        let Ok(out) = Command::new("security").args(["find-certificate", "-a", "-c", cn, "-Z"]).output() else {
            return Vec::new();
        };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.trim().strip_prefix("SHA-1 hash:"))
            .map(|h| h.trim().replace(' ', "").to_ascii_uppercase())
            .collect()
    }

    /// This user's keychain: the trust that matters for the game, and no administrator rights needed.
    fn login_keychain() -> String {
        crate::config::home().join("Library/Keychains/login.keychain-db").to_string_lossy().into_owned()
    }

    /// Whether that certificate name has an explicit SSL trust setting. A certificate that is only
    /// *present* in the keychain is not trusted — `security verify-cert` happily accepts it anyway, which is
    /// why the game still refused the connection while this check was missing.
    fn has_ssl_trust(cn: &str) -> bool {
        let Ok(out) = Command::new("security").arg("dump-trust-settings").output() else { return false };
        let text = String::from_utf8_lossy(&out.stdout);
        let mut ours = false;
        for line in text.lines() {
            let line = line.trim();
            if let Some(name) = line.strip_prefix("Cert ").and_then(|r| r.split_once(':').map(|(_, n)| n)) {
                ours = name.trim() == cn;
            } else if ours && line.contains("Policy OID") && line.contains("SSL") {
                return true;
            }
        }
        false
    }

    /// (does this Mac trust the server's *current* CA?, text for the UI)
    fn status() -> (bool, String) {
        let Ok(ca) = ca_file() else { return (false, t("cert_not_trusted").into()) };
        let current = ca::sha1_hex();
        let Some(cn) = common_name(&ca) else { return (false, t("cert_not_trusted").into()) };
        if !installed_fingerprints(&cn).contains(&current) {
            // the server regenerated its certificates, or none was ever installed here
            return (false, t("cert_not_installed").into());
        }
        if has_ssl_trust(&cn) {
            (true, t("cert_ok_macos").into())
        } else {
            (false, t("cert_not_trusted").into())
        }
    }

    pub fn certificate_status(_: &Settings) -> (bool, String) {
        status()
    }

    /// Installs the certificate as a trusted root for SSL in this user's keychain (no dialog, no admin).
    /// The system keychain would cover every user but needs the administrator authorisation, which macOS
    /// refuses unless the launcher runs in the graphical session; the user's own trust is what the game uses.
    fn install(ca: &Path) -> Result<(), String> {
        let out = Command::new("security")
            .args(["add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k"])
            .arg(login_keychain())
            .arg(ca)
            .output();
        match out {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(tf("cert_trust_failed", &[&String::from_utf8_lossy(&o.stderr).trim()])),
            Err(e) => Err(format!("security : {e}")),
        }
    }

    /// Makes this Mac trust the server's current CA. Ok(true): it had to be installed (or renewed).
    pub fn ensure_ca(_: &Settings) -> Result<bool, String> {
        if status().0 {
            return Ok(false);
        }
        install(&ca_file()?)?;
        if status().0 {
            Ok(true)
        } else {
            // just refusing the game with "cannot connect" would hide the reason
            Err(t("cert_not_trusted").into())
        }
    }

    pub fn repair(settings: &Settings) -> Result<(), String> {
        let mut errors = Vec::new();
        let ip = server_ip(&settings.server)?;
        let portal = &settings.server.portal;
        if !valid_portal(portal) {
            return Err(t("bad_portal").into());
        }
        if portal_resolves_to(portal) != Some(ip) {
            let script = write_file("hosts.sh", HOSTS_SCRIPT)?;
            let status = Command::new("osascript")
                .args(["-e", "on run argv",
                       "-e", "do shell script \"/bin/sh \" & quoted form of item 1 of argv & \" \" & quoted form of item 2 of argv & \" \" & quoted form of item 3 of argv with prompt (item 4 of argv) with administrator privileges",
                       "-e", "end run"])
                .arg(&script)
                .arg(ip.to_string())
                .arg(portal)
                .arg(t("hosts_prompt"))
                .output();
            match status {
                Ok(o) if o.status.success() => {}
                Ok(o) if String::from_utf8_lossy(&o.stderr).contains("-128") => errors.push(t("hosts_refused").to_string()),
                Ok(o) => errors.push(tf("hosts_write_failed", &[&String::from_utf8_lossy(&o.stderr).trim()])),
                Err(e) => errors.push(format!("osascript : {e}")),
            }
        }
        if !status().0 {
            // must run in the user's session (not as root): macOS asks for the authorisation itself, a root
            // process gets "no user interaction was possible"
            match ca_file().and_then(|ca| install(&ca)) {
                Ok(()) => {}
                Err(e) => errors.push(e),
            }
        }
        if errors.is_empty() { Ok(()) } else { Err(errors.join(" ; ")) }
    }
}

// ------------------------------------------------------------------------------------------------- Linux
#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::config::home;
    use std::path::Path;
    use std::process::Command;

    /// (name, path) of every Proton with a `proton` script, deduplicated by real path.
    pub fn list_protons() -> Vec<(String, String)> {
        let roots = [
            home().join(".steam/root/compatibilitytools.d"),
            home().join(".local/share/Steam/compatibilitytools.d"),
            "/usr/share/steam/compatibilitytools.d".into(),
            home().join(".local/share/Steam/steamapps/common"),
            home().join(".steam/steam/steamapps/common"),
        ];
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for root in roots {
            let Ok(dir) = std::fs::read_dir(&root) else { continue };
            let mut entries: Vec<_> = dir.flatten().map(|e| e.path()).collect();
            entries.sort_by_key(|p| p.file_name().map(|n| n.to_string_lossy().to_lowercase()));
            for p in entries {
                if !p.join("proton").is_file() {
                    continue;
                }
                let real = std::fs::canonicalize(&p).unwrap_or(p.clone());
                if seen.insert(real) {
                    out.push((p.file_name().unwrap().to_string_lossy().into_owned(), p.to_string_lossy().into_owned()));
                }
            }
        }
        out
    }

    /// Removes the variables an AppImage points into itself (LD_LIBRARY_PATH, GTK/GIO paths...), so that
    /// Wine, umu, gamescope and pkexec run with the system's own libraries.
    pub fn clean_env(cmd: &mut Command) -> &mut Command {
        cmd.env_remove("APPIMAGE").env_remove("APPDIR").env_remove("OWD").env_remove("ARGV0");
        if let Ok(appdir) = std::env::var("APPDIR") {
            for (k, v) in std::env::vars_os() {
                if v.to_string_lossy().contains(&appdir) {
                    cmd.env_remove(k);
                }
            }
        }
        cmd
    }

    pub fn which(cmd: &str) -> bool {
        std::env::var_os("PATH")
            .map(|paths| std::env::split_paths(&paths).any(|d| d.join(cmd).is_file()))
            .unwrap_or(false)
    }

    pub fn default_runner() -> String {
        let protons = list_protons();
        let rank = |n: &str| {
            let n = n.to_lowercase();
            (!n.contains("latest"), !n.contains("cachyos"), !(n.contains("ge-proton") || n.contains("proton-ge")))
        };
        match protons.iter().min_by_key(|(n, _)| rank(n)) {
            Some((_, p)) if which("umu-run") => p.clone(),
            _ => "wine".into(),
        }
    }

    pub fn keyboard_layout() -> String {
        if let Ok(o) = Command::new("gsettings").args(["get", "org.gnome.desktop.input-sources", "sources"]).output() {
            let s = String::from_utf8_lossy(&o.stdout);
            if let Some(start) = s.find("('xkb', '") {
                let rest = &s[start + 9..];
                if let Some(end) = rest.find('\'') {
                    return rest[..end].to_string();
                }
            }
        }
        if let Ok(o) = Command::new("localectl").arg("status").output() {
            let s = String::from_utf8_lossy(&o.stdout);
            let get = |k: &str| s.lines().find_map(|l| l.trim().strip_prefix(k).map(|v| v.trim().split(',').next().unwrap_or("").to_string()));
            if let Some(layout) = get("X11 Layout:").filter(|l| !l.is_empty()) {
                return match get("X11 Variant:").filter(|v| !v.is_empty()) {
                    Some(v) => format!("{layout}+{v}"),
                    None => layout,
                };
            }
        }
        "us".into()
    }

    /// UTF-8 POSIX locale installed on this PC for a game locale (frFR -> fr_FR.UTF-8).
    pub fn posix_locale(locale: &str) -> Option<String> {
        if locale.len() != 4 {
            return None;
        }
        let want = format!("{}_{}", &locale[..2], &locale[2..]).to_lowercase();
        let out = Command::new("locale").arg("-a").output().ok()?;
        let list = String::from_utf8_lossy(&out.stdout).to_lowercase();
        list.split_whitespace()
            .any(|l| l == format!("{want}.utf8") || l == format!("{want}.utf-8"))
            .then(|| format!("{}_{}.UTF-8", &locale[..2], &locale[2..]))
    }

    /// Command that runs a Windows program in the prefix (umu-run + Proton, or wine), with its environment.
    pub fn runner(settings: &Settings) -> Result<(Vec<String>, Vec<(String, String)>), String> {
        let l = &settings.linux;
        let mut env = vec![("WINEPREFIX".to_string(), l.prefix.clone())];
        if let Some(posix) = posix_locale(&settings.locale) {
            env.push(("LANG".into(), posix.clone()));
            env.push(("LC_ALL".into(), posix));
        }
        std::fs::create_dir_all(&l.prefix).map_err(|e| tf("prefix_error", &[&l.prefix, &e]))?;
        if l.runner == "wine" || l.runner.is_empty() {
            if !which("wine") {
                return Err(t("wine_not_found").into());
            }
            return Ok((vec!["wine".into()], env));
        }
        if !which("umu-run") {
            return Err(t("umu_not_found").into());
        }
        if !Path::new(&l.runner).join("proton").is_file() {
            return Err(tf("proton_not_found", &[&l.runner]));
        }
        env.push(("PROTONPATH".into(), l.runner.clone()));
        env.push(("GAMEID".into(), "umu-default".into()));
        env.push(("STORE".into(), "none".into()));
        Ok((vec!["umu-run".into()], env))
    }

    /// Runs a Windows program (e.g. reg.exe) in the prefix and waits for it.
    pub fn run_in_prefix(settings: &Settings, args: &[&str]) -> Result<(), String> {
        let (cmd, env) = runner(settings)?;
        let out = clean_env(&mut Command::new(&cmd[0])).args(&cmd[1..]).args(args).envs(env).output()
            .map_err(|e| format!("{} : {e}", cmd[0]))?;
        if out.status.success() {
            Ok(())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(tf("command_failed", &[&args.first().unwrap_or(&""), &err.chars().rev().take(300).collect::<String>().chars().rev().collect::<String>()]))
        }
    }

    fn prefix_has_ca(prefix: &str) -> bool {
        let sha = ca::sha1_hex();
        ["system.reg", "pfx/system.reg"].iter().any(|r| {
            std::fs::read_to_string(Path::new(prefix).join(r)).map(|t| t.contains(&sha)).unwrap_or(false)
        })
    }

    pub fn certificate_status(settings: &Settings) -> (bool, String) {
        // the client checks the certificate with the Windows root store of its Wine prefix
        if prefix_has_ca(&settings.linux.prefix) {
            (true, t("cert_ok_prefix").into())
        } else if !Path::new(&settings.linux.prefix).join("system.reg").exists() {
            (false, t("prefix_missing").into())
        } else {
            (false, t("cert_not_in_prefix").into())
        }
    }

    /// Adds the CA to the prefix root store (HKLM\...\Root\Certificates\<SHA1>\Blob).
    pub fn install_ca_in_prefix(settings: &Settings) -> Result<(), String> {
        if prefix_has_ca(&settings.linux.prefix) {
            return Ok(());
        }
        let der = ca::der();
        let sha = ca::sha1();
        let mut blob = Vec::with_capacity(der.len() + 40);
        for (prop, data) in [(3u32, &sha[..]), (0x20u32, &der[..])] {
            blob.extend(prop.to_le_bytes());
            blob.extend(1u32.to_le_bytes());
            blob.extend((data.len() as u32).to_le_bytes());
            blob.extend(data);
        }
        let key = format!(r"HKLM\Software\Microsoft\SystemCertificates\Root\Certificates\{}", hex::encode_upper(sha));
        run_in_prefix(settings, &["reg", "add", &key, "/v", "Blob", "/t", "REG_BINARY", "/d", &hex::encode_upper(blob), "/f"])
    }

    pub fn repair(settings: &Settings) -> Result<(), String> {
        let mut errors = Vec::new();
        let ip = server_ip(&settings.server)?;
        let portal = &settings.server.portal;
        if !valid_portal(portal) {
            return Err(t("bad_portal").into());
        }
        if portal_resolves_to(portal) != Some(ip) {
            // /etc/hosts through pkexec; arguments are passed separately, never interpolated into the script
            let script = r#"set -e
t=$(mktemp)
awk -v h="$2" '{ line=$0; sub(/#.*/, "", line); n=split(line, f, /[ \t]+/); keep=1; for (i=2; i<=n; i++) if (f[i]==h) keep=0; if (keep) print $0 }' /etc/hosts > "$t"
printf '%s %s  # Forever Launcher\n' "$1" "$2" >> "$t"
cat "$t" > /etc/hosts
rm -f "$t""#;
            match clean_env(&mut Command::new("pkexec")).args(["sh", "-c", script, "sh", &ip.to_string(), portal]).status() {
                Ok(s) if s.success() => {}
                Ok(s) if s.code() == Some(126) => errors.push(t("hosts_refused").to_string()),
                Ok(_) | Err(_) => errors.push(t("hosts_write_failed_pkexec").to_string()),
            }
        }
        if let Err(e) = install_ca_in_prefix(settings) {
            errors.push(e);
        }
        if errors.is_empty() { Ok(()) } else { Err(errors.join(" ; ")) }
    }

    /// Makes the game's Wine prefix trust the server's current CA. Ok(true): it had to be installed.
    pub fn ensure_ca(settings: &Settings) -> Result<bool, String> {
        if prefix_has_ca(&settings.linux.prefix) {
            return Ok(false);
        }
        install_ca_in_prefix(settings)?;
        if prefix_has_ca(&settings.linux.prefix) {
            Ok(true)
        } else {
            Err(t("cert_not_in_prefix").into())
        }
    }
}

pub use imp::*;
