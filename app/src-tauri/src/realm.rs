//! Client builds the realm runs, read from `client-build.txt` of the launcher repository at every start.
//!
//! The list used to be baked into the build (FOREVER_CLIENT_BUILD), so after a Battle.net update every installed
//! launcher warned about a client it could not do anything about until a new launcher was published. Now one line
//! in that file is enough: the launcher compares against the list it reads, and the build-time value is only the
//! fallback for a start without network.

use crate::config;
use std::sync::Mutex;
use std::time::Duration;

/// The list read from the repository; empty until a read succeeded.
static ACCEPTED: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// One build per line, further ones may be separated by commas; `#` starts a comment.
pub fn parse(text: &str) -> Vec<String> {
    let mut list: Vec<String> = Vec::new();
    for line in text.lines() {
        for cell in line.split('#').next().unwrap_or("").split([',', ';', ' ', '\t']) {
            let cell = cell.trim();
            if !cell.is_empty() && !list.iter().any(|v| v == cell) {
                list.push(cell.to_string());
            }
        }
    }
    list
}

/// The builds the installed client is compared against: the repository's list, else the one baked into this build.
pub fn accepted() -> Vec<String> {
    let cached = ACCEPTED.lock().unwrap().clone();
    if !cached.is_empty() {
        return cached;
    }
    config::expected_version().map(|v| vec![v.to_string()]).unwrap_or_default()
}

/// `client-build.txt` on the repository's default branch: a plain text file that can be edited in the browser.
fn url() -> String {
    format!("https://raw.githubusercontent.com/{}/HEAD/client-build.txt", crate::update::repo())
}

async fn fetch() -> Result<Vec<String>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .user_agent(concat!("ForeverLauncher/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client.get(url()).send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("HTTP {}", res.status().as_u16()));
    }
    let list = parse(&res.text().await.map_err(|e| e.to_string())?);
    // an empty or half-read file must not make every client look current
    if list.is_empty() {
        return Err("client-build.txt names no build".into());
    }
    Ok(list)
}

/// Reads the repository's list. A failed read keeps whatever this launcher already knows, so a player without
/// access to GitHub still sees the builds of the release. Returns the list in use.
pub async fn refresh() -> Vec<String> {
    match fetch().await {
        Ok(list) => {
            config::log_line(format!("client: the realm accepts {}", list.join(", ")));
            *ACCEPTED.lock().unwrap() = list;
        }
        Err(e) => config::log_line(format!("client: build list not read ({e}), using the built-in one")),
    }
    accepted()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_one_build_per_line() {
        assert_eq!(parse("1.60.1.71037\n"), vec!["1.60.1.71037"]);
        assert_eq!(parse("1.60.1.71037\r\n1.60.1.70959\r\n"), vec!["1.60.1.71037", "1.60.1.70959"]);
    }

    #[test]
    fn skips_comments_and_blank_lines() {
        let text = "# client build the realm runs\n\n1.60.1.71037 # live\n   \n";
        assert_eq!(parse(text), vec!["1.60.1.71037"]);
        // only comments: nothing to compare against
        assert!(parse("# nothing here\n\n").is_empty());
    }

    #[test]
    fn accepts_a_comma_separated_list() {
        assert_eq!(parse("1.60.1.71037, 1.60.1.70959\n"), vec!["1.60.1.71037", "1.60.1.70959"]);
        // a build named twice is compared once
        assert_eq!(parse("1.60.1.71037 1.60.1.71037"), vec!["1.60.1.71037"]);
    }
}
