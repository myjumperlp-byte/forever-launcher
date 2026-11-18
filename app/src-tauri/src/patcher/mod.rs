//! Writes the server's public key into the running client's key store.
//!
//! The client keeps 12 Ed25519 public keys (one per region group) in a heap array of 40-byte entries:
//! u32 id (1..12), 32-byte key, u8 flag, 3 bytes padding. The server signs EnterEncryptedMode with the key of
//! `Network.EnterEncryptedModeRegionGroup` (8), so that entry gets the server's key. Same logic as the official
//! forever-launcher-linux.py, except that the first padding byte is ignored (7f on Windows, 00 or 07 under Proton).
//!
//! Blizzard's keys change with client builds, so the table below is only the fast path: when it no longer matches
//! (the live client since build 1.60.1.70790 ships its own table), the store is recognised by its structure alone —
//! ids 1..12, the flags, the zero padding and twelve different keys that are not text. That keeps a client update
//! from breaking the start until the launcher is rebuilt with the new keys.

#[cfg(not(windows))]
mod lin;
#[cfg(windows)]
mod win;

#[cfg(not(windows))]
#[cfg_attr(target_os = "macos", allow(unused_imports))]
pub use lin::{find_client, ProcessMemory};
#[cfg(windows)]
pub use win::{find_client, ProcessMemory};

use crate::i18n::{t, tf};
use memchr::memmem;
use std::collections::HashSet;
use std::time::{Duration, Instant};

const KNOWN_KEYS: [&str; 12] = [
    "9B0671C815DFF513BFD4A2B26AE1F84EC9106841B2FB620DB65F6ADE7C21AD06",
    "112451B9843C2799E4750AA3D9B9AFABF536A645B863C4ADB2078B932B354E04",
    "A6B858485748BF38BE193517AB90F8DE169EFF0989EA9360DB346A378B0FFE15",
    "50FFDEB807F8FF73A299A16000AA6575C5945BE875ADFC8795374ED3415249AC",
    "9F842D078755647C008E5FE3E12B839A981DE02A1F520CB2545CC04CD2323E0E",
    "B8CC75864D8EF461D8DD6AA7425E2C63C24D3982066B8D773A1549BFE24E05EE",
    "76BB7BBDD9F34E124A4573C3AA227E3C87CC603506697D054F6FDEC342E56EBF",
    "1FD6DD8FA0EC30D39E3F72E755B8A045BDE0F70449DC71008B767C2EAA89FB9F",
    "15D618BD7DB577BD9A8D45769C59E4FC631633BF447398A4B489B4C26FBC03AD",
    "B34EC592D2AC4993F5FFC85B15C3DA9078694051CB224345592AF7136D796C99",
    "9E91586DD4B115AB0568B21959E181F6545910BC5E2F30B8975CA09D7BC3EFCE",
    "769C824A1DADD19AEEFA420414D1732DAF44537F98AA229FC5477BCA55F9D59A",
];
const EXPECTED_FLAGS: [u8; 12] = [1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1];
const ENTRY: usize = 40;
const COUNT: usize = 12;
const BLOCK: usize = ENTRY * COUNT;
const CHUNK: usize = 8 * 1024 * 1024;
/// How often the slower structure-only scan is repeated while no store is found.
const STRUCTURAL_EVERY: Duration = Duration::from_secs(5);

/// Access to another process's memory.
pub trait Memory {
    /// Private read/write regions (lo, hi).
    fn regions(&self) -> Vec<(u64, u64)>;
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>>;
    fn write(&self, addr: u64, data: &[u8]) -> bool;
    fn alive(&self) -> bool;
    fn pid(&self) -> u32;
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum State {
    Invalid,
    Original,
    Patched,
}

pub enum Event {
    Log(String),
    /// The key is in place: the player can enter the realm.
    Ready,
    Closed,
}

pub struct Patcher {
    keys: Vec<[u8; 32]>,
    new_key: [u8; 32],
    group: usize,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

/// An Ed25519 public key as it sits in the store: not zero, and not a readable string.
fn key_shaped(key: &[u8]) -> bool {
    key.iter().any(|b| *b != 0) && key.iter().filter(|b| b.is_ascii_graphic()).count() <= 8
}

impl Patcher {
    pub fn new(public_key: &str, region_group: u32) -> Result<Self, String> {
        let new_key = hex32(public_key).ok_or(t("bad_public_key"))?;
        if !(2..=12).contains(&region_group) || region_group == 9 {
            return Err(t("bad_region_group").into());
        }
        Ok(Self { keys: KNOWN_KEYS.iter().map(|k| hex32(k).unwrap()).collect(), new_key, group: region_group as usize })
    }

    /// The table of the builds this launcher was written against.
    fn exact_state(&self, mem: &dyn Memory, array: u64) -> State {
        let Some(raw) = mem.read(array, BLOCK) else { return State::Invalid };
        if raw.len() != BLOCK {
            return State::Invalid;
        }
        for e in 0..COUNT {
            let o = e * ENTRY;
            if u32::from_le_bytes(raw[o..o + 4].try_into().unwrap()) != e as u32 + 1 {
                return State::Invalid;
            }
            let key = &raw[o + 4..o + 36];
            let ok = if e == self.group - 1 { key == self.keys[e] || key == self.new_key } else { key == self.keys[e] };
            // raw[o + 37] is uninitialised padding: not checked
            if !ok || raw[o + 36] != EXPECTED_FLAGS[e] || raw[o + 38..o + 40] != [0, 0] {
                return State::Invalid;
            }
        }
        let t = (self.group - 1) * ENTRY + 4;
        if raw[t..t + 32] == self.new_key { State::Patched } else { State::Original }
    }

    /// Same store after a client update changed the keys: only the shape of the table is checked.
    fn structural_state(&self, mem: &dyn Memory, array: u64) -> State {
        let Some(raw) = mem.read(array, BLOCK) else { return State::Invalid };
        if raw.len() != BLOCK {
            return State::Invalid;
        }
        let mut seen: HashSet<&[u8]> = HashSet::new();
        for e in 0..COUNT {
            let o = e * ENTRY;
            if u32::from_le_bytes(raw[o..o + 4].try_into().unwrap()) != e as u32 + 1 {
                return State::Invalid;
            }
            if raw[o + 36] != EXPECTED_FLAGS[e] || raw[o + 38..o + 40] != [0, 0] {
                return State::Invalid;
            }
            let key = &raw[o + 4..o + 36];
            if !key_shaped(key) || !seen.insert(key) {
                return State::Invalid;
            }
        }
        let t = (self.group - 1) * ENTRY + 4;
        if raw[t..t + 32] == self.new_key { State::Patched } else { State::Original }
    }

    fn find_stores_exact(&self, mem: &dyn Memory) -> Vec<(u64, State)> {
        let needle = &self.keys[0];
        let finder = memmem::Finder::new(needle);
        let mut found = Vec::new();
        for (lo, hi) in mem.regions() {
            let mut off = lo;
            while off < hi {
                let take = CHUNK.min((hi - off) as usize);
                let Some(buf) = mem.read(off, take) else { break };
                for i in finder.find_iter(&buf) {
                    let hit = off + i as u64;
                    if hit % 4 == 0 && hit >= 4 {
                        let st = self.exact_state(mem, hit - 4);
                        if st != State::Invalid {
                            found.push((hit - 4, st));
                        }
                    }
                }
                if take < CHUNK {
                    break;
                }
                off += (CHUNK - needle.len()) as u64;
            }
        }
        found.sort_by_key(|f| f.0);
        found.dedup_by_key(|f| f.0);
        found
    }

    /// Scans every 4-byte aligned address for entry id 1 and validates the block. Slower, but independent of the
    /// keys the client ships.
    fn find_stores_structural(&self, mem: &dyn Memory) -> Vec<(u64, State)> {
        let mut found = Vec::new();
        for (lo, hi) in mem.regions() {
            let mut off = lo;
            while off < hi {
                let take = CHUNK.min((hi - off) as usize);
                let Some(buf) = mem.read(off, take) else { break };
                let mut i = 0usize;
                while i + 4 <= buf.len() {
                    if u32::from_le_bytes(buf[i..i + 4].try_into().unwrap()) == 1 {
                        let hit = off + i as u64;
                        let st = self.structural_state(mem, hit);
                        if st != State::Invalid {
                            found.push((hit, st));
                        }
                    }
                    i += 4;
                }
                if take < CHUNK {
                    break;
                }
                off += (CHUNK - 4) as u64;
            }
        }
        found.sort_by_key(|f| f.0);
        found.dedup_by_key(|f| f.0);
        found
    }

    /// (stores, recognised by structure only)
    fn find_stores(&self, mem: &dyn Memory) -> (Vec<(u64, State)>, bool) {
        let exact = self.find_stores_exact(mem);
        if !exact.is_empty() {
            return (exact, false);
        }
        (self.find_stores_structural(mem), true)
    }

    fn patch(&self, mem: &dyn Memory, array: u64) -> Result<(), String> {
        let addr = array + ((self.group - 1) * ENTRY + 4) as u64;
        for _ in 0..20 {
            match mem.read(addr, 32) {
                Some(cur) if cur.len() == 32 => {
                    if cur == self.new_key {
                        return Ok(());
                    }
                    if !mem.write(addr, &self.new_key) {
                        return Err(t("write_refused").into());
                    }
                    return match mem.read(addr, 32) {
                        Some(back) if back == self.new_key => Ok(()),
                        _ => Err(t("verify_failed").into()),
                    };
                }
                _ => std::thread::sleep(Duration::from_millis(300)),
            }
        }
        Err(t("memory_changed").into())
    }

    /// Watches the client until it closes. `switch` may return a better process (Linux: the Wine launcher process
    /// is found before the real game process).
    pub fn watch(&self, mut mem: Box<dyn Memory>, mut switch: impl FnMut(&dyn Memory) -> Option<Box<dyn Memory>>,
                 mut emit: impl FnMut(Event)) {
        // (store, recognised by structure only)
        let mut store: Option<(u64, bool)> = None;
        let mut last_switch = Instant::now();
        let mut last_structural = Instant::now() - STRUCTURAL_EVERY;
        let mut started = Instant::now();
        let mut said_waiting = false;
        let mut said_missing = false;
        loop {
            if !mem.alive() {
                if let Some(other) = switch(mem.as_ref()) {
                    mem = other;
                    continue;
                }
                emit(Event::Closed);
                return;
            }
            if let Some((array, structural)) = store {
                let state = if structural { self.structural_state(mem.as_ref(), array) } else { self.exact_state(mem.as_ref(), array) };
                match state {
                    State::Patched => std::thread::sleep(Duration::from_secs(2)),
                    State::Original => match self.patch(mem.as_ref(), array) {
                        Ok(()) => {
                            emit(Event::Log(t("key_restored").into()));
                            emit(Event::Ready);
                        }
                        Err(e) => {
                            emit(Event::Log(tf("key_write_error", &[&e])));
                            store = None;
                        }
                    },
                    State::Invalid => {
                        emit(Event::Log(t("key_store_freed").into()));
                        store = None;
                    }
                }
                continue;
            }
            if last_switch.elapsed() > Duration::from_secs(5) {
                last_switch = Instant::now();
                if let Some(other) = switch(mem.as_ref()) {
                    emit(Event::Log(tf("game_process", &[&other.pid()])));
                    mem = other;
                }
            }
            // the exact table is cheap to look for; the structure-only scan is the fallback after a client update
            let (stores, structural) = if last_structural.elapsed() >= STRUCTURAL_EVERY {
                last_structural = Instant::now();
                self.find_stores(mem.as_ref())
            } else {
                (self.find_stores_exact(mem.as_ref()), false)
            };
            match stores.as_slice() {
                [(array, st)] => {
                    let res = if *st == State::Patched { Ok(()) } else { self.patch(mem.as_ref(), *array) };
                    match res {
                        Ok(()) => {
                            emit(Event::Log(tf("key_written", &[&self.group])));
                            emit(Event::Ready);
                            store = Some((*array, structural));
                        }
                        Err(e) => emit(Event::Log(tf("key_write_retry", &[&e]))),
                    }
                }
                [] => {
                    if !said_waiting {
                        emit(Event::Log(t("waiting_realm").into()));
                        said_waiting = true;
                    }
                    if !said_missing && started.elapsed() > Duration::from_secs(20) {
                        emit(Event::Log(t("key_store_missing").into()));
                        said_missing = true;
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
                many => {
                    emit(Event::Log(tf("many_key_stores", &[&many.len()])));
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
            // keep the start time of the missing notice meaningful even if the game takes long to boot
            if started.elapsed() > Duration::from_secs(600) {
                started = Instant::now();
            }
        }
    }
}
