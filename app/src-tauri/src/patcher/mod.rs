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
/// Pause between two heap passes while no store is known, and the slower one after `IDLE_AFTER`: a client whose
/// table is never recognised must not keep a core busy for the whole session. A pass is short next to the world
/// server's wait before `SMSG_ENTER_ENCRYPTED_MODE` (`Network.EnterEncryptedModeDelay`), so the store is still
/// found in time.
const SCAN_PAUSE: Duration = Duration::from_millis(250);
const SCAN_PAUSE_IDLE: Duration = Duration::from_secs(2);
const IDLE_AFTER: Duration = Duration::from_secs(60);

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

/// Cheap test on a candidate block: entry 1 at its start, entry 2 behind it, the flag, the padding and a key that is
/// not text. A heap pass has millions of 4-byte aligned `1`s and only a handful of these, so the full check that
/// follows stays cheap.
fn looks_like_store_start(block: &[u8]) -> bool {
    block[..4] == [1, 0, 0, 0]
        && block[ENTRY..ENTRY + 4] == [2, 0, 0, 0]
        && block[36] == EXPECTED_FLAGS[0]
        && block[38..40] == [0, 0]
        && key_shaped(&block[4..36])
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

    /// One pass over the client's heap. Stores are recognised by the shipped table first; only when `structural` is
    /// set (the previous pass found none that way) are the structure-only candidates of the same pass validated, so
    /// the heap is read once either way. The second value says the stores were recognised by structure alone.
    fn scan(&self, mem: &dyn Memory, structural: bool) -> (Vec<(u64, State)>, bool) {
        let needle = &self.keys[0];
        let finder = memmem::Finder::new(needle);
        let mut exact = Vec::new();
        let mut candidates = Vec::new();
        for (lo, hi) in mem.regions() {
            let mut off = lo;
            while off < hi {
                let take = CHUNK.min((hi - off) as usize);
                let Some(buf) = mem.read(off, take) else { break };
                for i in finder.find_iter(&buf) {
                    let hit = off + i as u64;
                    if hit % 4 == 0 && hit >= 4 {
                        let state = self.exact_state(mem, hit - 4);
                        if state != State::Invalid {
                            exact.push((hit - 4, state));
                        }
                    }
                }
                if structural && exact.is_empty() {
                    let mut i = 0;
                    while i + BLOCK <= buf.len() {
                        if looks_like_store_start(&buf[i..i + BLOCK]) {
                            candidates.push(off + i as u64);
                        }
                        i += 4;
                    }
                }
                if take < CHUNK {
                    break;
                }
                // a store can straddle two chunks
                off += (CHUNK - BLOCK) as u64;
            }
        }
        exact.sort_by_key(|f| f.0);
        exact.dedup_by_key(|f| f.0);
        if !exact.is_empty() {
            return (exact, false);
        }
        let mut stores: Vec<(u64, State)> = candidates
            .into_iter()
            .filter_map(|array| match self.structural_state(mem, array) {
                State::Invalid => None,
                state => Some((array, state)),
            })
            .collect();
        stores.sort_by_key(|f| f.0);
        stores.dedup_by_key(|f| f.0);
        (stores, true)
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

    /// Patches every store that still holds a Blizzard key and returns the one to watch from now on. The client can
    /// keep more than one array (a second copy of the table, or a second install in the same process); every one of
    /// them passed the table check, so writing all of them is safe and beats leaving the client without the key.
    fn patch_all(&self, mem: &dyn Memory, stores: &[(u64, State)]) -> Result<u64, String> {
        let mut watched = None;
        let mut failure = None;
        for (array, state) in stores {
            if *state == State::Patched {
                watched.get_or_insert(*array);
                continue;
            }
            match self.patch(mem, *array) {
                Ok(()) => {
                    watched.get_or_insert(*array);
                }
                Err(e) => failure = Some(e),
            }
        }
        match watched {
            Some(array) => Ok(array),
            None => Err(failure.unwrap_or_else(|| t("memory_changed").into())),
        }
    }

    /// Watches the client until it closes. `switch` may return a better process (Linux: the Wine launcher process
    /// is found before the real game process).
    pub fn watch(&self, mut mem: Box<dyn Memory>, mut switch: impl FnMut(&dyn Memory) -> Option<Box<dyn Memory>>,
                 mut emit: impl FnMut(Event)) {
        // (store, recognised by structure only)
        let mut store: Option<(u64, bool)> = None;
        let mut last_switch = Instant::now();
        let started = Instant::now();
        let mut said_waiting = false;
        let mut said_missing = false;
        // set once a pass found no store by the shipped table: the next passes check the structure too
        let mut structural = false;
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
            let (stores, by_structure) = self.scan(mem.as_ref(), structural);
            if stores.is_empty() {
                structural = true;
                if !said_waiting {
                    emit(Event::Log(t("waiting_realm").into()));
                    said_waiting = true;
                }
                if !said_missing && started.elapsed() > Duration::from_secs(3) {
                    emit(Event::Log(t("key_store_missing").into()));
                    said_missing = true;
                }
                std::thread::sleep(if started.elapsed() > IDLE_AFTER { SCAN_PAUSE_IDLE } else { SCAN_PAUSE });
                continue;
            }
            structural = false;
            match self.patch_all(mem.as_ref(), &stores) {
                Ok(array) => {
                    emit(Event::Log(tf("key_written", &[&self.group])));
                    if stores.len() > 1 {
                        emit(Event::Log(tf("many_key_stores_patched", &[&stores.len()])));
                    }
                    emit(Event::Ready);
                    store = Some((array, by_structure));
                }
                Err(e) => emit(Event::Log(tf("key_write_retry", &[&e]))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const BASE: u64 = 0x10_0000;
    /// A fake client heap: one region, byte `i` at `BASE + i`, two key stores at 0x100 and 0x800.
    struct Heap(RefCell<Vec<u8>>);

    impl Heap {
        fn with_stores(keys: &[[u8; 32]]) -> Self {
            let mut data = vec![0u8; 0x1000];
            for offset in [0x100usize, 0x800] {
                for e in 0..COUNT {
                    let o = offset + e * ENTRY;
                    data[o..o + 4].copy_from_slice(&(e as u32 + 1).to_le_bytes());
                    data[o + 4..o + 36].copy_from_slice(&keys[e]);
                    data[o + 36] = EXPECTED_FLAGS[e];
                    data[o + 37] = 0x7f; // uninitialised padding byte: not checked
                }
            }
            Self(RefCell::new(data))
        }
    }

    impl Memory for Heap {
        fn regions(&self) -> Vec<(u64, u64)> {
            vec![(BASE, BASE + self.0.borrow().len() as u64)]
        }

        fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
            let data = self.0.borrow();
            let start = usize::try_from(addr.checked_sub(BASE)?).ok()?;
            if start >= data.len() {
                return None;
            }
            Some(data[start..(start + len).min(data.len())].to_vec())
        }

        fn write(&self, addr: u64, bytes: &[u8]) -> bool {
            let mut data = self.0.borrow_mut();
            let Ok(start) = usize::try_from(addr - BASE) else { return false };
            let end = start + bytes.len();
            if end > data.len() {
                return false;
            }
            data[start..end].copy_from_slice(bytes);
            true
        }

        fn alive(&self) -> bool {
            true
        }

        fn pid(&self) -> u32 {
            1
        }
    }

    fn patcher(key_byte: &str) -> Patcher {
        Patcher::new(&key_byte.repeat(32), 8).unwrap()
    }

    fn shipped_keys() -> Vec<[u8; 32]> {
        KNOWN_KEYS.iter().map(|k| hex32(k).unwrap()).collect()
    }

    #[test]
    fn patches_every_store_the_table_finds() {
        let p = patcher("AB");
        let heap = Heap::with_stores(&shipped_keys());
        let (stores, by_structure) = p.scan(&heap, false);
        assert_eq!(stores.len(), 2, "{stores:?}");
        assert!(!by_structure);

        let watched = p.patch_all(&heap, &stores).unwrap();
        assert_eq!(watched, BASE + 0x100);

        let (after, _) = p.scan(&heap, false);
        assert_eq!(after.len(), 2, "{after:?}");
        assert!(after.iter().all(|(_, state)| *state == State::Patched), "{after:?}");
    }

    #[test]
    fn finds_a_new_table_by_structure_only() {
        let p = patcher("CD");
        let keys: Vec<[u8; 32]> = (0..COUNT).map(|e| [e as u8 + 1; 32]).collect();
        let heap = Heap::with_stores(&keys);

        let (shipped, _) = p.scan(&heap, false);
        assert!(shipped.is_empty(), "the shipped table must not match: {shipped:?}");

        let (stores, by_structure) = p.scan(&heap, true);
        assert_eq!(stores.len(), 2, "{stores:?}");
        assert!(by_structure);
        assert!(stores.iter().all(|(_, state)| *state == State::Original), "{stores:?}");

        p.patch_all(&heap, &stores).unwrap();
        let (after, _) = p.scan(&heap, true);
        assert!(after.iter().all(|(_, state)| *state == State::Patched), "{after:?}");
    }
}
