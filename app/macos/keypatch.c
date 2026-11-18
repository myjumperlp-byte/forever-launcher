// Loaded into the re-signed macOS client with DYLD_INSERT_LIBRARIES: writes the server's public key into the
// client's key store, from inside the process (the official app is hardened, so task_for_pid is refused).
//
// Same logic as app/src-tauri/src/patcher/mod.rs: 12 entries of 40 bytes (u32 id 1..12, 32-byte Ed25519 key,
// u8 flag, 3 bytes padding) in a heap array; the entry of the region group (8) gets the server's key.
//
// Blizzard's keys change with client builds, so the table below is only the fast path. When it no longer matches
// (the live client since build 1.60.1.70790 ships its own table), the store is found by its structure alone:
// ids 1..12, the flags, the zero padding and twelve different keys that are not text.
//
// Environment: FOREVER_SERVER_KEY (64 hex chars, default: TrinityCore), FOREVER_REGION_GROUP (default 8),
// FOREVER_PATCH_LOG (log file, default: stderr).

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ENTRY 40
#define COUNT 12
#define BLOCK (ENTRY * COUNT)
#define CHUNK (8 * 1024 * 1024)
// how often the slower structure-only scan is repeated while no store is found
#define STRUCTURAL_EVERY 5

static const char *KNOWN_KEYS[COUNT] = {
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
};
static const uint8_t EXPECTED_FLAGS[COUNT] = {1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1};
static const char *STOCK_PUBLIC_KEY = "02596F0D0C061A8B30745988FD72C59E29EC367FB0F341F28E0F08D037BAFC69";

enum state { INVALID, ORIGINAL, PATCHED };

static uint8_t keys[COUNT][32];
static uint8_t new_key[32];
static int group = 8;
static int structural_mode = 0;
static FILE *log_file;
static uint8_t *chunk;

static void say(const char *fmt, ...) {
    time_t t = time(NULL);
    char ts[16];
    strftime(ts, sizeof ts, "%H:%M:%S", localtime(&t));
    fprintf(log_file, "%s [forever] ", ts);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(log_file, fmt, ap);
    va_end(ap);
    fputc('\n', log_file);
    fflush(log_file);
}

static int hex32(const char *s, uint8_t out[32]) {
    if (!s || strlen(s) != 64) return 0;
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

// Copies process memory without faulting if the region goes away meanwhile.
static int read_mem(mach_vm_address_t addr, void *buf, mach_vm_size_t len) {
    mach_vm_size_t got = 0;
    return mach_vm_read_overwrite(mach_task_self(), addr, len, (mach_vm_address_t)buf, &got) == KERN_SUCCESS &&
           got == len;
}

// An Ed25519 public key as it sits in the store: not zero, and not a readable string.
static int key_shaped(const uint8_t *k) {
    int nonzero = 0, printable = 0;
    for (int i = 0; i < 32; i++) {
        if (k[i]) nonzero = 1;
        if (k[i] >= 0x20 && k[i] < 0x7f) printable++;
    }
    return nonzero && printable <= 8;
}

static enum state store_state(mach_vm_address_t array) {
    uint8_t raw[BLOCK];
    if (!read_mem(array, raw, BLOCK)) return INVALID;
    for (int e = 0; e < COUNT; e++) {
        const uint8_t *o = raw + e * ENTRY;
        uint32_t id;
        memcpy(&id, o, 4);
        if (id != (uint32_t)e + 1) return INVALID;
        int ok = memcmp(o + 4, keys[e], 32) == 0 || (e == group - 1 && memcmp(o + 4, new_key, 32) == 0);
        // o[37] is uninitialised padding: not checked
        if (!ok || o[36] != EXPECTED_FLAGS[e] || o[38] || o[39]) return INVALID;
    }
    return memcmp(raw + (group - 1) * ENTRY + 4, new_key, 32) == 0 ? PATCHED : ORIGINAL;
}

// Same store after a client update changed the keys: only the shape of the table is checked.
static enum state structural_state(mach_vm_address_t array) {
    uint8_t raw[BLOCK];
    if (!read_mem(array, raw, BLOCK)) return INVALID;
    for (int e = 0; e < COUNT; e++) {
        const uint8_t *o = raw + e * ENTRY;
        uint32_t id;
        memcpy(&id, o, 4);
        if (id != (uint32_t)e + 1) return INVALID;
        if (o[36] != EXPECTED_FLAGS[e] || o[38] || o[39]) return INVALID;
        if (!key_shaped(o + 4)) return INVALID;
        for (int j = 0; j < e; j++) {
            if (memcmp(o + 4, raw + j * ENTRY + 4, 32) == 0) return INVALID;
        }
    }
    return memcmp(raw + (group - 1) * ENTRY + 4, new_key, 32) == 0 ? PATCHED : ORIGINAL;
}

static enum state state_of(mach_vm_address_t array) {
    return structural_mode ? structural_state(array) : store_state(array);
}

// Read/write regions holding a store. Returns the number found (at most `max` are stored in `out`).
static int find_stores_exact(mach_vm_address_t *out, int max) {
    int n = 0;
    mach_vm_address_t addr = 0;
    for (;;) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj;
        if (mach_vm_region(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt,
                           &obj) != KERN_SUCCESS)
            break;
        int rw = (info.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE);
        int ours = addr <= (mach_vm_address_t)chunk && (mach_vm_address_t)chunk < addr + size;
        if (rw && !ours) {
            for (mach_vm_address_t off = addr; off < addr + size;) {
                mach_vm_size_t take = addr + size - off < CHUNK ? addr + size - off : CHUNK;
                if (!read_mem(off, chunk, take)) break;
                for (uint8_t *p = chunk; (p = memmem(p, take - (p - chunk), keys[0], 32)); p++) {
                    mach_vm_address_t hit = off + (p - chunk);
                    if (hit % 4 == 0 && hit >= 4 && store_state(hit - 4) != INVALID) {
                        if (n < max) out[n] = hit - 4;
                        n++;
                    }
                }
                if (take < CHUNK) break;
                off += CHUNK - 32;
            }
        }
        addr += size;
    }
    return n;
}

// Scans every 4-byte aligned address for entry id 1 and validates the block. Slower, but independent of the keys
// the client ships.
static int find_stores_structural(mach_vm_address_t *out, int max) {
    int n = 0;
    mach_vm_address_t addr = 0;
    for (;;) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj;
        if (mach_vm_region(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt,
                           &obj) != KERN_SUCCESS)
            break;
        int rw = (info.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE);
        int ours = addr <= (mach_vm_address_t)chunk && (mach_vm_address_t)chunk < addr + size;
        if (rw && !ours) {
            for (mach_vm_address_t off = addr; off < addr + size;) {
                mach_vm_size_t take = addr + size - off < CHUNK ? addr + size - off : CHUNK;
                if (!read_mem(off, chunk, take)) break;
                for (mach_vm_size_t i = 0; i + 4 <= take; i += 4) {
                    uint32_t v;
                    memcpy(&v, chunk + i, 4);
                    if (v != 1) continue;
                    mach_vm_address_t hit = off + i;
                    if (structural_state(hit) != INVALID) {
                        if (n < max) out[n] = hit;
                        n++;
                    }
                }
                if (take < CHUNK) break;
                off += CHUNK - 4;
            }
        }
        addr += size;
    }
    return n;
}

static int patch(mach_vm_address_t array) {
    uint8_t *target = (uint8_t *)array + (group - 1) * ENTRY + 4;
    for (int i = 0; i < 20; i++) {
        uint8_t cur[32];
        if (read_mem((mach_vm_address_t)target, cur, 32)) {
            if (memcmp(cur, new_key, 32) == 0) return 1;
            memcpy(target, new_key, 32);
            uint8_t back[32];
            if (read_mem((mach_vm_address_t)target, back, 32) && memcmp(back, new_key, 32) == 0) return 1;
        }
        usleep(300 * 1000);
    }
    return 0;
}

static void *watch(void *arg) {
    (void)arg;
    mach_vm_address_t store = 0;
    int said_waiting = 0, said_missing = 0, slow = 0;
    time_t started = time(NULL);
    say("loaded (PID %d, group %d)", getpid(), group);
    for (;;) {
        if (store) {
            switch (state_of(store)) {
            case PATCHED:
                sleep(2);
                break;
            case ORIGINAL:
                if (patch(store)) {
                    say("server key put back");
                } else {
                    say("writing the key failed");
                    store = 0;
                }
                break;
            case INVALID:
                say("key store freed, searching again at the next login");
                store = 0;
                break;
            }
            continue;
        }
        mach_vm_address_t found[4];
        // the exact table is cheap to look for; the structure-only scan is the fallback after a client update
        int n = find_stores_exact(found, 4);
        structural_mode = 0;
        if (n == 0 && ++slow >= STRUCTURAL_EVERY * 2) {
            slow = 0;
            n = find_stores_structural(found, 4);
            if (n > 0) structural_mode = 1;
        }
        if (n == 1) {
            if (patch(found[0])) {
                say("server key written (group %d) at 0x%llx", group, (unsigned long long)found[0]);
                store = found[0];
            } else {
                say("writing the key failed, retrying");
            }
        } else if (n == 0) {
            if (!said_waiting) {
                say("waiting for the key store...");
                said_waiting = 1;
            }
            if (!said_missing && time(NULL) - started > 20) {
                say("key store not found: this client build may not be supported yet");
                said_missing = 1;
            }
            usleep(500 * 1000);
        } else {
            say("%d key stores at once: waiting", n);
            usleep(500 * 1000);
        }
    }
    return NULL;
}

__attribute__((constructor)) static void start(void) {
    const char *path = getenv("FOREVER_PATCH_LOG");
    log_file = path ? fopen(path, "a") : NULL;
    if (!log_file) log_file = stderr;
    // Child processes (helpers) must not inherit the injection.
    unsetenv("DYLD_INSERT_LIBRARIES");

    for (int i = 0; i < COUNT; i++) hex32(KNOWN_KEYS[i], keys[i]);
    const char *key = getenv("FOREVER_SERVER_KEY");
    if (!hex32(key ? key : STOCK_PUBLIC_KEY, new_key)) {
        say("invalid server public key");
        return;
    }
    const char *g = getenv("FOREVER_REGION_GROUP");
    if (g) group = atoi(g);
    if (group < 2 || group > 12 || group == 9) {
        say("invalid region group (2-12, except 9)");
        return;
    }
    chunk = malloc(CHUNK);
    pthread_t th;
    if (!chunk || pthread_create(&th, NULL, watch, NULL) != 0) {
        say("could not start");
        return;
    }
    pthread_detach(th);
}
