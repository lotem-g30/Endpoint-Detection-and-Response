#include <windows.h>
#include <pe_sieve_api.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <rpc.h>
#include <vector>
#include "argus/events.h"

#pragma comment(lib, "rpcrt4.lib")

static void get_timestamp(char* buf, size_t len) {
    time_t t = time(NULL);
    struct tm tm_info;
    gmtime_s(&tm_info, &t);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm_info);
}

static void gen_uuid(char* buf, size_t len) {
    UUID uuid;
    UuidCreate(&uuid);
    unsigned char* str = NULL;
    UuidToStringA(&uuid, &str);
    if (str) {
        strncpy(buf, (char*)str, len - 1);
        buf[len - 1] = '\0';
        RpcStringFreeA(&str);
    }
}

static const char* s_finding_type[] = {
    "FINDING_PRIVATE_EXECUTABLE",
    "FINDING_PE_HOLLOWING",
    "FINDING_PE_IMPLANT",
    "FINDING_REFLECTIVE_LOAD",
    "FINDING_CODE_CAVE",
    "FINDING_MODULE_STOMP",
    "FINDING_YARA_MATCH",
    "FINDING_ANOMALOUS_THREAD",
};

static const char* s_severity[] = {
    "LOW", "MEDIUM", "HIGH", "CRITICAL",
};

static void serialize_finding(const ScanFinding* f, char* buf, size_t buf_size) {
    const char* ftype = (f->finding_type < 8) ? s_finding_type[f->finding_type] : "UNKNOWN";
    const char* sev   = (f->severity    < 4) ? s_severity[f->severity]          : "UNKNOWN";

    snprintf(buf, buf_size,
        "{"
        "\"ts\":\"%s\","
        "\"session_id\":\"%s\","
        "\"scan_id\":\"%s\","
        "\"pid\":%lu,"
        "\"process_name\":\"%s\","
        "\"finding_type\":\"%s\","
        "\"severity\":\"%s\","
        "\"region\":{"
          "\"base_address\":\"0x%llx\","
          "\"size\":%llu,"
          "\"protect\":%lu,"
          "\"type\":%lu,"
          "\"state\":%lu"
        "},"
        "\"detail\":{"
          "\"reason\":\"%s\","
          "\"yara_rule\":\"%s\","
          "\"pe_anomaly\":\"%s\""
        "}"
        "}",
        f->ts, f->session_id, f->scan_id,
        (unsigned long)f->pid, f->process_name,
        ftype, sev,
        (unsigned long long)f->region.base_address,
        (unsigned long long)f->region.size,
        (unsigned long)f->region.protect,
        (unsigned long)f->region.type,
        (unsigned long)f->region.state,
        f->detail.reason,
        f->detail.yara_rule,
        f->detail.pe_anomaly
    );
}

// Retry connecting to the pipe for up to 3 seconds.
static HANDLE connect_to_pipe(void) {
    DWORD start = GetTickCount();
    while (1) {
        HANDLE h = CreateFileW(
            L"\\\\.\\pipe\\argus-pesieve",
            GENERIC_WRITE, 0, NULL,
            OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) return h;
        DWORD err = GetLastError();
        if (err != ERROR_PIPE_BUSY && err != ERROR_FILE_NOT_FOUND)
            return INVALID_HANDLE_VALUE;
        if ((GetTickCount() - start) >= 3000)
            return INVALID_HANDLE_VALUE;
        Sleep(100);
    }
}

static void emit_finding(HANDLE pipe,
                         DWORD self_pid,
                         const char* process_name,
                         const char* session_id,
                         const char* scan_id,
                         FindingType ft,
                         const char* anomaly)
{
    ScanFinding f;
    memset(&f, 0, sizeof(f));
    get_timestamp(f.ts, sizeof(f.ts));
    strncpy(f.session_id,    session_id,    ARGUS_MAX_UUID - 1);
    strncpy(f.scan_id,       scan_id,       ARGUS_MAX_UUID - 1);
    strncpy(f.process_name,  process_name,  ARGUS_MAX_NAME - 1);
    f.pid          = self_pid;
    f.finding_type = ft;
    f.severity     = SEVERITY_HIGH;
    f.region.state = MEM_COMMIT;
    strncpy(f.detail.pe_anomaly, anomaly, sizeof(f.detail.pe_anomaly) - 1);
    strncpy(f.detail.reason,     anomaly, sizeof(f.detail.reason)     - 1);

    char buf[4096];
    serialize_finding(&f, buf, sizeof(buf) - 2);
    size_t len = strlen(buf);
    buf[len]     = '\n';
    buf[len + 1] = '\0';

    DWORD written;
    WriteFile(pipe, buf, (DWORD)(len + 1), &written, NULL);
}

// ── Patch whitelist helpers ───────────────────────────────────────────────────
//
// PE-Sieve at JSON_DETAILS2 level emits per-patch records inside "patches_list"
// arrays.  Each record with "is_hook":1 has a "hook_target" object whose
// "module" field is the lowercase hex base address (no "0x" prefix) of the
// module that the patch redirects into.
//
// JSON shape (abbreviated):
//   "patches_list" : [
//     { "rva":"...", "size":5, "is_hook":1, "func_name":"VirtualAllocEx",
//       "hook_target" : {
//         "module_name" : "argus_hook.dll",   // optional — may be absent
//         "module"      : "7ffc1234abcd",     // bare hex, no "0x"
//         "rva"         : "0",
//         "status"      : 0
//       }
//     }, ...
//   ]

// Parse a bare hex string (no "0x" prefix, leading '"' and spaces skipped).
static ULONGLONG parse_hex_str(const char* s) {
    while (s && (*s == '"' || *s == ' ')) s++;
    if (!s || !*s) return 0ULL;
    char* end;
    ULONGLONG v = strtoull(s, &end, 16);
    return (end == s) ? 0ULL : v;
}

// Walk forward from 'after_open' (the character after the opening '{') and
// return the character position just past the matching closing '}'.
// PE-Sieve JSON values don't contain literal '{' or '}', so plain depth
// counting is safe here.
static const char* find_obj_end(const char* after_open) {
    int depth = 1;
    for (const char* p = after_open; *p; p++) {
        if      (*p == '{') ++depth;
        else if (*p == '}') { if (--depth == 0) return p + 1; }
    }
    return NULL; // malformed
}

// Returns true if the JSON_DETAILS2 scan report contains any patched byte
// sequence that does NOT redirect into our own hook DLL (hook_dll_base).
//
// Decision table per patch entry:
//   "is_hook" : 0  → raw code modification (not a JMP redirect) → FOREIGN
//   "is_hook" : 1 and hook_target.module != hook_dll_base        → FOREIGN
//   "is_hook" : 1 and hook_target.module == hook_dll_base        → OURS (safe)
//   any parse failure, missing fields, module == 0               → FOREIGN (fail-safe)
//
// Returns true (conservative) if no patch objects could be inspected at all.
static bool has_foreign_patches(const char* json, ULONGLONG hook_dll_base) {
    if (!json || !json[0] || hook_dll_base == 0) return true;

    const char* p = json;
    bool any_inspected = false;

    while ((p = strstr(p, "\"patches_list\"")) != NULL) {
        p += 14; // skip key
        const char* arr = strchr(p, '[');
        if (!arr) break;
        p = arr + 1;

        // Limit the current patches_list scope to just before the next one.
        const char* scope_end = strstr(p, "\"patches_list\"");
        const char* cursor    = p;

        while (1) {
            // Find the next patch object.
            const char* patch_obj = strchr(cursor, '{');
            if (!patch_obj || (scope_end && patch_obj >= scope_end)) break;

            // Determine this patch object's boundary so we don't bleed into
            // the next one when searching for field names.
            const char* patch_end = find_obj_end(patch_obj + 1);
            const char* obj_lim   = patch_end ? patch_end
                                    : (scope_end ? scope_end : NULL);

            any_inspected = true;

            // ── is_hook ───────────────────────────────────────────────────────
            const char* ih = strstr(patch_obj + 1, "\"is_hook\"");
            if (!ih || (obj_lim && ih >= obj_lim)) return true; // missing → foreign

            const char* v = ih + 9;
            while (*v == ' ' || *v == ':' || *v == '\n' || *v == '\r') v++;
            if (*v == '0') return true; // raw modification, no hook target → foreign

            // ── hook_target block ─────────────────────────────────────────────
            const char* ht = strstr(patch_obj + 1, "\"hook_target\"");
            if (!ht || (obj_lim && ht >= obj_lim)) return true;

            const char* ht_brace = strchr(ht + 13, '{');
            if (!ht_brace) return true;

            const char* ht_end = find_obj_end(ht_brace + 1);
            const char* ht_lim = ht_end ? ht_end : obj_lim;

            // ── "module" : "hex_base"  (not "module_name") ───────────────────
            // Use the exact token "\"module\" :" to avoid matching "module_name".
            const char* mod_key = strstr(ht_brace + 1, "\"module\" :");
            if (!mod_key || (ht_lim && mod_key >= ht_lim)) return true;

            const char* q = strchr(mod_key + 10, '"');
            if (!q || (ht_lim && q >= ht_lim)) return true;

            ULONGLONG target_base = parse_hex_str(q + 1);
            if (target_base == 0 || target_base != hook_dll_base) return true;

            // This patch redirects into our own hook DLL — it is safe.
            cursor = patch_end ? patch_end : (patch_obj + 1);
        }

        if (!scope_end) break;
        p = scope_end;
    }

    // Conservative: if no patch objects were reached in the JSON (e.g. the
    // buffer was still too small, or the format was unexpected), treat the
    // situation as a foreign patch so CODE_CAVE is not silently suppressed.
    return !any_inspected;
}

// ── Scan thread ───────────────────────────────────────────────────────────────

// Single background thread: scans immediately on start, then every 2 minutes.
static DWORD WINAPI scan_thread(LPVOID /*param*/) {
    DWORD self_pid = GetCurrentProcessId();

    char session_id[ARGUS_MAX_UUID];
    gen_uuid(session_id, sizeof(session_id));

    char process_name[ARGUS_MAX_NAME] = "unknown";
    char path[MAX_PATH] = {0};
    DWORD sz = MAX_PATH;
    if (QueryFullProcessImageNameA(GetCurrentProcess(), 0, path, &sz)) {
        const char* slash = strrchr(path, '\\');
        strncpy(process_name, slash ? slash + 1 : path, sizeof(process_name) - 1);
    }

    while (1) {
        char scan_id[ARGUS_MAX_UUID];
        gen_uuid(scan_id, sizeof(scan_id));

        // ── Layer 1: pre-scan module exclusion ───────────────────────────────
        // Record the hook DLL's base address before the scan so the result
        // cannot change between the check and the comparison below.
        HMODULE hook_dll      = GetModuleHandleA("argus_hook.dll");
        ULONGLONG hook_dll_base = (ULONGLONG)hook_dll;

        // Tell PE-Sieve to skip our own injected modules entirely, preventing
        // them from being flagged as PE implants.
        char ignored_buf[256] = "argus_pesieve.dll";
        if (hook_dll)
            strncat(ignored_buf, ";argus_hook.dll",
                    sizeof(ignored_buf) - strlen(ignored_buf) - 1);

        // ── PE-Sieve scan (JSON_DETAILS2 for per-patch hook destinations) ────
        pesieve::t_params params = {};
        params.pid            = self_pid;
        params.out_filter     = pesieve::OUT_NO_DIR;
        params.quiet          = true;
        params.json_lvl       = pesieve::JSON_DETAILS2;   // full patch detail
        params.results_filter = pesieve::SHOW_SUSPICIOUS; // only suspicious in JSON
        params.modules_ignored.buffer = ignored_buf;
        params.modules_ignored.length = (ULONG)strlen(ignored_buf);

        // Start with a 32 KB buffer; double it if PE-Sieve signals truncation.
        size_t buf_capacity = 32768;
        std::vector<char> json_buf(buf_capacity, '\0');
        size_t needed = 0;

        pesieve::t_report report = PESieve_scan_ex(
            &params, pesieve::REPORT_SCANNED,
            json_buf.data(), buf_capacity, &needed);

        if (needed > buf_capacity) {
            buf_capacity = needed + 1;
            json_buf.assign(buf_capacity, '\0');
            report = PESieve_scan_ex(
                &params, pesieve::REPORT_SCANNED,
                json_buf.data(), buf_capacity, &needed);
        }

        // ── Layer 2: translate report to findings with precise whitelist ──────
        HANDLE pipe = connect_to_pipe();
        if (pipe != INVALID_HANDLE_VALUE) {
            if (report.replaced > 0)
                emit_finding(pipe, self_pid, process_name, session_id, scan_id,
                             FINDING_PE_HOLLOWING, "PE hollowing detected");

            if (report.implanted_pe > 0 || report.implanted_shc > 0)
                emit_finding(pipe, self_pid, process_name, session_id, scan_id,
                             FINDING_PE_IMPLANT, "PE implant detected");

            // Per-patch inspection: parse hook_target.module for every detected
            // patch.  Only emit CODE_CAVE when at least one patch redirects
            // outside of argus_hook.dll — i.e. is NOT one of our Detours hooks.
            // Any parse failure conservatively emits the finding (fail-safe).
            if (report.patched > 0 &&
                has_foreign_patches(json_buf.data(), hook_dll_base))
            {
                emit_finding(pipe, self_pid, process_name, session_id, scan_id,
                             FINDING_CODE_CAVE, "Code cave/modification detected");
            }

            if (report.iat_hooked > 0)
                emit_finding(pipe, self_pid, process_name, session_id, scan_id,
                             FINDING_MODULE_STOMP, "IAT hook detected");

            CloseHandle(pipe);
        }

        Sleep(120000);  // 2-minute interval between scans
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID /*lpvReserved*/) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        HANDLE t = CreateThread(NULL, 0, scan_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
