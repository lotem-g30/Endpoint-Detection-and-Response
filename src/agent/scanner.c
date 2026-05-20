#include "scanner.h"
#include "pesieve_scanner.h"
#include "yara_scanner.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <rpc.h>

#pragma comment(lib, "rpcrt4.lib")

// ── Helpers ───────────────────────────────────────────────────────────────────

void generate_uuid(char* buf, size_t len) {
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

static void get_timestamp(char* buf, size_t len) {
    time_t t = time(NULL);
    struct tm tm_info;
    gmtime_s(&tm_info, &t);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm_info);
}

static void get_process_name(HANDLE hProc, char* name, size_t len) {
    char path[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameA(hProc, 0, path, &size)) {
        const char* slash = strrchr(path, '\\');
        strncpy(name, slash ? slash + 1 : path, len - 1);
        name[len - 1] = '\0';
    } else {
        strncpy(name, "unknown", len - 1);
    }
}

// ── Memory scanner (Section 5.3) ──────────────────────────────────────────────
// Finds committed, private, executable memory regions.

static int memscan_run(HANDLE hProc, DWORD pid, const char* process_name,
                       const char* session_id, const char* scan_id,
                       ScanFinding* out, size_t* count, size_t max) {
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* addr = NULL;

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        addr += mbi.RegionSize;

        if (mbi.State != MEM_COMMIT)  continue;
        if (mbi.Type  != MEM_PRIVATE) continue;

        // mask off modifier flags before testing executable bits
        DWORD protect = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
        if (!(protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            continue;

        if (*count >= max) break;

        ScanFinding* f = &out[*count];
        memset(f, 0, sizeof(*f));
        get_timestamp(f->ts, sizeof(f->ts));
        strncpy(f->session_id, session_id, ARGUS_MAX_UUID - 1);
        strncpy(f->scan_id,    scan_id,    ARGUS_MAX_UUID - 1);
        strncpy(f->process_name, process_name, ARGUS_MAX_NAME - 1);
        f->pid          = pid;
        f->finding_type = FINDING_PRIVATE_EXECUTABLE;
        f->severity     = SEVERITY_HIGH;
        f->region.base_address = (uint64_t)(uintptr_t)mbi.BaseAddress;
        f->region.size         = mbi.RegionSize;
        f->region.protect      = mbi.Protect;
        f->region.type         = mbi.Type;
        f->region.state        = mbi.State;
        strncpy(f->detail.reason,
                "Private committed executable memory region",
                sizeof(f->detail.reason) - 1);
        (*count)++;
    }
    return 0;
}

// ── Scanner orchestrator (Section 5.2) ────────────────────────────────────────

int scanner_run_pid(DWORD pid,
    const char* session_id,
    const char* scan_id,
    const ScanOptions* opts,
    ScanFinding* out_findings,
    size_t* out_count,
    size_t max_findings)
{
    *out_count = 0;

    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        printf("[SCANNER] Failed to open pid %lu (err=%lu)\n", pid, GetLastError());
        return -1;
    }

    char process_name[ARGUS_MAX_NAME] = "unknown";
    get_process_name(hProc, process_name, sizeof(process_name));

    if (opts->detect_private_executable) {
        int r = memscan_run(hProc, pid, process_name, session_id, scan_id,
                            out_findings, out_count, max_findings);
        if (r != 0)
            printf("[SCANNER] memscan failed for pid %lu\n", pid);
    }

#ifdef YARA_AVAILABLE
    if (opts->yara_rules != NULL) {
        int r = yara_scan_process(hProc, pid, process_name,
                                  session_id, scan_id,
                                  (YR_RULES*)opts->yara_rules,
                                  out_findings, out_count, max_findings);
        if (r != 0)
            printf("[SCANNER] yara_scan_process failed for pid %lu\n", pid);
    }
#endif

    if (opts->detect_pe_anomalies) {
        int r = pesieve_scan(pid, process_name, session_id, scan_id,
                             out_findings, out_count, max_findings);
        if (r != 0)
            printf("[SCANNER] pesieve_scan failed for pid %lu\n", pid);
    }

    CloseHandle(hProc);
    printf("[SCANNER] pid %lu -> %zu finding(s)\n", pid, *out_count);
    return 0;
}

// ── NDJSON serialization (Section 5.6) ────────────────────────────────────────

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

void scanner_serialize_finding(const ScanFinding* f, char* buf, size_t buf_size) {
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
        f->ts,
        f->session_id,
        f->scan_id,
        (unsigned long)f->pid,
        f->process_name,
        ftype,
        sev,
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
