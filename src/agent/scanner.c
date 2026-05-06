#include "scanner.h"
#include "pesieve_scanner.h"
#include "yara_scanner.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <rpc.h>

#pragma comment(lib, "rpcrt4.lib")

static void generate_uuid(char* buf, size_t len) {
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

int scanner_run_pid(DWORD pid,
    const char* session_id,
    const char* scan_id,
    const ScanOptions* opts,
    ScanFinding* out_findings,
    size_t* out_count,
    size_t max_findings)
{
    *out_count = 0;

    // open process handle
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    if (!hProcess) {
        printf("[SCANNER] Failed to open process %lu\n", pid);
        return -1;
    }

    // get process name
    char process_name[ARGUS_MAX_NAME] = "unknown";

    // run PE-sieve scanner
    if (opts->detect_pe_anomalies) {
        int r = pesieve_scan(pid, process_name, session_id, scan_id,
            out_findings, out_count, max_findings);
        if (r == -1)
            printf("[SCANNER] pesieve_scan failed or unavailable for pid %lu\n", pid);
    }

    // run YARA scanner
#ifdef YARA_AVAILABLE
    if (opts->yara_rules != NULL) {
        int r = yara_scan_process(hProcess, pid, process_name,
            session_id, scan_id,
            (YR_RULES*)opts->yara_rules,
            out_findings, out_count, max_findings);
        if (r == -1)
            printf("[SCANNER] yara_scan_process failed for pid %lu\n", pid);
    }
#endif

    CloseHandle(hProcess);

    printf("[SCANNER] Scan complete for pid %lu — %zu finding(s)\n",
        pid, *out_count);
    return 0;
}