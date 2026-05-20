#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "ipc_server.h"
#include "scanner.h"
#include "yara_scanner.h"
#include "argus/events.h"

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== ArgusAgent starting ===\n");

    // ── YARA global init (must happen before yara_load_rules) ────────────────
#ifdef YARA_AVAILABLE
    yara_global_init();
#endif

    // ── Scan options ──────────────────────────────────────────────────────────
    ScanOptions opts = {0};
    opts.detect_private_executable = true;
    opts.detect_pe_anomalies       = false;
    opts.yara_rules                = NULL;

#ifdef YARA_AVAILABLE
    YR_RULES* rules = NULL;
    if (yara_load_rules("rules", &rules) == 0) {
        opts.yara_rules = rules;
    } else {
        printf("[MAIN] Warning: no YARA rules loaded (rules/ missing or empty)\n");
    }
#endif

    // ── IPC server ────────────────────────────────────────────────────────────
    char session_id[ARGUS_MAX_UUID];
    generate_uuid(session_id, sizeof(session_id));
    ArgusIpcServer* server = ipc_server_create(session_id);
    if (!server) {
        fprintf(stderr, "[MAIN] Failed to create IPC server\n");
        return 1;
    }
    printf("[MAIN] IPC server listening on \\\\.\\pipe\\argus-events\n");
    printf("[MAIN] session_id = %s\n", session_id);
    printf("[MAIN] Waiting for hook events (inject argus_hook.dll with injector.exe)...\n\n");

    // ── Scanner orchestrator loop ─────────────────────────────────────────────
    ScanFinding findings[MAX_FINDINGS];
    char        scan_id[ARGUS_MAX_UUID];
    char        json_line[4096];

    while (1) {
        ScanTrigger trigger;
        if (!ipc_server_dequeue_trigger(server, 1000, &trigger))
            continue;

        generate_uuid(scan_id, sizeof(scan_id));
        printf("[MAIN] scan triggered: pid=%lu scan_id=%s\n", trigger.pid, scan_id);

        size_t count = 0;
        int r = scanner_run_pid(trigger.pid, session_id, scan_id,
                                &opts, findings, &count, MAX_FINDINGS);
        if (r != 0) {
            printf("[MAIN] scan failed for pid %lu\n", trigger.pid);
            continue;
        }

        for (size_t i = 0; i < count; i++) {
            scanner_serialize_finding(&findings[i], json_line, sizeof(json_line));
            printf("%s\n", json_line);
        }
        fflush(stdout);
    }

    // Cleanup (unreachable without signal; included for correctness)
#ifdef YARA_AVAILABLE
    if (rules) yr_rules_destroy(rules);
    yara_global_finalize();
#endif
    ipc_server_destroy(server);
    return 0;
}
