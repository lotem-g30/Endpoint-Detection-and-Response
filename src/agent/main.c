#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "ipc_server.h"
#include "pesieve_server.h"
#include "scanner.h"
#include "yara_scanner.h"
#include "correlator.h"
#include "argus/events.h"

static CRITICAL_SECTION g_output_lock;

typedef struct {
    DWORD        pid;
    char         session_id[ARGUS_MAX_UUID];
    ScanOptions* opts;
} ScanWorkerContext;

static DWORD WINAPI ScanWorkerThread(LPVOID param) {
    ScanWorkerContext* ctx = (ScanWorkerContext*)param;

    char         scan_id[ARGUS_MAX_UUID];
    ScanFinding  findings[MAX_FINDINGS];
    char         json_line[4096];
    size_t       count = 0;

    generate_uuid(scan_id, sizeof(scan_id));

    EnterCriticalSection(&g_output_lock);
    printf("[MAIN] scan triggered: pid=%lu scan_id=%s\n", ctx->pid, scan_id);
    LeaveCriticalSection(&g_output_lock);

    int r = scanner_run_pid(ctx->pid, ctx->session_id, scan_id,
                            ctx->opts, findings, &count, MAX_FINDINGS);
    if (r != 0) {
        EnterCriticalSection(&g_output_lock);
        printf("[MAIN] scan failed for pid %lu\n", ctx->pid);
        LeaveCriticalSection(&g_output_lock);
        free(ctx);
        return 1;
    }

    EnterCriticalSection(&g_output_lock);
    for (size_t i = 0; i < count; i++) {
        scanner_serialize_finding(&findings[i], json_line, sizeof(json_line));
        printf("%s\n", json_line);

        // Route YARA matches to the correlator (→ CRITICAL escalation).
        if (findings[i].finding_type == FINDING_YARA_MATCH)
            correlator_feed_yara(ctx->pid, findings[i].detail.yara_rule);
    }
    fflush(stdout);
    LeaveCriticalSection(&g_output_lock);

    free(ctx);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== ArgusAgent starting ===\n");

    // ── Correlator ────────────────────────────────────────────────────────────
    correlator_init();

    // ── YARA global init ──────────────────────────────────────────────────────
#ifdef YARA_AVAILABLE
    yara_global_init();
#endif

    // ── Scan options ──────────────────────────────────────────────────────────
    ScanOptions opts = {0};
    opts.detect_private_executable = true;
    opts.detect_pe_anomalies       = false;
    opts.yara_rules                = NULL;

#ifdef YARA_AVAILABLE
    // Load Multi_EICAR.yar by absolute path so the agent finds rules
    // regardless of the working directory it was launched from.
    YR_RULES* rules = NULL;
    char exe_path[MAX_PATH]   = {0};
    char rules_path[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char* last_sep = strrchr(exe_path, '\\');
    if (last_sep) {
        *last_sep = '\0';
        snprintf(rules_path, sizeof(rules_path),
                 "%s\\rules\\Multi_EICAR.yar", exe_path);
    } else {
        strncpy(rules_path, "rules\\Multi_EICAR.yar", sizeof(rules_path) - 1);
    }
    if (yara_load_rules(rules_path, &rules) == 0) {
        opts.yara_rules = rules;
    } else {
        printf("[MAIN] Warning: no YARA rules loaded from: %s\n", rules_path);
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

    // ── PE-Sieve DLL server ───────────────────────────────────────────────────
    ArgusPesieveServer* pesieve_srv = pesieve_server_create();
    if (!pesieve_srv) {
        fprintf(stderr, "[MAIN] Failed to create PE-Sieve server\n");
        ipc_server_destroy(server);
        return 1;
    }
    printf("[MAIN] PE-Sieve server listening on \\\\.\\pipe\\argus-pesieve\n");

    printf("[MAIN] session_id = %s\n", session_id);
    printf("[MAIN] Waiting for hook events (inject argus_hook.dll with injector.exe)...\n\n");

    // ── Scanner orchestrator loop ─────────────────────────────────────────────
    // Each trigger is dispatched to a thread-pool worker so the main thread
    // remains free to dequeue the next trigger immediately.
    InitializeCriticalSection(&g_output_lock);

    while (1) {
        ScanTrigger trigger;
        if (!ipc_server_dequeue_trigger(server, 1000, &trigger))
            continue;

        ScanWorkerContext* ctx =
            (ScanWorkerContext*)malloc(sizeof(ScanWorkerContext));
        if (!ctx) {
            fprintf(stderr, "[MAIN] OOM allocating worker context for pid %lu\n",
                    trigger.pid);
            continue;
        }
        ctx->pid  = trigger.pid;
        ctx->opts = &opts;
        strncpy(ctx->session_id, session_id, ARGUS_MAX_UUID - 1);
        ctx->session_id[ARGUS_MAX_UUID - 1] = '\0';

        if (!QueueUserWorkItem(ScanWorkerThread, ctx, WT_EXECUTEDEFAULT)) {
            fprintf(stderr, "[MAIN] QueueUserWorkItem failed for pid %lu (err=%lu)\n",
                    trigger.pid, GetLastError());
            free(ctx);
        }
    }

    // Cleanup (unreachable without signal; included for correctness)
    DeleteCriticalSection(&g_output_lock);
#ifdef YARA_AVAILABLE
    if (rules) yr_rules_destroy(rules);
    yara_global_finalize();
#endif
    correlator_destroy();
    pesieve_server_destroy(pesieve_srv);
    ipc_server_destroy(server);
    return 0;
}
