#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "event_queue.h"
#include "ipc_client.h"
#include "ipc_server.h"
#include "scanner.h"
#include "yara_scanner.h"

/**
 * Injects a DLL into a target process using the classic Win32 injection technique
 *
 * @param targetPid The process ID of the target process
 * @param dllPath The full or relative path to the DLL to inject
 * @return TRUE if injection succeeded, FALSE otherwise
 */
BOOL InjectDll(DWORD targetPid, const char* dllPath) {
    HANDLE hProcess = NULL;
    LPVOID remoteDllPath = NULL;
    HANDLE hRemoteThread = NULL;
    BOOL success = FALSE;

    printf("[INJECT] Starting DLL injection into PID %lu\n", targetPid);
    printf("[INJECT] DLL path: %s\n", dllPath);

    // Step 1: Open the target process with full access
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) {
        printf("[INJECT] ERROR: Failed to open process (PID %lu). Error: %lu\n",
               targetPid, GetLastError());
        printf("[INJECT] Hint: Make sure the process exists and you have sufficient privileges.\n");
        return FALSE;
    }
    printf("[INJECT] Successfully opened target process (handle: 0x%p)\n", hProcess);

    // Step 2: Allocate memory in the target process for the DLL path
    SIZE_T dllPathLen = strlen(dllPath) + 1;
    remoteDllPath = VirtualAllocEx(hProcess, NULL, dllPathLen,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteDllPath) {
        printf("[INJECT] ERROR: Failed to allocate memory in target process. Error: %lu\n",
               GetLastError());
        goto cleanup;
    }
    printf("[INJECT] Allocated %zu bytes at remote address 0x%p\n",
           dllPathLen, remoteDllPath);

    // Step 3: Write the DLL path into the allocated memory
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteDllPath, dllPath, dllPathLen, &bytesWritten)) {
        printf("[INJECT] ERROR: Failed to write DLL path to target process. Error: %lu\n",
               GetLastError());
        goto cleanup;
    }
    printf("[INJECT] Wrote %zu bytes to target process memory\n", bytesWritten);

    // Step 4: Get the address of LoadLibraryA from kernel32.dll
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        printf("[INJECT] ERROR: Failed to get handle to kernel32.dll. Error: %lu\n",
               GetLastError());
        goto cleanup;
    }

    LPTHREAD_START_ROUTINE loadLibraryAddr =
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
    if (!loadLibraryAddr) {
        printf("[INJECT] ERROR: Failed to get address of LoadLibraryA. Error: %lu\n",
               GetLastError());
        goto cleanup;
    }
    printf("[INJECT] LoadLibraryA address: 0x%p\n", loadLibraryAddr);

    // Step 5: Create a remote thread to execute LoadLibraryA with our DLL path
    hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr,
                                       remoteDllPath, 0, NULL);
    if (!hRemoteThread) {
        printf("[INJECT] ERROR: Failed to create remote thread. Error: %lu\n",
               GetLastError());
        goto cleanup;
    }
    printf("[INJECT] Remote thread created successfully (handle: 0x%p)\n", hRemoteThread);

    // Wait for the remote thread to complete (LoadLibraryA call to finish)
    printf("[INJECT] Waiting for DLL to load in target process...\n");
    DWORD waitResult = WaitForSingleObject(hRemoteThread, 5000);
    if (waitResult == WAIT_TIMEOUT) {
        printf("[INJECT] WARNING: Remote thread timeout after 5 seconds\n");
    } else if (waitResult == WAIT_OBJECT_0) {
        DWORD exitCode = 0;
        if (GetExitCodeThread(hRemoteThread, &exitCode)) {
            if (exitCode == 0) {
                printf("[INJECT] WARNING: LoadLibraryA returned NULL (DLL may have failed to load)\n");
            } else {
                printf("[INJECT] DLL loaded successfully! Module base: 0x%lx\n", exitCode);
                success = TRUE;
            }
        }
    }

cleanup:
    // Clean up handles (note: we don't free remoteDllPath as it's in the target process)
    if (hRemoteThread) {
        CloseHandle(hRemoteThread);
    }
    if (hProcess) {
        CloseHandle(hProcess);
    }

    if (success) {
        printf("[INJECT] Injection completed successfully!\n");
    } else {
        printf("[INJECT] Injection failed!\n");
    }

    return success;
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== ArgusAgent starting ===\n");

    // Parse command-line arguments for DLL injection
    if (argc < 2) {
        printf("\n[USAGE] %s <target_PID>\n", argv[0]);
        printf("[USAGE] Example: %s 1234\n", argv[0]);
        printf("[USAGE] This will inject argus_hook.dll into process with PID 1234\n\n");
        return 1;
    }

    // Parse target PID from command line
    DWORD targetPid = (DWORD)atoi(argv[1]);
    if (targetPid == 0) {
        printf("[ERROR] Invalid PID: %s\n", argv[1]);
        printf("[ERROR] PID must be a positive integer\n");
        return 1;
    }

    printf("[MAIN] Target PID: %lu\n", targetPid);

    // Perform DLL injection BEFORE starting IPC server
    const char* dllName = "argus_hook.dll";
    if (!InjectDll(targetPid, dllName)) {
        printf("[MAIN] ERROR: DLL injection failed. Aborting.\n");
        return 1;
    }

    printf("[MAIN] DLL injection successful. Starting IPC server to receive events...\n\n");

    // Continue with existing IPC server initialization
    EventQueue* queue = (EventQueue*)malloc(sizeof(EventQueue));
    eq_init(queue);
    printf("[MAIN] EventQueue initialized\n");

    ArgusIpcServer* server = ipc_server_create("session-001");
    if (!server) {
        printf("[MAIN] Failed to create IPC server\n");
        return 1;
    }
    printf("[MAIN] IPC server started\n");

    ArgusIpcClient* client = ipc_client_create(queue, 5000);
    if (!client) {
        printf("[MAIN] Failed to create IPC client\n");
        return 1;
    }
    printf("[MAIN] IPC client connected: %s\n",
        ipc_client_connected(client) ? "YES" : "NO");

    eq_push(queue, "{\"api\":\"VirtualAllocEx\",\"pid\":1234}");
    printf("[MAIN] Test event pushed to queue\n");

    ScanFinding findings[MAX_FINDINGS];
    size_t count = 0;

    ScanOptions opts = { 0 };
    opts.detect_private_executable = false;
    opts.detect_pe_anomalies = false;
    opts.yara_rules = NULL;

#ifdef YARA_AVAILABLE
    YR_RULES* rules = NULL;
    int yr = yara_load_rules("C:\\Users\\nikol\\source\\repos", &rules);
    printf("[MAIN] YARA rules loaded: %s\n", yr == 0 ? "YES" : "NO");
    opts.yara_rules = rules;
#endif

    DWORD my_pid = GetCurrentProcessId();
    printf("[MAIN] Running scan on self (pid=%lu)...\n", my_pid);
    scanner_run_pid(my_pid, "session-001", "scan-001",
        &opts, findings, &count, MAX_FINDINGS);

    printf("[MAIN] Findings: %zu\n", count);
    for (size_t i = 0; i < count; i++) {
        printf("[FINDING %zu] rule=%s region=0x%llx\n",
            i, findings[i].detail.yara_rule,
            findings[i].region.base_address);
    }

#ifdef YARA_AVAILABLE
    if (rules) yr_rules_destroy(rules);
#endif

    Sleep(2000);

    ipc_client_destroy(client);
    ipc_server_destroy(server);
    eq_destroy(queue);
    free(queue);

    printf("=== ArgusAgent stopped ===\n");
    return 0;
}