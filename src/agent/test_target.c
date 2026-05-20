/*
 * test_target.exe - Controllable target for end-to-end IPC testing
 *
 * Usage (section 6.4 of the guide):
 *   Terminal 1:  argus_agent.exe
 *   Terminal 2:  test_target.exe         <- you are here; note the PID
 *   Terminal 3:  injector.exe <PID> argus_hook.dll
 *   Terminal 2:  press ENTER             <- triggers VirtualAllocEx + WriteProcessMemory
 *
 * Expected result in Terminal 1 (argus_agent):
 *   [SERVER] Received: {"api":"VirtualAllocEx","pid":...}
 *   [SERVER] TRIGGER detected: VirtualAllocEx
 *   [SERVER] Received: {"api":"WriteProcessMemory","pid":...}
 *   [SERVER] TRIGGER detected: WriteProcessMemory
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== test_target.exe ===\n");
    printf("[target] PID = %lu\n", GetCurrentProcessId());
    printf("\n");
    printf("[target] Step 1: Make sure argus_agent.exe is running.\n");
    printf("[target] Step 2: In another terminal, run:\n");
    printf("[target]           injector.exe %lu argus_hook.dll\n",
           GetCurrentProcessId());
    printf("[target] Step 3: Press ENTER here to trigger the suspicious API calls.\n");

    getchar();   /* pause here - inject argus_hook.dll now */

    /* ------------------------------------------------------------------ */
    /* VirtualAllocEx - allocate RWX memory in our own process            */
    /* The hook will fire and push a JSON event to the agent.             */
    /* ------------------------------------------------------------------ */
    printf("\n[target] Calling VirtualAllocEx(self, 4096, RWX)...\n");
    LPVOID mem = VirtualAllocEx(
        GetCurrentProcess(), NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!mem) {
        printf("[target] ERROR: VirtualAllocEx failed (%lu)\n", GetLastError());
        return 1;
    }
    printf("[target] Allocated at %p\n", mem);

    /* ------------------------------------------------------------------ */
    /* WriteProcessMemory - write a known string YARA can match           */
    /* The hook will fire and push a JSON event to the agent.             */
    /* ------------------------------------------------------------------ */
    /* Build the EICAR string at runtime so the binary itself is not flagged
     * by AV (a literal would be embedded in the .rdata section and detected
     * before the process even launches).  The two halves are harmless alone.
     * In C, \\ inside a string literal becomes a single backslash byte —
     * matching exactly what the YARA rule's  $a = "...4\\PZX..."  expects. */
    char payload[80];
    snprintf(payload, sizeof(payload), "%s%s",
             "X5O!P%@AP[4\\PZX54(P^)7CC)7}",
             "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    printf("[target] Calling WriteProcessMemory(self, %p, EICAR string)...\n", mem);
    SIZE_T written = 0;
    if (!WriteProcessMemory(GetCurrentProcess(), mem,
                            payload, strlen(payload) + 1, &written)) {
        printf("[target] ERROR: WriteProcessMemory failed (%lu)\n", GetLastError());
    } else {
        printf("[target] Wrote %zu bytes (EICAR) to %p\n", (size_t)written, mem);
    }

    /* ------------------------------------------------------------------ */
    /* Keep process alive so the agent can scan it if you add Mission 5.  */
    /* ------------------------------------------------------------------ */
    printf("\n[target] API calls done. Check argus_agent.exe for events.\n");
    printf("[target] Press ENTER to exit and free memory.\n");

    getchar();

    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[target] Done.\n");
    return 0;
}