/*
 * test_target.c
 * Minimal target process for end-to-end EDR testing.
 *
 * Workflow:
 *   1. Start argus_agent.exe
 *   2. Start test_target.exe  (note the printed PID)
 *   3. Run: injector.exe <PID> argus_hook.dll
 *   4. Press ENTER in test_target to trigger VirtualAllocEx + WriteProcessMemory
 *   5. Watch argus_agent.exe for:
 *        - {"api":"VirtualAllocEx", ...}
 *        - {"finding_type":"FINDING_YARA_MATCH", "detail":{"yara_rule":"suspicious_string"}}
 *
 * Build (add to CMakeLists.txt):
 *   add_executable(test_target src/test_target/main.c)
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

 /* The string that YARA rule "suspicious_string" in rules/basic.yar looks for */
#define TEST_PAYLOAD "ARGUS_TEST_PAYLOAD"

int main(void)
{
    printf("============================================\n");
    printf("  ArgusEDR Test Target\n");
    printf("============================================\n");
    printf("[target] PID = %lu\n", GetCurrentProcessId());
    printf("\n");
    printf("[target] Step 1: In another terminal, run:\n");
    printf("           argus_agent.exe\n");
    printf("[target] Step 2: In a third terminal, inject the hook DLL:\n");
    printf("           injector.exe %lu argus_hook.dll\n", GetCurrentProcessId());
    printf("\n");
    printf("[target] Press ENTER after injection to trigger the test APIs...\n");
    getchar();   /* ? inject argus_hook.dll here */

    /* ------------------------------------------------------------------ */
    /* Trigger 1: VirtualAllocEx (self)                                    */
    /* Hook should send {"api":"VirtualAllocEx"} to ArgusAgent             */
    /* ArgusAgent should enqueue a ScanTrigger for this PID                */
    /* ------------------------------------------------------------------ */
    printf("[target] Calling VirtualAllocEx (RWX, 4096 bytes)...\n");
    LPVOID mem = VirtualAllocEx(
        GetCurrentProcess(),
        NULL,
        4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);   /* RWX — suspicious */

    if (!mem) {
        fprintf(stderr, "[target] VirtualAllocEx FAILED: %lu\n", GetLastError());
        return 1;
    }
    printf("[target] Allocated at %p\n", mem);

    /* ------------------------------------------------------------------ */
    /* Trigger 2: WriteProcessMemory                                       */
    /* Writes TEST_PAYLOAD — YARA rule "suspicious_string" should fire     */
    /* ------------------------------------------------------------------ */
    printf("[target] Writing YARA test payload via WriteProcessMemory...\n");
    SIZE_T written = 0;
    const char* payload = TEST_PAYLOAD;
    BOOL wpm_ok = WriteProcessMemory(
        GetCurrentProcess(),
        mem,
        payload,
        strlen(payload) + 1,
        &written);

    if (!wpm_ok) {
        fprintf(stderr, "[target] WriteProcessMemory FAILED: %lu\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }
    printf("[target] Written %zu bytes (\"%s\") to %p\n",
        written, TEST_PAYLOAD, mem);

    /* ------------------------------------------------------------------ */
    /* Wait — give ArgusAgent time to scan and print findings              */
    /* ------------------------------------------------------------------ */
    printf("\n");
    printf("[target] APIs triggered. Check ArgusAgent output for:\n");
    printf("           {\"api\":\"VirtualAllocEx\", ...}\n");
    printf("           {\"finding_type\":\"FINDING_YARA_MATCH\", "
        "\"detail\":{\"yara_rule\":\"suspicious_string\"}, ...}\n");
    printf("\n");
    printf("[target] Press ENTER to free memory and exit...\n");
    getchar();

    /* Cleanup */
    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[target] Cleaned up. Goodbye.\n");
    return 0;
}