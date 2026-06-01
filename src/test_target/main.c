/*
 * test_target.c
 * Minimal target process for Diamond FSM Correlator E2E testing.
 *
 * Executes the full "Trinity" injection sequence so every FSM capability
 * flag fires in order and the YARA scan catches the EICAR test string:
 *
 *   ALLOC   — VirtualAllocEx (PAGE_READWRITE)          → has_allocated → LOW
 *   WRITE   — WriteProcessMemory (EICAR test string)   → has_written   → MEDIUM
 *   PROTECT — VirtualProtect   (PAGE_EXECUTE_READ)     → has_protected → HIGH
 *             ↳ YARA scan triggers → Multi_EICAR_ac8f42d6 fires
 *               → correlator_feed_yara → has_yara → SEVERITY_CRITICAL
 *
 * !! WARNING !!
 * The EICAR payload string is the universal antivirus test signature.
 * Writing it to process memory WILL trigger Windows Defender and most
 * resident AV engines, which may kill this process before our EDR does.
 * Before running E2E tests, either:
 *   • Add the project build directory to Defender exclusions, OR
 *   • Disable real-time protection in a dedicated test VM.
 *
 * Manual workflow:
 *   1. Start argus_agent.exe
 *   2. Start test_target.exe  (note the printed PID)
 *   3. Run: injector.exe <PID> argus_hook.dll
 *   4. Press ENTER — Trinity executes
 *   5. Observe agent escalate LOW → MEDIUM → HIGH → CRITICAL
 *   6. Press ENTER again to free memory and exit
 *
 * Note: VirtualProtect (not VirtualProtectEx) is used intentionally —
 * argus_hook.dll hooks VirtualProtect directly via Detours.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * Standard EICAR antivirus test string — matched by Multi_EICAR.yar rule
 * "Multi_EICAR_ac8f42d6" (ascii fullword condition).
 * The single backslash in the original string is escaped as \\ in C.
 */
#define EICAR_PAYLOAD \
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

int main(void)
{
    printf("============================================\n");
    printf("  ArgusEDR Test Target — Trinity / EICAR\n");
    printf("============================================\n");
    printf("[target] PID = %lu\n", GetCurrentProcessId());
    printf("\n");
    printf("[target] Step 1: In another terminal, run:\n");
    printf("           argus_agent.exe\n");
    printf("[target] Step 2: In a third terminal, inject the hook DLL:\n");
    printf("           injector.exe %lu argus_hook.dll\n", GetCurrentProcessId());
    printf("\n");
    printf("[target] Press ENTER after injection to trigger Trinity...\n");
    getchar();

    /* ── ALLOC: VirtualAllocEx (PAGE_READWRITE) ─────────────────────────── */
    /* Deliberately RW-only so the FSM accumulates ALLOC and PROTECT as two  */
    /* distinct events rather than collapsing them via an RWX allocation.     */
    /* Hook fires → has_allocated = true → evaluate_state_and_severity → LOW */
    printf("[target] Calling VirtualAllocEx (RW, 4096 bytes)...\n");
    LPVOID mem = VirtualAllocEx(
        GetCurrentProcess(), NULL,
        4096, MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!mem) {
        fprintf(stderr, "[target] VirtualAllocEx FAILED: %lu\n", GetLastError());
        return 1;
    }
    printf("[target] Allocated at %p\n", mem);

    /* ── WRITE: WriteProcessMemory (EICAR string) ───────────────────────── */
    /* EICAR is written at offset 0 of the allocation so the YARA fullword    */
    /* match is satisfied: start-of-buffer counts as a word boundary.         */
    /* Hook fires → has_written = true → MEDIUM                               */
    printf("[target] Writing EICAR test payload via WriteProcessMemory...\n");
    const char* payload = EICAR_PAYLOAD;
    SIZE_T written = 0;
    BOOL wpm_ok = WriteProcessMemory(
        GetCurrentProcess(), mem,
        payload, strlen(payload) + 1,
        &written);

    if (!wpm_ok) {
        fprintf(stderr, "[target] WriteProcessMemory FAILED: %lu\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }
    printf("[target] Written %zu bytes to %p\n", written, mem);

    /* ── PROTECT: VirtualProtect (PAGE_EXECUTE_READ) ────────────────────── */
    /* exec-bit set → has_protected = true → HIGH (full Trinity assembled).   */
    /* This also queues a fresh YARA scan that will find the EICAR payload    */
    /* and fire Multi_EICAR_ac8f42d6 → has_yara = true → CRITICAL.           */
    printf("[target] Calling VirtualProtect (PAGE_EXECUTE_READ)...\n");
    DWORD old_protect = 0;
    BOOL vp_ok = VirtualProtect(mem, 4096, PAGE_EXECUTE_READ, &old_protect);

    if (!vp_ok) {
        fprintf(stderr, "[target] VirtualProtect FAILED: %lu\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }
    printf("[target] Protection changed 0x%lX → PAGE_EXECUTE_READ (0x20)\n",
           (unsigned long)old_protect);

    printf("\n");
    printf("[target] Trinity complete. Check ArgusAgent output for:\n");
    printf("           PROCESS_VERDICT severity:LOW\n");
    printf("           PROCESS_VERDICT severity:MEDIUM\n");
    printf("           PROCESS_VERDICT severity:HIGH\n");
    printf("           PROCESS_VERDICT severity:CRITICAL  (YARA: Multi_EICAR_ac8f42d6)\n");
    printf("\n");
    printf("[target] Press ENTER to free memory and exit...\n");
    getchar();

    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[target] Cleaned up. Goodbye.\n");
    return 0;
}
