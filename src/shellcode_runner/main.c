/*
 * shellcode_runner.c
 * Shellcode loader for ArgusEDR E2E testing.
 *
 * Executes a Metasploit windows/x64/exec CMD=calc.exe payload to verify
 * the full detection pipeline:
 *
 *   VirtualAlloc  (PAGE_EXECUTE_READWRITE) ? hook event ? scan trigger
 *   memcpy        (shellcode written)
 *   CreateThread  (shellcode executed)    ? hook event ? CRITICAL verdict
 *   calc.exe opens — visible confirmation shellcode ran
 *
 * Workflow:
 *   1. Start argus_agent.exe
 *   2. Start shellcode_runner.exe  (note the printed PID)
 *   3. Run: injector.exe <PID> argus_hook.dll
 *   4. Run: injector.exe <PID> argus_pesieve.dll
 *   5. Press ENTER — shellcode allocates + copies
 *   6. Press ENTER again — shellcode executes on a new thread
 *   7. calc.exe opens; ArgusAgent should log:
 *        hook event: VirtualAlloc protect=64 (RWX)
 *        FINDING_PRIVATE_EXECUTABLE
 *        hook event: CreateThread
 *        PROCESS_VERDICT severity:CRITICAL
 *
 * !! WARNING !!
 * This payload launches calc.exe and is structurally identical to a real
 * Metasploit stager. Windows Defender WILL flag it. Add the build output
 * directory to Defender exclusions before running, or use a dedicated VM.
 */

#include <windows.h>
#include <stdio.h>

 /* msfvenom -p windows/x64/exec CMD=calc.exe -f c -b '\x00' */
 /* Generated: x64/xor encoder, 319 bytes                     */
unsigned char buf[] =
"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\x9a\xcc\xb7\xa9\x14\xae\x10\x6a\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x66\x84\x34"
"\x4d\xe4\x46\xd0\x6a\x9a\xcc\xf6\xf8\x55\xfe\x42\x3b\xcc"
"\x84\x86\x7b\x71\xe6\x9b\x38\xfa\x84\x3c\xfb\x0c\xe6\x9b"
"\x38\xba\x84\x3c\xdb\x44\xe6\x1f\xdd\xd0\x86\xfa\x98\xdd"
"\xe6\x21\xaa\x36\xf0\xd6\xd5\x16\x82\x30\x2b\x5b\x05\xba"
"\xe8\x15\x6f\xf2\x87\xc8\x8d\xe6\xe1\x9f\xfc\x30\xe1\xd8"
"\xf0\xff\xa8\xc4\x25\x90\xe2\x9a\xcc\xb7\xe1\x91\x6e\x64"
"\x0d\xd2\xcd\x67\xf9\x9f\xe6\x08\x2e\x11\x8c\x97\xe0\x15"
"\x7e\xf3\x3c\xd2\x33\x7e\xe8\x9f\x9a\x98\x22\x9b\x1a\xfa"
"\x98\xdd\xe6\x21\xaa\x36\x8d\x76\x60\x19\xef\x11\xab\xa2"
"\x2c\xc2\x58\x58\xad\x5c\x4e\x92\x89\x8e\x78\x61\x76\x48"
"\x2e\x11\x8c\x93\xe0\x15\x7e\x76\x2b\x11\xc0\xff\xed\x9f"
"\xee\x0c\x23\x9b\x1c\xf6\x22\x10\x26\x58\x6b\x4a\x8d\xef"
"\xe8\x4c\xf0\x49\x30\xdb\x94\xf6\xf0\x55\xf4\x58\xe9\x76"
"\xec\xf6\xfb\xeb\x4e\x48\x2b\xc3\x96\xff\x22\x06\x47\x47"
"\x95\x65\x33\xea\xe1\xae\xaf\x10\x6a\x9a\xcc\xb7\xa9\x14"
"\xe6\x9d\xe7\x9b\xcd\xb7\xa9\x55\x14\x21\xe1\xf5\x4b\x48"
"\x7c\xaf\x63\x74\xf5\xf2\x8d\x0d\x0f\x81\x13\x8d\x95\x4f"
"\x84\x34\x6d\x3c\x92\x16\x16\x90\x4c\x4c\x49\x61\xab\xab"
"\x2d\x89\xbe\xd8\xc3\x14\xf7\x51\xe3\x40\x33\x62\xca\x75"
"\xc2\x73\x44\xff\xb4\xd2\xa9\x14\xae\x10\x6a";

int main(void)
{
    printf("============================================\n");
    printf("  ArgusEDR Shellcode Runner — calc.exe\n");
    printf("============================================\n");
    printf("[runner] PID = %lu\n", GetCurrentProcessId());
    printf("\n");
    printf("[runner] Step 1: start argus_agent.exe in another terminal\n");
    printf("[runner] Step 2: inject both DLLs:\n");
    printf("           injector.exe %lu argus_hook.dll\n", GetCurrentProcessId());
    printf("           injector.exe %lu argus_pesieve.dll\n", GetCurrentProcessId());
    printf("\n");
    printf("[runner] Press ENTER after injection to allocate + copy shellcode...\n");
    getchar();

    /* ?? Step 1: VirtualAlloc RWX ??????????????????????????????????????????? */
    /* PAGE_EXECUTE_READWRITE in one shot — the classic red flag.              */
    /* argus_hook.dll intercepts this ? sends hook event ? agent enqueues      */
    /* a scan trigger ? scanner finds FINDING_PRIVATE_EXECUTABLE.             */
    printf("[runner] Calling VirtualAlloc (RWX, %zu bytes)...\n", sizeof(buf));
    LPVOID lpShellcode = VirtualAlloc(
        NULL, sizeof(buf),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!lpShellcode) {
        fprintf(stderr, "[runner] VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[runner] Allocated at %p\n", lpShellcode);

    /* ?? Step 2: copy shellcode ????????????????????????????????????????????? */
    memcpy(lpShellcode, buf, sizeof(buf));
    printf("[runner] Shellcode copied (%zu bytes).\n", sizeof(buf));

    printf("\n");
    printf("[runner] Press ENTER to execute shellcode (calc.exe will open)...\n");
    getchar();

    /* ?? Step 3: CreateThread ? execute shellcode ??????????????????????????? */
    /* argus_hook.dll intercepts CreateThread ? correlator sets                */
    /* has_remote_thread = true ? SEVERITY_CRITICAL verdict emitted.          */
    printf("[runner] Calling CreateThread at %p...\n", lpShellcode);
    HANDLE hThread = CreateThread(
        NULL, 0,
        (LPTHREAD_START_ROUTINE)lpShellcode,
        NULL, 0, NULL);

    if (!hThread) {
        fprintf(stderr, "[runner] CreateThread failed: %lu\n", GetLastError());
        VirtualFree(lpShellcode, 0, MEM_RELEASE);
        return 1;
    }

    printf("[runner] Thread created — waiting for shellcode to finish...\n");
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);

    printf("\n");
    printf("[runner] Done. Check ArgusAgent output for:\n");
    printf("           hook event: VirtualAlloc protect=64 (RWX)\n");
    printf("           FINDING_PRIVATE_EXECUTABLE\n");
    printf("           hook event: CreateThread\n");
    printf("           PROCESS_VERDICT severity:CRITICAL\n");
    printf("\n");
    printf("[runner] Press ENTER to free memory and exit.\n");
    getchar();

    VirtualFree(lpShellcode, 0, MEM_RELEASE);
    printf("[runner] Cleaned up. Goodbye.\n");
    return 0;
}