/*
 * injector.exe - Classic DLL injector using CreateRemoteThread + LoadLibraryA.
 *
 * Usage:
 *   injector.exe <PID> <full-path-to-dll>
 *
 * Example:
 *   injector.exe 1234 C:\path\to\argus_hook.dll
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static BOOL inject(DWORD pid, const char *dll_path)
{
    HANDLE hProcess = NULL;
    LPVOID remote_buf = NULL;
    HANDLE hThread   = NULL;
    BOOL   ok        = FALSE;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        fprintf(stderr, "[!] OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        goto done;
    }

    size_t path_len = strlen(dll_path) + 1;
    remote_buf = VirtualAllocEx(hProcess, NULL, path_len,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_buf) {
        fprintf(stderr, "[!] VirtualAllocEx failed: %lu\n", GetLastError());
        goto done;
    }

    if (!WriteProcessMemory(hProcess, remote_buf, dll_path, path_len, NULL)) {
        fprintf(stderr, "[!] WriteProcessMemory failed: %lu\n", GetLastError());
        goto done;
    }

    LPVOID load_lib = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                             "LoadLibraryA");
    if (!load_lib) {
        fprintf(stderr, "[!] GetProcAddress(LoadLibraryA) failed: %lu\n", GetLastError());
        goto done;
    }

    hThread = CreateRemoteThread(hProcess, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)load_lib,
                                 remote_buf, 0, NULL);
    if (!hThread) {
        fprintf(stderr, "[!] CreateRemoteThread failed: %lu\n", GetLastError());
        goto done;
    }

    WaitForSingleObject(hThread, 5000);

    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    if (!exit_code) {
        fprintf(stderr, "[!] LoadLibraryA in target returned NULL — DLL not loaded\n");
        goto done;
    }

    printf("[+] DLL injected successfully (module base = 0x%lX)\n", exit_code);
    ok = TRUE;

done:
    if (hThread)    CloseHandle(hThread);
    if (remote_buf) VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
    if (hProcess)   CloseHandle(hProcess);
    return ok;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: injector.exe <PID> <dll-path>\n");
        return 1;
    }

    DWORD pid = (DWORD)strtoul(argv[1], NULL, 10);
    if (!pid) {
        fprintf(stderr, "[!] Invalid PID: %s\n", argv[1]);
        return 1;
    }

    char dll_full[MAX_PATH];
    if (!GetFullPathNameA(argv[2], MAX_PATH, dll_full, NULL)) {
        fprintf(stderr, "[!] GetFullPathNameA failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[*] Injecting '%s' into PID %lu\n", dll_full, pid);
    return inject(pid, dll_full) ? 0 : 1;
}
