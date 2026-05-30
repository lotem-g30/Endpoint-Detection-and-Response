#include "hooks.h"
#include "detours.h"
#include <stdio.h>

// Owns the global event queue; initialized by DllMain via eq_init(&g_queue)
EventQueue g_queue;

// ── VirtualAllocEx ────────────────────────────────────────────────────────────

static LPVOID (WINAPI *Real_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD)
    = VirtualAllocEx;

static LPVOID WINAPI Hook_VirtualAllocEx(
    HANDLE hProcess, LPVOID lpAddress,
    SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    LPVOID result = Real_VirtualAllocEx(
        hProcess, lpAddress, dwSize, flAllocationType, flProtect);

    char event[512];
    snprintf(event, sizeof(event),
        "{\"api\":\"VirtualAllocEx\",\"pid\":%lu,\"target_pid\":%lu,"
        "\"address\":\"%p\",\"size\":%zu,\"protect\":%lu}",
        GetCurrentProcessId(), GetProcessId(hProcess),
        result, (size_t)dwSize, (unsigned long)flProtect);
    eq_push(&g_queue, event);

    return result;
}

// ── WriteProcessMemory ────────────────────────────────────────────────────────

static BOOL (WINAPI *Real_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *)
    = WriteProcessMemory;

static BOOL WINAPI Hook_WriteProcessMemory(
    HANDLE hProcess, LPVOID lpBaseAddress,
    LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    BOOL result = Real_WriteProcessMemory(
        hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    char event[512];
    snprintf(event, sizeof(event),
        "{\"api\":\"WriteProcessMemory\",\"pid\":%lu,\"target_pid\":%lu,"
        "\"address\":\"%p\",\"size\":%zu}",
        GetCurrentProcessId(), GetProcessId(hProcess),
        lpBaseAddress, (size_t)nSize);
    eq_push(&g_queue, event);

    return result;
}

// ── CreateRemoteThread ────────────────────────────────────────────────────────

static HANDLE (WINAPI *Real_CreateRemoteThread)(
    HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)
    = CreateRemoteThread;

static HANDLE WINAPI Hook_CreateRemoteThread(
    HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    HANDLE result = Real_CreateRemoteThread(
        hProcess, lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

    char event[512];
    snprintf(event, sizeof(event),
        "{\"api\":\"CreateRemoteThread\",\"pid\":%lu,\"target_pid\":%lu,"
        "\"start_address\":\"%p\"}",
        GetCurrentProcessId(), GetProcessId(hProcess),
        (void *)lpStartAddress);
    eq_push(&g_queue, event);

    return result;
}

// ── VirtualProtect ────────────────────────────────────────────────────────────

static BOOL (WINAPI *Real_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD)
    = VirtualProtect;

static BOOL WINAPI Hook_VirtualProtect(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    BOOL result = Real_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

    char event[512];
    snprintf(event, sizeof(event),
        "{\"api\":\"VirtualProtect\",\"pid\":%lu,\"target_pid\":%lu,"
        "\"address\":\"%p\",\"size\":%zu,\"protect\":%lu}",
        GetCurrentProcessId(), GetCurrentProcessId(),
        lpAddress, (size_t)dwSize, (unsigned long)flNewProtect);
    eq_push(&g_queue, event);

    return result;
}

// ── Transaction helpers ───────────────────────────────────────────────────────

void hooks_install(void) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach((PVOID *)&Real_VirtualAllocEx,    Hook_VirtualAllocEx);
    DetourAttach((PVOID *)&Real_WriteProcessMemory, Hook_WriteProcessMemory);
    DetourAttach((PVOID *)&Real_CreateRemoteThread, Hook_CreateRemoteThread);
    DetourAttach((PVOID *)&Real_VirtualProtect,     Hook_VirtualProtect);
    DetourTransactionCommit();
}

void hooks_uninstall(void) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach((PVOID *)&Real_VirtualAllocEx,    Hook_VirtualAllocEx);
    DetourDetach((PVOID *)&Real_WriteProcessMemory, Hook_WriteProcessMemory);
    DetourDetach((PVOID *)&Real_CreateRemoteThread, Hook_CreateRemoteThread);
    DetourDetach((PVOID *)&Real_VirtualProtect,     Hook_VirtualProtect);
    DetourTransactionCommit();
}
