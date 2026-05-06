// COPY THIS ENTIRE FILE AND PASTE INTO YOUR dllmain.cpp
// Replace everything you have now with this

#include <Windows.h>
#include <stdio.h>
#include "detours.h"

#ifdef _M_X64
//#pragma comment(lib, "detoursx64.lib")
#endif

// Hook MessageBoxA
typedef int (WINAPI* fnMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
fnMessageBoxA g_pOriginalMessageBoxA = MessageBoxA;

INT WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    printf("[HOOK] Caught MessageBoxA!\n");
    printf("  Text: %s\n", lpText);
    printf("  Caption: %s\n", lpCaption);
    return g_pOriginalMessageBoxA(hWnd, "HOOKED TEXT!", "HOOKED!", uType);
}

BOOL InstallHook()
{
    printf("[+] Installing hook...\n");
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach((PVOID*)&g_pOriginalMessageBoxA, HookedMessageBoxA);
    DetourTransactionCommit();
    printf("[+] Hook installed!\n");
    return TRUE;
}

BOOL RemoveHook()
{
    printf("[+] Removing hook...\n");
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach((PVOID*)&g_pOriginalMessageBoxA, HookedMessageBoxA);
    DetourTransactionCommit();
    printf("[+] Hook removed!\n");
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        AllocConsole();
        FILE* pFile;
        freopen_s(&pFile, "CONOUT$", "w", stdout);
        printf("========================================\n");
        printf("  DLL LOADED!\n");
        printf("========================================\n");
        InstallHook();
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        RemoveHook();
        FreeConsole();
        break;
    }
    return TRUE;
}