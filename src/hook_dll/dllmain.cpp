#include <windows.h>

// Wrap C headers so the C++ compiler emits unmangled symbols matching the C .obj files
extern "C" {
#include "event_queue.h"
#include "ipc_client.h"
}
#include "hooks.h"

// g_queue is defined in hooks.c (C linkage); hooks.h already declares it extern "C"

static ArgusIpcClient *g_client = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        eq_init(&g_queue);
        g_client = ipc_client_create(&g_queue, 3000);
        if (g_client) hooks_install();
        break;

    case DLL_PROCESS_DETACH:
        hooks_uninstall();
        if (g_client) {
            ipc_client_destroy(g_client);
            g_client = NULL;
        }
        eq_destroy(&g_queue);
        break;
    }
    return TRUE;
}
