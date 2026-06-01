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
        // Install hooks before connecting IPC so the VirtualProtect calls
        // that Detours makes internally (to patch trampoline bytes) are
        // buffered in the queue but not yet sent to the agent.
        hooks_install();
        // Discard every event that accumulated during hook installation.
        // These are all Detours-internal VirtualProtect calls on code pages
        // that would otherwise pollute the correlator state before the
        // actual Trinity runs (setting has_protected=true and causing LOW
        // to be skipped).
        {
            char discard[EQ_MAX_EVENT_LEN];
            while (eq_pop(&g_queue, discard, sizeof(discard)))
                ;
        }
        // Now connect to the agent and start the drain thread with a
        // clean queue — only real hook events will be forwarded.
        g_client = ipc_client_create(&g_queue, 3000);
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
