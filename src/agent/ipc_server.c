#include "ipc_server.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Trigger APIs that cause a scan
static const char* TRIGGER_APIS[] = {
    "VirtualAllocEx",
    "CreateRemoteThread",
    "WriteProcessMemory",
    NULL
};

struct ArgusIpcServer {
    char    session_id[ARGUS_MAX_UUID];
    HANDLE  accept_thread;
    volatile bool running;
};

typedef struct {
    HANDLE pipe;
    char   session_id[ARGUS_MAX_UUID];
} ClientContext;

static bool is_trigger_api(const char* api_name) {
    for (int i = 0; TRIGGER_APIS[i] != NULL; i++) {
        if (strcmp(api_name, TRIGGER_APIS[i]) == 0)
            return true;
    }
    return false;
}

static DWORD WINAPI client_reader_thread(LPVOID param) {
    ClientContext* ctx = (ClientContext*)param;
    HANDLE pipe = ctx->pipe;

    char    accum[8192];
    int     accum_pos = 0;
    char    read_buf[4096];
    DWORD   bytes_read;

    while (1) {
        BOOL ok = ReadFile(pipe, read_buf, sizeof(read_buf) - 1, &bytes_read, NULL);
        if (!ok || bytes_read == 0) break;

        // append to accumulation buffer
        if (accum_pos + (int)bytes_read >= (int)sizeof(accum)) {
            // overflow — reset
            accum_pos = 0;
            continue;
        }
        memcpy(accum + accum_pos, read_buf, bytes_read);
        accum_pos += bytes_read;

        // scan for complete lines
        char* start = accum;
        char* newline;
        while ((newline = (char*)memchr(start, '\n',
            accum_pos - (int)(start - accum))) != NULL) {
            *newline = '\0';

            // we have a complete line in 'start'
            printf("[SERVER] Received: %s\n", start);

            // check for trigger API
            // simple string search since we don't have cJSON yet
            char* api_pos = strstr(start, "\"api\"");
            if (api_pos) {
                char* quote1 = strchr(api_pos + 6, '"');
                if (quote1) {
                    char* quote2 = strchr(quote1 + 1, '"');
                    if (quote2) {
                        char api_name[128] = { 0 };
                        size_t len = quote2 - quote1 - 1;
                        if (len < sizeof(api_name)) {
                            memcpy(api_name, quote1 + 1, len);
                            if (is_trigger_api(api_name))
                                printf("[SERVER] TRIGGER detected: %s\n", api_name);
                        }
                    }
                }
            }

            start = newline + 1;
        }

        // move leftover to front
        int remaining = accum_pos - (int)(start - accum);
        memmove(accum, start, remaining);
        accum_pos = remaining;
    }

    CloseHandle(pipe);
    free(ctx);
    return 0;
}

static DWORD WINAPI accept_loop_thread(LPVOID param) {
    ArgusIpcServer* s = (ArgusIpcServer*)param;

    while (s->running) {
        HANDLE pipe = CreateNamedPipeW(
            L"\\\\.\\pipe\\argus-events",
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            IPC_SERVER_MAX_INSTANCES,
            4096, 4096,
            0, NULL
        );
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(100);
            continue;
        }

        // block until a client connects
        BOOL connected = ConnectNamedPipe(pipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe);
            continue;
        }

        // spawn reader thread for this client
        ClientContext* ctx = (ClientContext*)calloc(1, sizeof(ClientContext));
        ctx->pipe = pipe;
        strncpy(ctx->session_id, s->session_id, ARGUS_MAX_UUID - 1);

        CreateThread(NULL, 0, client_reader_thread, ctx, 0, NULL);
    }

    return 0;
}

ArgusIpcServer* ipc_server_create(const char* session_id) {
    ArgusIpcServer* s = (ArgusIpcServer*)calloc(1, sizeof(ArgusIpcServer));
    if (!s) return NULL;

    strncpy(s->session_id, session_id, ARGUS_MAX_UUID - 1);
    s->running = true;

    s->accept_thread = CreateThread(NULL, 0, accept_loop_thread, s, 0, NULL);
    return s;
}

void ipc_server_destroy(ArgusIpcServer* s) {
    s->running = false;
    WaitForSingleObject(s->accept_thread, 3000);
    CloseHandle(s->accept_thread);
    free(s);
}