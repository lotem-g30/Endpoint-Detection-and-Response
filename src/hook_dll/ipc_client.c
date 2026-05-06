#include "ipc_client.h"
#include <stdio.h>
#include <string.h>

struct ArgusIpcClient {
    EventQueue* queue;
    HANDLE      pipe;
    HANDLE      thread;
    HANDLE      stop_event;
    volatile bool connected;
    uint64_t    last_seen_drops;
};

// forward declaration
static DWORD WINAPI drain_thread(LPVOID param);

static HANDLE connect_to_pipe(DWORD retry_ms) {
    DWORD start = GetTickCount();
    while (1) {
        WaitNamedPipeW(PIPE_NAME, 1000);
        HANDLE h = CreateFileW(
            PIPE_NAME,
            GENERIC_WRITE,
            0, NULL,
            OPEN_EXISTING,
            0, NULL
        );
        if (h != INVALID_HANDLE_VALUE)
            return h;
        if (GetTickCount() - start >= retry_ms)
            return INVALID_HANDLE_VALUE;
        Sleep(100);
    }
}

ArgusIpcClient* ipc_client_create(EventQueue* queue, DWORD retry_ms) {
    ArgusIpcClient* c = (ArgusIpcClient*)calloc(1, sizeof(ArgusIpcClient));
    if (!c) return NULL;

    c->queue = queue;
    c->stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    c->pipe = connect_to_pipe(retry_ms);
    c->connected = (c->pipe != INVALID_HANDLE_VALUE);

    c->thread = CreateThread(NULL, 0, drain_thread, c, 0, NULL);
    return c;
}

void ipc_client_destroy(ArgusIpcClient* c) {
    SetEvent(c->stop_event);
    WaitForSingleObject(c->thread, INFINITE);
    CloseHandle(c->pipe);
    CloseHandle(c->stop_event);
    CloseHandle(c->thread);
    free(c);
}

bool ipc_client_connected(ArgusIpcClient* c) {
    return c->connected;
}

static DWORD WINAPI drain_thread(LPVOID param) {
    ArgusIpcClient* c = (ArgusIpcClient*)param;
    //char buf[EQ_MAX_EVENT_LEN + 2]; // +2 for \n and \0

    while (1) {
        // check stop signal
        if (WaitForSingleObject(c->stop_event, 1) == WAIT_OBJECT_0)
            break;

        // check for drops — emit drop_notice first
        uint64_t current_drops = eq_dropped(c->queue);
        if (current_drops > c->last_seen_drops) {
            char notice[128];
            sprintf(notice, "{\"type\":\"drop_notice\",\"dropped\":%llu}\n",
                (unsigned long long)(current_drops - c->last_seen_drops));
            DWORD written;
            WriteFile(c->pipe, notice, (DWORD)strlen(notice), &written, NULL);
            c->last_seen_drops = current_drops;
        }

        // pop and send one event
        char event[EQ_MAX_EVENT_LEN];
        if (eq_pop(c->queue, event, sizeof(event))) {
            size_t len = strlen(event);
            event[len] = '\n';
            event[len + 1] = '\0';
            DWORD written;
            BOOL ok = WriteFile(c->pipe, event, (DWORD)(len + 1), &written, NULL);
            if (!ok && GetLastError() == ERROR_BROKEN_PIPE) {
                // reconnect
                CloseHandle(c->pipe);
                c->connected = false;
                c->pipe = connect_to_pipe(5000);
                c->connected = (c->pipe != INVALID_HANDLE_VALUE);
            }
        }
    }

    // drain remaining events before exit
    char event[EQ_MAX_EVENT_LEN];
    while (eq_pop(c->queue, event, sizeof(event))) {
        size_t len = strlen(event);
        event[len] = '\n';
        DWORD written;
        WriteFile(c->pipe, event, (DWORD)(len + 1), &written, NULL);
    }

    return 0;
}