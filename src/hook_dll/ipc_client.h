#pragma once
#include <windows.h>
#include <stdbool.h>
#include "event_queue.h"

#define PIPE_NAME L"\\\\.\\pipe\\argus-events"

typedef struct ArgusIpcClient ArgusIpcClient;

ArgusIpcClient* ipc_client_create(EventQueue* queue, DWORD retry_ms);
void            ipc_client_destroy(ArgusIpcClient* c);
bool            ipc_client_connected(ArgusIpcClient* c);