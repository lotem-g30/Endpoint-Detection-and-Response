#pragma once
#include <windows.h>
#include <stdbool.h>
#include "argus/events.h"

#define IPC_SERVER_MAX_INSTANCES 64

typedef struct ArgusIpcServer ArgusIpcServer;

ArgusIpcServer* ipc_server_create(const char* session_id);
void            ipc_server_destroy(ArgusIpcServer* s);
