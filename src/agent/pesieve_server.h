#pragma once
#include <windows.h>
#include <stdbool.h>

typedef struct ArgusPesieveServer ArgusPesieveServer;

// Creates a named-pipe server on \\.\pipe\argus-pesieve that reads
// NDJSON ScanFinding lines emitted by argus_pesieve.dll and logs them.
ArgusPesieveServer* pesieve_server_create(void);
void                pesieve_server_destroy(ArgusPesieveServer* s);
