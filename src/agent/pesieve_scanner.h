#pragma once
#include <windows.h>
#include "argus/events.h"

#ifdef __cplusplus
extern "C" {
#endif

    int pesieve_scan(DWORD pid,
        const char* process_name,
        const char* session_id,
        const char* scan_id,
        ScanFinding* out_findings,
        size_t* out_count,
        size_t max_findings);

#ifdef __cplusplus
}
#endif