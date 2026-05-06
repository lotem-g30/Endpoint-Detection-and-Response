#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include "argus/events.h"

#ifdef YARA_AVAILABLE
#include <yara.h>

int yara_load_rules(const char* path, YR_RULES** rules_out);

int yara_scan_process(HANDLE hProcess,
    DWORD pid,
    const char* process_name,
    const char* session_id,
    const char* scan_id,
    YR_RULES* rules,
    ScanFinding* out_findings,
    size_t* out_count,
    size_t max_findings);
#endif