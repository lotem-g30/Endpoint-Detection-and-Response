#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include "argus/events.h"

#ifdef YARA_AVAILABLE
#include <yara.h>

// Call once at agent startup before yara_load_rules.
void yara_global_init(void);

// Call once at agent shutdown after yr_rules_destroy.
void yara_global_finalize(void);

// Compile rules from a single .yar file or all *.yar files in a directory.
// Returns 0 on success, -1 on failure.
int yara_load_rules(const char* path, YR_RULES** rules_out);

// Scan every readable committed region of hProcess against rules.
// Appends ScanFinding entries to out_findings[*out_count .. max_findings-1].
int yara_scan_process(HANDLE hProcess,
    DWORD pid,
    const char* process_name,
    const char* session_id,
    const char* scan_id,
    YR_RULES* rules,
    ScanFinding* out_findings,
    size_t* out_count,
    size_t max_findings);

#endif // YARA_AVAILABLE
