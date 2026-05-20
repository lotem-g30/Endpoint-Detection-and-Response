#pragma once
#include <windows.h>
#include <stdbool.h>
#include "argus/events.h"
#include "yara_scanner.h"

#define MAX_FINDINGS 1024

typedef struct {
    bool      detect_private_executable;
    bool      detect_pe_anomalies;
#ifdef YARA_AVAILABLE
    YR_RULES* yara_rules;
#else
    void* yara_rules;
#endif
} ScanOptions;

int scanner_run_pid(DWORD pid,
    const char* session_id,
    const char* scan_id,
    const ScanOptions* opts,
    ScanFinding* out_findings,
    size_t* out_count,
    size_t max_findings);

// Serializes a ScanFinding to a single NDJSON line (no trailing newline).
void scanner_serialize_finding(const ScanFinding* f, char* buf, size_t buf_size);

// Generates a new UUID string into buf (36 chars + null terminator).
void generate_uuid(char* buf, size_t len);
