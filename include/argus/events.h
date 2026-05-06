#pragma once
#include <windows.h>
#include <stdint.h>

// Constants
#define ARGUS_MAX_UUID 37
#define ARGUS_MAX_NAME 260
#define ARGUS_MAX_TS   32

// Finding types
typedef enum {
    FINDING_PRIVATE_EXECUTABLE,
    FINDING_PE_HOLLOWING,
    FINDING_PE_IMPLANT,
    FINDING_REFLECTIVE_LOAD,
    FINDING_CODE_CAVE,
    FINDING_MODULE_STOMP,
    FINDING_YARA_MATCH,
    FINDING_ANOMALOUS_THREAD,
} FindingType;

// Severity levels
typedef enum {
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
} Severity;

// Memory region information
typedef struct {
    uint64_t base_address;
    uint64_t size;
    uint32_t protect;
    uint32_t type;
    uint32_t state;
} MemoryRegion;

// Finding details
typedef struct {
    char reason[256];
    char yara_rule[128];
    char pe_anomaly[128];
} FindingDetail;

// Complete scan finding
typedef struct {
    char        ts[ARGUS_MAX_TS];
    char        session_id[ARGUS_MAX_UUID];
    char        scan_id[ARGUS_MAX_UUID];
    uint32_t    pid;
    char        process_name[ARGUS_MAX_NAME];
    FindingType finding_type;
    Severity    severity;
    MemoryRegion region;
    FindingDetail detail;
} ScanFinding;
