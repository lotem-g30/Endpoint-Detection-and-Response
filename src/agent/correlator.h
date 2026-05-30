#pragma once
#include <windows.h>
#include "argus/events.h"

// Initialize the correlator. Call once from main() before any threads start.
void correlator_init(void);

// Tear down the correlator. Call once from main() at shutdown.
void correlator_destroy(void);

// Feed a PE-Sieve finding. finding_type_str is the string representation,
// e.g. "FINDING_CODE_CAVE". Escalates the PID's severity to at least MEDIUM.
void correlator_feed_pesieve(DWORD pid, const char* finding_type_str);

// Feed a hook event from the argus-events pipe.
// api_name: e.g. "VirtualProtect", "CreateRemoteThread", "VirtualAllocEx".
// protect_flags: flNewProtect for VirtualProtect; 0 for all other APIs.
// Escalation rules:
//   CreateRemoteThread  → CRITICAL (terminal injection action)
//   VirtualProtect + exec bit set → raise by one tier
//   All others          → at least MEDIUM
void correlator_feed_hook_event(DWORD pid, const char* api_name, DWORD protect_flags);

// Feed a YARA match. Escalates the PID's severity to CRITICAL immediately.
void correlator_feed_yara(DWORD pid, const char* rule_name);
