#include "correlator.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define MAX_TRACKED_PIDS 512

static const char* s_sev[] = { "LOW", "MEDIUM", "HIGH", "CRITICAL" };

typedef struct {
    DWORD         pid;
    Severity      severity;
    bool          active;
    int           region_count;
    TrackedRegion regions[CORRELATOR_MAX_REGIONS];
} PidEntry;

static PidEntry          s_table[MAX_TRACKED_PIDS];
static CRITICAL_SECTION  s_lock;

void correlator_init(void) {
    memset(s_table, 0, sizeof(s_table));
    InitializeCriticalSection(&s_lock);
}

void correlator_destroy(void) {
    DeleteCriticalSection(&s_lock);
}

// Must be called with s_lock held.
static PidEntry* find_or_create(DWORD pid) {
    PidEntry* free_slot = NULL;
    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (s_table[i].active && s_table[i].pid == pid)
            return &s_table[i];
        if (!s_table[i].active && !free_slot)
            free_slot = &s_table[i];
    }
    if (free_slot) {
        memset(free_slot, 0, sizeof(*free_slot));
        free_slot->pid      = pid;
        free_slot->severity = SEVERITY_LOW;
        free_slot->active   = true;
    }
    return free_slot;
}

// Must be called with s_lock held.
// Returns true if severity was raised.
static bool set_at_least(PidEntry* e, Severity target) {
    if (target > e->severity) {
        e->severity = target;
        return true;
    }
    return false;
}

// Must be called with s_lock held.
// Increments severity by one tier; returns true if raised.
static bool raise_by_one(PidEntry* e) {
    if (e->severity < SEVERITY_CRITICAL) {
        e->severity = (Severity)(e->severity + 1);
        return true;
    }
    return false;
}

static void emit_verdict(DWORD pid, Severity sev, const char* trigger) {
    printf("{\"type\":\"PROCESS_VERDICT\",\"pid\":%lu,"
           "\"severity\":\"%s\",\"trigger\":\"%s\"}\n",
           (unsigned long)pid, s_sev[sev], trigger);
    fflush(stdout);
}

void correlator_feed_pesieve(DWORD pid, const char* finding_type_str,
                             ULONGLONG base_address)
{
    char trigger[256];
    snprintf(trigger, sizeof(trigger), "PE-Sieve: %s",
             finding_type_str ? finding_type_str : "unknown");

    // ── Deduplication matrix ──────────────────────────────────────────────────
    bool is_structural =
        finding_type_str &&
        (strcmp(finding_type_str, "FINDING_PE_IMPLANT")      == 0 ||
         strcmp(finding_type_str, "FINDING_PE_HOLLOWING")    == 0 ||
         strcmp(finding_type_str, "FINDING_REFLECTIVE_LOAD") == 0);

    bool is_local_mod =
        finding_type_str &&
        (strcmp(finding_type_str, "FINDING_CODE_CAVE")    == 0 ||
         strcmp(finding_type_str, "FINDING_MODULE_STOMP") == 0);

    bool     escalated   = false;
    bool     deduped     = false;
    Severity new_sev     = SEVERITY_MEDIUM;
    char     dup_api[32] = {0};

    EnterCriticalSection(&s_lock);
    PidEntry* e = find_or_create(pid);
    if (e) {
        if (is_structural) {
            // Structural findings (PE hollowing/implant/reflective load) are
            // never deduplicated — they are always a higher-severity event.
            escalated = set_at_least(e, SEVERITY_HIGH);
            new_sev   = e->severity;
        } else if (is_local_mod && base_address != 0) {
            // Check whether this region was already captured by a hook event
            // that we recorded.  Only VirtualProtect and WriteProcessMemory
            // hooks describe inline patches — VirtualAllocEx only allocates.
            for (int i = 0; i < e->region_count; i++) {
                TrackedRegion* r = &e->regions[i];
                if (base_address >= r->base_address &&
                    base_address <  r->base_address + r->size &&
                    (strcmp(r->source_api, "VirtualProtect")     == 0 ||
                     strcmp(r->source_api, "WriteProcessMemory") == 0)) {
                    deduped = true;
                    strncpy(dup_api, r->source_api, sizeof(dup_api) - 1);
                    break;
                }
            }
            if (!deduped) {
                escalated = set_at_least(e, SEVERITY_MEDIUM);
                new_sev   = e->severity;
            }
        } else {
            escalated = set_at_least(e, SEVERITY_MEDIUM);
            new_sev   = e->severity;
        }
    }
    LeaveCriticalSection(&s_lock);

    if (deduped) {
        printf("[CORRELATOR] Deduplicated PE-Sieve finding %s at 0x%llx "
               "due to prior %s hook.\n",
               finding_type_str,
               (unsigned long long)base_address,
               dup_api);
        fflush(stdout);
        return;
    }

    if (escalated)
        emit_verdict(pid, new_sev, trigger);
}

void correlator_feed_hook_event(DWORD pid, const char* api_name,
                                DWORD protect_flags,
                                ULONGLONG address, ULONGLONG size)
{
    if (!api_name) return;

    bool     escalated = false;
    Severity new_sev   = SEVERITY_LOW;
    char     trigger[256];

    EnterCriticalSection(&s_lock);
    PidEntry* e = find_or_create(pid);
    if (e) {
        // Record the region so PE-Sieve findings at the same address can be
        // deduplicated.  Only the APIs that describe a specific memory region
        // are tracked; CreateRemoteThread has no meaningful base_address.
        bool track =
            address != 0 && size != 0 &&
            (strcmp(api_name, "VirtualAllocEx")    == 0 ||
             strcmp(api_name, "WriteProcessMemory") == 0 ||
             strcmp(api_name, "VirtualProtect")     == 0);

        if (track && e->region_count < CORRELATOR_MAX_REGIONS) {
            TrackedRegion* r = &e->regions[e->region_count++];
            r->base_address  = address;
            r->size          = size;
            strncpy(r->source_api, api_name, sizeof(r->source_api) - 1);
        }

        // Severity escalation (unchanged logic).
        if (strcmp(api_name, "CreateRemoteThread") == 0) {
            snprintf(trigger, sizeof(trigger), "Hook: CreateRemoteThread");
            escalated = set_at_least(e, SEVERITY_CRITICAL);
        } else if (strcmp(api_name, "VirtualProtect") == 0) {
            snprintf(trigger, sizeof(trigger),
                     "Hook: VirtualProtect(protect=0x%lx)",
                     (unsigned long)protect_flags);
            bool is_exec = (protect_flags & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                             PAGE_EXECUTE_READWRITE |
                                             PAGE_EXECUTE_WRITECOPY)) != 0;
            if (is_exec)
                escalated = raise_by_one(e);
        } else {
            snprintf(trigger, sizeof(trigger), "Hook: %s", api_name);
            escalated = set_at_least(e, SEVERITY_MEDIUM);
        }
        new_sev = e->severity;
    }
    LeaveCriticalSection(&s_lock);

    if (escalated)
        emit_verdict(pid, new_sev, trigger);
}

void correlator_feed_yara(DWORD pid, const char* rule_name) {
    char trigger[256];
    snprintf(trigger, sizeof(trigger), "YARA: %s",
             rule_name && rule_name[0] ? rule_name : "unknown");

    bool escalated = false;

    EnterCriticalSection(&s_lock);
    PidEntry* e = find_or_create(pid);
    if (e)
        escalated = set_at_least(e, SEVERITY_CRITICAL);
    LeaveCriticalSection(&s_lock);

    if (escalated)
        emit_verdict(pid, SEVERITY_CRITICAL, trigger);
}
