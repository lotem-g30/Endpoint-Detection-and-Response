#include "correlator.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define MAX_TRACKED_PIDS 512

static const char* s_sev[] = { "LOW", "MEDIUM", "HIGH", "CRITICAL" };

typedef struct {
    DWORD         pid;
    Severity      severity;     /* last emitted severity level              */
    bool          active;
    int           region_count;
    TrackedRegion regions[CORRELATOR_MAX_REGIONS];
    /* Diamond / Capabilities FSM flags */
    bool          has_allocated;    /* VirtualAllocEx / VirtualAlloc seen   */
    bool          has_written;      /* WriteProcessMemory seen after alloc   */
    bool          has_protected;    /* memory became executable (3 paths)   */
    bool          has_remote_thread;/* CreateRemoteThread seen              */
    bool          has_yara;         /* YARA rule fired                      */
    bool          is_dead;          /* CRITICAL reached — no further action */
    /* Set by callers before evaluate_state_and_severity() so the verdict
     * trigger string names the actual event rather than generic capability text. */
    char          last_context[256];
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

/* Must be called with s_lock held. */
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
        free_slot->severity = (Severity)-1; /* sentinel: below LOW, no verdict yet */
        free_slot->active   = true;
    }
    return free_slot;
}

static void emit_verdict(DWORD pid, Severity sev, const char* trigger) {
    printf("{\"type\":\"PROCESS_VERDICT\",\"pid\":%lu,"
           "\"severity\":\"%s\",\"trigger\":\"%s\"}\n",
           (unsigned long)pid, s_sev[sev], trigger);
    fflush(stdout);
}

/*
 * Derives severity from accumulated capability flags using a highest-wins
 * ladder and emits a verdict if the severity has increased.
 * Sets is_dead = true when SEVERITY_CRITICAL is reached.
 * Callers must populate e->last_context before calling this function.
 * Must be called with s_lock held.
 */
static void evaluate_state_and_severity(PidEntry* e) {
    if (e->is_dead) return;

    Severity derived;

    if (e->has_remote_thread || e->has_yara) {
        derived = SEVERITY_CRITICAL;
    } else if (e->has_written && e->has_protected) {
        derived = SEVERITY_HIGH;
    } else if (e->has_written || e->has_protected) {
        derived = SEVERITY_MEDIUM;
    } else if (e->has_allocated) {
        derived = SEVERITY_LOW;
    } else {
        return; /* no flags — nothing to report */
    }

    if (derived > e->severity) {
        e->severity = derived;
        emit_verdict(e->pid, derived, e->last_context);
        if (derived == SEVERITY_CRITICAL)
            e->is_dead = true;
    }
}

void correlator_feed_pesieve(DWORD pid, const char* finding_type_str,
                             ULONGLONG base_address)
{
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

    bool     deduped     = false;
    char     dup_api[32] = {0};

    EnterCriticalSection(&s_lock);
    PidEntry* e = find_or_create(pid);
    if (e) {
        snprintf(e->last_context, sizeof(e->last_context), "PE-Sieve: %s",
                 finding_type_str ? finding_type_str : "unknown");

        if (is_structural) {
            /* Structural implants confirm both a write and an executable mapping
             * exist — set both flags so the ladder reaches SEVERITY_HIGH. */
            e->has_written   = true;
            e->has_protected = true;
            evaluate_state_and_severity(e);
        } else if (is_local_mod && base_address != 0) {
            /* Check whether this region was already captured by a hook event
             * that we recorded.  Only VirtualProtect and WriteProcessMemory
             * hooks describe inline patches — VirtualAllocEx only allocates. */
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
                /* Local patch in an unknown region — existing code is executable. */
                e->has_protected = true;
                evaluate_state_and_severity(e);
            }
        } else {
            /* Generic finding (e.g. FINDING_PRIVATE_EXECUTABLE):
             * private executable page detected — treat as PROTECT capability. */
            e->has_protected = true;
            evaluate_state_and_severity(e);
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
    }
}

void correlator_feed_hook_event(DWORD pid, const char* api_name,
                                DWORD protect_flags,
                                ULONGLONG address, ULONGLONG size)
{
    if (!api_name) return;

    bool is_exec = (protect_flags & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                     PAGE_EXECUTE_READWRITE |
                                     PAGE_EXECUTE_WRITECOPY)) != 0;

    EnterCriticalSection(&s_lock);
    PidEntry* e = find_or_create(pid);
    if (e) {
        // Record the region so PE-Sieve findings at the same address can be
        // deduplicated.  Only the APIs that describe a specific memory region
        // are tracked; CreateRemoteThread has no meaningful base_address.
        bool track =
            address != 0 && size != 0 &&
            (strcmp(api_name, "VirtualAlloc")       == 0 ||
             strcmp(api_name, "VirtualAllocEx")     == 0 ||
             strcmp(api_name, "WriteProcessMemory") == 0 ||
             strcmp(api_name, "VirtualProtect")     == 0);

        if (track && e->region_count < CORRELATOR_MAX_REGIONS) {
            TrackedRegion* r = &e->regions[e->region_count++];
            r->base_address  = address;
            r->size          = size;
            strncpy(r->source_api, api_name, sizeof(r->source_api) - 1);
        }

        /* Build event-specific trigger context for the verdict. */
        if (strcmp(api_name, "VirtualProtect")   == 0 ||
            strcmp(api_name, "VirtualProtectEx") == 0) {
            snprintf(e->last_context, sizeof(e->last_context),
                     "Hook: %s(protect=0x%lx)", api_name,
                     (unsigned long)protect_flags);
        } else {
            snprintf(e->last_context, sizeof(e->last_context),
                     "Hook: %s", api_name);
        }

        /* Capability flag updates. */
        if (strcmp(api_name, "VirtualAllocEx") == 0 ||
            strcmp(api_name, "VirtualAlloc")   == 0) {
            e->has_allocated = true;
            if (is_exec)
                e->has_protected = true; /* RWX allocation: alloc + protect in one shot */
        } else if (strcmp(api_name, "WriteProcessMemory") == 0) {
            if (e->has_allocated) /* write only counts after a tracked allocation */
                e->has_written = true;
        } else if (strcmp(api_name, "VirtualProtect")   == 0 ||
                   strcmp(api_name, "VirtualProtectEx") == 0) {
            if (is_exec)
                e->has_protected = true;
        } else if (strcmp(api_name, "CreateRemoteThread") == 0 ||
                   strcmp(api_name, "CreateThread")       == 0) {
            e->has_remote_thread = true;
        }

        evaluate_state_and_severity(e);
    }
    LeaveCriticalSection(&s_lock);
}

void correlator_feed_yara(DWORD pid, const char* rule_name) {
    EnterCriticalSection(&s_lock);
    PidEntry* e = find_or_create(pid);
    if (e) {
        snprintf(e->last_context, sizeof(e->last_context), "YARA: %s",
                 rule_name && rule_name[0] ? rule_name : "unknown");
        e->has_yara = true;
        evaluate_state_and_severity(e);
    }
    LeaveCriticalSection(&s_lock);
}
