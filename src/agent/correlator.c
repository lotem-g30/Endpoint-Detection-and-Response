#include "correlator.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define MAX_TRACKED_PIDS 512

static const char* s_sev[] = { "LOW", "MEDIUM", "HIGH", "CRITICAL" };

typedef struct {
    DWORD    pid;
    Severity severity;
    bool     active;
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

void correlator_feed_pesieve(DWORD pid, const char* finding_type_str) {
    char trigger[256];
    snprintf(trigger, sizeof(trigger), "PE-Sieve: %s",
             finding_type_str ? finding_type_str : "unknown");

    bool     escalated = false;
    Severity new_sev   = SEVERITY_MEDIUM;

    EnterCriticalSection(&s_lock);
    PidEntry* e = find_or_create(pid);
    if (e) {
        escalated = set_at_least(e, SEVERITY_MEDIUM);
        new_sev   = e->severity;
    }
    LeaveCriticalSection(&s_lock);

    if (escalated)
        emit_verdict(pid, new_sev, trigger);
}

void correlator_feed_hook_event(DWORD pid, const char* api_name, DWORD protect_flags) {
    if (!api_name) return;

    bool     escalated = false;
    Severity new_sev   = SEVERITY_LOW;
    char     trigger[256];

    EnterCriticalSection(&s_lock);
    PidEntry* e = find_or_create(pid);
    if (e) {
        if (strcmp(api_name, "CreateRemoteThread") == 0) {
            snprintf(trigger, sizeof(trigger), "Hook: CreateRemoteThread");
            escalated = set_at_least(e, SEVERITY_CRITICAL);
        } else if (strcmp(api_name, "VirtualProtect") == 0) {
            snprintf(trigger, sizeof(trigger),
                     "Hook: VirtualProtect(protect=0x%lx)",
                     (unsigned long)protect_flags);
            // Only escalate if the new protection includes an execute bit.
            bool is_exec = (protect_flags & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                             PAGE_EXECUTE_READWRITE |
                                             PAGE_EXECUTE_WRITECOPY)) != 0;
            if (is_exec)
                escalated = raise_by_one(e);
        } else {
            // VirtualAllocEx, WriteProcessMemory, and any other hooked API.
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
