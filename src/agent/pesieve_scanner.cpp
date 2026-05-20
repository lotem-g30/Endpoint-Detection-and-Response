#include "pesieve_scanner.h"
#include <string.h>
#include <time.h> // Required for generating the ISO-8601 timestamp

#ifdef PESIEVE_AVAILABLE
#include <pe_sieve_api.h> // Corrected header name
#endif

// Helper function to generate the ISO-8601 timestamp required by the guide
void get_current_timestamp(char* buf, size_t max_len) {
    time_t now = time(NULL);
    struct tm t;
    gmtime_s(&t, &now);
    strftime(buf, max_len, "%Y-%m-%dT%H:%M:%SZ", &t);
}

extern "C" int pesieve_scan(DWORD pid,
    const char* process_name,
    const char* session_id,
    const char* scan_id,
    ScanFinding* out_findings,
    size_t* out_count,
    size_t max_findings)
{
#ifndef PESIEVE_AVAILABLE
    // Library not available at build time
    return -1;
#define OUT_NO_DIR 1
#else
    pesieve::t_params params = {};
    params.pid = pid;
    params.out_filter = pesieve::OUT_NO_DIR;
    params.quiet = true;   // Suppress console noise

    // Execute scan using the standard API discovered by Claude
    pesieve::t_report report = PESieve_scan(&params);

    // Check if we have reached the maximum allowed findings
    if (*out_count >= max_findings) return 0;

    // Map aggregate counts to ScanFinding entries if anomalies are detected
    if (report.replaced > 0 || report.implanted_pe > 0 || report.implanted_shc > 0 || report.patched > 0) {
        ScanFinding* f = &out_findings[*out_count];
        memset(f, 0, sizeof(*f));

        // 1. Populate general identifiers and timestamp
        get_current_timestamp(f->ts, sizeof(f->ts));
        strncpy(f->session_id, session_id, ARGUS_MAX_UUID - 1);
        strncpy(f->scan_id, scan_id, ARGUS_MAX_UUID - 1);
        strncpy(f->process_name, process_name, ARGUS_MAX_NAME - 1);
        f->pid = pid;
        f->severity = SEVERITY_HIGH;

        // 2. Populate memory region status
        f->region.state = MEM_COMMIT;

        // 3. Map the specific anomaly type
        if (report.replaced > 0) {
            f->finding_type = FINDING_PE_HOLLOWING;
            strncpy(f->detail.pe_anomaly, "PE hollowing detected", sizeof(f->detail.pe_anomaly) - 1);
        }
        else if (report.implanted_pe > 0 || report.implanted_shc > 0) {
            f->finding_type = FINDING_PE_IMPLANT;
            strncpy(f->detail.pe_anomaly, "PE implant detected", sizeof(f->detail.pe_anomaly) - 1);
        }
        else if (report.patched > 0) {
            f->finding_type = FINDING_CODE_CAVE;
            strncpy(f->detail.pe_anomaly, "Code cave/modification detected", sizeof(f->detail.pe_anomaly) - 1);
        }

        strncpy(f->detail.reason, f->detail.pe_anomaly, sizeof(f->detail.reason) - 1);
        (*out_count)++;
    }

    return 0;
#endif
}