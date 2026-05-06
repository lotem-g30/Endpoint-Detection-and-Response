#include "pesieve_scanner.h"
#include <string.h>

#ifdef PESIEVE_AVAILABLE
#include <peresieve.h>
#endif

extern "C" int pesieve_scan(DWORD pid,
    const char* process_name,
    const char* session_id,
    const char* scan_id,
    ScanFinding* out_findings,
    size_t* out_count,
    size_t max_findings)
{
#ifndef PESIEVE_AVAILABLE
    // library not available at build time
    return -1;
#else
    pesieve::t_params params = {};
    params.pid = pid;
    params.no_dump = true;

    pesieve::t_report_ex report = {};
    PESieve_scan_ex(params, PE_IMSC_MODULES, &report);

    for (size_t i = 0; i < report.moduleReports.size(); i++) {
        if (*out_count >= max_findings) break;

        auto& mod = report.moduleReports[i];
        if (mod.status == 0) continue; // no anomaly

        ScanFinding* f = &out_findings[*out_count];
        memset(f, 0, sizeof(*f));

        strncpy(f->session_id, session_id, ARGUS_MAX_UUID - 1);
        strncpy(f->scan_id, scan_id, ARGUS_MAX_UUID - 1);
        strncpy(f->process_name, process_name, ARGUS_MAX_NAME - 1);
        f->pid = pid;
        f->severity = SEVERITY_HIGH;

        if (mod.status == SHOW_REPLACED) {
            f->finding_type = FINDING_PE_HOLLOWING;
            strncpy(f->detail.pe_anomaly, "PE hollowing detected", sizeof(f->detail.pe_anomaly) - 1);
        }
        else if (mod.status == SHOW_IMPLANTED) {
            f->finding_type = FINDING_PE_IMPLANT;
            strncpy(f->detail.pe_anomaly, "PE implant detected", sizeof(f->detail.pe_anomaly) - 1);
        }
        else if (mod.status == SHOW_REFLECTIVE) {
            f->finding_type = FINDING_REFLECTIVE_LOAD;
            strncpy(f->detail.pe_anomaly, "Reflective load detected", sizeof(f->detail.pe_anomaly) - 1);
        }
        else {
            continue;
        }

        strncpy(f->detail.reason, f->detail.pe_anomaly, sizeof(f->detail.reason) - 1);
        (*out_count)++;
    }

    return 0;
#endif
}