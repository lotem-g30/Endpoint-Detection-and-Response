#include "pesieve_scanner.h"
#include <string.h>
#include <time.h>

#ifdef PESIEVE_AVAILABLE
#include <pe_sieve_api.h>
#include <vector>
#endif

static void get_current_timestamp(char* buf, size_t max_len) {
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
    return -1;
#else
    pesieve::t_params params = {};
    params.pid            = pid;
    params.out_filter     = pesieve::OUT_NO_DIR;
    params.quiet          = true;
    // SHELLC_PATTERNS_OR_STATS enables the working-set walker so PE-Sieve
    // visits private executable regions and can detect shellcode patterns /
    // high-entropy payloads beyond what the PEB module scan covers.
    params.shellcode      = pesieve::SHELLC_PATTERNS_OR_STATS;
    params.json_lvl       = pesieve::JSON_DETAILS;
    params.results_filter = pesieve::SHOW_SUSPICIOUS;

    // Two-pass scan: allocate 64 KB initially, resize if PE-Sieve signals
    // truncation via the needed_size output parameter.
    std::vector<char> json_buf(65536, '\0');
    size_t needed = 0;

    pesieve::t_report report = PESieve_scan_ex(
        &params, pesieve::REPORT_SCANNED,
        json_buf.data(), json_buf.size(), &needed);

    if (needed > json_buf.size()) {
        json_buf.assign(needed + 1, '\0');
        report = PESieve_scan_ex(
            &params, pesieve::REPORT_SCANNED,
            json_buf.data(), json_buf.size(), &needed);
    }

    // Helper lambda: append one ScanFinding to the output array.
    auto add_finding = [&](FindingType ft, const char* anomaly) -> bool {
        if (*out_count >= max_findings) return false;
        ScanFinding* f = &out_findings[*out_count];
        memset(f, 0, sizeof(*f));
        get_current_timestamp(f->ts, sizeof(f->ts));
        strncpy(f->session_id,    session_id,    ARGUS_MAX_UUID - 1);
        strncpy(f->scan_id,       scan_id,       ARGUS_MAX_UUID - 1);
        strncpy(f->process_name,  process_name,  ARGUS_MAX_NAME - 1);
        f->pid          = pid;
        f->finding_type = ft;
        f->severity     = SEVERITY_HIGH;
        f->region.state = MEM_COMMIT;
        strncpy(f->detail.pe_anomaly, anomaly, sizeof(f->detail.pe_anomaly) - 1);
        strncpy(f->detail.reason,     anomaly, sizeof(f->detail.reason)     - 1);
        (*out_count)++;
        return true;
    };

    if (report.replaced > 0)
        add_finding(FINDING_PE_HOLLOWING, "PE hollowing detected");

    if (report.implanted_pe > 0 || report.implanted_shc > 0)
        add_finding(FINDING_PE_IMPLANT, "PE implant detected");

    if (report.patched > 0)
        add_finding(FINDING_CODE_CAVE, "Code cave/modification detected");

    if (report.iat_hooked > 0)
        add_finding(FINDING_MODULE_STOMP, "IAT hook detected");

    return 0;
#endif
}
