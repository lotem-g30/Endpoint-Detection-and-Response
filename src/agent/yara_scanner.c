#include "yara_scanner.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// Max region size to scan (100 MB)
#define MAX_REGION_SIZE (100 * 1024 * 1024)

static void get_timestamp(char* buf, size_t len) {
    time_t t = time(NULL);
    struct tm tm_info;
    gmtime_s(&tm_info, &t);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm_info);
}

#ifdef YARA_AVAILABLE

static int yara_initialized = 0;

typedef struct {
    DWORD        pid;
    const char* process_name;
    const char* session_id;
    const char* scan_id;
    ScanFinding* out_findings;
    size_t* out_count;
    size_t       max_findings;
    MemoryRegion current_region;
} YaraCallbackCtx;

static int yara_callback(YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
    if (message != CALLBACK_MSG_RULE_MATCHING)
        return CALLBACK_CONTINUE;

    YaraCallbackCtx* ctx = (YaraCallbackCtx*)user_data;
    if (*ctx->out_count >= ctx->max_findings)
        return CALLBACK_ABORT;

    YR_RULE* rule = (YR_RULE*)message_data;
    ScanFinding* f = &ctx->out_findings[*ctx->out_count];
    memset(f, 0, sizeof(*f));

    get_timestamp(f->ts, sizeof(f->ts));
    strncpy(f->session_id, ctx->session_id, ARGUS_MAX_UUID - 1);
    strncpy(f->scan_id, ctx->scan_id, ARGUS_MAX_UUID - 1);
    strncpy(f->process_name, ctx->process_name, ARGUS_MAX_NAME - 1);
    f->pid = ctx->pid;
    f->finding_type = FINDING_YARA_MATCH;
    f->severity = SEVERITY_HIGH;
    f->region = ctx->current_region;

    strncpy(f->detail.yara_rule, rule->identifier, sizeof(f->detail.yara_rule) - 1);
    strncpy(f->detail.reason, "YARA rule matched memory region", sizeof(f->detail.reason) - 1);

    (*ctx->out_count)++;
    return CALLBACK_CONTINUE;
}

int yara_load_rules(const char* path, YR_RULES** rules_out) {
    if (!yara_initialized) {
        yr_initialize();
        yara_initialized = 1;
    }

    YR_COMPILER* compiler = NULL;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
        return -1;

    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        yr_compiler_destroy(compiler);
        return -1;
    }

    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        // load all .yar files in directory
        char pattern[MAX_PATH];
        snprintf(pattern, sizeof(pattern), "%s\\*.yar", path);

        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(pattern, &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            yr_compiler_destroy(compiler);
            return -1;
        }
        do {
            char full_path[MAX_PATH];
            snprintf(full_path, sizeof(full_path), "%s\\%s", path, fd.cFileName);
            FILE* fp = fopen(full_path, "r");
            if (fp) {
                yr_compiler_add_file(compiler, fp, NULL, fd.cFileName);
                fclose(fp);
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    else {
        // single file
        FILE* fp = fopen(path, "r");
        if (!fp) {
            yr_compiler_destroy(compiler);
            return -1;
        }
        yr_compiler_add_file(compiler, fp, NULL, path);
        fclose(fp);
    }

    if (yr_compiler_get_rules(compiler, rules_out) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        return -1;
    }

    yr_compiler_destroy(compiler);
    return 0;
}

int yara_scan_process(HANDLE hProcess,
    DWORD pid,
    const char* process_name,
    const char* session_id,
    const char* scan_id,
    YR_RULES* rules,
    ScanFinding* out_findings,
    size_t* out_count,
    size_t max_findings)
{
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* address = 0;

    YaraCallbackCtx ctx = { 0 };
    ctx.pid = pid;
    ctx.process_name = process_name;
    ctx.session_id = session_id;
    ctx.scan_id = scan_id;
    ctx.out_findings = out_findings;
    ctx.out_count = out_count;
    ctx.max_findings = max_findings;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        address += mbi.RegionSize;

        // skip non-committed and non-readable
        if (mbi.State != MEM_COMMIT)                          continue;
        if (mbi.Protect & PAGE_NOACCESS)                      continue;
        if (mbi.Protect & PAGE_GUARD)                         continue;
        if (mbi.RegionSize > MAX_REGION_SIZE)                 continue;

        // copy region into local buffer
        BYTE* buf = (BYTE*)malloc(mbi.RegionSize);
        if (!buf) continue;

        SIZE_T bytes_read;
        if (!ReadProcessMemory(hProcess, mbi.BaseAddress, buf, mbi.RegionSize, &bytes_read)) {
            free(buf);
            continue;
        }

        // fill current region info for callback
        ctx.current_region.base_address = (uint64_t)(uintptr_t)mbi.BaseAddress;
        ctx.current_region.size = mbi.RegionSize;
        ctx.current_region.protect = mbi.Protect;
        ctx.current_region.type = mbi.Type;
        ctx.current_region.state = mbi.State;

        yr_rules_scan_mem(rules, buf, bytes_read, 0, yara_callback, &ctx, 0);
        free(buf);
    }

    return 0;
}

#endif // YARA_AVAILABLE