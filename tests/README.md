# Argus Test Suite

## test_pesieve_integration.py

End-to-end integration test that verifies the injected PE-Sieve architecture
works from DLL injection all the way to a `[PESIEVE]` NDJSON line on the
agent's stdout.

### What it tests

```
injector.exe ──► notepad.exe
                    │
                    ├─ argus_hook.dll (Detours hooks installed)
                    │       │
                    │       └──► \\.\pipe\argus-events ──► argus_agent.exe
                    │                                            │ trigger
                    │                                            ▼
                    │                                       scanner_run_pid
                    │
                    └─ argus_pesieve.dll (PE-Sieve scan in-process)
                            │
                            └──► \\.\pipe\argus-pesieve ──► argus_agent.exe
                                                               │
                                                               └──► [PESIEVE] {...}
```

The test PASSES only when the agent prints a `[PESIEVE]` line containing the
configured `EXPECTED_FINDING_TYPE`.

---

### Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10/11 | Test uses Windows-only APIs |
| Python 3.9+ | No third-party packages needed |
| **Run as Administrator** | The injector needs `PROCESS_ALL_ACCESS` on notepad |
| Project built in Debug mode | Binaries expected in `build/bin/Debug/` |

Build the project before running:

```powershell
cd build
cmake --build . --config Debug
```

---

### Running the test

From the project root, in an **elevated** PowerShell prompt:

```powershell
python tests\test_pesieve_integration.py
```

Example of a passing run:

```
============================================================
[SETUP] Starting argus_agent.exe ...
[AGENT] === ArgusAgent starting ===
[AGENT] [MAIN] IPC server listening on \\.\pipe\argus-events
[AGENT] [MAIN] PE-Sieve server listening on \\.\pipe\argus-pesieve
[SETUP] Agent ready — both pipe servers are listening.

[SETUP] Launching notepad.exe (target process) ...
[SETUP] Target PID = 9876

[STEP 3] Injecting argus_hook.dll ...
[*] Injecting '...\argus_hook.dll' into PID 9876
[+] DLL injected successfully (module base = 0x...)

[STEP 4] Injecting argus_pesieve.dll ...
[*] Injecting '...\argus_pesieve.dll' into PID 9876
[+] DLL injected successfully (module base = 0x...)

[TEST] Monitoring agent output for up to 10 s ...
[AGENT] [PESIEVE-SERVER] DLL connected — reading findings
[AGENT] [PESIEVE] {"ts":"...","finding_type":"FINDING_CODE_CAVE",...}
[TEST] PE-Sieve IPC pipeline alive.

[TEARDOWN] Cleaning up ...
[TEARDOWN] notepad.exe terminated
[TEARDOWN] argus_agent.exe terminated

============================================================
  Result: PASS
============================================================
```

---

### Expected finding type and the LoadLibraryA caveat

The `EXPECTED_FINDING_TYPE` constant at the top of the script controls which
finding must appear. It defaults to `"FINDING_PE_IMPLANT"`.

**Why the default may produce a `FAIL`**

The injector (`src/injector/main.c`) uses
`CreateRemoteThread + LoadLibraryA`. Because `LoadLibraryA` goes through the
standard Windows loader, the injected DLL is registered in the PEB LDR module
list. PE-Sieve only flags a PE as *implanted* when it is mapped into memory
**without** appearing in the module list (manual-mapping technique).

What PE-Sieve actually detects with this injector:

| PE-Sieve counter | Source | Mapped to |
|---|---|---|
| `report.replaced` | PE headers swapped | `FINDING_PE_HOLLOWING` |
| `report.implanted_pe/shc` | Module not in PEB list | `FINDING_PE_IMPLANT` |
| **`report.patched`** | **Detours inline hooks on kernel32** | **`FINDING_CODE_CAVE`** |
| `report.iat_hooked` | IAT hook (Detours does NOT use IAT) | `FINDING_MODULE_STOMP` |

Detours patches the first bytes of `VirtualAllocEx`, `WriteProcessMemory`, and
`CreateRemoteThread` in `kernel32.dll` with a JMP trampoline. PE-Sieve detects
these as code modifications → `report.patched > 0` → `FINDING_CODE_CAVE`.

**To make the test pass with the current injector, change the constant:**

```python
# tests/test_pesieve_integration.py, line ~48
EXPECTED_FINDING_TYPE = "FINDING_CODE_CAVE"
```

**To make `FINDING_PE_IMPLANT` trigger**, rewrite the injector to use manual
PE mapping (no `LoadLibraryA`) so the DLL never enters the PEB module list.

---

### Troubleshooting

| Symptom | Likely cause |
|---|---|
| `FAIL — argus_agent did not start` | Binary not built; missing `pe-sieve.dll` next to the exe |
| `FAIL — hook DLL injection failed` | Not running as Administrator |
| `FAIL — no [PESIEVE] output` | `argus_pesieve.dll` couldn't connect to the pipe within 3 s; check the agent is still running |
| Agent output shows `[!] LoadLibraryA in target returned NULL` | DLL depends on a missing `.dll` (e.g., `pe-sieve.dll`); verify all DLLs are in `build/bin/Debug/` |
| Test hangs at `[STEP 4]` | The injector's `WaitForSingleObject` is waiting for the remote thread; PE-Sieve scan on a large process can take several seconds — this is expected |
