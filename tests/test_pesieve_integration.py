#!/usr/bin/env python3
"""
tests/test_pesieve_integration.py
----------------------------------
End-to-end integration test for the injected PE-Sieve architecture.

Flow
----
  1. Start argus_agent.exe; stream its stdout to the console and to an
     in-memory line buffer.
  2. Launch notepad.exe as the target (benign) process.
  3. Inject argus_hook.dll  -> hook DLL connects to \\.\pipe\argus-events.
  4. Inject argus_pesieve.dll -> scan thread runs PESieve_scan_ex inside
     notepad, connects to \\.\pipe\argus-pesieve, writes NDJSON findings.
  5. Verify the agent printed a [PESIEVE] line containing EXPECTED_FINDING_TYPE.
  6. Tear down both processes (always, even on failure).

Run as Administrator
  The injector calls OpenProcess(PROCESS_ALL_ACCESS) on notepad.exe.
  Without elevation the injection will silently fail.

Expected finding type — LoadLibraryA vs manual-mapping
  This injector uses CreateRemoteThread + LoadLibraryA.  Because LoadLibraryA
  goes through the standard Windows loader, argus_hook.dll appears in the PEB
  module list and PE-Sieve does NOT classify it as FINDING_PE_IMPLANT.

  What PE-Sieve actually sees:
    - Detours patches the first bytes of VirtualAllocEx / WriteProcessMemory /
      CreateRemoteThread in kernel32.dll  ->  report.patched > 0
    - dllmain.cpp maps patched > 0  ->  FINDING_CODE_CAVE

  EXPECTED_FINDING_TYPE below defaults to "FINDING_PE_IMPLANT" per the spec.
  Change it to "FINDING_CODE_CAVE" when testing with a LoadLibraryA/Detours
  scenario, or upgrade the injector to a manual-mapping technique to make
  FINDING_PE_IMPLANT trigger.
"""

import pathlib
import subprocess
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Configuration — adjust these for your environment
# ---------------------------------------------------------------------------

SCRIPT_DIR  = pathlib.Path(__file__).parent.resolve()
PROJECT_DIR = SCRIPT_DIR.parent

# Prefer Debug build; fall back to Release.
def _locate_bin_dir():
    for config in ("Debug", "Release"):
        candidate = PROJECT_DIR / "build" / "bin" / config
        if candidate.is_dir():
            return candidate
    return PROJECT_DIR / "build" / "bin" / "Debug"   # will fail gracefully below

BIN_DIR = _locate_bin_dir()

AGENT_EXE    = BIN_DIR / "argus_agent.exe"
INJECTOR_EXE = BIN_DIR / "injector.exe"
HOOK_DLL     = BIN_DIR / "argus_hook.dll"
PESIEVE_DLL  = BIN_DIR / "argus_pesieve.dll"

# Maximum seconds to wait for the PE-Sieve finding to appear.
MONITOR_SECONDS = 10

# ---------------------------------------------------------------------------
# Primary assertion.  See the module docstring for why FINDING_CODE_CAVE is
# the realistic outcome with a LoadLibraryA injector.  Changing this constant
# is the only edit needed to align the test with the actual injector technique.
# ---------------------------------------------------------------------------
EXPECTED_FINDING_TYPE = "FINDING_PE_IMPLANT"


# ---------------------------------------------------------------------------
# Line collector — thread-safe rolling buffer of agent stdout lines
# ---------------------------------------------------------------------------

class LineCollector:
    """Read lines from a subprocess pipe in a background thread."""

    def __init__(self, label):
        self._label  = label
        self._lines  = []
        self._lock   = threading.Lock()

    def reader_thread(self, pipe):
        """Target for threading.Thread(daemon=True)."""
        for raw in iter(pipe.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip()
            with self._lock:
                self._lines.append(line)
            print(f"[{self._label}] {line}", flush=True)
        # pipe closed — process exited or teardown happened
        pipe.close()

    def wait_for(self, *substrings, timeout):
        """
        Block until a collected line contains ALL substrings, then return it.
        Returns None on timeout.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                for line in self._lines:
                    if all(s in line for s in substrings):
                        return line
            time.sleep(0.1)
        return None

    def matching(self, *substrings):
        """Return all collected lines that contain every substring."""
        with self._lock:
            return [l for l in self._lines
                    if all(s in l for s in substrings)]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_binaries():
    """Abort early with a clear message if any required file is missing."""
    missing = [str(p) for p in [AGENT_EXE, INJECTOR_EXE, HOOK_DLL, PESIEVE_DLL]
               if not p.exists()]
    if not missing:
        return
    print("FAIL — required binaries not found:")
    for path in missing:
        print(f"  {path}")
    print()
    print("  Build the project first:")
    print("    cd build")
    print("    cmake --build . --config Debug")
    sys.exit(1)


def _inject(pid, dll_path, label):
    """
    Run injector.exe <pid> <dll_path>.
    Returns True on success, False on any error.
    """
    print(f"[INJECT] {label} → PID {pid} ...", flush=True)
    try:
        result = subprocess.run(
            [str(INJECTOR_EXE), str(pid), str(dll_path)],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        print(f"[INJECT] TIMEOUT waiting for {label} injection")
        return False
    except FileNotFoundError:
        print(f"[INJECT] injector.exe not found: {INJECTOR_EXE}")
        return False

    stdout = result.stdout.strip()
    if stdout:
        print(stdout)
    if result.returncode != 0:
        print(f"[INJECT] FAILED (rc={result.returncode}): {result.stderr.strip()}")
        return False
    return True


def _kill(proc, label, timeout=3.0):
    """Terminate a Popen object, escalating to kill on timeout."""
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    print(f"[TEARDOWN] {label} terminated", flush=True)


def _print_diagnostic(received_lines):
    """Explain the LoadLibraryA / FINDING_CODE_CAVE mismatch."""
    print()
    print("  ── Diagnostic ──────────────────────────────────────────────────")
    print(f"  Received {len(received_lines)} [PESIEVE] line(s) but none contained")
    print(f"  '{EXPECTED_FINDING_TYPE}'.")
    print()
    if received_lines:
        print("  Lines received from PE-Sieve server:")
        for line in received_lines:
            print(f"    {line}")
        print()
    print("  Root cause (LoadLibraryA injector vs manual mapping):")
    print("    The injector uses CreateRemoteThread + LoadLibraryA.  The hook DLL")
    print("    is loaded via the standard Windows loader and therefore appears in")
    print("    the PEB LDR module list.  PE-Sieve does not classify a properly-")
    print("    listed module as 'implanted', so report.implanted_pe stays 0.")
    print()
    print("    What PE-Sieve DOES detect:")
    print("      Detours patches the first bytes of VirtualAllocEx, WriteProcess-")
    print("      Memory, and CreateRemoteThread in kernel32.dll (inline trampolines).")
    print("      PE-Sieve sees this as report.patched > 0, which dllmain.cpp maps")
    print("      to FINDING_CODE_CAVE.")
    print()
    print("  Fix options:")
    print("    A) To pass this test as-is:")
    print("         Set EXPECTED_FINDING_TYPE = 'FINDING_CODE_CAVE' in this script.")
    print()
    print("    B) To make FINDING_PE_IMPLANT trigger:")
    print("         Rewrite the injector to use manual mapping (VirtualAllocEx +")
    print("         WriteProcessMemory + custom PE loader) instead of LoadLibraryA.")
    print("         A manually-mapped DLL does NOT appear in the PEB module list,")
    print("         so PE-Sieve flags it as implanted_pe > 0.")
    print("  ────────────────────────────────────────────────────────────────")
    print()


# ---------------------------------------------------------------------------
# Test body
# ---------------------------------------------------------------------------

def run_test():
    _check_binaries()

    agent_proc   = None
    notepad_proc = None

    try:
        # ── Step 1: Start argus_agent ─────────────────────────────────────────
        print("=" * 60)
        print("[SETUP] Starting argus_agent.exe ...")
        try:
            agent_proc = subprocess.Popen(
                [str(AGENT_EXE)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=str(BIN_DIR),
            )
        except FileNotFoundError:
            print(f"FAIL — cannot launch agent: {AGENT_EXE}")
            return False

        collector = LineCollector("AGENT")
        reader = threading.Thread(
            target=collector.reader_thread,
            args=(agent_proc.stdout,),
            daemon=True,
        )
        reader.start()

        # Wait for the agent to announce both pipe servers.
        if not collector.wait_for("argus-events", timeout=8):
            print("FAIL — argus_agent did not start within 8 s "
                  "(pipe server announcement missing)")
            return False

        if not collector.wait_for("argus-pesieve", timeout=4):
            print("FAIL — PE-Sieve server did not start on "
                  "\\\\.\\pipe\\argus-pesieve")
            return False

        # Verify YARA rules compiled successfully.
        yara_ok = collector.wait_for("[YARA] Compiled", timeout=4)
        if not yara_ok:
            # Non-fatal: agent runs without YARA if rules are missing or YARA is
            # not compiled in.  Print a warning so CI logs surface the issue.
            yara_warn = collector.matching("Warning: no YARA rules loaded")
            if yara_warn:
                print("[WARN] YARA rules failed to load — check rules/ directory "
                      "and the build output for compiler errors.")
            else:
                print("[INFO] YARA not compiled into this build (YARA_AVAILABLE not set).")
        else:
            print(f"[SETUP] YARA rules loaded: {yara_ok}")

        print("[SETUP] Agent ready — both pipe servers are listening.")

        # ── Step 2: Launch notepad.exe ────────────────────────────────────────
        print("\n[SETUP] Launching notepad.exe (target process) ...")
        try:
            notepad_proc = subprocess.Popen(["notepad.exe"])
        except FileNotFoundError:
            print("FAIL — notepad.exe not found on PATH")
            return False

        target_pid = notepad_proc.pid
        print(f"[SETUP] Target PID = {target_pid}")
        time.sleep(0.5)   # let notepad complete its startup

        # ── Step 3: Inject argus_hook.dll ─────────────────────────────────────
        print("\n[STEP 3] Injecting argus_hook.dll ...")
        if not _inject(target_pid, HOOK_DLL, "argus_hook.dll"):
            print("FAIL — hook DLL injection failed")
            return False

        # Allow the hook to connect to \\.\pipe\argus-events before we scan.
        time.sleep(1.0)

        # ── Step 4: Inject argus_pesieve.dll ──────────────────────────────────
        print("\n[STEP 4] Injecting argus_pesieve.dll ...")
        if not _inject(target_pid, PESIEVE_DLL, "argus_pesieve.dll"):
            print("FAIL — PE-Sieve DLL injection failed")
            return False

        # ── Step 5: Monitor ───────────────────────────────────────────────────
        print(f"\n[TEST] Monitoring agent output for up to {MONITOR_SECONDS} s ...")

        # Smoke check: did anything come back from the PE-Sieve pipeline at all?
        any_pesieve_line = collector.wait_for(
            "[PESIEVE]", timeout=MONITOR_SECONDS
        )
        if not any_pesieve_line:
            print(
                f"FAIL — no [PESIEVE] output received within {MONITOR_SECONDS} s.\n"
                "       The IPC pipeline (argus_pesieve.dll → "
                "\\\\.\\pipe\\argus-pesieve → agent) produced no output.\n"
                "       Possible causes:\n"
                "         • Injection of argus_pesieve.dll failed silently\n"
                "         • PE-Sieve scan found nothing (unlikely for a Detours "
                "          process)\n"
                "         • The DLL could not connect to the pipe within 3 s"
            )
            return False

        print(f"[TEST] PE-Sieve IPC pipeline alive. First line: {any_pesieve_line}")

        # Primary assertion: the specified finding type must be present.
        matched = collector.matching("[PESIEVE]", EXPECTED_FINDING_TYPE)
        if not matched:
            _print_diagnostic(collector.matching("[PESIEVE]"))
            print(f"FAIL — '{EXPECTED_FINDING_TYPE}' was not found in any "
                  "[PESIEVE] log line.")
            return False

        print(f"\n[TEST] '{EXPECTED_FINDING_TYPE}' confirmed in PE-Sieve output:")
        for line in matched:
            print(f"  {line}")
        return True

    finally:
        # ── Step 6: Teardown (always runs) ────────────────────────────────────
        print("\n[TEARDOWN] Cleaning up ...")
        _kill(notepad_proc, "notepad.exe")
        _kill(agent_proc,   "argus_agent.exe")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    passed = run_test()
    print()
    print("=" * 60)
    print(f"  Result: {'PASS' if passed else 'FAIL'}")
    print("=" * 60)
    sys.exit(0 if passed else 1)
