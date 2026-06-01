"""
tests/e2e_full_system_test.py
ArgusEDR — End-to-End test for the Diamond FSM Correlator.

Orchestrates the full system:
  argus_agent.exe  (IPC server + YARA scanner + Diamond FSM correlator)
  test_target.exe  (victim; performs the Alloc+Write+Protect Trinity)
  injector.exe     (loads argus_hook.dll into test_target via CreateRemoteThread)

Expected FSM escalation path:
  VirtualAllocEx   (PAGE_READWRITE)      → has_allocated               → LOW
  WriteProcessMemory (EICAR payload)     → has_written                 → MEDIUM
  VirtualProtect   (PAGE_EXECUTE_READ)   → has_protected               → HIGH
  YARA: Multi_EICAR_ac8f42d6 fires       → has_yara → is_dead          → CRITICAL

!! AV WARNING !!
The EICAR test string written by test_target.exe will trigger Windows Defender
and most resident AV engines.  Add the project build directory to Defender
exclusions, or disable real-time protection, before running this test.
Failure to do so will cause Defender to kill test_target.exe and the test
will time out waiting for the CRITICAL verdict.

Exit codes:  0 = PASS,  1 = FAIL

Usage:
  python tests/e2e_full_system_test.py [--bin-dir <path>]

  --bin-dir defaults to <project_root>/build/bin/Debug
"""

import argparse
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────

_HERE        = Path(__file__).resolve().parent
PROJECT_ROOT = _HERE.parent


def _resolve_bin_dir(override: str | None) -> Path:
    if override:
        return Path(override).resolve()
    return PROJECT_ROOT / "build" / "bin" / "Debug"


# ── Timeouts (seconds) ────────────────────────────────────────────────────────

T_AGENT_READY   = 15   # wait for IPC + PE-Sieve pipes open, YARA compiled
T_TARGET_PID    =  5   # wait for "[target] PID = …"
T_INJECT        = 15   # injector subprocess total wall-clock budget
T_IPC_CONNECT   =  8   # hook DLL connects to the IPC pipe after injection
T_VERDICT       = 45   # total budget for FSM to reach CRITICAL after Trinity

# ── Regex patterns ────────────────────────────────────────────────────────────

_RE_PID           = re.compile(r"\[target\] PID = (\d+)")
_RE_HIGH          = re.compile(r'"severity"\s*:\s*"HIGH"')
_RE_CRITICAL      = re.compile(r'"severity"\s*:\s*"CRITICAL"')
# Specifically confirm the CRITICAL came from the EICAR YARA rule
_RE_CRITICAL_EICAR = re.compile(
    r'"severity"\s*:\s*"CRITICAL".*YARA.*Multi_EICAR'
)

# ── Thread-safe line accumulator ──────────────────────────────────────────────

class LineCollector:
    """
    Reads UTF-8 lines from a subprocess stream in a daemon thread and
    accumulates them in a list protected by a Condition.  The main thread
    can block-wait for a predicate match, scanning all lines seen so far.

    Every wait_for() call scans from line 0, so it never misses lines that
    arrived before the call was issued.
    """

    def __init__(self, label: str, stream):
        self._label  = label
        self._lines: list[str] = []
        self._cond   = threading.Condition(threading.Lock())
        t = threading.Thread(
            target=self._pump, args=(stream,),
            daemon=True, name=f"reader-{label}",
        )
        t.start()

    def _pump(self, stream):
        try:
            for raw in stream:
                line = raw.rstrip("\r\n")
                print(f"    [{self._label}] {line}", flush=True)
                with self._cond:
                    self._lines.append(line)
                    self._cond.notify_all()
        except Exception:
            pass  # stream closed — exit quietly

    def wait_for(self, predicate, timeout: float) -> str | None:
        """
        Block until predicate(line) returns True for some collected line.
        Returns the first matching line, or None if timeout expires.
        """
        deadline = time.monotonic() + timeout
        checked  = 0
        with self._cond:
            while True:
                new = self._lines[checked:]
                for line in new:
                    if predicate(line):
                        return line
                checked  += len(new)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(timeout=min(0.5, remaining))

    def snapshot(self) -> list[str]:
        with self._cond:
            return list(self._lines)


# ── Predicate factories ───────────────────────────────────────────────────────

def _has(s: str):
    """Match lines that contain substring s."""
    return lambda line: s in line

def _rx(p: re.Pattern):
    """Match lines where compiled pattern p matches."""
    return lambda line: bool(p.search(line))


# ── Process cleanup ───────────────────────────────────────────────────────────

def _kill(proc: subprocess.Popen | None, name: str) -> None:
    if proc is None or proc.poll() is not None:
        return
    print(f"    [CLEANUP] Terminating {name} (PID {proc.pid}) …", flush=True)
    proc.terminate()
    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        print(f"    [CLEANUP] Force-killing {name}", flush=True)
        proc.kill()
        proc.wait()


# ── Preflight ─────────────────────────────────────────────────────────────────

def _check_binaries(bin_dir: Path) -> dict[str, Path]:
    required = {
        "argus_agent": bin_dir / "argus_agent.exe",
        "test_target": bin_dir / "test_target.exe",
        "injector":    bin_dir / "injector.exe",
        "argus_hook":  bin_dir / "argus_hook.dll",
    }
    missing = [str(p) for p in required.values() if not p.exists()]
    if missing:
        print("PREFLIGHT FAIL — missing binaries (rebuild the project first):",
              file=sys.stderr)
        for p in missing:
            print(f"  {p}", file=sys.stderr)
        sys.exit(1)
    return required


# ── Test body ─────────────────────────────────────────────────────────────────

def run_test(bin_dir: Path) -> bool:
    bins   = _check_binaries(bin_dir)
    agent  = None
    target = None
    passed = False

    try:
        # ── Step 1: Launch argus_agent.exe ───────────────────────────────────
        print("\n[TEST] Launching argus_agent.exe …")
        agent = subprocess.Popen(
            [str(bins["argus_agent"])],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(bin_dir),   # agent resolves rules/ relative to its own exe
        )
        agent_out = LineCollector("AGENT", agent.stdout)

        # Both named pipes must be open before injection can proceed
        if not agent_out.wait_for(_has("IPC server listening"), T_AGENT_READY):
            raise RuntimeError(
                f"argus_agent did not open IPC pipe within {T_AGENT_READY}s"
            )
        agent_out.wait_for(_has("PE-Sieve server listening"), T_AGENT_READY)

        # Confirm YARA rules compiled — requires YARA_AVAILABLE build flag
        yara_line = agent_out.wait_for(_has("[YARA]"), timeout=3)
        if yara_line:
            print(f"[TEST] YARA ready — {yara_line.strip()}")
        else:
            print(
                "[TEST] WARNING: [YARA] line not seen.\n"
                "         → Is argus_agent built with YARA_AVAILABLE?\n"
                "         → CRITICAL verdict requires a YARA match.",
                file=sys.stderr,
            )

        print("[TEST] Agent ready.")

        # ── Step 2: Launch test_target.exe ───────────────────────────────────
        print("\n[TEST] Launching test_target.exe …")
        target = subprocess.Popen(
            [str(bins["test_target"])],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(bin_dir),
        )
        target_out = LineCollector("TARGET", target.stdout)

        line = target_out.wait_for(_has("[target] PID ="), T_TARGET_PID)
        if not line:
            raise RuntimeError(
                f"test_target did not print its PID within {T_TARGET_PID}s"
            )
        m = _RE_PID.search(line)
        if not m:
            raise RuntimeError(f"Cannot parse PID from: {line!r}")
        target_pid = int(m.group(1))
        print(f"[TEST] Target PID: {target_pid}")

        # ── Step 3: Inject argus_hook.dll ────────────────────────────────────
        print(f"\n[TEST] Injecting {bins['argus_hook'].name} into PID {target_pid} …")
        try:
            inj = subprocess.run(
                [str(bins["injector"]), str(target_pid), str(bins["argus_hook"])],
                capture_output=True,
                text=True,
                timeout=T_INJECT,
                cwd=str(bin_dir),
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Injector timed out after {T_INJECT}s")

        stdout_clean = inj.stdout.strip()
        print(f"[INJECTOR] rc={inj.returncode}  {stdout_clean}")
        if inj.returncode != 0:
            raise RuntimeError(
                f"Injection failed (rc={inj.returncode}): {inj.stderr.strip()}"
            )
        if "DLL injected successfully" not in stdout_clean:
            raise RuntimeError(
                f"Injector returned 0 but success message missing: {stdout_clean!r}"
            )

        # Hook DLL connects its IPC drain thread to the agent pipe
        print("\n[TEST] Waiting for hook DLL IPC connection …")
        if not agent_out.wait_for(_has("[IPC] client connected"), T_IPC_CONNECT):
            raise RuntimeError(
                f"Hook DLL did not connect to IPC pipe within {T_IPC_CONNECT}s"
            )
        print("[TEST] Hook connected.")

        # ── Step 4: Trigger the Trinity ──────────────────────────────────────
        # VirtualAllocEx → WriteProcessMemory (EICAR) → VirtualProtect (RX)
        print("\n[TEST] Sending ENTER → triggering Alloc + Write(EICAR) + Protect …")
        target.stdin.write("\n")
        target.stdin.flush()

        # ── Step 5: Watch FSM escalate ───────────────────────────────────────
        print(f"\n[TEST] Watching FSM escalation (budget: {T_VERDICT}s) …")
        print("[TEST] Expected path:  LOW → MEDIUM → HIGH → CRITICAL")
        t0 = time.monotonic()
        steps_seen: dict[str, str] = {}  # severity → first matching line

        def _elapsed() -> str:
            return f"{time.monotonic() - t0:.1f}s"

        def _extract_trigger(line: str) -> str:
            m = re.search(r'"trigger"\s*:\s*"([^"]+)"', line)
            return m.group(1) if m else line.strip()

        # Each step has its own 15-second budget; wait_for scans from line 0
        # so already-received lines are found immediately.
        for sev, pred in [
            ("LOW",    _has('"severity":"LOW"')),
            ("MEDIUM", _has('"severity":"MEDIUM"')),
            ("HIGH",   _rx(_RE_HIGH)),
        ]:
            line = agent_out.wait_for(pred, timeout=15)
            if line:
                steps_seen[sev] = line
                print(f"[TEST]   {sev:<8} @ {_elapsed():>5}  trigger: {_extract_trigger(line)}")
            else:
                print(f"[TEST]   {sev:<8} NOT SEEN (15 s budget expired)", file=sys.stderr)
                if target.poll() is not None:
                    print(
                        f"[TEST] WARNING: test_target.exe exited "
                        f"(rc={target.returncode}) — "
                        "Windows Defender may have killed it.\n"
                        "         Add the build directory to AV exclusions and retry.",
                        file=sys.stderr,
                    )

        # CRITICAL: YARA fires on EICAR in executable memory → Multi_EICAR_ac8f42d6
        remaining = T_VERDICT - (time.monotonic() - t0)
        critical_line = agent_out.wait_for(
            _rx(_RE_CRITICAL_EICAR), timeout=max(remaining, 5)
        )

        # Fall back to any CRITICAL in case rule name text differs slightly
        if not critical_line:
            remaining = T_VERDICT - (time.monotonic() - t0)
            critical_line = agent_out.wait_for(
                _rx(_RE_CRITICAL), timeout=max(remaining, 2)
            )
            if critical_line:
                print(
                    "[TEST] WARNING: CRITICAL found but Multi_EICAR rule name absent.\n"
                    "         Verify Multi_EICAR.yar is in rules/ and "
                    "-DYARA_AVAILABLE is set.",
                    file=sys.stderr,
                )

        if critical_line:
            steps_seen["CRITICAL"] = critical_line
            print(f"[TEST]   CRITICAL @ {_elapsed():>5}  trigger: {_extract_trigger(critical_line)}")
        else:
            print("[TEST]   CRITICAL NOT SEEN (YARA timed out)", file=sys.stderr)

        # ── Step 6: Assert ───────────────────────────────────────────────────
        REQUIRED = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        missing  = [s for s in REQUIRED if s not in steps_seen]
        passed   = not missing

        print()
        print("=" * 68)
        if passed:
            print(f"  RESULT  : PASS — all {len(REQUIRED)} severity steps observed "
                  f"({_elapsed()} after Trinity)")
        else:
            print(f"  RESULT  : FAIL — missing severity steps: {', '.join(missing)}")

        print()
        print("  FSM escalation path (hook events + YARA → Diamond FSM):")
        for sev in REQUIRED:
            if sev in steps_seen:
                trigger = _extract_trigger(steps_seen[sev])
                print(f"    {sev:<8}  SEEN    trigger: {trigger}")
            else:
                print(f"    {sev:<8}  MISSING ← REQUIRED")

        if missing:
            print()
            print("  Likely causes:")
            if target.poll() is not None:
                print(f"  • test_target.exe exited early (rc={target.returncode})")
                print("    → Add build directory to Windows Defender exclusions")
            if "CRITICAL" in missing:
                print("  • argus_agent not compiled with -DYARA_AVAILABLE")
                print("  • Multi_EICAR.yar absent from rules/ next to argus_agent.exe")
            if any(s in missing for s in ("LOW", "MEDIUM", "HIGH")):
                print("  • Hook DLL events not reaching the agent (IPC pipe issue)")
                print("  • injector.exe failed or argus_hook.dll path is wrong")
            print()
            print("  Full agent output:")
            for l in agent_out.snapshot():
                print(f"    {l}")
        print("=" * 68)

    finally:
        # ── Step 7: Cleanup ──────────────────────────────────────────────────
        print("\n[TEST] Cleaning up …")
        if target and target.poll() is None:
            try:
                target.stdin.write("\n")   # release second getchar() → clean exit
                target.stdin.flush()
            except Exception:
                pass
            try:
                target.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        _kill(target, "test_target")
        _kill(agent,  "argus_agent")

    return passed


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ArgusEDR E2E test — Diamond FSM Correlator with EICAR YARA match"
    )
    parser.add_argument(
        "--bin-dir",
        metavar="PATH",
        help="Directory containing the built executables (default: build/bin/Debug)",
    )
    args   = parser.parse_args()
    bin_dir = _resolve_bin_dir(args.bin_dir)

    print("=" * 68)
    print("  ArgusEDR E2E Test — Diamond FSM Correlator")
    print(f"  Binaries : {bin_dir}")
    print(f"  YARA rule: Multi_EICAR_ac8f42d6  (Multi_EICAR.yar)")
    print("=" * 68)

    ok = run_test(bin_dir)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
