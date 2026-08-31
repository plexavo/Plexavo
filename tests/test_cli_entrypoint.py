"""Checks that `python -m plexavo` works and is equivalent to the installed
`plexavo` command / `python -m plexavo.cli`.

This is the Windows install path (README Install section): the venv option
runs the tool via `py -m plexavo` instead of the Smart-App-Control-blocked
`plexavo.exe` launcher. If the `plexavo/__main__.py` shim regresses, that
path breaks.

Run: python test_cli_entrypoint.py
"""

import subprocess
import sys

failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


def run(*args):
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
    )


print("=== python -m plexavo --version ===")
mod = run("-m", "plexavo", "--version")
assert_true(mod.returncode == 0, f"exits 0 (got {mod.returncode}, stderr: {mod.stderr!r})")
assert_true("plexavo" in (mod.stdout + mod.stderr).lower(), "prints the version string")

print("\n=== equivalent to python -m plexavo.cli ===")
cli = run("-m", "plexavo.cli", "--version")
assert_true(mod.stdout == cli.stdout, f"same --version output ({mod.stdout!r} vs {cli.stdout!r})")

print("\n=== python -m plexavo --help mentions the scan subcommand ===")
helptext = run("-m", "plexavo", "--help")
assert_true(helptext.returncode == 0, f"--help exits 0 (got {helptext.returncode})")
assert_true("scan" in helptext.stdout, "help lists the scan subcommand")
assert_true("usage: plexavo" in helptext.stdout,
            "usage line shows 'plexavo', not '__main__.py'")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
