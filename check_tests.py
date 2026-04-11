"""Runs pytest and writes summary to check_result.txt."""
import subprocess, sys, pathlib
r = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/", "-x", "--tb=short", "-q"],
    capture_output=True, text=True, cwd=pathlib.Path(__file__).parent
)
out = r.stdout + r.stderr
pathlib.Path("check_result.txt").write_text(out, encoding="utf-8")
# Print only last 30 lines so PSReadLine doesn't overflow
lines = out.splitlines()
print("\n".join(lines[-30:]))
sys.exit(r.returncode)
