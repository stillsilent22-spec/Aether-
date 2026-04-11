import subprocess, sys
result = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/", "-q", "--tb=short"],
    capture_output=True, text=True, encoding="utf-8", errors="replace"
)
out = result.stdout + result.stderr
with open("test_results.txt", "w", encoding="utf-8") as f:
    f.write(out)
print("DONE. Exit code:", result.returncode)
# Print just the last summary
lines = out.strip().splitlines()
for line in lines[-20:]:
    print(line)
