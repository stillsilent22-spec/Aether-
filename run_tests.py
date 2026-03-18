"""Hilfsskript: networkx installieren + alle Tests ausfuehren."""
import subprocess, sys

BASE = r"c:\Users\kalle\Downloads\Aether_master (1) (1)\aether_final"

# 1. networkx installieren
print("=== Installiere networkx ===")
r = subprocess.run([sys.executable, "-m", "pip", "install", "networkx", "-q"],
                   cwd=BASE, capture_output=True, text=True)
if r.returncode == 0:
    print("networkx OK")
else:
    print("pip stderr:", r.stderr[:300])

# 2. Alle Tests
print("\n=== Starte alle Tests ===")
r2 = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/", "--tb=short", "-q"],
    cwd=BASE, capture_output=True, text=True
)
print(r2.stdout)
if r2.stderr:
    print("STDERR:", r2.stderr[:500])
print("Exit-Code:", r2.returncode)
