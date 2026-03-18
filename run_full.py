"""
run_full.py — Einzel-Script fuer:
  1. networkx + weiteres installieren
  2. Alle Tests laufen lassen
  3. Ergebnisse in test_results.txt schreiben

Aufruf:  python run_full.py
"""
import subprocess, sys, os

BASE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(BASE, "test_results.txt")

def run(args, **kw):
    r = subprocess.run(args, capture_output=True, text=True, cwd=BASE, **kw)
    return r.stdout + r.stderr

# 1. Abhaengigkeiten
print("[1/2] Installiere Abhaengigkeiten...")
for pkg in ["networkx", "numpy", "cryptography"]:
    out = run([sys.executable, "-m", "pip", "install", pkg, "-q"])
    try:
        __import__(pkg.split("[")[0])
        print(f"      {pkg} OK")
    except ImportError:
        print(f"      {pkg} FEHLER: {out[:100]}")

# 2. Tests
print("[2/2] Starte alle Tests...")
out2 = run([sys.executable, "-m", "pytest", "tests/", "--tb=short", "-q"])
print(out2)

with open(OUT, "w", encoding="utf-8") as f:
    f.write(out2)

print(f"\nErgebnis gespeichert: {OUT}")
