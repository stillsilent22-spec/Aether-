import sys
fname = sys.argv[1] if len(sys.argv) > 1 else "pytest_out.txt"
try:
    print(open(fname, "r", encoding="utf-16").read())
except Exception:
    print(open(fname, "r", encoding="utf-8").read())
