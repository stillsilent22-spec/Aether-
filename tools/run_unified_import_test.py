import sys, traceback, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))
try:
    import modules.unified_cascade as uc
    print('OK')
except Exception:
    traceback.print_exc()
    print('IMPORT_FAIL')
