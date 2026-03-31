import sys, traceback, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))
try:
    import modules.unified_cascade
    print('UNIFIED_IMPORT_OK')
except Exception:
    traceback.print_exc()
    print('UNIFIED_IMPORT_FAIL')
