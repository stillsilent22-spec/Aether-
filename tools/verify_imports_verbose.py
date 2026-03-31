print('PY_START')
try:
    import sys
    print('sys ok')
    import modules.lan_beacon as lb; print('lan_beacon ok')
    import modules.capability_score as cs; print('capability ok')
    import modules.unified_cascade as uc; print('unified ok')
    from aether_dropper import _detect_anchor, _safe_child_path, AetherDropper; print('dropper ok')
    print('ALLE_OK')
except Exception:
    import traceback, sys
    print('IMPORT_ERR')
    traceback.print_exc()
    sys.exit(1)
