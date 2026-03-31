from pathlib import Path
p = Path('modules/analysis_capsule.py')
s = p.read_text(encoding='utf-8')
old_block = """try:
    from sce_engine import sce_engine
except Exception:  # pragma: no cover - root-level helper may be unavailable in some tests
    sce_engine = None  # type: ignore[assignment]
"""
if old_block in s:
    new_block = """try:
    from sce_engine import sce_engine
except ImportError:
    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        from sce_engine import sce_engine
    except Exception:
        sce_engine = None
"""
    backup = p.with_suffix('.py.bak')
    backup.write_text(s, encoding='utf-8')
    s = s.replace(old_block, new_block)
    p.write_text(s, encoding='utf-8')
    print('TASK4_PATCHED', p, 'backup->', backup)
else:
    print('TASK4_NO_CHANGE')
