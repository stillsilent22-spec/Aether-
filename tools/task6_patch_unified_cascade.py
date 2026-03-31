from pathlib import Path
p = Path('modules/unified_cascade.py')
s = p.read_text(encoding='utf-8')
orig = s
changed = False
# Replace typing import
if 'from typing import Callable' in s and 'Optional' not in s:
    s = s.replace('from typing import Callable', 'from typing import Callable, Optional, List')
    changed = True
# Replace union | None with Optional[]
s = s.replace('Callable[[str], None] | None', 'Optional[Callable[[str], None]]')
if s != orig:
    changed = True
# Replace return annotation list[str] to List[str]
s = s.replace('-> list[str]', '-> List[str]')
# Replace any other occurrences of ' | None' that are in annotations (quick heuristic)
s = s.replace(' | None', 'Optional')
# Write back if changed
if changed:
    backup = p.with_suffix('.py.bak')
    backup.write_text(orig, encoding='utf-8')
    p.write_text(s, encoding='utf-8')
    print('TASK6_PATCHED_unified_cascade', p, 'backup->', backup)
else:
    print('TASK6_NO_CHANGES_needed')
