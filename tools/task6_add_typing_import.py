from pathlib import Path
from datetime import datetime
p = Path('modules/unified_cascade.py')
if not p.exists():
    print('MISSING')
else:
    s = p.read_text(encoding='utf-8')
    lines = s.splitlines()
    found = None
    for i, line in enumerate(lines[:60]):
        if line.strip().startswith('from typing import'):
            found = (i, line)
            break
    if not found:
        print('NO_TYPING_IMPORT_FOUND')
    else:
        i, line = found
        new_line = line
        added = False
        if 'Optional' not in line:
            new_line = new_line.rstrip() + ', Optional'
            added = True
        if 'List' not in line:
            new_line = new_line.rstrip() + ', List'
            added = True
        if added:
            # backup
            bak = p.with_suffix(p.suffix + '.bak')
            if bak.exists():
                bak = p.with_suffix(p.suffix + '.bak.' + datetime.now().strftime('%Y%m%d%H%M%S'))
            bak.write_text(s, encoding='utf-8')
            lines[i] = new_line
            p.write_text('\n'.join(lines), encoding='utf-8')
            print('UPDATED_TYPING_IMPORT ->', bak)
        else:
            print('ALREADY_OK')
