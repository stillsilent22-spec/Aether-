from pathlib import Path
from datetime import datetime
p = Path('modules/unified_cascade.py')
if not p.exists():
    print('MISSING')
else:
    s = p.read_text(encoding='utf-8')
    lines = s.splitlines()
    # Find first typing import line within first 80 lines
    idx = None
    for i, line in enumerate(lines[:80]):
        if line.strip().startswith('from typing import'):
            idx = i
            break
    if idx is None:
        # fallback: insert after pathlib import
        insert_at = None
        for i, line in enumerate(lines[:80]):
            if line.startswith('from pathlib') or line.startswith('import json'):
                insert_at = i+1
        if insert_at is None:
            insert_at = 0
        new_import = 'from typing import Callable, Optional, List, Dict, Any, Tuple, Set'
        lines.insert(insert_at, new_import)
        bak = p.with_suffix(p.suffix + '.bak.' + datetime.now().strftime('%Y%m%d%H%M%S'))
        bak.write_text(s, encoding='utf-8')
        p.write_text('\n'.join(lines), encoding='utf-8')
        print('INSERTED_IMPORT ->', bak)
    else:
        line = lines[idx]
        # ensure required names are present
        names = ['Callable','Optional','List','Dict','Any','Tuple','Set']
        for n in names:
            if n not in line:
                line = line.rstrip().rstrip(',') + ', ' + n
        lines[idx] = line
        new_s = '\n'.join(lines)
        # replace PEP-585 generics used in annotations
        new_s = new_s.replace('list[', 'List[').replace('dict[', 'Dict[').replace('tuple[', 'Tuple[').replace('set[', 'Set[')
        bak = p.with_suffix(p.suffix + '.bak.' + datetime.now().strftime('%Y%m%d%H%M%S'))
        bak.write_text(s, encoding='utf-8')
        p.write_text(new_s, encoding='utf-8')
        print('PATCHED generics ->', bak)
