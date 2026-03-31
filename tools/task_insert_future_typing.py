from pathlib import Path
from datetime import datetime
p = Path('modules/unified_cascade.py')
if not p.exists():
    print('MISSING')
else:
    s = p.read_text(encoding='utf-8')
    lines = s.splitlines()
    top4 = "\n".join(lines[:4])
    if 'from __future__ import annotations' in top4:
        print('ALREADY_HAS_FUTURE')
    else:
        bak = p.with_suffix(p.suffix + '.bak.' + datetime.now().strftime('%Y%m%d%H%M%S'))
        bak.write_text(s, encoding='utf-8')
        new = 'from __future__ import annotations\nfrom typing import Any, Callable, Dict, List, Optional\n\n' + s
        p.write_text(new, encoding='utf-8')
        print('INSERTED ->', bak)
