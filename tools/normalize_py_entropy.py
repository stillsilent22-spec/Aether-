from pathlib import Path
from datetime import datetime
p = Path('src/py_entropy.rs')
if not p.exists():
    print('MISSING')
else:
    s = p.read_text(encoding='utf-8')
    if '\\n' in s:
        ts = datetime.now().strftime('%Y%m%d%H%M%S')
        bak = p.with_name(p.name + '.bak.' + ts)
        bak.write_text(s, encoding='utf-8')
        s2 = s.replace('\\n', '\n')
        p.write_text(s2, encoding='utf-8')
        print('NORMALIZED ->', bak)
    else:
        print('NO_CHANGE')
