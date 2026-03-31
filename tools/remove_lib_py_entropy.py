from pathlib import Path
from datetime import datetime
p = Path('src/lib.rs')
if not p.exists():
    print('MISSING_LIB_RS')
else:
    s = p.read_text(encoding='utf-8')
    lines = s.splitlines()
    removed = [ln for ln in lines if ln.strip() == 'pub mod py_entropy;']
    ts = datetime.now().strftime('%Y%m%d%H%M%S')
    bak = p.with_name(p.name + '.bak.' + ts)
    bak.write_text(s, encoding='utf-8')
    if removed:
        new_lines = [ln for ln in lines if ln.strip() != 'pub mod py_entropy;']
        p.write_text('\n'.join(new_lines) + '\n', encoding='utf-8')
        print('REMOVED_LINES:')
        for r in removed:
            print(r)
        print('BACKUP_CREATED->', bak)
    else:
        print('NO_MATCH; BACKUP_CREATED->', bak)
