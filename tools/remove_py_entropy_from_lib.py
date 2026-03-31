from pathlib import Path
from datetime import datetime
p = Path('src/lib.rs')
if not p.exists():
    print('MISSING_LIB_RS')
else:
    s = p.read_text(encoding='utf-8')
    lines = s.splitlines()
    removed = [ln for ln in lines if 'py_entropy' in ln]
    ts = datetime.now().strftime('%Y%m%d%H%M%S')
    bak = p.with_name(p.name + '.bak.' + ts)
    bak.write_text(s, encoding='utf-8')
    if removed:
        new_lines = [ln for ln in lines if 'py_entropy' not in ln]
        p.write_text('\n'.join(new_lines) + '\n', encoding='utf-8')
        Path('removed_lines.txt').write_text('\n'.join(removed) + '\n', encoding='utf-8')
        print('REMOVED_LINES_FILE->removed_lines.txt')
    else:
        print('NO_LINES_REMOVED; BACKUP->', bak)
