from pathlib import Path
import re
paths = [
    'src/lib.rs',
    'tools/full_read/src/lib.rs',
]
for p in paths:
    fp = Path(p)
    if not fp.exists():
        print('MISSING', p)
        continue
    s = fp.read_text(encoding='utf-8')
    new_s = re.sub(r'(?m)^\s*pub\s+mod\s+py_entropy\s*;\s*$', '#[cfg(feature = "python")]\npub mod py_entropy;', s)
    if s == new_s:
        print('UNCHANGED', p)
    else:
        backup = fp.with_suffix(fp.suffix + '.bak')
        backup.write_text(s, encoding='utf-8')
        fp.write_text(new_s, encoding='utf-8')
        print('PATCHED', p, '-> backup at', backup)
