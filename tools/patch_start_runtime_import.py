from pathlib import Path
from datetime import datetime
p = Path('start.py')
if not p.exists():
    print('MISSING_START')
else:
    s = p.read_text(encoding='utf-8')
    lines = s.splitlines()
    # find import line
    target = 'from modules.runtime_core import init_runtime'
    pos = None
    for i,l in enumerate(lines):
        if target in l:
            pos = i
            break
    if pos is None:
        print('IMPORT_LINE_NOT_FOUND')
    else:
        # find try block start (nearest 'try:' above)
        try_idx = None
        for j in range(pos, -1, -1):
            if lines[j].strip() == 'try:':
                try_idx = j
                break
        if try_idx is None:
            print('TRY_BLOCK_START_NOT_FOUND')
        else:
            # find next try after pos (to delimit block)
            next_try = None
            for k in range(pos+1, len(lines)):
                if lines[k].strip() == 'try:':
                    next_try = k
                    break
            end_idx = next_try if next_try is not None else len(lines)
            # create backup
            ts = datetime.now().strftime('%Y%m%d%H%M%S')
            bak = p.with_name(p.name + '.bak.' + ts)
            bak.write_text(s, encoding='utf-8')
            # compute indentation for try line
            indent = lines[try_idx][:len(lines[try_idx]) - len(lines[try_idx].lstrip())]
            inner = indent + '\t'
            new_block = [indent + 'try:',
                         inner + 'from modules.runtime_core import init_runtime',
                         indent + "except ModuleNotFoundError:",
                         inner + "import sys as _sys, os as _os",
                         inner + "_sys.path.insert(0, _os.path.dirname(__file__))",
                         inner + "from runtime_core import init_runtime",
            ]
            # replace range
            new_lines = lines[:try_idx] + new_block + lines[end_idx:]
            p.write_text('\n'.join(new_lines) + '\n', encoding='utf-8')
            print('PATCHED_START ->', bak)
