from pathlib import Path
p=Path('modules/unified_cascade.py')
s=p.read_text(encoding='utf-8')
if 'from typing import Callable' in s and 'Optional' not in s:
    s=s.replace('from typing import Callable','from typing import Callable, Optional, List')
    p.write_text(s,encoding='utf-8')
    print('UPDATED_TYPING_IMPORT')
else:
    print('NO_CHANGE')
