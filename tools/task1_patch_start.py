from pathlib import Path
import sys
p = Path('start.py')
s = p.read_text(encoding='utf-8')
old_marker = 'from aether_dropper import AetherDropper'
if old_marker not in s:
    print('START_PARSER: marker not found, aborting')
    sys.exit(1)
start_idx = s.find(old_marker)
# find beginning of the try block (search backwards for the preceding 'try:')
try_idx = s.rfind('try', 0, start_idx)
if try_idx == -1:
    # fallback to start_idx
    try_idx = s.find('\n', 0, start_idx)
# find the 'return 0' that ends the main
ret_idx = s.find('\n\treturn 0', start_idx)
if ret_idx == -1:
    # try without tab
    ret_idx = s.find('\nreturn 0', start_idx)
if ret_idx == -1:
    print('START_PARSER: end marker not found, aborting')
    sys.exit(1)
end_idx = ret_idx + len('\n\treturn 0')
new_block = '''\n\ttry:\n\t\tfrom modules.runtime_core import init_runtime\n\t\tfrom modules.runtime_loop import run_loop\n\t\truntime = init_runtime()\n\t\tprint("[START] Runtime-Kern initialisiert.")\n\texcept Exception as exc:\n\t\tprint(f"[START] Runtime-Kern konnte nicht geladen werden: {exc}")\n\t\treturn 1\n\n\ttry:\n\t\tfrom modules.unified_cascade import run_full_pipeline\n\t\tprint("[START] Pipeline bereit.")\n\texcept Exception as exc:\n\t\tprint(f"[START] Pipeline konnte nicht geladen werden: {exc}")\n\t\treturn 1\n\n\tprint("[START] Aether laeuft. Druecke Ctrl+C zum Beenden.")\n\ttry:\n\t\timport time\n\t\twhile True:\n\t\t\ttime.sleep(10)\n\texcept KeyboardInterrupt:\n\t\tprint("[START] Aether gestoppt.")\n\treturn 0\n'''
new_s = s[:try_idx] + new_block + s[end_idx:]
backup = p.with_suffix('.py.bak')
backup.write_text(s, encoding='utf-8')
p.write_text(new_s, encoding='utf-8')
print('TASK1_PATCHED', p, 'backup->', backup)
