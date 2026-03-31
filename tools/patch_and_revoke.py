from pathlib import Path
import json,sys,subprocess
root = Path.cwd()
lan = root / 'modules' / 'lan_beacon.py'
if not lan.exists():
    print('NO_LAN_BEACON')
    sys.exit(1)
s = lan.read_text(encoding='utf-8')
if '_is_revoked' in s:
    print('ALREADY_PATCHED')
else:
    insert_point = 'def _apply_interface_binding'
    idx = s.find(insert_point)
    if idx == -1:
        print('INSERT_POINT_NOT_FOUND')
        sys.exit(1)
    before = s[:idx]
    after = s[idx:]
    extra = '''

def _revoked_nodes_path() -> Path:
    return _root_dir() / "config" / "revoked_nodes.json"

def _load_revoked_nodes() -> set:
    p = _revoked_nodes_path()
    try:
        if not p.exists():
            return set()
        data = json.loads(p.read_text(encoding='utf-8'))
        if isinstance(data, dict):
            lst = data.get('revoked', []) or data.get('node_ids', []) or []
            return set(str(x) for x in lst)
        if isinstance(data, list):
            return set(str(x) for x in data)
    except Exception:
        pass
    return set()

def _is_revoked(node_id: str) -> bool:
    try:
        if not node_id:
            return False
        return str(node_id).strip() in _load_revoked_nodes()
    except Exception:
        return False

'''
    new_s = before + extra + after
    # insert revocation check into _receive_once
    old_block = "    if remote_node_id and remote_node_id == local_node_id:\n        return\n"
    if old_block in new_s:
        new_s = new_s.replace(old_block, old_block + "    if _is_revoked(remote_node_id):\n        return\n")
    else:
        print('RECEIVE_ONCE_PATTERN_NOT_FOUND')
        sys.exit(1)
    lan.write_text(new_s, encoding='utf-8')
    print('PATCHED_LAN_BEACON')
# build revoked list
revoked = set()
# add historical compromised id(s)
revoked.add('6c9e2fcad95e2bd0')
rotmap = root / 'tools' / 'rotated_keys_map.json'
if rotmap.exists():
    try:
        d = json.loads(rotmap.read_text(encoding='utf-8'))
        for it in d.get('items', []):
            old = it.get('old_node_id')
            if old:
                revoked.add(old)
    except Exception:
        pass
cfg_dir = root / 'config'
cfg_dir.mkdir(parents=True, exist_ok=True)
cfg = cfg_dir / 'revoked_nodes.json'
cfg.write_text(json.dumps({'revoked': sorted(list(revoked))}, indent=2), encoding='utf-8')
print('WROTE_REVOKE', cfg)
# git add, commit, push
try:
    subprocess.run(['git','add','modules/lan_beacon.py','config/revoked_nodes.json'], check=True)
    msg = 'security: add revocation list and enforce in LAN beacon; revoke compromised genesis node'
    p = subprocess.run(['git','commit','-m', msg], capture_output=True, text=True)
    print('GIT_COMMIT_OUT')
    print(p.stdout)
    print(p.stderr)
    p2 = subprocess.run(['git','push'], capture_output=True, text=True)
    print('GIT_PUSH_OUT')
    print(p2.stdout)
    print(p2.stderr)
except subprocess.CalledProcessError as e:
    print('GIT_CMD_FAILED', e)

