import json, subprocess, time, shutil, sys, os
from pathlib import Path
root = Path.cwd()
node_json_path = root / 'data' / 'swarm' / 'node.json'
out_tools = root / 'tools'
res = {}
if not node_json_path.exists():
    print('NO_NODE_JSON')
    sys.exit(1)
try:
    node_data = json.loads(node_json_path.read_text(encoding='utf-8'))
except Exception as e:
    print('READ_NODE_JSON_ERROR', e)
    sys.exit(1)
current_node_id = str(node_data.get('node_id','')).strip()
res['current_node_id'] = current_node_id
rotmap_path = out_tools / 'rotated_keys_map.json'
if not rotmap_path.exists():
    print('NO_ROT_MAP')
    sys.exit(1)
rotmap = json.loads(rotmap_path.read_text(encoding='utf-8'))
items = rotmap.get('items', [])
mapping = None
for it in items:
    if str(it.get('old_node_id','')) == current_node_id:
        mapping = it
        break
if mapping is None:
    for it in reversed(items):
        orig = str(it.get('original',''))
        if 'generated_keys' in orig or 'generated_keys' in str(it.get('rotated_private','')):
            mapping = it
            break
if mapping is None and items:
    mapping = items[-1]
if mapping is None:
    print('NO_MAPPING_FOUND')
    sys.exit(1)
new_node_id = str(mapping.get('new_node_id','')).strip()
res['new_node_id'] = new_node_id
rotated_public = mapping.get('rotated_public') or mapping.get('rotated_public_key')
if not rotated_public:
    print('NO_ROTATED_PUBLIC_PATH')
    sys.exit(1)
rot_path = Path(rotated_public)
if not rot_path.exists():
    print('ROTATED_PUBLIC_MISSING', str(rot_path))
    sys.exit(1)
rot_pub_pem = rot_path.read_text(encoding='utf-8')
ts = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
backup_root = Path.home() / '.aether_key_backups' / ts / 'apply_rotation'
backup_root.mkdir(parents=True, exist_ok=True)
shutil.copy2(str(node_json_path), str(backup_root / 'node.json.bak'))
node_data['node_id'] = new_node_id
node_data['public_key_pem'] = rot_pub_pem
node_data['registered_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
node_json_path.write_text(json.dumps(node_data, ensure_ascii=False, indent=2), encoding='utf-8')
res['node_json_updated_path'] = str(node_json_path)
try:
    p = subprocess.run(['git','grep','-I','-l', current_node_id], cwd=str(root), capture_output=True, text=True)
    files = [l.strip() for l in p.stdout.splitlines() if l.strip()]
except Exception:
    files = []
res['tracked_files_found'] = files
modified = []
for f in files:
    fp = root / f
    try:
        dest = backup_root / f
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(fp), str(dest))
        txt = fp.read_text(encoding='utf-8', errors='ignore')
        newtxt = txt.replace(current_node_id, new_node_id)
        if newtxt != txt:
            fp.write_text(newtxt, encoding='utf-8')
            modified.append(f)
    except Exception:
        continue
res['modified_count'] = len(modified)
res['modified_files'] = modified
try:
    subprocess.run(['git','ls-files','--error-unmatch','data/swarm/node.json'], cwd=str(root), check=True, capture_output=True)
    node_json_tracked = True
except subprocess.CalledProcessError:
    node_json_tracked = False
res['node_json_tracked'] = node_json_tracked
if modified or node_json_tracked:
    add_list = modified[:]
    if node_json_tracked:
        add_list.append(str(node_json_path))
    if add_list:
        subprocess.run(['git','add'] + add_list, cwd=str(root))
        msg = f'chore(node): rotate genesis node to {new_node_id}'
        res['commit_message'] = msg
        p = subprocess.run(['git','commit','-m', msg], cwd=str(root), capture_output=True, text=True)
        res['commit_stdout'] = p.stdout
        res['commit_stderr'] = p.stderr
        p2 = subprocess.run(['git','push'], cwd=str(root), capture_output=True, text=True)
        res['push_stdout'] = p2.stdout
        res['push_stderr'] = p2.stderr
        res['push_returncode'] = p2.returncode
else:
    res['commit_message'] = None
(out_tools / 'rotation_apply_summary.json').write_text(json.dumps(res, indent=2), encoding='utf-8')
(out_tools / 'rotation_apply_result.txt').write_text(json.dumps(res, indent=2), encoding='utf-8')
print('ROTATION_APPLIED', res.get('new_node_id'))
