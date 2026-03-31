from pathlib import Path
import os,sys,json,time,hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

home = Path.home()
backups_root = home / '.aether_key_backups'
if not backups_root.exists():
    print('NO_BACKUPS')
    sys.exit(0)
# gather candidate key files
key_files = []
for p in backups_root.rglob('*'):
    try:
        if not p.is_file():
            continue
        name = p.name.lower()
        if p.suffix.lower() in ('.key', '.pem') or 'private' in name:
            try:
                txt = p.read_text(encoding='utf-8',errors='ignore')
            except Exception:
                txt = ''
            if 'BEGIN PRIVATE KEY' in txt or 'OPENSSH PRIVATE' in txt or p.suffix.lower() in ('.key',):
                key_files.append(str(p))
        else:
            try:
                txt = p.read_text(encoding='utf-8',errors='ignore')
            except Exception:
                txt = ''
            if 'BEGIN PRIVATE KEY' in txt:
                key_files.append(str(p))
    except Exception:
        continue

key_files = sorted(set(key_files))
if not key_files:
    print('NO_KEYS_FOUND')
    sys.exit(0)

rot_dir = backups_root / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-rotated')
rot_dir.mkdir(parents=True, exist_ok=True)

mapping = []
for kf in key_files:
    kp = Path(kf)
    old_node_id = None
    pub_candidate = None
    try:
        # try to find explicit public key file nearby
        for cand in ['node_public.pem','node_public.key','node_public.pub','node_public.pem','node_public']:
            candp = kp.parent / cand
            if candp.exists():
                pub_candidate = candp
                break
        # try to compute old node id
        if pub_candidate is not None:
            try:
                pubtxt = pub_candidate.read_text(encoding='utf-8',errors='ignore')
                pub = load_pem_public_key(pubtxt.encode('utf-8'))
                raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                old_node_id = hashlib.sha256(raw).hexdigest()[:16]
            except Exception:
                old_node_id = None
        if old_node_id is None:
            # try deriving from private key
            try:
                data = kp.read_bytes()
                pvt = load_pem_private_key(data, password=None)
                pub = pvt.public_key()
                raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                old_node_id = hashlib.sha256(raw).hexdigest()[:16]
            except Exception:
                old_node_id = None
        # generate new ed25519 key
        priv = ed25519.Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        pubk = priv.public_key()
        pub_pem = pubk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        raw_pub = pubk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        new_node_id = hashlib.sha256(raw_pub).hexdigest()[:16]
        out_priv = rot_dir / (kp.name + '.rotated.pem')
        out_pub = rot_dir / (kp.name + '.rotated.pub.pem')
        out_priv.write_bytes(priv_pem)
        out_pub.write_bytes(pub_pem)
        mapping.append({
            'original': str(kp),
            'original_public_candidate': str(pub_candidate) if pub_candidate else None,
            'old_node_id': old_node_id,
            'rotated_private': str(out_priv),
            'rotated_public': str(out_pub),
            'new_node_id': new_node_id
        })
    except Exception as e:
        mapping.append({'original': str(kp), 'error': str(e)})

mapfile = Path('tools/rotated_keys_map.json')
mapfile.write_text(json.dumps({'rotated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'items': mapping}, indent=2))
summary = Path('tools/rotated_keys_summary.txt')
with summary.open('w', encoding='utf-8') as f:
    f.write('Rotated keys written to: ' + str(rot_dir) + '\n')
    for m in mapping:
        if 'error' in m:
            f.write('ERROR for: ' + m.get('original','?') + ' -> ' + m.get('error','') + '\n')
        else:
            f.write('original: ' + m.get('original','') + '\n')
            f.write('  old_node_id: ' + str(m.get('old_node_id')) + '\n')
            f.write('  new_node_id: ' + str(m.get('new_node_id')) + '\n')
            f.write('  rotated_private: ' + str(m.get('rotated_private')) + '\n')
            f.write('  rotated_public: ' + str(m.get('rotated_public')) + '\n')

print('ROTATED_COUNT', len(mapping))
print('ROTATED_DIR', str(rot_dir))
print('MAP_FILE', str(mapfile))
