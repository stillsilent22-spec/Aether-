import json
from pathlib import Path

root = Path(__file__).resolve().parent
pyfiles = sorted([p for p in root.rglob('*.py') if p.is_file()])
summary = {'total_py_files': len(pyfiles), 'files': []}
keywords = [
    'AlgoToken', 'gossip', 'AethernetTransport', 'cascade', 'delta_hash',
    'session_key', 'sign', 'encrypt', 'hash_anchor', 'seal_invariant',
    'export_invariants', 'push_algo_token', 'receive_algo_token',
    'push_pack', 'receive_gossip', 'delta_encrypted_hex', 'tree_signature',
    'source_node_id', 'public_key_pem', 'node_private.key'
]
for p in pyfiles:
    text = p.read_text(encoding='utf-8', errors='ignore')
    lines = text.splitlines()
    defs = [l.strip() for l in lines if l.lstrip().startswith('def ') or l.lstrip().startswith('class ')]
    imps = [l.strip() for l in lines if l.lstrip().startswith('import ') or l.lstrip().startswith('from ')]
    hits = {kw: [] for kw in keywords}
    for i, line in enumerate(lines, 1):
        for kw in keywords:
            if kw in line:
                hits[kw].append(i)
    summary['files'].append({
        'path': str(p.relative_to(root)),
        'lines': len(lines),
        'first_line': lines[0] if lines else '',
        'defs': defs[:20],
        'imports': imps[:20],
        'keyword_hits': {k: len(v) for k, v in hits.items() if v},
    })
summary_path = root / 'repo_code_summary.json'
summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'Wrote {summary_path} with {len(pyfiles)} python files')
