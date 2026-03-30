#!/usr/bin/env python3
"""Repository-wide scanner: read every file (textual), flag secrets, subprocess/git/socket/use of eval, and produce JSON report.

Saves: tools/repo_scan_report.json
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent / "repo_scan_report.json"

# Exclude heavy binary/build folders (still reads most project files)
EXCLUDE_PARTS = ["/target/", "/.git/", "/aether_repo/extracted/", "/aether-symbiont/node_modules/", "/node_modules/", "/data/_pytest_tmp/", "/.venv/", "/build/", "/dist/"]

KEY_PATTERNS = [
    r"-----BEGIN PRIVATE KEY-----",
    r"-----BEGIN RSA PRIVATE KEY-----",
    r"-----BEGIN OPENSSH PRIVATE KEY-----",
    r"-----BEGIN PRIVATE KEY-----",
    r"-----BEGIN PUBLIC KEY-----",
    r"password=",
    r"api[_-]?key",
    r"pinata",
    r"secret",
    r"token",
    r"node_secret",
    r"node_private",
]

SHELL_PATTERNS = [r"subprocess\.run", r"subprocess\.Popen", r"os\.system", r"taskkill", r"msiexec", r"ar ", r"pkgutil", r"git add", r"git commit", r"git push", r"sh -c"]

EVAL_PATTERNS = [r"\beval\(", r"\bexec\(", r"compile\("]

SOCKET_PATTERNS = [r"socket\.", r"\bbind\(", r"\blisten\(", r"\baccept\(", r"recv\(", r"send\("]

PICKLE_YAML = [r"pickle\.load", r"pickle\.loads", r"yaml\.load"]

TEXT_EXTS = {'.py', '.md', '.rs', '.toml', '.json', '.yaml', '.yml', '.txt', '.md', '.js', '.ts', '.html', '.css', '.cfg', '.ini', '.spec', '.sh', '.ps1'}


def is_excluded(path: Path) -> bool:
    s = str(path).replace('\\', '/')
    for p in EXCLUDE_PARTS:
        if p in s:
            return True
    return False


def is_likely_text(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTS:
        return True
    try:
        with path.open('rb') as f:
            head = f.read(2048)
            if b'\x00' in head:
                return False
            # heuristic: many non-printable bytes -> binary
            nonprint = sum(1 for b in head if b < 9 or (b > 13 and b < 32))
            if len(head) > 0 and (nonprint / len(head)) > 0.30:
                return False
            return True
    except Exception:
        return False


def scan_file(path: Path) -> Dict:
    rel = path.relative_to(ROOT)
    result: Dict = {
        'path': str(rel).replace('\\', '/'),
        'size': path.stat().st_size,
        'is_binary': False,
        'lines': 0,
        'head': [],
        'tail': [],
        'flags': [],
    }
    if not is_likely_text(path):
        result['is_binary'] = True
        return result

    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        result['is_binary'] = True
        return result

    lines = text.splitlines()
    result['lines'] = len(lines)
    result['head'] = lines[:40]
    result['tail'] = lines[-40:]

    lowered = text.lower()

    for p in KEY_PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            result['flags'].append({'kind': 'key_like', 'pattern': p})

    for p in SHELL_PATTERNS:
        if re.search(p, text):
            result['flags'].append({'kind': 'shell', 'pattern': p})

    for p in EVAL_PATTERNS:
        if re.search(p, text):
            result['flags'].append({'kind': 'eval', 'pattern': p})

    for p in SOCKET_PATTERNS:
        if re.search(p, text):
            result['flags'].append({'kind': 'socket', 'pattern': p})

    for p in PICKLE_YAML:
        if re.search(p, text):
            result['flags'].append({'kind': 'pickle_yaml', 'pattern': p})

    # git actions: explicit
    if 'git add' in text or 'git commit' in text or 'git push' in text:
        result['flags'].append({'kind': 'git_ops', 'pattern': 'git'})

    # yggdrasil/pinata detection
    if 'yggdrasil' in lowered:
        result['flags'].append({'kind': 'yggdrasil', 'pattern': 'yggdrasil'})
    if 'pinata' in lowered:
        result['flags'].append({'kind': 'pinata', 'pattern': 'pinata'})

    return result


def main() -> int:
    files = []
    for p in sorted(ROOT.rglob('*')):
        if p.is_file():
            if is_excluded(p):
                continue
            files.append(p)

    results: List[Dict] = []
    summary = {
        'total_files': len(files),
        'total_text_files': 0,
        'key_like_files': 0,
        'git_ops_files': 0,
        'yggdrasil_files': 0,
        'pinata_files': 0,
        'shell_files': 0,
        'eval_files': 0,
        'socket_files': 0,
    }

    for path in files:
        try:
            r = scan_file(path)
        except Exception as e:
            r = {'path': str(path.relative_to(ROOT)).replace('\\', '/'), 'error': str(e)}
        results.append(r)
        # aggregate
        if not r.get('is_binary', False):
            summary['total_text_files'] += 1
            for f in r.get('flags', []):
                kind = f.get('kind')
                if kind == 'key_like':
                    summary['key_like_files'] += 1
                if kind == 'git_ops':
                    summary['git_ops_files'] += 1
                if kind == 'yggdrasil':
                    summary['yggdrasil_files'] += 1
                if kind == 'pinata':
                    summary['pinata_files'] += 1
                if kind == 'shell':
                    summary['shell_files'] += 1
                if kind == 'eval':
                    summary['eval_files'] += 1
                if kind == 'socket':
                    summary['socket_files'] += 1

    out = {
        'root': str(ROOT),
        'summary': summary,
        'files': results,
    }

    try:
        OUT.write_text(json.dumps(out, indent=2), encoding='utf-8')
        print(f'Wrote {OUT} (files scanned: {len(results)})')
    except Exception as e:
        print('Failed to write report:', e)
        return 2

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
