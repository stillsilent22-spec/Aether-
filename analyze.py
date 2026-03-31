"""
analyze.py — Aether Datei- und Text-Analyse (lokal, ohne Netzwerk/LLM)

Aufruf:
    python analyze.py path/to/datei.txt
    python analyze.py "Erklaere mir Python-Dekoratoren"   # Text direkt
    python analyze.py --interactive                        # Interaktiver Modus
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Pfad-Setup
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Berechnet Shannon-Entropie des Textes (Bits/Zeichen)."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _h_lambda(text: str) -> float:
    """
    Vereinfachter h_lambda-Proxy:
    Verhältnis einzigartiger Wörter zu Gesamtwörtern (semantische Dichte).
    Skaliert 0–10. Niedrig = deterministisch. Hoch = Unsicherheit.
    """
    words = re.findall(r"\b\w+\b", text.lower())
    if not words:
        return 10.0
    unique_ratio = len(set(words)) / len(words)
    # Invertiert: viele Wiederholungen → niedriges h_lambda
    return round(unique_ratio * 7.0, 2)


def _trust_score(text: str) -> float:
    """
    Einfacher Trust-Proxy aus Textmerkmalen:
    - Vollständige Sätze: +
    - Sehr kurzer Text: -
    - Viele Sonderzeichen: -
    """
    score = 0.7
    if len(text) < 50:
        score -= 0.2
    if len(text) > 500:
        score += 0.1
    sentences = re.split(r"[.!?]+", text)
    complete = sum(1 for s in sentences if len(s.strip().split()) >= 4)
    score += min(0.2, complete * 0.05)
    special = sum(1 for c in text if not c.isalnum() and c not in " \n\t.,;:!?-")
    score -= min(0.2, special * 0.01)
    return max(0.0, min(1.0, round(score, 3)))


def _file_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def analyze_text(text: str, source_label: str = "direkte Eingabe") -> dict:
    """Analysiert beliebigen Text anhand struktureller Metriken."""
    h = _h_lambda(text)
    trust = _trust_score(text)
    # Verdict ausschließlich auf Metriken basiert
    if h > 5.5:
        verdict = f"STRUKTURELL UNSICHER — h_lambda={h} (>5.5)"
    elif trust < 0.45:
        verdict = f"STRUKTURELL UNSICHER — trust={trust} (<0.45)"
    else:
        verdict = "STRUKTURELL OK"
    return {
        "source": source_label,
        "length": len(text),
        "words": len(re.findall(r"\b\w+\b", text)),
        "shannon_entropy": round(_shannon_entropy(text), 4),
        "h_lambda": h,
        "trust_score": trust,
        "verdict": verdict,
        "output": text[:500],
    }


def analyze_file(path: str) -> dict:
    """Liest und analysiert eine Datei."""
    p = Path(path)
    if not p.exists():
        return {"error": f"Datei nicht gefunden: {path}"}
    if not p.is_file():
        return {"error": f"Kein reguläre Datei: {path}"}

    raw = p.read_bytes()
    file_hash = _file_hash(raw)

    # Text-Extraktion (UTF-8, Fallback Latin-1)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except Exception:
            return {"error": "Datei konnte nicht als Text gelesen werden (Binärdatei?)"}

    result = analyze_text(text, source_label=str(p))
    result["file"] = str(p)
    result["size_bytes"] = len(raw)
    result["sha256_prefix"] = file_hash
    result["extension"] = p.suffix.lower()
    return result


def _print_result(r: dict) -> None:
    """Gibt das Analyse-Ergebnis formatiert aus."""
    print()
    print("=" * 64)
    print("  AETHER ANALYSE")
    print("=" * 64)

    if "error" in r:
        print(f"  FEHLER: {r['error']}")
        return

    src = r.get("file") or r.get("source", "?")
    print(f"  Quelle       : {src}")
    if "size_bytes" in r:
        print(f"  Größe        : {r['size_bytes']} Bytes")
    if "sha256_prefix" in r:
        print(f"  SHA-256 (16) : {r['sha256_prefix']}")

    print()
    print("  — Metriken —")
    print(f"  Länge        : {r['length']} Zeichen, {r['words']} Wörter")
    print(f"  Shannon-H    : {r['shannon_entropy']} bit/Zeichen")
    print(f"  h_lambda     : {r['h_lambda']}  (>5.5 → Schweigen)")
    print(f"  Trust        : {r['trust_score']}  (<0.45 → Schweigen)")

    print()
    print(f"  URTEIL       : {r.get('verdict', '?')}")

    out = r.get("output", "")
    if out:
        preview = out[:300].replace("\n", " ").strip()
        if len(out) > 300:
            preview += " [...]"
        print()
        print("  — Textvorschau (bereinigt) —")
        print(f"  {preview}")

    print("=" * 64)
    print()


def interactive_mode() -> None:
    """Interaktiver Analyse-Modus."""
    print("\nAETHER ANALYSE — Interaktiver Modus")
    print("Eingabe: Text oder Dateipfad. 'exit' zum Beenden.\n")
    while True:
        try:
            inp = input("Aether> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBeendet.")
            break
        if not inp or inp.lower() in ("exit", "quit", "q"):
            print("Beendet.")
            break

        p = Path(inp)
        if p.exists() and p.is_file():
            r = analyze_file(str(p))
        else:
            r = analyze_text(inp, source_label="Direkteingabe")

        _print_result(r)


# ---------------------------------------------------------------------------
# Einstiegspunkt
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from modules.session_guard import require_session
    require_session()
    if len(sys.argv) < 2 or sys.argv[1] in ("-i", "--interactive"):
        interactive_mode()
    else:
        arg = " ".join(sys.argv[1:])
        p = Path(arg)
        if p.exists() and p.is_file():
            r = analyze_file(str(p))
        else:
            # Direkt als Text behandeln
            r = analyze_text(arg, source_label="Direkteingabe")
        _print_result(r)
