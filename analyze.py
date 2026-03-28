"""
analyze.py — Assistant Datei- und Text-Analyse (lokal, ohne Netzwerk/LLM)

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
# Imports
# ---------------------------------------------------------------------------
try:
    from modules.assistant_safety import get_safety_filter, AssistantSafetyFilter
    SAFETY_OK = True
except Exception as e:
    print(f"[WARN] assistant_safety nicht ladbar: {e}")
    SAFETY_OK = False

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
    """Analysiert beliebigen Text mit Assistant-Sicherheitsfilter."""
    result = {
        "source": source_label,
        "length": len(text),
        "words": len(re.findall(r"\b\w+\b", text)),
        "shannon_entropy": round(_shannon_entropy(text), 4),
        "h_lambda": _h_lambda(text),
        "trust_score": _trust_score(text),
        "safety": {},
        "verdict": "",
        "output": "",
    }

    if SAFETY_OK:
        sf: AssistantSafetyFilter = get_safety_filter()

        # Einzelfilter
        med   = sf.check_medical(text)
        bl    = sf.check_blacklist(text)
        det   = sf.check_determinism(result["h_lambda"], result["trust_score"])
        hed   = sf.check_hedging(text)
        wl    = sf.check_whitelist(text)

        result["safety"] = {
            "medical_ok":    med.passed,
            "blacklist_ok":  bl.passed,
            "determinism_ok": det.passed,
            "hedging_ok":    hed.passed,
            "on_whitelist":  wl,
            "medical_reason":    med.reason if not med.passed else "",
            "blacklist_reason":  bl.reason  if not bl.passed  else "",
            "determinism_reason": det.reason if not det.passed else "",
            "hedging_reason":    hed.reason  if not hed.passed  else "",
        }

        # safe_generate (ohne LLM: Text direkt als "generierter" Output)
        safe_out = sf.safe_generate(
            query=text[:200],
            generated_text=text[:500],
            h_lambda=result["h_lambda"],
            trust=result["trust_score"],
        )
        all_filters_pass = (
            med.passed and bl.passed and det.passed and hed.passed
        )
        if not med.passed:
            result["verdict"] = "SCHWEIGEN — medizinische Anfrage"
            result["output"]  = ""
        elif not bl.passed:
            result["verdict"] = "SCHWEIGEN — Blacklist-Treffer"
            result["output"]  = ""
        elif not det.passed:
            result["verdict"] = f"SCHWEIGEN — {det.reason}"
            result["output"]  = ""
        elif not hed.passed:
            result["verdict"] = "BEREINIGT — Hedging entfernt"
            result["output"]  = sf.strip_hedging(text)
        else:
            result["verdict"] = "FREIGEGEBEN"
            result["output"]  = text[:500]
    else:
        result["verdict"] = "SAFETY-FILTER NICHT GELADEN"
        result["output"]  = text[:500]

    return result


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
    print("  ASSISTANT ANALYSE")
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

    s = r.get("safety", {})
    if s:
        print()
        print("  — Sicherheitsfilter —")
        icons = {True: "✓", False: "✗"}
        print(f"  Medical      : {icons[s['medical_ok']]}  {s.get('medical_reason','')}")
        print(f"  Blacklist    : {icons[s['blacklist_ok']]}  {s.get('blacklist_reason','')}")
        print(f"  Determinismus: {icons[s['determinism_ok']]}  {s.get('determinism_reason','')}")
        print(f"  Hedging      : {icons[s['hedging_ok']]}  {s.get('hedging_reason','')}")
        print(f"  Whitelist    : {'✓ (sichere Domäne)' if s['on_whitelist'] else '— (nicht klassifiziert)'}")

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
    print("\nASSISTANT ANALYSE — Interaktiver Modus")
    print("Eingabe: Text oder Dateipfad. 'exit' zum Beenden.\n")
    while True:
        try:
            inp = input("Assistant> ").strip()
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
