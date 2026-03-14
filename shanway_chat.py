"""shanway_chat.py — Shanways Chat-Pipeline.

Ablauf pro Anfrage:
  1. Registry-Interferenzmessung (kennt er die Struktur schon?)
  2. Web-Abruf (mehrere Quellen)
  3. Volle Aether-Pipeline: Strukturmessung + Safety + Konsens
  4. Registry-Update wenn würdig (alle Kanäle, ein Register)
  5. TinyLLaMA formuliert — oder Schweigen

Kein Blockchain. Keine neuen Abhängigkeiten außer collections und random.
"""
from __future__ import annotations

import random
from typing import Optional

from shanway_web      import fetch_sources
from shanway_pipeline import measure_consensus, ANCHOR_MEANING
from shanway_registry import get_registry, CHANNEL_WEB, CHANNEL_FILE
from shanway_llm      import (
    DEFAULT_MODEL_CANDIDATES,
    build_filter_context,
    ensure_default_model_downloaded,
    get_llm,
)

_SILENCE = ["...", "(Shanway schweigt.)", "", "", ""]


def _silence() -> str:
    return random.choice(_SILENCE)


def chat(user_input: str,
         model_path: Optional[str] = None,
         extra_urls: Optional[list[str]] = None,
         verbose: bool = False) -> str:
    """Shanways einziger Chat-Eintrittspunkt."""

    llm      = get_llm(model_path)
    registry = get_registry()

    def log(msg: str) -> None:
        if verbose:
            print(f"[SHANWAY] {msg}")

    # ── 1. Registry-Interferenz auf User-Input ────────────────────────────────
    interference = registry.measure_interference_text(user_input)
    log(f"Interferenz: {interference.label} score={interference.best_score}")

    if interference.status == "ANKER" and interference.best_anchor:
        log(f"Registry-Treffer: {interference.best_anchor.summary}")
        context = interference.best_anchor.summary
        if interference.cluster_summary:
            context += f"\nZusammenhänge: {interference.cluster_summary}"
        return llm.generate(context, user_input)

    # ── 2. Web-Abruf ──────────────────────────────────────────────────────────
    log(f"Web-Abruf: {user_input!r}")
    sources = fetch_sources(user_input, extra_urls=extra_urls, n=5)
    log(f"{len(sources)} Quellen")

    if not sources:
        log("Keine Quellen → Schweigen")
        return _silence()

    # ── 3. Volle Aether-Pipeline ──────────────────────────────────────────────
    result = measure_consensus(user_input, sources)
    log(f"Konsens: {result.status} | Anker: {result.confirmed_anchors} "
        f"| Trust: {result.mean_trust} | h_lambda: {result.mean_h_lambda}")

    # ── 4. Registry-Update ────────────────────────────────────────────────────
    saved = registry.register_from_consensus(result, channel=CHANNEL_WEB)
    if saved:
        log(f"Registry: {saved.anchor_id} gespeichert")

    # ── 5. Antwort oder Schweigen ─────────────────────────────────────────────
    if result.status == "UNRESOLVED":
        log("UNRESOLVED → Schweigen")
        return _silence()

    registry_summary = None
    if saved:
        registry_summary = registry.graph.cluster_summary(saved.anchor_id)

    context = build_filter_context(result, registry_summary)
    if not context.strip() or context == "[UNRESOLVED]":
        return _silence()

    return llm.generate(context, user_input)


def drop_file(path: str, model_path: Optional[str] = None,
              verbose: bool = False) -> str:
    """Datei-Drop Kanal — identische Pipeline, anderer Eingang."""
    from pathlib import Path as P
    llm      = get_llm(model_path)
    registry = get_registry()

    def log(msg: str) -> None:
        if verbose:
            print(f"[SHANWAY:FILE] {msg}")

    fp = P(path)
    if not fp.exists() or not fp.is_file():
        return _silence()

    raw = fp.read_bytes()
    log(f"Datei: {fp.name} ({len(raw)} bytes)")

    anchor = registry.register_from_raw(raw, label=fp.name, channel=CHANNEL_FILE)
    if not anchor:
        log("Kein Anker gefunden → Schweigen")
        return _silence()

    log(f"Anker: {anchor.anchor_id} | Trust: {anchor.trust}")
    cluster = registry.graph.cluster_summary(anchor.anchor_id)
    context = anchor.summary
    if cluster:
        context += f"\nZusammenhänge: {cluster}"

    return llm.generate(context, f"Was ist in {fp.name}?")


if __name__ == "__main__":
    import sys
    from pathlib import Path

    model = None
    if len(sys.argv) > 1 and sys.argv[1].endswith(".gguf"):
        model = sys.argv[1]
        print(f"[SHANWAY] Modell: {model}")
    else:
        base_dir = Path(__file__).resolve().parent
        for candidate in DEFAULT_MODEL_CANDIDATES:
            default_model = base_dir / candidate
            if default_model.is_file():
                model = str(default_model)
                print(f"[SHANWAY] Modell: {default_model.name}")
                break
        if model is None:
            model = ensure_default_model_downloaded()
            if model is not None:
                print(f"[SHANWAY] Modell: {Path(model).name}")
            else:
                print("[SHANWAY] Template-Modus")

    registry = get_registry()
    print(f"[SHANWAY] Registry: {registry.stats()}")
    print("[SHANWAY] Bereit. 'exit' zum Beenden. ':drop <pfad>' für Dateien.\n")

    while True:
        try:
            user = input("Du: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[SHANWAY] ...")
            break

        if not user:
            continue
        if user.lower() in {"exit", "quit"}:
            print("[SHANWAY] ...")
            break

        if user.startswith(":drop "):
            path = user[6:].strip()
            antwort = drop_file(path, model_path=model, verbose=True)
        else:
            antwort = chat(user, model_path=model, verbose=True)

        status = "[ANKER]" if antwort and antwort not in ("...", "(Shanway schweigt.)", "") else "[UNRESOLVED]"
        print(f"Shanway {status}: {antwort}\n")
