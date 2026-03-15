"""shanway_chat.py - Shanways Chat-Eintrittspunkte."""

from __future__ import annotations

import random
from typing import Any, Optional

from modules.browser_engine import BrowserEngine
from modules.preload_optimizer import PreloadOptimizer
from modules.shanway import ShanwayEngine
from modules.shanway_interface import ShanwayInterface
from modules.shanway_response_builder import ShanwayResponseBuilder
from shanway_llm import (
    DEFAULT_MODEL_CANDIDATES,
    ensure_default_model_downloaded,
    get_llm,
)
from shanway_registry import CHANNEL_FILE, get_registry

_SILENCE = ["...", "(Shanway schweigt.)", "", "", ""]
_INTERFACE: ShanwayInterface | None = None
_RESPONSE_BUILDER: ShanwayResponseBuilder | None = None


def _silence() -> str:
    """Liefert bewusst einen stillen Fallback statt spekulativer Ausgabe."""
    return random.choice(_SILENCE)


def _get_interface() -> ShanwayInterface:
    """Initialisiert Shanways Interface-Backend fuer Multi-Source-Webkontext genau einmal."""
    global _INTERFACE
    if _INTERFACE is None:
        _INTERFACE = ShanwayInterface(
            shanway_engine=ShanwayEngine(),
            preload_optimizer=PreloadOptimizer(),
            browser_engine=BrowserEngine(),
            auto_push_ttd=False,
        )
    return _INTERFACE


def _get_response_builder() -> ShanwayResponseBuilder:
    """Liefert den bestehenden 6-Felder-Renderer fuer CLI-Antworten."""
    global _RESPONSE_BUILDER
    if _RESPONSE_BUILDER is None:
        _RESPONSE_BUILDER = ShanwayResponseBuilder()
    return _RESPONSE_BUILDER


def _build_verified_context(interface_result: Any) -> str:
    """Verdichtet nur Konsens-Seiten und auditierbare Metadaten fuer TinyLLaMA."""
    web_context = dict(getattr(interface_result, "web_context", {}) or {})
    if not bool(web_context.get("ok", False)):
        return ""
    lines: list[str] = []
    summary = str(web_context.get("verified_context", "") or web_context.get("summary", "") or "").strip()
    if summary:
        lines.append(summary)
    pages = [
        dict(item)
        for item in list(web_context.get("pages", []) or [])
        if bool(dict(item or {}).get("consensus_eligible", False))
    ][:4]
    if pages:
        page_line = "; ".join(
            f"{str(item.get('domain', '') or item.get('url', ''))} (trust={float(item.get('trust_score', 0.0) or 0.0):.2f})"
            for item in pages
        )
        lines.append(f"Verifizierte Quellen: {page_line}")
    return "\n".join(line for line in lines if line.strip()).strip()


def chat(
    user_input: str,
    model_path: Optional[str] = None,
    extra_urls: Optional[list[str]] = None,
    verbose: bool = False,
) -> str:
    """Leitet Chat-Anfragen ueber ShanwayInterface und den 6-Felder-Output."""
    llm = get_llm(model_path)
    interface = _get_interface()
    response_builder = _get_response_builder()

    def log(msg: str) -> None:
        if verbose:
            print(f"[SHANWAY] {msg}")

    interface_result = interface.analyze(user_input)
    web_context = dict(interface_result.web_context or {})
    log(
        f"Route: {web_context.get('query_route', 'general')} | "
        f"Quellen {web_context.get('source_count', 0)}/{web_context.get('sources_used', 0)} | "
        f"Konsistenz {web_context.get('consistency', 'none')}"
    )
    verified_context = _build_verified_context(interface_result)
    raw_answer = llm.generate(verified_context, user_input) if verified_context else ""
    structured = response_builder.build(
        interface_result.assessment,
        interface_result,
        raw_answer=raw_answer,
    )
    rendered = structured.render()
    warnings = [str(item).strip() for item in list(web_context.get("warnings", []) or []) if str(item).strip()]
    if warnings:
        rendered = rendered + "\n\n" + "\n".join(warnings)
    return rendered if rendered.strip() else _silence()


def drop_file(path: str, model_path: Optional[str] = None, verbose: bool = False) -> str:
    """Datei-Drop Kanal - identische Registry-Pipeline, anderer Eingang."""
    from pathlib import Path as P

    llm = get_llm(model_path)
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
        log("Kein Anker gefunden -> Schweigen")
        return _silence()

    log(f"Anker: {anchor.anchor_id} | Trust: {anchor.trust}")
    cluster = registry.graph.cluster_summary(anchor.anchor_id)
    context = anchor.summary
    if cluster:
        context += f"\nZusammenhaenge: {cluster}"

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
    print("[SHANWAY] Bereit. 'exit' zum Beenden. ':drop <pfad>' fuer Dateien.\n")

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
