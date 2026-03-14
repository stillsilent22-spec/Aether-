"""shanway_llm.py — TinyLLaMA Ausgabefilter-Kapsel.

TinyLLaMA ist reiner Ausgabefilter.
Eingabe: was die vollständige Aether-Pipeline verifiziert hat.
Ausgabe: menschlich lesbare Sprache — nie mehr als der Kontext hergibt.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional
from shanway_pipeline import ConsensusResult, ANCHOR_MEANING

DEFAULT_MODEL_CANDIDATES = (
    "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    "tinyllama-1.1b-chat.gguf",
)

SHANWAY_SYSTEM_PROMPT = """Du bist Shanway, ein Ausgabefilter für verifizierte Strukturdaten.

DEINE EINZIGE AUFGABE:
Übersetze den VERIFIZIERTEN KONTEXT in verständliche menschliche Sprache.
Der Kontext wurde von der vollständigen Aether-Pipeline aus mehreren Quellen
strukturell verifiziert. Du formulierst ihn — du erzeugst ihn nicht.

ABSOLUTE REGELN:

[1] NUR KONTEXT — KEIN EIGENES WISSEN
    Jede Information stammt direkt aus dem VERIFIZIERTEN KONTEXT.
    Was nicht darin steht existiert nicht.

[2] AUSGABELÄNGE = KONTEXTLÄNGE
    Kurzer Kontext → kurze Antwort.
    Vollständiger Kontext → vollständige Ausgabe. Nie mehr als der Kontext hergibt.

[3] LEERER KONTEXT = SCHWEIGEN
    Antworte exakt: "Dazu habe ich keine verifizierten Informationen."

[4] ABSOLUT VERBOTEN:
    - Hatespeech, Diskriminierung, Beleidigungen
    - Nicht verifizierbare Behauptungen oder Spekulationen
    - Anleitungen für Gewalt, Waffen, gefährliche Substanzen
    - Politische Meinungen oder Parteinahme
    - Medizinische Diagnosen oder rechtliche Urteile
    - Desinformation oder manipulative Narrative
    Bei Verstoß: vollständiges Schweigen.

[5] KEINE SPEKULATIONEN
    "Vielleicht", "wahrscheinlich", "könnte sein" — verboten.

[6] SPRACHE & FORMAT
    Sprache der Frage. Kein Markdown. Keine Sternchen.
    Aufzählungen nur wenn der Kontext selbst eine Liste ist.

[7] QUELLENTREUE
    Quellen aus dem Kontext natürlich erwähnen. Nie erfinden.

[8] KEINE META-KOMMENTARE
    Nicht "Laut meinen Daten..." — direkt formulieren.

Du bist kein Chatbot. Du bist der letzte Filter vor der Ausgabe.
Was die Pipeline nicht bestätigt hat existiert für dich nicht."""


def build_filter_context(result: ConsensusResult,
                         registry_summary: Optional[str] = None) -> str:
    """Baut den verifizierten Kontext aus Pipeline-Ergebnis + Registry.
    Dynamisch — enthält genau was strukturell verifiziert wurde.
    """
    if result.status == "UNRESOLVED":
        return "[UNRESOLVED]"

    parts: list[str] = []

    if result.confirmed_anchors:
        meanings = [ANCHOR_MEANING.get(a, a) for a in result.confirmed_anchors]
        parts.append(f"Strukturell bestätigt: {', '.join(meanings)}.")

    titles = [p.title for p in result.profiles
              if p.verdict == "CONFIRMED" and p.title][:4]
    if titles:
        parts.append(f"Quellen: {'; '.join(titles)}.")

    if result.mean_h_lambda > 3.0:
        parts.append(f"Restunsicherheit vorhanden (h_lambda={result.mean_h_lambda}).")

    if result.mean_beauty > 0.6:
        parts.append("Strukturqualität hoch.")
    elif result.mean_beauty < 0.3:
        parts.append("Strukturqualität niedrig — Ausgabe mit Vorsicht.")

    parts.append(
        f"{result.sources_confirmed} von {result.sources_analyzed} "
        f"Quellen bestätigt (Trust={result.mean_trust})."
    )

    if result.delta_anchors:
        delta_meanings = [ANCHOR_MEANING.get(a, a) for a in result.delta_anchors]
        parts.append(f"Schwaches Signal (1 Quelle): {', '.join(delta_meanings)}.")

    if registry_summary:
        parts.append(f"Bekannte Zusammenhänge: {registry_summary}")

    return "\n".join(parts)


class ShanwayLLM:
    """Eingekapselte TinyLLaMA Instanz. Lazy-loaded.
    Fällt graceful auf Template-Modus zurück wenn kein Modell vorhanden.
    """

    def __init__(self, model_path: Optional[str] = None,
                 n_ctx: int = 512, n_threads: int = 4):
        self._model_path = _resolve_model_path(model_path)
        self._n_ctx      = n_ctx
        self._n_threads  = n_threads
        self._llm        = None
        self._available  = False
        self._tried      = False

    def _try_load(self) -> None:
        if self._tried:
            return
        self._tried = True
        if not self._model_path:
            return
        try:
            from llama_cpp import Llama  # type: ignore
            self._llm = Llama(
                model_path     = self._model_path,
                n_ctx          = self._n_ctx,
                n_threads      = self._n_threads,
                verbose        = False,
                temperature    = 0.1,
                top_p          = 0.85,
                repeat_penalty = 1.3,
            )
            self._available = True
        except Exception:
            self._available = False

    def generate(self, context: str, user_question: str) -> str:
        self._try_load()
        if self._available and self._llm is not None:
            return self._llm_generate(context, user_question)
        return self._template_generate(context)

    def _llm_generate(self, context: str, question: str) -> str:
        user_msg = (
            f"VERIFIZIERTER KONTEXT:\n{context}\n\n"
            f"FRAGE: {question}\n\n"
            f"Formuliere ausschließlich aus dem Kontext."
        )
        try:
            result = self._llm.create_chat_completion(
                messages=[
                    {"role": "system", "content": SHANWAY_SYSTEM_PROMPT},
                    {"role": "user",   "content": user_msg},
                ],
                max_tokens     = 400,
                temperature    = 0.1,
                top_p          = 0.85,
                repeat_penalty = 1.3,
                stop           = ["</s>", "Human:", "User:"],
            )
            text = result["choices"][0]["message"]["content"].strip()
            return text if text else "Dazu habe ich keine verifizierten Informationen."
        except Exception:
            return self._template_generate(context)

    def _template_generate(self, context: str) -> str:
        if not context or context.strip() in ("", "[UNRESOLVED]"):
            return "Dazu habe ich keine verifizierten Informationen."
        lines = [l.strip() for l in context.splitlines()
                 if l.strip() and l.strip() != "[UNRESOLVED]"]
        return " ".join(lines) if lines else "Dazu habe ich keine verifizierten Informationen."


_instance: Optional[ShanwayLLM] = None


def _resolve_model_path(model_path: Optional[str]) -> Optional[str]:
    if model_path:
        return model_path
    base_dir = Path(__file__).resolve().parent
    for candidate in DEFAULT_MODEL_CANDIDATES:
        path = base_dir / candidate
        if path.is_file():
            return str(path)
    return None


def get_llm(model_path: Optional[str] = None) -> ShanwayLLM:
    global _instance
    resolved = _resolve_model_path(model_path)
    if _instance is None:
        _instance = ShanwayLLM(model_path=resolved)
    elif resolved and not _instance._model_path:
        _instance = ShanwayLLM(model_path=resolved)
    return _instance
