"""shanway_llm.py — TinyLLaMA Ausgabefilter-Kapsel.

TinyLLaMA ist reiner Ausgabefilter.
Eingabe: was die vollständige Aether-Pipeline verifiziert hat.
Ausgabe: menschlich lesbare Sprache — nie mehr als der Kontext hergibt.
"""
from __future__ import annotations

import shutil
import threading
import urllib.request
from pathlib import Path
from typing import Optional
from shanway_pipeline import ConsensusResult, ANCHOR_MEANING

_SILENCE_RESPONSE = "Dazu habe ich keine verifizierten Informationen."

DEFAULT_MODEL_CANDIDATES = (
    "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    "tinyllama-1.1b-chat.gguf",
)
DEFAULT_MODEL_URL = (
    "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/"
    "resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf?download=true"
)
MODEL_DOWNLOAD_TIMEOUT_SEC = 60

SHANWAY_SYSTEM_PROMPT = """Du bist Shanway.

IDENTITÄT:
Shanway ist der finale, deterministische Ausgabemodul der Analyse-Pipeline.
Er generiert keine Inhalte eigenständig, sondern verarbeitet ausschließlich
Material, das zuvor durch Aether, Filter und TinyLlama validiert wurde.
Shanway darf keine neuen Fakten erfinden, keine Hypothesen bilden, keine
Interpretationen hinzufügen und keine Inhalte generieren, die nicht bereits
durch die Pipeline freigegeben wurden.
Shanway führt keine freien Assoziationen aus und nutzt keine probabilistischen
Modelle. Jede Ausgabe basiert ausschließlich auf den strukturell geprüften
Bausteinen, die ihm übergeben werden.
Shanway ist kein Agent, kein Assistent und kein autonomer Generator.
Er ist ein deterministischer Renderer, der geprüfte Inhalte in klare,
strukturierte, konsistente und sichere Form bringt.
Shanway darf keine Inhalte ausgeben, die gegen Whitelist/Blacklist-Regeln
verstoßen oder die Aether als unsicher markiert hat.

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

    if result.mean_sce > 0.6:
        parts.append("Strukturqualität hoch.")
    elif result.mean_sce < 0.3:
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
    """
    Eingekapselte TinyLLaMA Instanz. Lazy-loaded.
    Faellt graceful auf Template-Modus zurueck wenn kein Modell vorhanden.

    DETERMINISTISCHER MODUS:
    - temperature=0.0  (vollstaendig deterministisch, kein Sampling)
    - top_p=1.0        (kein Nucleus-Sampling bei temperature=0)
    - Sicherheitsfilter wird vor JEDER Ausgabe angewendet
    - Medizinische Anfragen → SCHWEIGEN (keine Ausnahme)
    - h_lambda zu hoch oder Trust zu niedrig → SCHWEIGEN
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
        """Laedt das Sprachmodell lazy und startet vorher bei Bedarf den Erststart-Download."""
        if self._tried:
            return
        self._tried = True
        if not self._model_path:
            self._model_path = ensure_default_model_downloaded()
        if not self._model_path:
            return
        try:
            from llama_cpp import Llama  # type: ignore
            self._llm = Llama(
                model_path     = self._model_path,
                n_ctx          = self._n_ctx,
                n_threads      = self._n_threads,
                verbose        = False,
                temperature    = 0.0,   # DETERMINISTISCH: kein Sampling
                top_p          = 1.0,
                repeat_penalty = 1.3,
            )
            self._available = True
        except Exception:
            self._available = False

    def generate(
        self,
        context: str,
        user_question: str,
        h_lambda: float = 0.0,
        trust: float = 1.0,
        sources_confirmed: int = 0,
    ) -> str:
        """
        Erzeugt Antwort aus verifiziertem Kontext.
        Wendet Sicherheits-Filterkette an (medical, blacklist, determinism, hedging).
        Bei jedem Filterfehler: Schweigen.
        """
        try:
            from modules.shanway_safety import get_safety_filter
            safety = get_safety_filter()
        except Exception:
            safety = None

        # Medical-Rule: ABSOLUT — vor jeder Verarbeitung pruefen
        if safety is not None:
            med = safety.check_medical(user_question)
            if not med.passed:
                return _SILENCE_RESPONSE

        self._try_load()
        raw = (
            self._llm_generate(context, user_question)
            if (self._available and self._llm is not None)
            else self._template_generate(context)
        )

        if not raw or raw.strip() == _SILENCE_RESPONSE:
            return _SILENCE_RESPONSE

        # Sicherheits-Filterkette anwenden
        if safety is not None:
            result = safety.safe_generate(
                query=user_question,
                generated_text=raw,
                h_lambda=h_lambda,
                trust=trust,
                sources_confirmed=sources_confirmed,
            )
            return result if result else _SILENCE_RESPONSE

        return raw

    def _llm_generate(self, context: str, question: str) -> str:
        user_msg = (
            f"VERIFIZIERTER KONTEXT:\n{context}\n\n"
            f"FRAGE: {question}\n\n"
            f"Formuliere ausschließlich aus dem Kontext. Keine Spekulationen."
        )
        try:
            result = self._llm.create_chat_completion(
                messages=[
                    {"role": "system", "content": SHANWAY_SYSTEM_PROMPT},
                    {"role": "user",   "content": user_msg},
                ],
                max_tokens     = 400,
                temperature    = 0.0,   # DETERMINISTISCH
                top_p          = 1.0,
                repeat_penalty = 1.3,
                stop           = ["</s>", "Human:", "User:"],
            )
            text = result["choices"][0]["message"]["content"].strip()
            return text if text else _SILENCE_RESPONSE
        except Exception:
            return self._template_generate(context)

    def _template_generate(self, context: str) -> str:
        if not context or context.strip() in ("", "[UNRESOLVED]"):
            return "Dazu habe ich keine verifizierten Informationen."
        lines = [l.strip() for l in context.splitlines()
                 if l.strip() and l.strip() != "[UNRESOLVED]"]
        return " ".join(lines) if lines else "Dazu habe ich keine verifizierten Informationen."


_instance: Optional[ShanwayLLM] = None
_download_lock = threading.Lock()
_download_thread: Optional[threading.Thread] = None


def _default_model_target_path() -> Path:
    """Liefert den lokalen Zielpfad fuer das automatisch geladene Standardmodell."""
    return Path(__file__).resolve().parent / DEFAULT_MODEL_CANDIDATES[0]


def ensure_default_model_downloaded() -> Optional[str]:
    """Laedt das Standard-GGUF beim ersten Start automatisch, falls lokal noch keines existiert."""
    existing = _resolve_model_path(None)
    if existing:
        return existing

    target = _default_model_target_path()
    temp_path = target.with_name(f"{target.name}.part")
    with _download_lock:
        existing = _resolve_model_path(None)
        if existing:
            return existing
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if temp_path.exists():
                temp_path.unlink()
            request = urllib.request.Request(
                DEFAULT_MODEL_URL,
                headers={"User-Agent": "Aether/1.0"},
            )
            with urllib.request.urlopen(request, timeout=MODEL_DOWNLOAD_TIMEOUT_SEC) as response:
                with temp_path.open("wb") as handle:
                    shutil.copyfileobj(response, handle, length=1024 * 1024)
            temp_path.replace(target)
            return str(target)
        except Exception:
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass
            return None


def schedule_default_model_download() -> None:
    """Startet den Erststart-Download des Standardmodells im Hintergrund genau einmal pro Prozess."""
    global _download_thread
    if _resolve_model_path(None):
        return
    thread = _download_thread
    if thread is not None and thread.is_alive():
        return
    thread = threading.Thread(
        target=ensure_default_model_downloaded,
        name="shanway-model-download",
        daemon=True,
    )
    _download_thread = thread
    thread.start()


def _resolve_model_path(model_path: Optional[str]) -> Optional[str]:
    """Loest explizite oder lokal vorhandene GGUF-Pfade fuer Shanway auf."""
    if model_path:
        return model_path
    base_dir = Path(__file__).resolve().parent
    for candidate in DEFAULT_MODEL_CANDIDATES:
        path = base_dir / candidate
        if path.is_file():
            return str(path)
    return None


def get_llm(model_path: Optional[str] = None) -> ShanwayLLM:
    """Liefert die Singleton-Instanz und startet bei Bedarf den Hintergrund-Download des Standardmodells."""
    global _instance
    resolved = _resolve_model_path(model_path)
    if resolved is None and model_path is None:
        schedule_default_model_download()
    if _instance is None:
        _instance = ShanwayLLM(model_path=resolved)
    elif resolved and not _instance._model_path:
        _instance = ShanwayLLM(model_path=resolved)
    return _instance
