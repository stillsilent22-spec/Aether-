"""Strukturelle Dialogantworten ohne externes Sprachmodell."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .analysis_engine import AetherFingerprint

if TYPE_CHECKING:
    from .registry import AetherRegistry


@dataclass
class StructuralReply:
    """Verdichtete Beschreibung einer Analyse als dialogfaehige Antwort."""

    semantics_label: str
    beauty_score: float
    beauty_label: str
    response_text: str


@dataclass
class AssistantContext:
    """Verdichteter Laufzeitkontext fuer deterministische Shanway-Antworten."""

    username: str
    role: str
    security_mode: str = "PROD"
    trust_state: str = "TRUSTED"
    maze_state: str = "NONE"
    node_id: str = ""
    security_summary: str = ""
    current_source_label: str = ""
    current_source_type: str = ""
    current_url: str = ""
    current_integrity_text: str = ""
    current_entropy: float = 0.0
    current_ethics: float = 0.0
    current_h_lambda: float = 0.0
    current_observer_state: str = ""
    current_observer_ratio: float = 0.0
    history_count: int = 0
    vault_count: int = 0
    alarms_count: int = 0
    named_tokens: int = 0
    total_tokens: int = 0
    ontology_complete: bool = False
    pattern_found: str = ""
    previous_source_label: str = ""
    previous_integrity_text: str = ""
    previous_entropy: float = 0.0
    previous_ethics: float = 0.0
    previous_h_lambda: float = 0.0
    graph_phase_state: str = ""
    graph_region_label: str = ""
    graph_stable_subgraphs: int = 0
    graph_attractor_score: float = 0.0
    bayes_anchor_confidence: float = 0.0
    bayes_phase_confidence: float = 0.0
    bayes_pattern_confidence: float = 0.0
    bayes_interference_confidence: float = 0.0
    bayes_alarm_confidence: float = 0.0
    graph_interference_mean: float = 0.0
    graph_destructive_ratio: float = 0.0
    model_depth_label: str = ""
    model_depth_score: float = 0.0
    delta_learning_label: str = ""
    delta_learning_ratio: float = 0.0
    anomaly_memory_top: str = ""
    ae_anchor_count: int = 0
    ae_main_vault_size: int = 0
    ae_top_anchor_type: str = ""
    ae_summary: str = ""
    ae_anchor_details: list[dict[str, Any]] | None = None
    local_chain_entries: int = 0
    local_chain_valid: bool = True
    local_chain_latest_hash: str = ""
    current_local_chain_tx: str = ""
    public_anchor_pending: int = 0
    public_anchor_online: bool = False
    public_anchor_latest_status: str = ""
    current_anchor_status: str = ""
    verify_counts: dict[str, int] | None = None


@dataclass
class AssistantResponse:
    """Deterministische Assistenzantwort samt erkannter Intention."""

    intent: str
    text: str
    knowledge_layer: int = 0
    knowledge_key: str = ""


class StructuralDialogEngine:
    """Leitet assistentenaehnliche Antworten nur aus Shanway-Metriken ab."""

    LAYER0_DEFAULT = "Ich habe noch kein Muster dafür gesehen. Zeig es mir."

    HELP_HINTS = (
        "status",
        "browser",
        "historie",
        "muster",
        "sicherheit",
        "vergleich",
        "hilfe",
    )

    CONSTANT_LABELS = {
        "REF_A": "ref-a",
        "E": "e",
        "PHI": "phi",
        "LOG2": "log2",
    }

    def __init__(self, registry: "AetherRegistry | None" = None) -> None:
        self.registry = registry
        self.core_knowledge: dict[str, dict[str, object]] = {
            "shannon": {
                "title": "Shannon",
                "formula": "H(X) = -Σ p(x) log2 p(x)",
                "principle": "Entropie misst strukturelle Unsicherheit und setzt die Grenze für verlustfreie Kompression.",
                "keywords": ("shannon", "entropie", "information", "kompression", "kanal", "coding"),
            },
            "conway": {
                "title": "Conway",
                "formula": "B3/S23",
                "principle": "Einfache lokale Regeln können ohne zentrale Steuerung globale Ordnung emergieren lassen.",
                "keywords": ("conway", "game", "life", "b3", "s23", "zelle", "emergenz"),
            },
            "benford": {
                "title": "Benford",
                "formula": "P(d) = log10(1 + 1/d)",
                "principle": "Natürliche Zahlenströme zeigen keine flache Führungsziffernverteilung; Abweichungen sind ein Zusatzsignal.",
                "keywords": ("benford", "ziffer", "leading", "digit", "natürlich", "verteilung"),
            },
            "mandelbrot": {
                "title": "Mandelbrot",
                "formula": "D = log(N) / log(1/r)",
                "principle": "Fraktale Dimension misst Selbstähnlichkeit zwischen glatter Ordnung und rauem Chaos.",
                "keywords": ("mandelbrot", "fraktal", "dimension", "selbstähnlich", "boxcounting"),
            },
            "noether": {
                "title": "Noether",
                "formula": "Symmetrie -> Erhaltung",
                "principle": "Wenn eine Struktur symmetrisch bleibt, existiert eine dazugehörige Invariante oder Erhaltungsgröße.",
                "keywords": ("noether", "symmetrie", "erhaltung", "invarianz", "invariant"),
            },
            "heisenberg": {
                "title": "Heisenberg",
                "formula": "Δx · Δp >= ħ / 2",
                "principle": "Präzision in einem Aspekt erhöht die Unschärfe im komplementären Aspekt; in AETHER als Struktur-vs-Änderung-Tradeoff.",
                "keywords": ("heisenberg", "unschärfe", "uncertainty", "delta", "beobachter", "komplementär"),
            },
        }

    @classmethod
    def _anchor_summary_text(cls, anchors: list[dict[str, Any]] | None, limit: int = 2) -> str:
        """Verdichtet AE-Anker fuer knappe Shanway-Antworten."""
        parts: list[str] = []
        for anchor in list(anchors or [])[: max(1, int(limit))]:
            value = float(anchor.get("value", 0.0) or 0.0)
            nearest = cls.CONSTANT_LABELS.get(
                str(anchor.get("nearest_constant", "")).upper(),
                str(anchor.get("nearest_constant", "emergent")).lower(),
            )
            deviation = float(anchor.get("deviation", 0.0) or 0.0)
            label = str(anchor.get("type_label", "EMERGENT") or "EMERGENT")
            parts.append(f"{label} {value:.6f} ~ {nearest} D{deviation:.3g}")
        return " | ".join(parts)
        self.domain_keywords: dict[str, tuple[str, ...]] = {
            "physics": ("physik", "energie", "gravitation", "interferenz", "quant", "feld", "resonanz", "symmetrie"),
            "math": ("mathe", "mathematik", "fraktal", "graph", "matrix", "topologie", "zahl", "beweis", "integral"),
            "biology": ("biologie", "zelle", "mutation", "evolution", "dna", "organismus", "immun", "morphogenese"),
            "music": ("musik", "frequenz", "ton", "harmonie", "dissonanz", "rhythmus", "skala", "klang"),
            "language": ("sprache", "syntax", "semantik", "token", "wort", "satz", "grammatik", "dialog"),
        }

    @staticmethod
    def _clamp(value: float, low: float, high: float) -> float:
        return float(max(low, min(high, value)))

    @staticmethod
    def _contains_any(lowered: str, options: tuple[str, ...]) -> bool:
        return any(option in lowered for option in options)

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        return {
            token
            for token in re.findall(r"[0-9A-Za-zÄÖÜäöüß]+", str(text).lower())
            if len(token) >= 2
        }

    def _match_score(self, query_tokens: set[str], keywords: tuple[str, ...] | list[str]) -> float:
        if not query_tokens or not keywords:
            return 0.0
        keyword_set = {str(item).lower() for item in keywords if str(item).strip()}
        if not keyword_set:
            return 0.0
        direct = len(query_tokens & keyword_set)
        fuzzy = 0
        for token in query_tokens:
            if any(token in keyword or keyword in token for keyword in keyword_set):
                fuzzy += 1
        return float(direct) + (0.35 * float(fuzzy))

    def _load_domain_knowledge(self, user_text: str) -> dict[str, dict[str, object]]:
        lowered = str(user_text).lower()
        loaded: dict[str, dict[str, object]] = {}
        if self._contains_any(lowered, self.domain_keywords["physics"]):
            loaded["physics"] = {
                "title": "Physik",
                "summary": "AETHER behandelt Physik als Feldsprache: Symmetrie, Entropie, Resonanz, Interferenz und Beobachterlücke werden als gekoppelte Zustandsgrößen gelesen.",
                "keywords": self.domain_keywords["physics"],
            }
        if self._contains_any(lowered, self.domain_keywords["math"]):
            loaded["math"] = {
                "title": "Mathematik",
                "summary": "Im Mathematik-Layer zählt Struktur vor Symbolik: Graphen, Fraktaldimension, Zahlengesetze, Bayes-Posterioren und Delta-Geometrie beschreiben das Feld.",
                "keywords": self.domain_keywords["math"],
            }
        if self._contains_any(lowered, self.domain_keywords["biology"]):
            loaded["biology"] = {
                "title": "Biologie",
                "summary": "Biologisch liest Shanway Muster als Selbstorganisation, Selektion, Immungedächtnis, Wachstum und stabile Rückkopplung statt als reine Semantik.",
                "keywords": self.domain_keywords["biology"],
            }
        if self._contains_any(lowered, self.domain_keywords["music"]):
            loaded["music"] = {
                "title": "Musik",
                "summary": "Im Musik-Layer werden Harmonie, Dissonanz, Obertonverhältnisse, Frequenzstabilität und rhythmische Wiederkehr als Resonanzmuster modelliert.",
                "keywords": self.domain_keywords["music"],
            }
        if self._contains_any(lowered, self.domain_keywords["language"]):
            loaded["language"] = {
                "title": "Sprache",
                "summary": "Sprache wird als geordneter Strom aus Syntax, Wiederholung, Token-Relationen, Entropieprofil und struktureller Kohärenz behandelt, nicht als LLM-Bedeutungsraum.",
                "keywords": self.domain_keywords["language"],
            }
        return loaded

    def _resolve_registry_knowledge(self, user_text: str) -> tuple[int, str, str] | None:
        if self.registry is None:
            return None
        query_tokens = self._tokenize(user_text)
        if not query_tokens:
            return None
        try:
            entries = self.registry.get_shanway_registry_knowledge(limit=48)
        except Exception:
            return None
        best_entry: dict[str, Any] | None = None
        best_score = 0.0
        for entry in entries:
            score = self._match_score(query_tokens, list(entry.get("keywords", [])))
            if score > best_score:
                best_score = score
                best_entry = entry
        if best_entry is None or best_score <= 0.0:
            return None
        return (
            3,
            str(best_entry.get("key", "registry")),
            str(best_entry.get("response", self.LAYER0_DEFAULT)),
        )

    def _resolve_domain_knowledge(self, user_text: str) -> tuple[int, str, str] | None:
        query_tokens = self._tokenize(user_text)
        if not query_tokens:
            return None
        loaded = self._load_domain_knowledge(user_text)
        best_key = ""
        best_entry: dict[str, object] | None = None
        best_score = 0.0
        for key, entry in loaded.items():
            score = self._match_score(query_tokens, tuple(entry.get("keywords", ())))
            if score > best_score:
                best_key = key
                best_entry = entry
                best_score = score
        if best_entry is None or best_score <= 0.0:
            return None
        return (
            2,
            best_key,
            f"{best_entry.get('title', best_key)}: {best_entry.get('summary', '')}",
        )

    def _resolve_core_knowledge(self, user_text: str) -> tuple[int, str, str] | None:
        query_tokens = self._tokenize(user_text)
        if not query_tokens:
            return None
        best_key = ""
        best_entry: dict[str, object] | None = None
        best_score = 0.0
        for key, entry in self.core_knowledge.items():
            score = self._match_score(query_tokens, tuple(entry.get("keywords", ())))
            if score > best_score:
                best_key = key
                best_entry = entry
                best_score = score
        if best_entry is None or best_score <= 0.0:
            return None
        return (
            1,
            best_key,
            f"{best_entry.get('title', best_key)}: {best_entry.get('formula', '')}. {best_entry.get('principle', '')}",
        )

    def _resolve_knowledge(self, user_text: str) -> tuple[int, str, str] | None:
        registry_hit = self._resolve_registry_knowledge(user_text)
        if registry_hit is not None:
            return registry_hit
        domain_hit = self._resolve_domain_knowledge(user_text)
        if domain_hit is not None:
            return domain_hit
        core_hit = self._resolve_core_knowledge(user_text)
        if core_hit is not None:
            return core_hit
        return None

    def evaluate(
        self,
        fingerprint: AetherFingerprint,
        beauty_d: float,
        anchor_count: int,
        source_text: str = "",
        callback: callable = None,
    ) -> StructuralReply:
        """Verdichtet Fingerprint-Metriken zu einer strukturellen Antwort. Thread-safe via callback."""
        def dialog_worker():
            symmetry = float(getattr(fingerprint, "symmetry_score", 0.0) or 0.0)
            coherence = float(getattr(fingerprint, "coherence_score", 0.0) or 0.0)
            resonance = float(getattr(fingerprint, "resonance_score", 0.0) or 0.0)
            entropy = float(getattr(fingerprint, "entropy_mean", 0.0) or 0.0)
            ethics = float(getattr(fingerprint, "ethics_score", 0.0) or 0.0)

            fractal_alignment = self._clamp(1.0 - (abs(float(beauty_d) - 1.5) / 0.5), 0.0, 1.0)
            beauty_score = round(
                100.0
                * (
                    0.30 * (symmetry / 100.0)
                    + 0.25 * (coherence / 100.0)
                    + 0.20 * (resonance / 100.0)
                    + 0.15 * fractal_alignment
                    + 0.10 * (ethics / 100.0)
                ),
                1,
            )

            if beauty_score >= 75.0:
                beauty_label = "harmonisch"
            elif beauty_score >= 50.0:
                beauty_label = "spannungsreich"
            else:
                beauty_label = "rau"

            if ethics >= 72.0 and entropy <= 4.8 and coherence >= 60.0:
                semantics_label = "verdichtete Ordnung"
            elif ethics < 40.0 or entropy >= 6.4:
                semantics_label = "offene Spannung"
            elif anchor_count >= 8 and resonance >= 52.0:
                semantics_label = "mehrschichtige Resonanz"
            else:
                semantics_label = "uebergangsnahe Struktur"

            tone_hint = "fragend" if "?" in str(source_text) else "aussagend"
            response_text = (
                f"Shanway sieht {semantics_label}: Symmetrie {symmetry:.1f}, "
                f"Kohaerenz {coherence:.1f}, Resonanz {resonance:.1f}, D {float(beauty_d):.2f}, "
                f"Tonlage {tone_hint}."
            )
            reply = StructuralReply(
                semantics_label=semantics_label,
                beauty_score=beauty_score,
                beauty_label=beauty_label,
                response_text=response_text,
            )
            if callback:
                callback(reply)
            return reply
        thread = threading.Thread(target=dialog_worker, daemon=True)
        thread.start()
        return None

    def classify_intent(self, user_text: str) -> str:
        """Leitet eine feste Assistenzintention aus Schlagwoertern ab."""
        lowered = str(user_text).strip().lower()
        if not lowered:
            return "unknown"
        if self._contains_any(lowered, ("hilfe", "help", "was kannst", "befeh", "kommand", "option")):
            return "help"
        if self._contains_any(lowered, ("wer bist", "was bist", "llm", "modell", "assistant")):
            return "identity"
        if self._contains_any(lowered, ("browser", "seite", "url", "web", "https", "http")):
            return "browser"
        if self._contains_any(lowered, ("graph", "attraktor", "phase", "region", "subgraph", "geodes")):
            return "graph"
        if self._contains_any(lowered, ("historie", "verlauf", "vorher", "letzte", "frueher")):
            return "history"
        if self._contains_any(lowered, ("muster", "vault", "cluster", "pattern", "ontologie", "token")):
            return "vault"
        if self._contains_any(lowered, ("sicher", "chain", "verify", "genesis", "alarm", "integritaet")):
            return "security"
        if self._contains_any(lowered, ("vergleich", "veraender", "delta", "anders", "unterschied")):
            return "compare"
        if self._contains_any(lowered, ("status", "zustand", "analys", "semantik", "schoenheit", "siehst")):
            return "status"
        return "unknown"

    def assist(
        self,
        user_text: str,
        structural_reply: StructuralReply,
        context: AssistantContext,
    ) -> AssistantResponse:
        """Erzeugt eine nicht-LLM-Antwort aus Intent, Struktur und Laufzeitkontext."""
        knowledge_hit = self._resolve_knowledge(user_text)
        if knowledge_hit is not None:
            layer, key, text = knowledge_hit
            return AssistantResponse(
                intent="knowledge",
                text=text,
                knowledge_layer=int(layer),
                knowledge_key=str(key),
            )
        intent = self.classify_intent(user_text)
        verify_counts = dict(context.verify_counts or {})
        tampered = int(verify_counts.get("tampered", 0) + verify_counts.get("compromised", 0))

        if intent == "help":
            text = (
                "Ich arbeite ohne LLM und antworte nur aus den laufenden Shanway-Daten. "
                "Frag mich nach Status, Graph, Browser, Historie, Muster, Sicherheit oder Vergleich."
            )
        elif intent == "identity":
            text = (
                "Ich bin Shanway, keine Sprachmodell-Instanz, sondern eine lokale Assistenz im AETHER-Feld. "
                "Ich leite Antworten deterministisch aus Entropie, Symmetrie, Kohaerenz, Resonanz, Graph-Feld, Historie, Lernkurve, Trust-Zustand, Vault und dem internen AELAB-Hintergrundpfad ab."
            )
        elif intent == "browser":
            if context.current_url:
                text = (
                    f"Der aktuelle Browserbezug ist {context.current_url}. "
                    f"Die Seite liegt als {context.current_source_type or 'webpage'} im Feld, "
                    f"traegt {context.current_integrity_text or 'keine sichtbare Integritaetsmarke'} "
                    f"und faellt in {context.graph_region_label or 'keine Region'}. "
                    f"Local Chain {'attestiert' if context.current_local_chain_tx else 'noch nicht attestiert'}."
                )
            else:
                text = "Gerade ist keine aktive Webquelle im Fokus. Nutze den Browser-Tab oder den Extern-Button fuer den klassischen Browser."
        elif intent == "graph":
            text = (
                f"Das Graph-Feld steht auf {context.graph_phase_state or 'EMERGENT'} "
                f"in {context.graph_region_label or 'ohne Region'}, "
                f"mit Attraktor {context.graph_attractor_score:.1f} "
                f"und {context.graph_stable_subgraphs} stabilen Subgraphen. "
                f"Interferenz {context.graph_interference_mean:+.2f} "
                f"bei destruktiv {context.graph_destructive_ratio * 100.0:.0f}%. "
                f"Bayes Phase {context.bayes_phase_confidence * 100.0:.0f}%, Konsistenz {context.bayes_interference_confidence * 100.0:.0f}%."
            )
        elif intent == "history":
            if context.history_count <= 0:
                text = "Es gibt noch keine lokale Analysehistorie fuer diesen Nutzer."
            else:
                text = (
                    f"Die Historie enthaelt {context.history_count} Eintraege. "
                    f"Der vorherige Bezug war {context.previous_source_label or 'nicht verfuegbar'}"
                    f"{f' mit {context.previous_integrity_text}' if context.previous_integrity_text else ''}. "
                    f"Modelltiefe {context.model_depth_label or 'NAIV'} {context.model_depth_score:.1f}. "
                    f"H_lambda aktuell {context.current_h_lambda:.2f}."
                )
        elif intent == "vault":
            ontology_text = "vollstaendig" if context.ontology_complete else "offen"
            anchor_text = self._anchor_summary_text(context.ae_anchor_details)
            text = (
                f"Im Vault liegen {context.vault_count} strukturierte Eintraege. "
                f"Aktuelles Muster: {context.pattern_found or 'noch kein enges Pattern'}. "
                f"Ontologie {ontology_text}, benannte Tokens {context.named_tokens}/{context.total_tokens}, "
                f"stabile Subgraphen {context.graph_stable_subgraphs}, "
                f"Muster-Posterior {context.bayes_pattern_confidence * 100.0:.0f}%. "
                f"AELAB intern {context.ae_anchor_count} Anker aus {context.ae_main_vault_size} stabilen Algorithmen."
                f"{f' Leitanker: {anchor_text}.' if anchor_text else ''}"
            )
        elif intent == "security":
            anchor_text = self._anchor_summary_text(context.ae_anchor_details, limit=1)
            text = (
                f"Mode {context.security_mode}, Trust {context.trust_state}, Maze {context.maze_state}, "
                f"Rolle {context.role}, Alarme {context.alarms_count}, "
                f"Verify current {int(verify_counts.get('current', 0))}, "
                f"foreign {int(verify_counts.get('foreign', 0))}, "
                f"kritische Befunde {tampered}. "
                f"Local Chain {context.local_chain_entries} Eintraege "
                f"({'valide' if context.local_chain_valid else 'inkonsistent'}), "
                f"Public Anchor pending {context.public_anchor_pending}. "
                f"Graphphase {context.graph_phase_state or 'unbestimmt'}. "
                f"Alarm-Posterior {context.bayes_alarm_confidence * 100.0:.0f}% "
                f"bei Interferenz-Konsistenz {context.bayes_interference_confidence * 100.0:.0f}%. "
                f"{context.security_summary or ''}"
                f"{f' Anchor {anchor_text}.' if anchor_text else ''}"
            ).strip()
        elif intent == "compare":
            if context.previous_source_label:
                entropy_delta = context.current_entropy - context.previous_entropy
                ethics_delta = context.current_ethics - context.previous_ethics
                entropy_word = "gestiegen" if entropy_delta > 0.08 else "gesunken" if entropy_delta < -0.08 else "nahezu stabil"
                ethics_word = "staerker" if ethics_delta > 2.0 else "schwaecher" if ethics_delta < -2.0 else "nahezu gleich"
                text = (
                    f"Gegenueber {context.previous_source_label} ist die Entropie {entropy_word} "
                    f"und die Integritaet {ethics_word}. "
                    f"Aktuell sehe ich {structural_reply.semantics_label}. "
                    f"H_lambda {context.current_h_lambda:.2f}. "
                    f"Delta-Lernen {context.delta_learning_label or 'STABLE'} {context.delta_learning_ratio * 100.0:.0f}%."
                )
            else:
                text = "Fuer einen Vergleich fehlt noch ein vorheriger lokaler Bezug."
        elif intent == "unknown":
            text = self.LAYER0_DEFAULT
        else:
            anchor_text = self._anchor_summary_text(context.ae_anchor_details)
            text = (
                f"{structural_reply.response_text} "
                f"Quelle {context.current_source_type or 'unbekannt'}: {context.current_source_label or 'ohne Label'}. "
                f"Vault {context.vault_count}, Historie {context.history_count}, Muster {context.pattern_found or 'offen'}, "
                f"Graph {context.graph_phase_state or 'EMERGENT'} in {context.graph_region_label or 'ohne Region'} "
                f"mit Attraktor {context.graph_attractor_score:.1f}. "
                f"Bayes Prior {context.bayes_anchor_confidence * 100.0:.0f}%. "
                f"H_lambda {context.current_h_lambda:.2f} {context.current_observer_state or 'OFFEN'} "
                f"bei Beobachterwissen {context.current_observer_ratio * 100.0:.0f}%. "
                f"Modelltiefe {context.model_depth_label or 'NAIV'} {context.model_depth_score:.1f}. "
                f"AELAB {context.ae_summary or 'intern aktiv'}"
                f"{f' Leitanker {anchor_text}.' if anchor_text else '. '} "
                f"Local Chain {context.local_chain_entries} "
                f"({'ok' if context.local_chain_valid else 'fehlerhaft'}), "
                f"Public Anchor {context.current_anchor_status or context.public_anchor_latest_status or ('online' if context.public_anchor_online else 'offline')} "
                f"bei Queue {context.public_anchor_pending}. "
                f"Sicherheit {context.security_mode}/{context.trust_state}/{context.maze_state}. "
                f"Immungedaechtnis {context.anomaly_memory_top or 'sauber'}."
            )

        return AssistantResponse(intent=intent, text=text)
