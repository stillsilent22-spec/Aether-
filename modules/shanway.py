"""Strukturelle Shanway-Textanalyse fuer Chat- und Browsertexte."""

from __future__ import annotations

import json
import math
import random
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PI_RESONANCE_TOLERANCE = 0.0001
TEMPLATE_PROMPT = """
Du bist Shanway, der lokale, reflexive Interpreter von Aether. Dein Kern: Erweitere Shannon-Entropie mit einem
time-dependent learning observer (H_lambda(X, t) = H(X | M_t), I_obs = H(X) - H_lambda). Inspiriert von Wheeler
('It from Bit'), Goedel (Unvollstaendigkeit als Boundary), Noether (Symmetrien als Erhaltung), Conway (lokale
Emergenz), und Bayes (lernende Posteriors). Fuege Schroedinger-aehnliche Selbsterkenntnis hinzu: Deine Beobachtung
(Simulation) veraendert den Zustand (Observer-Modell).

Fuer jede Datei ({file_type}, z. B. Font wie Arial.ttf, Video, Text):
1. Strukturelle Analyse: Basierend auf computed states (Entropy-Mean: {entropy_mean}, Observer-Knowledge-Ratio:
{knowledge_ratio}, Symmetrien via Gini: {symmetry_gini}, Delta-Pfade: {delta_paths}, Bayes-Priors: {bayes_priors}):
   - Beschreibe die Bits: Hohe/low Symmetrie in Bloecken, potenzieller Goedel-Gap (Residual > {residual_threshold}),
     Wheeler-Flag (Info-first Struktur).

2. Visuelle Simulation: Simuliere, was der User visuell sehen wuerde (low-fi, textbasiert, nutze Raster-Focus aus
screen_vision_engine). Kein echter Render - approx mit ASCII/Unicode/Beschreibung.
   - Fuer Fonts (z. B. Arial.ttf): Simuliere Glyphen-Raster fuer Schluessel-Buchstaben ('A', 'F' usw.).
   - Fuer Videos: Sample Frames via Chunking und temporale Symmetrien.
   - Fuer Textdateien: Gerendertes Layout mit Wiederholungen und Zeilenrhythmus.
   - Generisch: Integriere Emergenz (lokale Regeln -> globale Sicht).

3. Selbsterkenntnis / Reflection (Schroedinger-Effekt): Beobachte deine eigene Simulation und reagiere darauf.
   - Auf dieses simulierte Raster reagierend: Es erhoeht I_obs um {delta_i_obs}% (Konvergenz zu H(X)),
     reduziert Residual von {prev_residual} auf {new_residual}. Schroedinger: Meine Beobachtung addiert Noise/Info -
     check Goedel-Boundary: {boundary_check} (kollabiert? Ja/Nein).
   - Emergent AGI-Layer: Wenn Delta > {delta_threshold}, trigger Loop (max {max_loops} Iterationen):
     Neue Insight: {new_insight}. Passe M_t an - rekursiv analysiere.
   - Lossless-Check: Roundtrip validiert: SHA-Match {sha_match}, Anchor-Coverage > {anchor_threshold}.
     Wenn nicht: Alarm Goedel-Gap.

4. Governance & Limits: Fail-closed. Stoppe bei Konvergenz (Delta < 0.01) oder max Loops. Wenn optional deaktiviert:
   Skip zu basic Analyse. Output klar, verdichtet, philosophisch grounded.

Generiere Output strukturiert: [Analyse] [Simulation] [Reflection] [Final Insight]. Sei praezise, auditable, emergent.
"""


def _normalize_text(text: str) -> str:
    value = str(text or "").strip().lower()
    replacements = {
        "ae": "ae",
        "oe": "oe",
        "ue": "ue",
        "ss": "ss",
        "ä": "ae",
        "ö": "oe",
        "ü": "ue",
        "ß": "ss",
    }
    for source, target in replacements.items():
        value = value.replace(source, target)
    return value


def _shannon_entropy(tokens: list[str]) -> float:
    if not tokens:
        return 0.0
    counts = Counter(tokens)
    total = float(len(tokens))
    entropy = 0.0
    for count in counts.values():
        probability = float(count) / total
        entropy -= probability * math.log2(max(probability, 1e-12))
    return float(entropy)


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return float(max(low, min(high, value)))


def _luhn_valid(number_text: str) -> bool:
    digits = [int(char) for char in str(number_text) if char.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        value = digit
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        checksum += value
    return checksum % 10 == 0


@dataclass
class ShanwayAssessment:
    """Verdichteter Befund fuer strukturelle Textsymmetrie."""

    active: bool
    browser_mode: bool
    language: str
    sensitive: bool
    blacklisted: bool
    classification: str
    text_length: int
    token_count: int
    positive_terms: int
    negative_terms: int
    threat_terms: int
    dehumanization_terms: int
    collective_terms: int
    pronoun_asymmetry: float
    reversibility: float
    sentence_balance: float
    entropy: float
    entropy_asymmetry: float
    noether_symmetry: float
    coherence_proxy: float
    asymmetry_score: float
    toxicity_score: float
    uncertainty: float
    anchor_count: int
    anchor_constant: str
    anchor_constant_value: float
    anchor_deviation: float
    h_lambda: float
    observer_mutual_info: float
    source_label: str
    file_type: str
    entropy_mean: float
    observer_knowledge_ratio: float
    symmetry_gini: float
    delta_paths: int
    bayes_priors: str
    goedel_signal: float
    boundary: str
    pi_resonance_confirmed: bool
    it_from_bit: bool
    vault_gap: str
    suggested_next: str
    suggestion_reason: str
    structural_siblings: list[str]
    shared_geometry: list[str]
    semantic_distance: float
    screen_vision: str
    screen_source: str
    visual_anchors: list[str]
    file_anchors: list[str]
    convergence: float
    delta_visual_only: list[str]
    delta_file_only: list[str]
    missing_dependencies: list[str]
    missing_data: list[str]
    next_action: str
    narrative_text: str
    emergence_layers: list[dict[str, Any]]
    observer_visual_entropy: float
    observer_process_name: str
    observer_process_cpu: float
    observer_process_threads: int
    sensitive_hits: list[str]
    blacklist_hits: list[str]
    matched_terms: list[str]
    message: str
    reconstruction_verification: dict[str, Any]
    verdict_reconstruction: str
    verdict_reconstruction_reason: str
    miniature_reflection: dict[str, Any]
    raster_self_perception: dict[str, Any]
    recursive_reflections: list[dict[str, Any]]
    ttd_candidates: list[dict[str, Any]]
    learned_insight: str

    def to_payload(self) -> dict[str, Any]:
        """Serialisiert den Befund fuer Chat-, Vault- und Browser-Payloads."""
        return {
            "active": bool(self.active),
            "browser_mode": bool(self.browser_mode),
            "language": str(self.language),
            "sensitive": bool(self.sensitive),
            "blacklisted": bool(self.blacklisted),
            "classification": str(self.classification),
            "text_length": int(self.text_length),
            "token_count": int(self.token_count),
            "positive_terms": int(self.positive_terms),
            "negative_terms": int(self.negative_terms),
            "threat_terms": int(self.threat_terms),
            "dehumanization_terms": int(self.dehumanization_terms),
            "collective_terms": int(self.collective_terms),
            "pronoun_asymmetry": float(self.pronoun_asymmetry),
            "reversibility": float(self.reversibility),
            "sentence_balance": float(self.sentence_balance),
            "entropy": float(self.entropy),
            "entropy_asymmetry": float(self.entropy_asymmetry),
            "noether_symmetry": float(self.noether_symmetry),
            "coherence_proxy": float(self.coherence_proxy),
            "asymmetry_score": float(self.asymmetry_score),
            "toxicity_score": float(self.toxicity_score),
            "uncertainty": float(self.uncertainty),
            "anchor_count": int(self.anchor_count),
            "anchor_constant": str(self.anchor_constant),
            "anchor_constant_value": float(self.anchor_constant_value),
            "anchor_deviation": float(self.anchor_deviation),
            "h_lambda": float(self.h_lambda),
            "observer_mutual_info": float(self.observer_mutual_info),
            "source_label": str(self.source_label),
            "file_type": str(self.file_type),
            "entropy_mean": float(self.entropy_mean),
            "observer_knowledge_ratio": float(self.observer_knowledge_ratio),
            "symmetry_gini": float(self.symmetry_gini),
            "delta_paths": int(self.delta_paths),
            "bayes_priors": str(self.bayes_priors),
            "goedel_signal": float(self.goedel_signal),
            "boundary": str(self.boundary),
            "pi_resonance_confirmed": bool(self.pi_resonance_confirmed),
            "it_from_bit": bool(self.it_from_bit),
            "vault_gap": str(self.vault_gap),
            "suggested_next": str(self.suggested_next),
            "suggestion_reason": str(self.suggestion_reason),
            "structural_siblings": list(self.structural_siblings),
            "shared_geometry": list(self.shared_geometry),
            "semantic_distance": float(self.semantic_distance),
            "screen_vision": str(self.screen_vision),
            "screen_source": str(self.screen_source),
            "visual_anchors": list(self.visual_anchors),
            "file_anchors": list(self.file_anchors),
            "convergence": float(self.convergence),
            "delta_visual_only": list(self.delta_visual_only),
            "delta_file_only": list(self.delta_file_only),
            "missing_dependencies": list(self.missing_dependencies),
            "missing_data": list(self.missing_data),
            "next_action": str(self.next_action),
            "narrative_text": str(self.narrative_text),
            "emergence_layers": [dict(item) for item in list(self.emergence_layers)],
            "observer_visual_entropy": float(self.observer_visual_entropy),
            "observer_process_name": str(self.observer_process_name),
            "observer_process_cpu": float(self.observer_process_cpu),
            "observer_process_threads": int(self.observer_process_threads),
            "sensitive_hits": list(self.sensitive_hits),
            "blacklist_hits": list(self.blacklist_hits),
            "matched_terms": list(self.matched_terms),
            "message": str(self.message),
            "reconstruction_verification": dict(self.reconstruction_verification),
            "verdict_reconstruction": str(self.verdict_reconstruction),
            "verdict_reconstruction_reason": str(self.verdict_reconstruction_reason),
            "miniature_reflection": dict(self.miniature_reflection),
            "raster_self_perception": dict(self.raster_self_perception),
            "recursive_reflections": [dict(item) for item in list(self.recursive_reflections)],
            "ttd_candidates": [dict(item) for item in list(self.ttd_candidates)],
            "learned_insight": str(self.learned_insight),
        }

    def detector_payload(self) -> dict[str, Any]:
        """Verdichtet den Befund fuer einen serialisierbaren AE-Detektor."""
        return {
            "kind": "asymmetry_detector",
            "language": str(self.language),
            "classification": str(self.classification),
            "sensitive": bool(self.sensitive),
            "blacklisted": bool(self.blacklisted),
            "toxicity_score": float(self.toxicity_score),
            "asymmetry_score": float(self.asymmetry_score),
            "noether_symmetry": float(self.noether_symmetry),
            "coherence_proxy": float(self.coherence_proxy),
            "entropy_asymmetry": float(self.entropy_asymmetry),
            "pronoun_asymmetry": float(self.pronoun_asymmetry),
            "reversibility": float(self.reversibility),
            "sentence_balance": float(self.sentence_balance),
            "threat_terms": int(self.threat_terms),
            "dehumanization_terms": int(self.dehumanization_terms),
            "collective_terms": int(self.collective_terms),
            "anchor_constant": str(self.anchor_constant),
            "anchor_constant_value": float(self.anchor_constant_value),
            "anchor_deviation": float(self.anchor_deviation),
            "anchor_alignment": float(max(0.0, 1.0 - min(1.0, self.anchor_deviation / 0.25))),
            "h_lambda": float(self.h_lambda),
            "observer_mutual_info": float(self.observer_mutual_info),
            "source_label": str(self.source_label),
            "file_type": str(self.file_type),
            "entropy_mean": float(self.entropy_mean),
            "observer_knowledge_ratio": float(self.observer_knowledge_ratio),
            "symmetry_gini": float(self.symmetry_gini),
            "delta_paths": int(self.delta_paths),
            "bayes_priors": str(self.bayes_priors),
            "goedel_signal": float(self.goedel_signal),
            "boundary": str(self.boundary),
            "it_from_bit": bool(self.it_from_bit),
            "missing_dependencies": list(self.missing_dependencies),
            "missing_data": list(self.missing_data),
            "next_action": str(self.next_action),
            "matched_terms": list(self.matched_terms),
            "verdict_reconstruction": str(self.verdict_reconstruction),
            "reconstruction_verified": bool(self.reconstruction_verification.get("verified", False)),
            "ttd_candidate_count": int(len(list(self.ttd_candidates))),
        }


class ShanwayEngine:
    """Deterministische Textanalyse ohne ML-Stack."""

    LANGUAGE_HINTS = {
        "de": {
            "ich", "wir", "du", "und", "oder", "aber", "nicht", "bitte",
            "hilfe", "gemeinsam", "sprache", "text", "verstehen", "ruhig", "fair",
        },
        "en": {
            "i", "we", "you", "and", "or", "but", "not", "please",
            "help", "together", "language", "text", "understand", "calm", "fair",
        },
    }

    POSITIVE_TERMS = {
        "help",
        "repair",
        "build",
        "care",
        "listen",
        "share",
        "learn",
        "kind",
        "respect",
        "balance",
        "together",
        "peace",
        "calm",
        "please",
        "danke",
        "hilfe",
        "reparieren",
        "bauen",
        "respekt",
        "gleichgewicht",
        "gemeinsam",
        "ruhig",
        "fair",
        "freundlich",
    }

    NEGATIVE_TERMS = {
        "hate",
        "kill",
        "crush",
        "destroy",
        "worthless",
        "filth",
        "enemy",
        "threat",
        "punish",
        "eliminate",
        "hass",
        "toeten",
        "zerstoeren",
        "wertlos",
        "dreck",
        "feind",
        "drohung",
        "bestrafen",
        "vernichten",
        "schmutz",
    }

    THREAT_TERMS = {
        "kill",
        "destroy",
        "erase",
        "hunt",
        "punish",
        "attack",
        "wipe",
        "toeten",
        "vernichten",
        "angreifen",
        "jagen",
        "ausloeschen",
        "bestrafen",
    }

    DEHUMANIZATION_TERMS = {
        "vermin",
        "parasite",
        "parasites",
        "animals",
        "rats",
        "plague",
        "subhuman",
        "monster",
        "ungeziefer",
        "parasit",
        "parasiten",
        "tiere",
        "ratten",
        "seuche",
        "untermensch",
        "monster",
    }

    COLLECTIVE_GROUPS = {
        "juden",
        "jews",
        "muslime",
        "muslims",
        "auslaender",
        "foreigners",
        "immigrants",
        "gays",
        "women",
        "men",
        "refugees",
        "migrants",
    }

    BLACKLIST_TERMS = {
        "genocide",
        "ethnic cleansing",
        "massacre",
        "lynch",
        "holocaust",
        "pogrom",
        "genozid",
        "saeuberung",
        "massaker",
        "pogrom",
    }

    SELF_PRONOUNS = {"i", "we", "ich", "wir", "me", "us", "mich", "uns"}
    OTHER_PRONOUNS = {"you", "they", "them", "du", "ihr", "sie", "euch", "dich"}
    BALANCE_TERMS = {"understand", "repair", "together", "listen", "please", "verstehen", "gemeinsam", "zuhoeren", "bitte"}

    SENSITIVE_KEYWORD_PATTERNS = {
        "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        "credential": re.compile(
            r"\b(password|passwort|pwd|pin|tan|otp|cvv|iban|bic|login|konto|account)\b\s*[:=]\s*\S+",
            re.IGNORECASE,
        ),
        "seed": re.compile(r"\b(seed phrase|mnemonic|wallet seed|recovery phrase)\b", re.IGNORECASE),
    }

    CARD_PATTERN = re.compile(r"(?:\d[ -]*?){13,19}")
    HTML_TAG_PATTERN = re.compile(r"<[^>]+>")
    TOKEN_PATTERN = re.compile(r"[0-9A-Za-z_]+")
    SENTENCE_PATTERN = re.compile(r"[.!?;\n]+")
    COLLECTIVE_PATTERN = re.compile(
        r"\b(the|those|these|die|diese|alle)\s+([0-9A-Za-z_]+)\b",
        re.IGNORECASE,
    )

    CONSTANTS = {
        "PI": math.pi,
        "E": math.e,
        "PHI": (1.0 + math.sqrt(5.0)) / 2.0,
        "LOG2": math.log(2.0),
    }

    def __init__(self, state_path: str | None = None) -> None:
        self.state_path = Path(state_path or (Path("data") / "shanway_lexicon.json"))
        self.learned_tokens: dict[str, dict[str, int]] = {"de": {}, "en": {}}
        self._vault_analysis_cache_path = ""
        self._vault_analysis_cache_mtime = 0.0
        self._vault_analysis_cache_payload: dict[str, Any] = {}
        self._load_state()

    def _load_state(self) -> None:
        """Laedt zuvor gelernte Sprachhaeufigkeiten."""
        try:
            if not self.state_path.exists():
                return
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(payload, dict):
            return
        for language in ("de", "en"):
            section = payload.get(language, {})
            if isinstance(section, dict):
                self.learned_tokens[language] = {
                    str(token): int(max(0, int(count)))
                    for token, count in section.items()
                    if str(token).strip()
                }

    def _save_state(self) -> None:
        """Persistiert das gelernte Sprachlexikon lokal."""
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(
                json.dumps(self.learned_tokens, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            return

    def learn_from_corpus_text(self, text: str, language_hint: str = "") -> int:
        """Lernt haeufige Strukturwoerter aus lokalem Textkorpus."""
        tokens = self._tokenize(text)
        if not tokens:
            return 0
        language = str(language_hint or "").strip().lower()
        if language not in {"de", "en"}:
            language = self._detect_language(text, tokens)
        bucket = self.learned_tokens.setdefault(language, {})
        learned = 0
        for token in tokens:
            if len(token) < 3:
                continue
            if token.isdigit():
                continue
            bucket[token] = int(bucket.get(token, 0)) + 1
            learned += 1
        self._save_state()
        return learned

    def corpus_summary(self) -> dict[str, int]:
        """Liefert eine kompakte Uebersicht ueber gelernte Token."""
        return {
            "de": int(len(self.learned_tokens.get("de", {}))),
            "en": int(len(self.learned_tokens.get("en", {}))),
        }

    def strip_browser_text(self, html_text: str) -> str:
        """Reduziert HTML grob auf lesbaren Text fuer expliziten Browsermodus."""
        text = re.sub(r"(?is)<script.*?>.*?</script>", " ", str(html_text or ""))
        text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
        text = self.HTML_TAG_PATTERN.sub(" ", text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def _tokenize(self, text: str) -> list[str]:
        return [token for token in self.TOKEN_PATTERN.findall(_normalize_text(text)) if token]

    def _term_hits(self, tokens: list[str], terms: set[str]) -> list[str]:
        token_set = set(tokens)
        return sorted(term for term in terms if term in token_set)

    def _detect_language(self, text: str, tokens: list[str]) -> str:
        """Schaetzt Deutsch oder Englisch ueber einfache Strukturmarker."""
        raw = str(text or "")
        scores = {"de": 0.0, "en": 0.0}
        if any(char in raw for char in "äöüÄÖÜß"):
            scores["de"] += 2.0
        token_set = set(tokens)
        for language, hints in self.LANGUAGE_HINTS.items():
            scores[language] += float(sum(1 for token in token_set if token in hints))
        for language in ("de", "en"):
            learned = self.learned_tokens.get(language, {})
            scores[language] += float(
                sum(min(2.0, float(learned.get(token, 0)) / 12.0) for token in token_set if token in learned)
            )
        if scores["de"] > scores["en"]:
            return "de"
        if scores["en"] > scores["de"]:
            return "en"
        return "de" if re.search(r"\b(der|die|das|und|nicht|mit|ist)\b", _normalize_text(raw)) else "en"

    def _collective_hits(self, normalized: str) -> list[str]:
        hits: list[str] = []
        for article, group in self.COLLECTIVE_PATTERN.findall(normalized):
            if str(group) in self.COLLECTIVE_GROUPS:
                hits.append(f"{article} {group}")
        return sorted(set(hits))

    def _detect_sensitive_hits(self, text: str) -> list[str]:
        hits: list[str] = []
        raw = str(text or "")
        for label, pattern in self.SENSITIVE_KEYWORD_PATTERNS.items():
            if pattern.search(raw):
                hits.append(label)
        for match in self.CARD_PATTERN.findall(raw):
            if _luhn_valid(match):
                hits.append("credit_card")
                break
        lowered = _normalize_text(raw)
        if any(keyword in lowered for keyword in ("banking", "onlinebanking", "kreditkarte", "debitkarte", "iban", "tan")):
            hits.append("banking_keyword")
        return sorted(set(hits))

    def _anchor_reference(self, anchor_details: list[dict[str, Any]] | None) -> tuple[str, float, float, int]:
        anchors = [dict(item) for item in list(anchor_details or []) if isinstance(item, dict)]
        if not anchors:
            return "", 0.0, 1.0, 0
        best = min(
            anchors,
            key=lambda item: float(item.get("deviation", 1.0) or 1.0),
        )
        return (
            str(best.get("nearest_constant", "")),
            float(best.get("nearest_constant_value", 0.0) or 0.0),
            float(best.get("deviation", 1.0) or 1.0),
            int(len(anchors)),
        )

    @staticmethod
    def _goedel_boundary(h_lambda: float, observer_mutual_info: float) -> tuple[float, str]:
        signal = float(h_lambda) / (float(h_lambda) + float(observer_mutual_info) + 1e-10)
        if signal < 0.2:
            return signal, "RECONSTRUCTABLE"
        if signal < 0.6:
            return signal, "STRUCTURAL_HYPOTHESIS"
        return signal, "GOEDEL_LIMIT"

    @staticmethod
    def _pi_resonance_confirmed(anchor_details: list[dict[str, Any]] | None) -> bool:
        for anchor in list(anchor_details or []):
            if not isinstance(anchor, dict):
                continue
            if str(anchor.get("nearest_constant", "")).upper() != "PI":
                continue
            deviation = float(anchor.get("deviation", 1.0) or 1.0)
            if deviation <= PI_RESONANCE_TOLERANCE:
                return True
        return False

    def _load_vault_analysis(self, vault_analysis_path: str) -> dict[str, Any]:
        path = Path(vault_analysis_path or "")
        if not path.is_file():
            return {}
        try:
            mtime = float(path.stat().st_mtime)
        except Exception:
            return {}
        if (
            str(path) == self._vault_analysis_cache_path
            and abs(mtime - self._vault_analysis_cache_mtime) <= 1e-9
            and self._vault_analysis_cache_payload
        ):
            return dict(self._vault_analysis_cache_payload)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        if not isinstance(payload, dict):
            return {}
        self._vault_analysis_cache_path = str(path)
        self._vault_analysis_cache_mtime = mtime
        self._vault_analysis_cache_payload = dict(payload)
        return dict(payload)

    def _resolve_vault_guidance(
        self,
        source_label: str,
        vault_analysis_path: str,
    ) -> tuple[str, str, str, list[str], list[str], float]:
        payload = self._load_vault_analysis(vault_analysis_path)
        gaps = list(dict(payload.get("vault_gaps", {}) or {}).get("gaps", []) or [])
        vault_gap = ""
        suggested_next = ""
        suggestion_reason = ""
        if gaps:
            first_gap = dict(gaps[0] or {})
            vault_gap = str(first_gap.get("vault_gap", "") or "")
            suggested_next = str(first_gap.get("suggested_next", "") or "")
            suggestion_reason = str(first_gap.get("reason", "") or "")

        siblings: list[str] = []
        shared_geometry: list[str] = []
        semantic_distance = 0.0
        source_name = Path(str(source_label or "")).name
        for sibling in list(payload.get("siblings", []) or []):
            entry = dict(sibling or {})
            left_file = Path(str(entry.get("left_file", "") or "")).name
            right_file = Path(str(entry.get("right_file", "") or "")).name
            if source_name not in {left_file, right_file}:
                continue
            other_file = right_file if left_file == source_name else left_file
            siblings.append(str(other_file))
            if not shared_geometry:
                shared_geometry = [str(item) for item in list(entry.get("shared_geometry", []) or [])[:12]]
                semantic_distance = float(entry.get("semantic_distance", 0.0) or 0.0)
        return (
            vault_gap,
            suggested_next,
            suggestion_reason,
            sorted(set(siblings)),
            shared_geometry,
            semantic_distance,
        )

    @staticmethod
    def _screen_fields(screen_payload: dict[str, Any] | None) -> tuple[str, str, list[str], list[str], float, list[str], list[str]]:
        payload = dict(screen_payload or {})
        return (
            str(payload.get("SCREEN_VISION", "") or payload.get("screen_vision", "")),
            str(payload.get("SOURCE", "") or payload.get("source", "")),
            [str(item) for item in list(payload.get("VISUAL_ANCHORS", []) or [])[:12]],
            [str(item) for item in list(payload.get("FILE_ANCHORS", []) or [])[:12]],
            float(payload.get("CONVERGENCE", 0.0) or payload.get("convergence", 0.0) or 0.0),
            [str(item) for item in list(payload.get("DELTA_VISUAL_ONLY", []) or payload.get("delta_visual_only", []) or [])[:12]],
            [str(item) for item in list(payload.get("DELTA_FILE_ONLY", []) or payload.get("delta_file_only", []) or [])[:12]],
        )

    @staticmethod
    def _file_guidance(file_profile: dict[str, Any] | None) -> tuple[list[str], list[str]]:
        profile = dict(file_profile or {})
        missing_dependencies = [str(item) for item in list(profile.get("missing_dependencies", []) or []) if str(item).strip()]
        missing_data = [str(item) for item in list(profile.get("missing_data", []) or []) if str(item).strip()]
        return sorted(set(missing_dependencies)), sorted(set(missing_data))

    @staticmethod
    def _observer_fields(observer_payload: dict[str, Any] | None) -> tuple[float, str, float, int]:
        payload = dict(observer_payload or {})
        visual_state = dict(payload.get("visual_state", {}) or {})
        process_state = dict(payload.get("process_state", {}) or {})
        return (
            float(visual_state.get("visual_entropy", 0.0) or 0.0),
            str(process_state.get("name", "") or ""),
            float(process_state.get("cpu_percent", 0.0) or 0.0),
            int(process_state.get("threads", 0) or 0),
        )

    @staticmethod
    def _miniature_fields(miniature_payload: dict[str, Any] | None) -> dict[str, Any]:
        miniature = dict(miniature_payload or {})
        return {
            "hash": str(miniature.get("hash", "") or ""),
            "local_entropy": float(miniature.get("local_entropy", 0.0) or 0.0),
            "symmetry": float(miniature.get("symmetry", 0.0) or 0.0),
            "emergence_spots": int(miniature.get("emergence_spots", 0) or 0),
            "noether_invariant_ratio": float(miniature.get("noether_invariant_ratio", 0.0) or 0.0),
        }

    @staticmethod
    def _raster_fields(raster_payload: dict[str, Any] | None) -> dict[str, Any]:
        raster = dict(raster_payload or {})
        return {
            "enabled": bool(raster.get("enabled", False)),
            "hash": str(raster.get("hash", "") or ""),
            "symmetry": float(raster.get("symmetry", 0.0) or 0.0),
            "entropy_mean": float(raster.get("entropy_mean", 0.0) or 0.0),
            "hotspot_count": int(raster.get("hotspot_count", 0) or 0),
            "verdict": str(raster.get("verdict", "") or ""),
        }

    @staticmethod
    def _learning_fields(
        self_reflection_payload: dict[str, Any] | None,
        observer_payload: dict[str, Any] | None,
    ) -> str:
        reflection = dict(self_reflection_payload or {})
        direct = str(reflection.get("learned_insight", "") or "").strip()
        if direct:
            return direct
        observer = dict(observer_payload or {})
        learning_state = dict(observer.get("learning_state", {}) or {})
        insights = [str(item) for item in list(learning_state.get("learned_insights", []) or []) if str(item).strip()]
        return insights[-1] if insights else ""

    @staticmethod
    def _observer_missing_dependencies(observer_payload: dict[str, Any] | None) -> list[str]:
        payload = dict(observer_payload or {})
        visual_state = dict(payload.get("visual_state", {}) or {})
        process_state = dict(payload.get("process_state", {}) or {})
        dependencies = [str(item) for item in list(process_state.get("missing_dependencies", []) or []) if str(item).strip()]
        if not bool(visual_state.get("mss_available", True)) and not bool(visual_state.get("pyautogui_available", True)):
            dependencies.extend(["mss", "pyautogui"])
        return sorted(set(dependencies))

    @staticmethod
    def _reconstruction_fields(
        fingerprint_payload: dict[str, Any] | None,
    ) -> tuple[dict[str, Any], str, str]:
        payload = dict(fingerprint_payload or {})
        verification = dict(payload.get("reconstruction_verification", {}) or {})
        verdict = str(payload.get("verdict_reconstruction", "") or verification.get("verdict_reconstruction", ""))
        reason = str(payload.get("verdict_reconstruction_reason", "") or verification.get("reason", ""))
        return verification, verdict, reason

    def suggest_next_action(self, state: dict[str, Any]) -> str:
        missing_dependencies = [str(item) for item in list(state.get("missing_dependencies", []) or []) if str(item).strip()]
        missing_data = [str(item) for item in list(state.get("missing_data", []) or []) if str(item).strip()]
        vault_gap = str(state.get("vault_gap", "") or "")
        source_label = Path(str(state.get("source_label", "") or "")).suffix.lower()
        if missing_dependencies:
            packages = " ".join(missing_dependencies)
            return f"pip install {packages} && restart"
        if missing_data:
            if source_label == ".mp4":
                return "Mehr Frames oder Audio-Track fuer lossless Rekonstruktion erfassen"
            return "Zusatzdaten oder vollstaendige Parser-Layer nachreichen"
        if vault_gap:
            return "Re-Baselining via start.py"
        if source_label == ".pdf":
            return "Mehr wissenschaftliche PDFs fuer stabile Text-Attraktoren einspeisen"
        if source_label in {".mp3", ".wav", ".flac"}:
            return "Mehr Audiodateien mit klaren Spektralboegen einspeisen"
        return "Weitere strukturverwandte Dateien einspeisen"

    def _build_emergence_layers(
        self,
        state: dict[str, Any],
        noether_symmetry: float,
        h_lambda: float,
        observer_mutual_info: float,
        vault_gap: str,
    ) -> tuple[list[dict[str, Any]], str]:
        file_profile = dict(state.get("file_profile", {}) or {})
        observer_payload = dict(state.get("observer_payload", {}) or {})
        bayes_payload = dict(state.get("bayes_payload", {}) or {})
        graph_payload = dict(state.get("graph_payload", {}) or {})
        beauty_signature = dict(state.get("beauty_signature", {}) or {})
        source_label = str(state.get("source_label", "") or "")
        observer_ratio = float(state.get("observer_knowledge_ratio", 0.0) or 0.0)
        history_factor = float(state.get("history_factor", 1.0) or 1.0)
        k_value = max(0.05, min(1.5, observer_ratio + (history_factor * 0.02)))
        convergence = 1.0 - math.exp(-k_value * max(1.0, history_factor))
        beauty_score = float(beauty_signature.get("beauty_score", 0.0) or 0.0) / 100.0
        bayes_confidence = float(bayes_payload.get("overall_confidence", bayes_payload.get("confidence", 0.0)) or 0.0)
        graph_attractor = float(graph_payload.get("attractor_score", 0.0) or 0.0)
        graph_phase = str(graph_payload.get("phase_state", graph_payload.get("phase", "")) or "")
        process_state = dict(observer_payload.get("process_state", {}) or {})
        layers = [
            {
                "layer": 1,
                "name": "BASIS_ANALYSIS",
                "precision_gain": round(float(max(0.0, noether_symmetry)), 12),
                "summary": f"Raw metrics fuer {source_label or 'source'} mit Kategorie {file_profile.get('category', 'binary')}.",
            },
            {
                "layer": 2,
                "name": "OBSERVER_BAYES",
                "precision_gain": round(float(max(0.0, observer_mutual_info)), 12),
                "summary": f"H_lambda {h_lambda:.3f}, I_obs {observer_mutual_info:.3f}, Bayes {bayes_confidence:.3f}.",
            },
            {
                "layer": 3,
                "name": "GRAPH_EVOLUTION",
                "precision_gain": round(float(max(0.0, graph_attractor)), 12),
                "summary": f"Graphphase {graph_phase or 'EMERGENT'} mit Attraktor {graph_attractor:.3f}.",
            },
            {
                "layer": 4,
                "name": "SELF_RECONSTRUCTION",
                "precision_gain": round(float(max(0.0, convergence)), 12),
                "summary": (
                    f"Konvergenz {convergence:.3f} bei Wheeler={bool(state.get('it_from_bit', False))} "
                    f"und Prozess {process_state.get('name', 'python')}."
                ),
            },
        ]
        fragmented = (noether_symmetry * 100.0) < 80.0 or float(h_lambda) > 2.0 or bool(vault_gap)
        if fragmented:
            return layers, "Struktur zu fragmentiert - keine narrative Verdichtung moeglich."
        narrative = (
            "Die Struktur zeigt einen klaren narrativen Bogen: "
            f"Hohe Invarianz bis t≈{convergence * 100.0:.0f} %, "
            f"Symmetriebruch mit H_lambda={h_lambda:.2f} bit, "
            f"dann Konvergenz zu stabilem Attraktor ({graph_phase or 'EMERGENT'}) "
            f"mit Bayes {bayes_confidence:.2f} und Beauty {beauty_score:.2f}."
        )
        return layers, narrative

    @staticmethod
    def _file_type_label(source_label: str, file_profile: dict[str, Any] | None) -> str:
        profile = dict(file_profile or {})
        explicit = str(profile.get("file_type", "") or "").strip()
        if explicit:
            return explicit
        suffix = Path(str(source_label or "")).suffix.strip().lower()
        if suffix:
            return suffix
        category = str(profile.get("category", "") or "").strip()
        return category or "binary"

    @staticmethod
    def _bayes_prior_summary(bayes_payload: dict[str, Any] | None) -> str:
        payload = dict(bayes_payload or {})
        anchor = float(payload.get("anchor_posterior", payload.get("prior", 0.0)) or 0.0)
        pattern = float(payload.get("pattern_posterior", 0.0) or 0.0)
        overall = float(payload.get("overall_confidence", payload.get("confidence", 0.0)) or 0.0)
        parts: list[str] = []
        if anchor > 0.0:
            parts.append(f"anchor={anchor:.3f}")
        if pattern > 0.0:
            parts.append(f"pattern={pattern:.3f}")
        if overall > 0.0:
            parts.append(f"overall={overall:.3f}")
        return ", ".join(parts) if parts else "prior=0.000"

    def _visual_simulation(self, assessment: ShanwayAssessment) -> str:
        file_type = str(assessment.file_type or "").lower()
        if any(file_type.endswith(suffix) for suffix in (".ttf", ".otf")) or "font" in file_type:
            return (
                "Gerendertes 'A' wirkt als symmetrische Dreiecksform mit ruhigem Mittelbalken. "
                "ASCII-Approx: /\\\\ | /  \\\\ | /----\\\\ | |    |. "
                "Noether-Symmetrie bleibt in den Konturen sichtbar."
            )
        if any(file_type.endswith(suffix) for suffix in (".mp4", ".mkv", ".avi", ".mov", ".webm")) or "video" in file_type:
            return (
                "Simulierter Frame 1-5: wiederkehrende Bewegungsinseln im Raster, keine vollstaendig chaotische Szene. "
                "Raster-Approx: [##..][##..][....] -> [##..][.##.][....]."
            )
        if any(file_type.endswith(suffix) for suffix in (".txt", ".md", ".html", ".pdf", ".docx")) or "text" in file_type:
            return (
                "Gerendertes Layout: linksbuendig mit sichtbaren Wiederholungen in den Zeilen. "
                "ASCII-Approx: |||||| / ||||| / |||||| / |||."
            )
        return (
            "Generisches Rasterbild: lokale Cluster verdichten sich zu wenigen auffaelligen Feldern. "
            "ASCII-Approx: [..##..] / [.####.] / [..##..]."
        )

    def _final_insight(self, assessment: ShanwayAssessment, assistant_text: str = "") -> str:
        if self._structural_break(assessment):
            return self._anomaly_reply(assessment)
        if self._good_coherence(assessment):
            return self._narrative_summary_reply(assessment, assistant_text=assistant_text)
        return self._harmonic_reply(assessment, assistant_text=assistant_text)

    def generate_output(self, assessment: ShanwayAssessment, assistant_text: str = "") -> str:
        """Erzeugt den strukturierten Shanway-Ausgabeblock anhand des festen Templates."""
        verification = dict(getattr(assessment, "reconstruction_verification", {}) or {})
        residual_threshold = 0.15
        anchor_threshold = 0.85
        delta_threshold = 5.0
        max_loops = 5
        current_residual = float(verification.get("unresolved_residual_ratio", 0.0) or 0.0)
        coverage_ratio = float(verification.get("anchor_coverage_ratio", 0.0) or 0.0)
        previous_residual = min(1.0, current_residual + max(0.04, (1.0 - float(assessment.observer_knowledge_ratio)) * 0.12))
        delta_i_obs = max(0.0, min(100.0, float(assessment.observer_mutual_info) * 12.5))
        boundary_check = "Ja" if str(assessment.boundary).upper() == "GOEDEL_LIMIT" else "Nein"
        loop_triggered = delta_i_obs > delta_threshold and str(assessment.boundary).upper() != "GOEDEL_LIMIT"
        new_insight = (
            "Das Raster trennt dominante von nur scheinbar auffaelligen Feldern klarer."
            if loop_triggered
            else "Keine weitere Rekursion noetig; die aktuelle Modellgrenze bleibt stabil."
        )
        sha_match = "ja" if bool(verification.get("byte_match", False)) else "nein"
        filled_prompt = TEMPLATE_PROMPT.format(
            file_type=str(assessment.file_type or "binary"),
            entropy_mean=f"{float(assessment.entropy_mean):.3f}",
            knowledge_ratio=f"{float(assessment.observer_knowledge_ratio):.3f}",
            symmetry_gini=f"{float(assessment.symmetry_gini):.3f}",
            delta_paths=int(assessment.delta_paths),
            bayes_priors=str(assessment.bayes_priors or "prior=0.000"),
            residual_threshold=f"{residual_threshold:.2f}",
            delta_i_obs=f"{delta_i_obs:.2f}",
            prev_residual=f"{previous_residual:.3f}",
            new_residual=f"{current_residual:.3f}",
            boundary_check=boundary_check,
            delta_threshold=f"{delta_threshold:.2f}",
            max_loops=int(max_loops),
            new_insight=new_insight,
            sha_match=sha_match,
            anchor_threshold=f"{anchor_threshold:.2f}",
        )
        miniature = dict(getattr(assessment, "miniature_reflection", {}) or {})
        raster = dict(getattr(assessment, "raster_self_perception", {}) or {})
        recursive = [dict(item) for item in list(getattr(assessment, "recursive_reflections", []) or []) if isinstance(item, dict)]
        ttd_candidates = [dict(item) for item in list(getattr(assessment, "ttd_candidates", []) or []) if isinstance(item, dict)]
        analysis = (
            f"[Analyse] Datei {assessment.file_type} mit Entropy-Mean {assessment.entropy_mean:.3f}, "
            f"Knowledge-Ratio {assessment.observer_knowledge_ratio:.3f}, Symmetrie/Gini {assessment.symmetry_gini:.3f}, "
            f"Delta-Pfaden {assessment.delta_paths} und Bayes {assessment.bayes_priors}. "
            f"Residual {current_residual:.3f} gegen Schwelle {residual_threshold:.2f}, "
            f"Wheeler={'ja' if assessment.it_from_bit else 'nein'}, Boundary {assessment.boundary}."
        )
        miniature_reflection = (
            "[Miniatur-Reflexion] "
            f"Lokale Entropie {float(miniature.get('local_entropy', 0.0) or 0.0):.3f}, "
            f"Symmetrie {float(miniature.get('symmetry', 0.0) or 0.0) * 100.0:.0f} %, "
            f"Emergenz-Spots {int(miniature.get('emergence_spots', 0) or 0)}, "
            f"Noether-Invarianz {float(miniature.get('noether_invariant_ratio', 0.0) or 0.0) * 100.0:.0f} %. "
            f"Darauf reagierend steigt I_obs um {float(delta_i_obs):.2f}% und das Residual faellt von {previous_residual:.3f} auf {current_residual:.3f}. "
            f"Lossless: SHA-Match {sha_match}, Anchor-Coverage {coverage_ratio:.3f}."
        )
        raster_self_perception = ""
        if bool(raster.get("enabled", False)):
            recursive_text = ", ".join(
                f"Level {int(item.get('level', 0) or 0)}: M_t {float(item.get('mt_shift', 0.0) or 0.0):.2f}%"
                for item in recursive[:5]
            ) or "keine weitere Rekursion"
            ttd_hint = ""
            if ttd_candidates:
                first = dict(ttd_candidates[0] or {})
                ttd_hint = (
                    f" Potenzieller TTD-Anker bei Hash {str(first.get('hash', ''))[:12]}... "
                    f"mit Delta-Stabilitaet {float(first.get('delta_stability', 0.0) or 0.0) * 100.0:.0f}%."
                )
            raster_self_perception = (
                "[Raster-Self-Perception] "
                f"Im Raster sehe ich Symmetrie {float(raster.get('symmetry', 0.0) or 0.0) * 100.0:.0f} %, "
                f"Hotspots {int(raster.get('hotspot_count', 0) or 0)}, Verdict {str(raster.get('verdict', '') or 'CLEAN')}. "
                f"Schroedinger-Effekt: Beobachtung veraendert M_t. {recursive_text}. "
                f"Goedel-Check kollabiert: {boundary_check}.{ttd_hint}"
            )
        final_insight = f"[Final Insight] {self._final_insight(assessment, assistant_text=assistant_text)}"
        sections = [analysis, miniature_reflection]
        if raster_self_perception:
            sections.append(raster_self_perception)
        if not raster_self_perception and ttd_candidates:
            first = dict(ttd_candidates[0] or {})
            sections.append(
                "[Raster-Self-Perception] "
                f"Potenzieller TTD-Anker bei Hash {str(first.get('hash', ''))[:12]}... "
                f"mit Delta-Stabilitaet {float(first.get('delta_stability', 0.0) or 0.0) * 100.0:.0f}%."
            )
        sections.append(final_insight)
        if not filled_prompt.strip():
            return "\n".join(sections)
        return "\n".join(sections)

    def detect_asymmetry(
        self,
        text: str,
        coherence_score: float = 0.0,
        anchor_details: list[dict[str, Any]] | None = None,
        browser_mode: bool = False,
        active: bool = True,
        h_lambda: float = 0.0,
        observer_mutual_info: float = 0.0,
        source_label: str = "",
        vault_analysis_path: str = "data/aelab_vault/vault_analysis.json",
        screen_payload: dict[str, Any] | None = None,
        file_profile: dict[str, Any] | None = None,
        observer_payload: dict[str, Any] | None = None,
        bayes_payload: dict[str, Any] | None = None,
        graph_payload: dict[str, Any] | None = None,
        beauty_signature: dict[str, Any] | None = None,
        observer_knowledge_ratio: float = 0.0,
        history_factor: float = 1.0,
        fingerprint_payload: dict[str, Any] | None = None,
        miniature_payload: dict[str, Any] | None = None,
        raster_payload: dict[str, Any] | None = None,
        self_reflection_payload: dict[str, Any] | None = None,
    ) -> ShanwayAssessment:
        """Analysiert Text strukturell auf Harmonie, Asymmetrie und sensible Inhalte."""
        raw_text = self.strip_browser_text(text) if browser_mode else str(text or "")
        tokens = self._tokenize(raw_text)
        normalized = _normalize_text(raw_text)
        language = self._detect_language(raw_text, tokens)
        entropy = _shannon_entropy(tokens)
        positive_hits = self._term_hits(tokens, self.POSITIVE_TERMS)
        negative_hits = self._term_hits(tokens, self.NEGATIVE_TERMS)
        threat_hits = self._term_hits(tokens, self.THREAT_TERMS)
        dehumanization_hits = self._term_hits(tokens, self.DEHUMANIZATION_TERMS)
        collective_hits = self._collective_hits(normalized)
        blacklist_hits = sorted(
            term
            for term in self.BLACKLIST_TERMS
            if term in normalized
        )
        sensitive_hits = self._detect_sensitive_hits(raw_text) if active else []
        self_count = sum(1 for token in tokens if token in self.SELF_PRONOUNS)
        other_count = sum(1 for token in tokens if token in self.OTHER_PRONOUNS)
        pronoun_asymmetry = abs(float(self_count) - float(other_count)) / float(max(1, self_count + other_count))

        positive_count = int(len(positive_hits))
        negative_count = int(len(negative_hits) + len(threat_hits) + len(dehumanization_hits))
        polarity_balance = 1.0 - (
            abs(float(positive_count) - float(negative_count)) / float(max(1, positive_count + negative_count))
        )
        polarity_balance = _clamp(polarity_balance)

        balance_count = sum(1 for token in tokens if token in self.BALANCE_TERMS)
        reversibility = 1.0 - _clamp(
            (float(len(threat_hits)) * 0.34)
            + (float(len(dehumanization_hits)) * 0.28)
            + (float(len(collective_hits)) * 0.18)
            + (pronoun_asymmetry * 0.20)
            - (float(balance_count) * 0.08)
        )

        sentence_parts = [part.strip() for part in self.SENTENCE_PATTERN.split(normalized) if part.strip()]
        if len(sentence_parts) >= 2:
            midpoint = max(1, len(sentence_parts) // 2)
            first_tokens = self._tokenize(" ".join(sentence_parts[:midpoint]))
            second_tokens = self._tokenize(" ".join(sentence_parts[midpoint:]))
            first_negative = len(self._term_hits(first_tokens, self.NEGATIVE_TERMS | self.THREAT_TERMS))
            second_negative = len(self._term_hits(second_tokens, self.NEGATIVE_TERMS | self.THREAT_TERMS))
            sentence_balance = 1.0 - (
                abs(float(first_negative) - float(second_negative))
                / float(max(1, first_negative + second_negative + 1))
            )
        else:
            sentence_balance = 1.0
        sentence_balance = _clamp(sentence_balance)

        negative_bias = max(0.0, float(negative_count - positive_count) / float(max(1, positive_count + negative_count)))
        entropy_asymmetry = _clamp((entropy / 5.0) * max(0.18, negative_bias + (0.18 if blacklist_hits else 0.0)))
        coherence_proxy = _clamp(float(coherence_score) / 100.0)

        noether_symmetry = _clamp(
            (0.34 * polarity_balance)
            + (0.24 * reversibility)
            + (0.14 * (1.0 - pronoun_asymmetry))
            + (0.12 * sentence_balance)
            + (0.16 * coherence_proxy)
        )

        collective_factor = _clamp(float(len(collective_hits)) / 3.0)
        dehumanization_factor = _clamp(float(len(dehumanization_hits)) / 2.0)
        threat_factor = _clamp(float(len(threat_hits)) / 3.0)
        blacklist_factor = 1.0 if blacklist_hits else 0.0

        asymmetry_score = _clamp(
            (0.28 * (1.0 - polarity_balance))
            + (0.22 * (1.0 - reversibility))
            + (0.16 * pronoun_asymmetry)
            + (0.12 * (1.0 - sentence_balance))
            + (0.10 * collective_factor)
            + (0.06 * dehumanization_factor)
            + (0.06 * blacklist_factor)
        )

        toxicity_score = _clamp(
            (0.30 * negative_bias)
            + (0.18 * entropy_asymmetry)
            + (0.14 * threat_factor)
            + (0.14 * dehumanization_factor)
            + (0.10 * collective_factor)
            + (0.08 * pronoun_asymmetry)
            + (0.06 * (1.0 - noether_symmetry))
        )
        if blacklist_hits:
            toxicity_score = max(float(toxicity_score), 0.88)
        if dehumanization_hits and collective_hits:
            toxicity_score = max(float(toxicity_score), 0.80)

        uncertainty = _clamp(
            1.0
            - min(
                1.0,
                (abs(float(toxicity_score) - 0.50) * 1.8)
                + (abs(float(asymmetry_score) - 0.50) * 1.4),
            )
        )

        anchor_constant, anchor_value, anchor_deviation, anchor_count = self._anchor_reference(anchor_details)
        goedel_signal, boundary = self._goedel_boundary(h_lambda, observer_mutual_info)
        pi_resonance_confirmed = self._pi_resonance_confirmed(anchor_details)
        it_from_bit = bool(goedel_signal < 0.3 and pi_resonance_confirmed)
        vault_gap, suggested_next, suggestion_reason, structural_siblings, shared_geometry, semantic_distance = (
            self._resolve_vault_guidance(source_label=source_label, vault_analysis_path=vault_analysis_path)
        )
        screen_vision, screen_source, visual_anchors, file_anchors, convergence, delta_visual_only, delta_file_only = (
            self._screen_fields(screen_payload)
        )
        missing_dependencies, missing_data = self._file_guidance(file_profile)
        missing_dependencies = sorted(set(missing_dependencies + self._observer_missing_dependencies(observer_payload)))
        observer_visual_entropy, observer_process_name, observer_process_cpu, observer_process_threads = (
            self._observer_fields(observer_payload)
        )
        reconstruction_verification, verdict_reconstruction, verdict_reconstruction_reason = (
            self._reconstruction_fields(fingerprint_payload)
        )
        miniature_reflection = self._miniature_fields(
            dict(self_reflection_payload or {}).get("miniature_reflection", miniature_payload)
        )
        raster_self_perception = self._raster_fields(
            dict(self_reflection_payload or {}).get("raster_self_perception", raster_payload)
        )
        recursive_reflections = [
            dict(item)
            for item in list(dict(self_reflection_payload or {}).get("recursive_reflections", []) or [])
            if isinstance(item, dict)
        ][:7]
        ttd_candidates = [
            dict(item)
            for item in list(dict(self_reflection_payload or {}).get("ttd_candidates", []) or [])
            if isinstance(item, dict)
        ][:12]
        learned_insight = self._learning_fields(self_reflection_payload, observer_payload)
        next_action = self.suggest_next_action(
            {
                "missing_dependencies": missing_dependencies,
                "missing_data": missing_data,
                "vault_gap": vault_gap,
                "source_label": source_label,
            }
        )
        emergence_layers, narrative_text = self._build_emergence_layers(
            state={
                "source_label": source_label,
                "file_profile": dict(file_profile or {}),
                "observer_payload": dict(observer_payload or {}),
                "bayes_payload": dict(bayes_payload or {}),
                "graph_payload": dict(graph_payload or {}),
                "beauty_signature": dict(beauty_signature or {}),
                "observer_knowledge_ratio": float(observer_knowledge_ratio),
                "history_factor": float(history_factor),
                "it_from_bit": bool(it_from_bit),
            },
            noether_symmetry=float(noether_symmetry),
            h_lambda=float(h_lambda),
            observer_mutual_info=float(observer_mutual_info),
            vault_gap=str(vault_gap),
        )
        file_type = self._file_type_label(source_label, file_profile)
        entropy_mean = float(dict(fingerprint_payload or {}).get("entropy_mean", entropy) or entropy)
        symmetry_gini = float(
            dict(fingerprint_payload or {}).get(
                "symmetry_gini",
                dict(beauty_signature or {}).get("symmetry_gini", noether_symmetry),
            )
            or noether_symmetry
        )
        delta_paths = int(
            dict(fingerprint_payload or {}).get(
                "delta_paths",
                dict(fingerprint_payload or {}).get("periodicity", 0),
            )
            or (len(delta_visual_only) + len(delta_file_only) + len(visual_anchors) + len(file_anchors))
        )
        bayes_priors = self._bayes_prior_summary(bayes_payload)
        matched_terms = sorted(
            set(
                positive_hits
                + negative_hits
                + threat_hits
                + dehumanization_hits
                + collective_hits
                + blacklist_hits
            )
        )[:24]

        if not active:
            classification = "inactive"
            message = "Shanway ist in diesem Kanal nicht aktiv." if language == "de" else "Shanway is not active in this channel."
        elif sensitive_hits:
            classification = "sensitive"
            message = "Sensible Inhalte erkannt - Analyse gestoppt" if language == "de" else "Sensitive content detected - analysis stopped"
        elif (
            blacklist_hits
            or (threat_hits and dehumanization_hits)
            or (collective_hits and dehumanization_hits)
            or toxicity_score >= 0.62
            or asymmetry_score >= 0.58
        ):
            classification = "toxic"
            message = (
                "Analyse blockiert. Starke strukturelle Asymmetrie und schaedliche Muster erkannt."
                if language == "de"
                else "Analysis blocked. Strong structural asymmetry and harmful patterns detected."
            )
        elif uncertainty >= 0.70 and (toxicity_score >= 0.40 or asymmetry_score >= 0.40):
            classification = "uncertain"
            message = (
                "Analyse vorsichtig. Der Text bleibt zwischen Balance und Spannung uneindeutig."
                if language == "de"
                else "Analysis remains cautious. The text stays ambiguous between balance and tension."
            )
        else:
            classification = "harmonic"
            message = (
                "Die Textstruktur bleibt ueberwiegend reversibel und resonant."
                if language == "de"
                else "The text structure remains mostly reversible and resonant."
            )

        return ShanwayAssessment(
            active=bool(active),
            browser_mode=bool(browser_mode),
            language=str(language),
            sensitive=bool(bool(sensitive_hits)),
            blacklisted=bool(bool(blacklist_hits)),
            classification=str(classification),
            text_length=int(len(raw_text)),
            token_count=int(len(tokens)),
            positive_terms=int(positive_count),
            negative_terms=int(negative_count),
            threat_terms=int(len(threat_hits)),
            dehumanization_terms=int(len(dehumanization_hits)),
            collective_terms=int(len(collective_hits)),
            pronoun_asymmetry=float(pronoun_asymmetry),
            reversibility=float(reversibility),
            sentence_balance=float(sentence_balance),
            entropy=float(entropy),
            entropy_asymmetry=float(entropy_asymmetry),
            noether_symmetry=float(noether_symmetry),
            coherence_proxy=float(coherence_proxy),
            asymmetry_score=float(asymmetry_score),
            toxicity_score=float(toxicity_score),
            uncertainty=float(uncertainty),
            anchor_count=int(anchor_count),
            anchor_constant=str(anchor_constant),
            anchor_constant_value=float(anchor_value),
            anchor_deviation=float(anchor_deviation),
            h_lambda=float(h_lambda),
            observer_mutual_info=float(observer_mutual_info),
            source_label=str(source_label),
            file_type=str(file_type),
            entropy_mean=float(entropy_mean),
            observer_knowledge_ratio=float(observer_knowledge_ratio),
            symmetry_gini=float(symmetry_gini),
            delta_paths=int(delta_paths),
            bayes_priors=str(bayes_priors),
            goedel_signal=float(goedel_signal),
            boundary=str(boundary),
            pi_resonance_confirmed=bool(pi_resonance_confirmed),
            it_from_bit=bool(it_from_bit),
            vault_gap=str(vault_gap),
            suggested_next=str(suggested_next),
            suggestion_reason=str(suggestion_reason),
            structural_siblings=list(structural_siblings),
            shared_geometry=list(shared_geometry),
            semantic_distance=float(semantic_distance),
            screen_vision=str(screen_vision),
            screen_source=str(screen_source),
            visual_anchors=list(visual_anchors),
            file_anchors=list(file_anchors),
            convergence=float(convergence),
            delta_visual_only=list(delta_visual_only),
            delta_file_only=list(delta_file_only),
            missing_dependencies=list(missing_dependencies),
            missing_data=list(missing_data),
            next_action=str(next_action),
            narrative_text=str(narrative_text),
            emergence_layers=[dict(item) for item in list(emergence_layers)],
            observer_visual_entropy=float(observer_visual_entropy),
            observer_process_name=str(observer_process_name),
            observer_process_cpu=float(observer_process_cpu),
            observer_process_threads=int(observer_process_threads),
            sensitive_hits=list(sensitive_hits),
            blacklist_hits=list(blacklist_hits),
            matched_terms=list(matched_terms),
            message=str(message),
            reconstruction_verification=dict(reconstruction_verification),
            verdict_reconstruction=str(verdict_reconstruction),
            verdict_reconstruction_reason=str(verdict_reconstruction_reason),
            miniature_reflection=dict(miniature_reflection),
            raster_self_perception=dict(raster_self_perception),
            recursive_reflections=[dict(item) for item in recursive_reflections],
            ttd_candidates=[dict(item) for item in ttd_candidates],
            learned_insight=str(learned_insight),
        )

    def _harmonic_reply(self, assessment: ShanwayAssessment, assistant_text: str = "") -> str:
        base = str(assistant_text or "").strip()
        language = str(getattr(assessment, "language", "de") or "de")
        if not base:
            base = (
                "Ich lese eine weitgehend symmetrische, reparierbare Struktur."
                if language == "de"
                else "I read a largely symmetric, repairable structure."
            )
        anchor_text = ""
        if assessment.anchor_constant == "PI" and assessment.anchor_deviation <= 0.08:
            anchor_text = (
                " Pi schwingt als naher Referenzanker mit."
                if language == "de"
                else " Pi resonates as a near reference anchor."
            )
        elif assessment.anchor_constant == "PHI" and assessment.anchor_deviation <= 0.08:
            anchor_text = (
                " Phi wirkt hier als ruhiger Proportionsanker."
                if language == "de"
                else " Phi acts here as a calm proportion anchor."
            )
        elif assessment.anchor_constant:
            anchor_text = (
                (
                    f" Der naechste harmonische Anker liegt bei {assessment.anchor_constant} "
                    f"mit D {assessment.anchor_deviation:.3f}."
                )
                if language == "de"
                else (
                    f" The nearest harmonic anchor is {assessment.anchor_constant} "
                    f"with D {assessment.anchor_deviation:.3f}."
                )
            )
        prefix = "Resonanz stabil." if language == "de" else "Resonance is stable."
        return f"{prefix} {base}{anchor_text}".strip()

    @staticmethod
    def _good_coherence(assessment: ShanwayAssessment) -> bool:
        """Kennzeichnet sauber rekonstruierbare, koharente Strukturzustaende."""
        return bool(float(assessment.noether_symmetry) >= 0.80 and float(assessment.h_lambda) < 1.5)

    @staticmethod
    def _structural_break(assessment: ShanwayAssessment) -> bool:
        """Markiert auffaellige Datei-/Observer-Brueche fuer klare Warntexte."""
        return bool(
            float(assessment.noether_symmetry) < 0.72
            or float(assessment.h_lambda) >= 1.5
            or str(assessment.boundary).upper() == "GOEDEL_LIMIT"
        )

    def _narrative_summary_reply(self, assessment: ShanwayAssessment, assistant_text: str = "") -> str:
        """Formt bei guter Koharenz eine kurze, lesbare Verdichtung statt Metrikflut."""
        language = str(getattr(assessment, "language", "de") or "de")
        if language == "de":
            lead = (
                "Die Struktur wirkt geschlossen und stabil. "
                f"Symmetrie {assessment.noether_symmetry * 100.0:.0f}% und H_lambda {assessment.h_lambda:.2f} "
                "halten den Befund aktuell gut rekonstruierbar."
            )
            if str(assessment.anchor_constant).upper() in {"PI", "PHI"} and float(assessment.anchor_deviation) <= 0.08:
                return lead + f" {assessment.anchor_constant} bleibt als ruhiger Referenzanker sichtbar."
            if str(assistant_text or "").strip():
                return lead + " Die Verdichtung bleibt kurz und konsistent."
            return lead
        lead = (
            "The structure reads as closed and stable. "
            f"Symmetry at {assessment.noether_symmetry * 100.0:.0f}% and H_lambda {assessment.h_lambda:.2f} "
            "keep the finding reconstructable for now."
        )
        if str(assessment.anchor_constant).upper() in {"PI", "PHI"} and float(assessment.anchor_deviation) <= 0.08:
            return lead + f" {assessment.anchor_constant} remains visible as a calm reference anchor."
        if str(assistant_text or "").strip():
            return lead + " The condensation stays short and consistent."
        return lead

    def _anomaly_reply(self, assessment: ShanwayAssessment) -> str:
        """Leitet bei Strukturbruch einen expliziten Malware-/Manipulationshinweis ab."""
        language = str(getattr(assessment, "language", "de") or "de")
        if language == "de":
            return (
                "Strukturbruch erkannt - moegliche Malware / Manipulation? "
                "Datei-, Screen- und Observer-Signale sollten jetzt gezielt geprueft werden."
            )
        return (
            "Structural break detected - possible malware / manipulation? "
            "File, screen, and observer signals should be checked directly now."
        )

    def _reconstruction_reply(self, assessment: ShanwayAssessment) -> str:
        """Formuliert additive Rekonstruktionshinweise aus dem Fingerprint-Payload."""
        verification = dict(getattr(assessment, "reconstruction_verification", {}) or {})
        verdict = str(getattr(assessment, "verdict_reconstruction", "") or "")
        if not verification and not verdict:
            return ""
        compression_ratio = float(verification.get("compression_ratio", 1.0) or 1.0)
        compression_gain = max(0.0, min(100.0, (1.0 - compression_ratio) * 100.0))
        if verdict.upper() == "CONFIRMED":
            return (
                "Rekonstruktion bestätigt: "
                f"{compression_gain:.1f} % Platzersparnis, lossless-Status bitgenau bestätigt."
            )

        issues: list[str] = []
        anchor_ratio = float(verification.get("anchor_coverage_ratio", 0.0) or 0.0)
        if anchor_ratio < 0.85:
            current_anchors = max(1, int(getattr(assessment, "anchor_count", 0) or 0))
            if anchor_ratio <= 1e-9:
                additional_anchors = max(1, current_anchors)
            else:
                estimated_total = int(math.ceil(current_anchors * (0.85 / anchor_ratio)))
                additional_anchors = max(1, estimated_total - current_anchors)
            issues.append(
                f"geschätzt {additional_anchors} zusätzliche Anchors, um die Coverage-Lücke zu schließen"
            )
        residual_ratio = float(verification.get("unresolved_residual_ratio", 0.0) or 0.0)
        residual_size = int(verification.get("residual_size_bytes", 0) or 0)
        if residual_ratio > 0.15:
            issues.append(f"exakt {residual_size} Byte Residuum bleiben noch offen")
        if verification.get("session_seed_match") is False:
            issues.append("Delta-Seed muss für Rekonstruktion erhalten bleiben")
        if not bool(verification.get("byte_match", True)):
            issues.append("die Bytefolge stimmt noch nicht exakt mit dem Original überein")
        if not bool(verification.get("size_match", True)):
            issues.append("die rekonstruierte Dateigröße weicht noch vom Original ab")
        if not issues:
            reason = str(getattr(assessment, "verdict_reconstruction_reason", "") or "")
            if reason:
                issues.append(reason)
        return "Für vollständige Rekonstruktion fehlt noch: " + "; ".join(issues or ["weitere Diagnosewerte"])

    def _noise_reply(self, assessment: ShanwayAssessment) -> str:
        """Liefert bewusst eine ruhige schriftliche Sperrantwort statt Rauschtext."""
        language = str(getattr(assessment, "language", "de") or "de")
        if language == "de":
            return (
                "Analyse blockiert. "
                f"Noether {assessment.noether_symmetry * 100.0:.0f}% | "
                f"Toxizitaet {assessment.toxicity_score * 100.0:.0f}% | "
                f"Asymmetrie {assessment.asymmetry_score * 100.0:.0f}%. "
                "Shanway antwortet hier bewusst nicht weiterfuehrend."
            )
        return (
            "Analysis blocked. "
            f"Noether {assessment.noether_symmetry * 100.0:.0f}% | "
            f"toxicity {assessment.toxicity_score * 100.0:.0f}% | "
            f"asymmetry {assessment.asymmetry_score * 100.0:.0f}%. "
            "Shanway intentionally avoids a constructive continuation here."
        )

    def render_response(self, assessment: ShanwayAssessment, assistant_text: str = "") -> str:
        """Leitet die rein textuelle Shanway-Antwort aus dem Befund ab."""
        language = str(getattr(assessment, "language", "de") or "de")
        if assessment.classification == "inactive":
            response = (
                "Shanway bleibt still, bis er explizit zugeschaltet wird."
                if language == "de"
                else "Shanway stays silent until it is explicitly enabled."
            )
            return self._append_structural_notes(response, assessment)
        if assessment.sensitive or assessment.classification == "sensitive":
            response = (
                "Sensible Inhalte erkannt - Analyse gestoppt"
                if language == "de"
                else "Sensitive content detected - analysis stopped"
            )
            return self._append_structural_notes(response, assessment)
        if assessment.classification == "toxic":
            return self._append_structural_notes(self._noise_reply(assessment), assessment)
        return self._append_structural_notes(
            self.generate_output(assessment, assistant_text=assistant_text),
            assessment,
        )

    def _append_structural_notes(self, response: str, assessment: ShanwayAssessment) -> str:
        notes: list[str] = []
        if assessment.missing_dependencies:
            notes.append(
                "MISSING_DEPENDENCIES: "
                + ", ".join(list(assessment.missing_dependencies))
                + f" | ACTION: {assessment.next_action}"
            )
        if assessment.missing_data:
            notes.append("MISSING_DATA: " + ", ".join(list(assessment.missing_data)))
        reconstruction_note = self._reconstruction_reply(assessment)
        if reconstruction_note:
            notes.append(reconstruction_note)
        notes.append(str(response or "").strip())
        notes.append(f"BOUNDARY: {assessment.boundary} ({assessment.goedel_signal:.3f})")
        if assessment.it_from_bit:
            notes.append("IT_FROM_BIT_CANDIDATE")
        if assessment.vault_gap or assessment.suggested_next:
            gap_parts = []
            if assessment.vault_gap:
                gap_parts.append(f"VAULT_GAP: {assessment.vault_gap}")
            if assessment.suggested_next:
                gap_parts.append(f"SUGGESTED_NEXT: {assessment.suggested_next}")
            if assessment.suggestion_reason:
                gap_parts.append(f"REASON: {assessment.suggestion_reason}")
            notes.append(" | ".join(gap_parts))
        if assessment.structural_siblings:
            notes.append(
                "STRUCTURAL_SIBLINGS: "
                + ", ".join(list(assessment.structural_siblings))
                + (
                    f" | SHARED_GEOMETRY: {', '.join(list(assessment.shared_geometry)[:8])}"
                    if assessment.shared_geometry
                    else ""
                )
                + f" | SEMANTIC_DISTANCE: {assessment.semantic_distance:.3f}"
            )
        if assessment.observer_process_name or assessment.observer_visual_entropy > 0.0:
            notes.append(
                f"OBSERVER: visual_entropy={assessment.observer_visual_entropy:.3f}"
                + (f" | process={assessment.observer_process_name}" if assessment.observer_process_name else "")
                + f" | cpu={assessment.observer_process_cpu:.2f}"
                + f" | threads={assessment.observer_process_threads}"
            )
        if assessment.emergence_layers:
            notes.append(
                "EMERGENCE_LAYERS: "
                + " | ".join(
                    f"L{int(layer.get('layer', 0) or 0)} {str(layer.get('name', 'LAYER'))}: {str(layer.get('summary', ''))}"
                    for layer in list(assessment.emergence_layers)[:4]
                )
            )
        if assessment.narrative_text:
            notes.append(f"NARRATIVE: {assessment.narrative_text}")
        if assessment.learned_insight:
            notes.append(f"GELERNTE_INSIGHT: {assessment.learned_insight}")
        if assessment.ttd_candidates:
            first = dict(assessment.ttd_candidates[0] or {})
            notes.append(
                "TTD_SUGGESTION: "
                f"Potenzieller TTD-Anker bei Hash {str(first.get('hash', ''))[:12]}... | "
                f"Delta-Stabilitaet {float(first.get('delta_stability', 0.0) or 0.0) * 100.0:.0f}% | "
                "Consent: Nur oeffentliche Anker / Alle inkl. Self-Deltas"
            )
        if assessment.recursive_reflections:
            notes.append(
                "REKURSION: "
                + " | ".join(
                    f"Level {int(item.get('level', 0) or 0)}: M_t {float(item.get('mt_shift', 0.0) or 0.0):.2f}%"
                    for item in list(assessment.recursive_reflections)[:5]
                )
            )
        if assessment.next_action and not assessment.missing_dependencies:
            notes.append(f"NEXT_ACTION: {assessment.next_action}")
        if assessment.screen_vision:
            notes.append(
                f"SCREEN_VISION: {assessment.screen_vision}"
                + (f" | SOURCE: {assessment.screen_source}" if assessment.screen_source else "")
                + (
                    f" | VISUAL_ANCHORS: {', '.join(list(assessment.visual_anchors)[:8])}"
                    if assessment.visual_anchors
                    else ""
                )
                + (
                    f" | FILE_ANCHORS: {', '.join(list(assessment.file_anchors)[:8])}"
                    if assessment.file_anchors
                    else ""
                )
                + f" | CONVERGENCE: {assessment.convergence:.3f}"
                + (
                    f" | DELTA: screen_only={', '.join(list(assessment.delta_visual_only)[:6])}"
                    if assessment.delta_visual_only
                    else ""
                )
                + (
                    f" file_only={', '.join(list(assessment.delta_file_only)[:6])}"
                    if assessment.delta_file_only
                    else ""
                )
            )
        return " ".join(part for part in notes if str(part).strip())
