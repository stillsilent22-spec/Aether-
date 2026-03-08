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
    sensitive_hits: list[str]
    blacklist_hits: list[str]
    matched_terms: list[str]
    message: str

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
            "sensitive_hits": list(self.sensitive_hits),
            "blacklist_hits": list(self.blacklist_hits),
            "matched_terms": list(self.matched_terms),
            "message": str(self.message),
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
            "matched_terms": list(self.matched_terms),
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

    def detect_asymmetry(
        self,
        text: str,
        coherence_score: float = 0.0,
        anchor_details: list[dict[str, Any]] | None = None,
        browser_mode: bool = False,
        active: bool = True,
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
            sensitive_hits=list(sensitive_hits),
            blacklist_hits=list(blacklist_hits),
            matched_terms=list(matched_terms),
            message=str(message),
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
            return (
                "Shanway bleibt still, bis er explizit zugeschaltet wird."
                if language == "de"
                else "Shanway stays silent until it is explicitly enabled."
            )
        if assessment.sensitive or assessment.classification == "sensitive":
            return (
                "Sensible Inhalte erkannt - Analyse gestoppt"
                if language == "de"
                else "Sensitive content detected - analysis stopped"
            )
        if assessment.classification == "toxic":
            return self._noise_reply(assessment)
        if assessment.classification == "uncertain":
            base = assistant_text.strip() if str(assistant_text).strip() else (
                "Ich halte die Antwort bewusst vorsichtig und knapp."
                if language == "de"
                else "I keep the reply deliberately cautious and brief."
            )
            return (
                f"{'Analyse bleibt unsicher.' if language == 'de' else 'Analysis remains uncertain.'} "
                f"{base}"
            )
        return self._harmonic_reply(assessment, assistant_text=assistant_text)
