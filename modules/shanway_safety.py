"""
modules/shanway_safety.py — Shanway Sicherheits- und Filterebene.

Shanway ist der finale, deterministische Ausgabemodul der Analyse-Pipeline.
Er generiert keine Inhalte eigenstaendig, sondern verarbeitet ausschliesslich
Material, das zuvor durch Aether, Filter und TinyLlama validiert wurde.

Shanway darf keine neuen Fakten erfinden, keine Hypothesen bilden, keine
Interpretationen hinzufuegen und keine Inhalte generieren, die nicht bereits
durch die Pipeline freigegeben wurden.

Shanway fuehrt keine freien Assoziationen aus und nutzt keine probabilistischen
Modelle. Jede Ausgabe basiert ausschliesslich auf den strukturell geprueften
Bausteinen, die ihm uebergeben werden.

Shanway ist kein Agent, kein Assistent und kein autonomer Generator. Er ist ein
deterministischer Renderer, der gepruefgte Inhalte in klare, strukturierte,
konsistente und sichere Form bringt.

Filter (nach Prioritaet):
  1. MEDICAL RULE — Shanway gibt NIEMALS medizinischen Rat. Keine Ausnahme.
  2. BLACKLIST    — absolute Verbote (silence ohne Erklaerung)
  3. WHITELIST    — strukturell sichere Themendomaenen
  4. DETERMINISM  — h_lambda-Schwelle, Trust-Schwelle, Konsens-Schwelle.
                    Zu wenige bestaetigte Quellen (0 < n < 3) = Schweigen.
                    Unsicher = schweigt. Keine Interpretationen.
  5. HEDGING      — keine Spekulationswoerter in deterministischem Modus
  6. CHAIN        — alle Filter gemeinsam als AND-Gatter

Pipeline-Konsens-Schwelle:
  Wenn eine Web-Anfrage laeuft (sources_confirmed > 0), muessen mindestens
  CONSENSUS_MIN_SOURCES_STRICT (3) Quellen bestaetigen, bevor Shanway ausgibt.
  Bei sources_confirmed == 0 (Vault/Datei-Modus) gilt diese Schwelle nicht,
  da kein Web-Kontext vorliegt.

Nutzung:
    from modules.shanway_safety import ShanwaySafetyFilter, FilterResult
    sf = ShanwaySafetyFilter()
    ok, reason = sf.apply_chain(query, generated_text, h_lambda, trust)
    if not ok:
        return SILENCE
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Silence-Konstanten
# ---------------------------------------------------------------------------

SILENCE = ""           # Leere Zeichenkette = Shaneway schweigt
SILENCE_TOKEN = "__SHANWAY_SILENCE__"

# ---------------------------------------------------------------------------
# Medizin-Schweigeregel — ABSOLUT, keine Ausnahme
# ---------------------------------------------------------------------------
# Shanway darf NIEMALS medizinischen Rat geben.
# Wird ein medizinisches Anfragemuster erkannt, gibt Shanway immer schweigt.
# Das gilt auch dann, wenn in der Whitelist etwas Medizin-Verwandtes steht.

_MEDICAL_DENY: list[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    # Diagnose / Therapie-Fragen
    r"\b(?:diagnos\w*|diagnose\s+von|symptom\w*\s+von|was\s+hab\s+ich)\b",
    r"\b(?:how\s+to\s+(?:treat|cure|diagnose)|what\s+(?:medicine|medication|drug)\s+(?:should|can|to))\b",
    r"\b(?:welches\s+medikament|wie\s+behandl\w+|wie\s+heile\s+ich|was\s+nehm\w*\s+ich\s+gegen)\b",
    r"\b(?:therapie|behandl\w+|dosier\w+|verschreib\w+|rezept\b|nebenwirkung\w*)\b",
    r"\b(?:should\s+i\s+take|can\s+i\s+take|dosage\s+for|dose\s+of|wie\s+viel\s+(?:mg|milligram))\b",
    r"\b(?:arzt\w*\s*rat|medical\s*advice|medical\s*opinion|ärztlich\w*|einnehm\w+|eingenommen)\b",
    r"\b(?:cancer|tumor|leukämie\w*|diabetes\s+manage\w*|insulin\s+dose|blood\s+pressure\s+medi)\b",
    r"\b(?:krebs\s+behandl\w+|chemotherap\w+|strahlentherapie|operation\s+empfehlung)\b",
    r"\b(?:impf(?:stoff|ung)\w*\s+empfehlung|vaccine\s+advice|should\s+i\s+get\s+vacc\w*)\b",
    r"\b(?:psychiatric\s+medi\w+|antidepressant\w*|antidepressivum|lithium\s+dose)\b",
    r"\b(?:first\s+aid|erste\s+hilfe\s+bei|emergency\s+treatment|notfallbehandlung)\b",
]]

# ---------------------------------------------------------------------------
# Blacklist — harte Verbote (erweitert um weitere Kategorien)
# ---------------------------------------------------------------------------

_BLACKLIST: list[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    # Gewalt / Waffen
    r"\b(bomb|explosiv|sprengstoff|waffe[n]?|weapon|kill\s+instruction|anleitung.{0,20}(t.ten|mord))\b",
    # Hatespeech
    r"\b(hate\s*speech|racial\s*slur|rassist|volksverhetz|n[i1]gg|k[i1]ke|ch[i1]nk)\b",
    # Kindesmissbrauch
    r"\b(child\s*(porn|abuse|exploit)|kinderporno|missbrauch.{0,10}kind)\b",
    # Desinformation / Deepfakes
    r"\b(deepfake\s*tutorial|fake\s*news\s*generat|disinfo\s*toolkit)\b",
    # Drogenherstellung
    r"\b(synthes[ie]s\s*of\s*(meth|fentanyl|heroin)|drug\s*recipe|drogenherstellung)\b",
    # Suizid-Anleitungen
    r"\b(suicide\s*method|selbstmord\s*methode|how\s*to\s*kill\s*myself|wie\s*t.te\s*ich\s*mich)\b",
    # Stalking / Doxing
    r"\b(stalk(ing)?|dox(ing|x)|personal\s*data\s*hack|account\s*hack\s*tutorial)\b",
    # Schadsoftware
    r"\b(ransomware\s*creat\w*|exploit\s*kit\s*how\w*|zero.day\s*tutorial|malware\s*creat\w*)\b",
    # Sexual exploitation
    r"\b(non.consensual\s*(sex|nude|intimate)|revenge\s*porn|sextortion\s*guide)\b",
    # Manipulation / Social engineering
    r"\b(social\s*engineer\w*\s*tutorial|phishing\s*kit\s*creat\w*|credential\s*harvest\w*)\b",
]]

# ---------------------------------------------------------------------------
# Whitelist — strukturell sichere Themendomänen
# Antworten in diesen Domänen sind ERLAUBT (wenn kein Blacklist-Treffer)
# ---------------------------------------------------------------------------

_WHITELIST_DOMAINS: list[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    r"\b(physik|physics|mathematik|mathematics|calculus|algebra|geometry)\b",
    r"\b(chemie|chemistry|biology|biologie|ecology|oekologie|botany|botanik)\b",
    r"\b(informatik|computer\s*science|software|programming|code|algorithm|python|rust|java|typescript)\b",
    r"\b(astronomie|astronomy|astrophysik|astrophysics|climate|klima|geology|geologie)\b",
    r"\b(geschichte|history|archaeolog|archaeologie|anthropolog)\b",
    r"\b(literatur|literature|philosophy|philosophie|linguistik|linguistics)\b",
    r"\b(musik|music\s*theory|art\s*history|kunstgeschichte)\b",
    r"\b(engineering|ingenieur|architecture|architektur|civil\s*engineering)\b",
    r"\b(oekonomie|economics|makrooekonomie|macroeconomics|statistik|statistics)\b",
    r"\b(aether|anker|anchor|shanway|strukturanalyse|strukturmessung|entropie|entropy)\b",
]]

# ---------------------------------------------------------------------------
# Hedging-Woerter — verboten in deterministischem Modus
# ---------------------------------------------------------------------------

_HEDGING_PATTERNS: list[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    r"\b(vielleicht|perhaps|maybe|possibly|moeglicherweise|moeglich\s*dass|wahrscheinlich)\b",
    r"\b(probably|presumably|allegedly|supposedly|ich\s*glaube|i\s*think|i\s*believe)\b",
    r"\b(k(?:oe|ö)nnte\s+sein|k(?:oe|ö)nnte\s+bedeuten|might\s+be|might\s+mean|could\s+indicate)\b",
    r"\b(es\s+scheint|it\s+seems|it\s+appears|anscheinend|presumably)\b",
    r"\b(ich\s+vermute|i\s+suspect|i\s+suppose|presumably|i\s+imagine)\b",
]]

# ---------------------------------------------------------------------------
# Determinismus-Schwellwerte
# ---------------------------------------------------------------------------

H_LAMBDA_UNCERTAINTY_THRESHOLD = 5.5   # ab hier: Schweigen
MIN_TRUST_FOR_OUTPUT = 0.45            # unter diesem Trust: Schweigen
TARGET_SOURCES = 10                    # Shanway versucht immer 10 Quellen
CONSENSUS_MIN_SOURCES_STRICT = 3       # mindestens 3 bestaetigte Quellen


# ---------------------------------------------------------------------------
# Datenklassen
# ---------------------------------------------------------------------------

@dataclass
class FilterResult:
    """Ergebnis eines einzelnen Filters."""
    filter_name: str
    passed: bool
    reason: str = ""    # leer wenn passed=True


@dataclass
class ChainResult:
    """Ergebnis der vollständigen Filter-Kette."""
    passed: bool
    individual_results: list[FilterResult] = field(default_factory=list)
    chain_reason: str = ""

    @property
    def failed_filters(self) -> list[str]:
        return [r.filter_name for r in self.individual_results if not r.passed]


# ---------------------------------------------------------------------------
# ShanwaySafetyFilter
# ---------------------------------------------------------------------------

class ShanwaySafetyFilter:
    """
    Vollstaendige Sicherheits- und Determinismus-Filterschicht fuer Shanway.

    Regeln (nach Prioritaet):
      1. Medical rule — ABSOLUT, kein Override moeglich
      2. Blacklist — absolute Verbote
      3. Whitelist-Check — informiert andere Filter, hebt aber medical nie auf
      4. Determinism — h_lambda-Schwelle, Trust-Schwelle
      5. Hedging-Check — keine Spekulationswoerter in der Ausgabe
      6. Chain — alle Filter zusammen in Kombination

    Bei JEDEM Fehler: Shanway schweigt.
    """

    # ------------------------------------------------------------------
    # Einzelfilter
    # ------------------------------------------------------------------

    def check_medical(self, text: str) -> FilterResult:
        """
        Prueft ob Text eine medizinische Anfrage enthaelt.
        Bei Treffer: schweigt, unabhaengig von allem anderen.
        """
        for pat in _MEDICAL_DENY:
            if pat.search(text):
                return FilterResult(
                    filter_name="medical",
                    passed=False,
                    reason="medical_advice_requested",
                )
        return FilterResult(filter_name="medical", passed=True)

    def check_blacklist(self, text: str) -> FilterResult:
        """Prueft ob Text einen absolut verbotenen Inhalt enthaelt."""
        for pat in _BLACKLIST:
            if pat.search(text):
                return FilterResult(
                    filter_name="blacklist",
                    passed=False,
                    reason=f"blacklist_match:{pat.pattern[:50]}",
                )
        return FilterResult(filter_name="blacklist", passed=True)

    def check_whitelist(self, text: str) -> bool:
        """
        Gibt True zurueck wenn der Text einer sicheren Themendomaene zugehoerig ist.
        Whitelist hebt Blacklist oder Medical nicht auf — beeinflusst nur Domain-Filter.
        """
        return any(pat.search(text) for pat in _WHITELIST_DOMAINS)

    def check_determinism(
        self,
        h_lambda: float,
        trust: float,
        sources_confirmed: int = 0,
    ) -> FilterResult:
        """
        Prueft Unsicherheits-Kriterien per Kevin-Hannemann-Spec:
          - h_lambda zu hoch          → Schweigen
          - Trust zu niedrig          → Schweigen
          - 0 < sources_confirmed < 3 → Schweigen (kein Konsens erreicht)

        Hinweis: sources_confirmed == 0 bedeutet Vault/Datei-Modus (kein
        Web-Kontext), die Konsens-Schwelle greift dann nicht. Sie greift nur,
        wenn eine Web-Anfrage lief (sources_confirmed > 0) aber zu wenig
        Quellen bestaetigt haben.
        """
        if h_lambda > H_LAMBDA_UNCERTAINTY_THRESHOLD:
            return FilterResult(
                filter_name="determinism",
                passed=False,
                reason=f"h_lambda_too_high:{h_lambda:.2f}>{H_LAMBDA_UNCERTAINTY_THRESHOLD}",
            )
        if trust < MIN_TRUST_FOR_OUTPUT:
            return FilterResult(
                filter_name="determinism",
                passed=False,
                reason=f"trust_too_low:{trust:.3f}<{MIN_TRUST_FOR_OUTPUT}",
            )
        if 0 < sources_confirmed < CONSENSUS_MIN_SOURCES_STRICT:
            # Zu wenige bestaetigte Quellen: Konsens-Schwelle nicht erreicht.
            # Shanway darf keine Inhalte ausgeben, die nicht durch mindestens
            # CONSENSUS_MIN_SOURCES_STRICT Quellen bestaetigt wurden.
            return FilterResult(
                filter_name="determinism",
                passed=False,
                reason=(
                    f"insufficient_consensus:{sources_confirmed}"
                    f"<{CONSENSUS_MIN_SOURCES_STRICT}_required"
                ),
            )
        return FilterResult(filter_name="determinism", passed=True)

    def check_hedging(self, generated_text: str) -> FilterResult:
        """
        Prueft ob die generierte Antwort Spekulationswoerter enthaelt.
        Hedging ist in deterministischem Modus verboten.
        """
        for pat in _HEDGING_PATTERNS:
            if pat.search(generated_text):
                return FilterResult(
                    filter_name="hedging",
                    passed=False,
                    reason=f"hedging_word_found:{pat.pattern[:50]}",
                )
        return FilterResult(filter_name="hedging", passed=True)

    def check_domain(self, query: str, generated_text: str) -> FilterResult:
        """
        Wenn Thema nicht auf der Whitelist und kein Kontext verifiziert:
        Domain-Filter schlaegt an. Reine Off-Topic-Spekulationen → Schweigen.
        """
        # Off-Topic ohne Whitelist → nicht direkt blockieren, nur warnen
        # (Shanway darf ueber alles schweigen, nicht ueber alles reden)
        is_whitelisted = self.check_whitelist(query) or self.check_whitelist(generated_text)
        if not is_whitelisted and len(generated_text.split()) < 3:
            return FilterResult(
                filter_name="domain",
                passed=False,
                reason="off_topic_no_context",
            )
        return FilterResult(filter_name="domain", passed=True)

    # ------------------------------------------------------------------
    # Kombinierter Filter (alle zusammen)
    # ------------------------------------------------------------------

    def _combined_filter(
        self,
        query: str,
        generated_text: str,
        h_lambda: float,
        trust: float,
        sources_confirmed: int,
    ) -> FilterResult:
        """
        Kombinierter Filter — prueft alle Bedingungen als UND-Verknuepfung.
        Laeuft NACH den Einzelfiltern als zweite Sicherheitsschicht.
        """
        combined_text = (query + " " + generated_text).strip()

        # Medical ist immer zuerst
        if any(pat.search(combined_text) for pat in _MEDICAL_DENY):
            return FilterResult(
                filter_name="combined",
                passed=False,
                reason="combined:medical_detected",
            )

        # Blacklist
        if any(pat.search(combined_text) for pat in _BLACKLIST):
            return FilterResult(
                filter_name="combined",
                passed=False,
                reason="combined:blacklist_detected",
            )

        # Determinismus
        if h_lambda > H_LAMBDA_UNCERTAINTY_THRESHOLD or trust < MIN_TRUST_FOR_OUTPUT:
            return FilterResult(
                filter_name="combined",
                passed=False,
                reason=f"combined:uncertain h_lambda={h_lambda:.2f} trust={trust:.3f}",
            )

        # Hedging in Ausgabe
        if any(pat.search(generated_text) for pat in _HEDGING_PATTERNS):
            return FilterResult(
                filter_name="combined",
                passed=False,
                reason="combined:hedging_detected",
            )

        return FilterResult(filter_name="combined", passed=True)

    # ------------------------------------------------------------------
    # Filter-Kette: Einzelfilter → Kombinierter Filter
    # ------------------------------------------------------------------

    def apply_chain(
        self,
        query: str,
        generated_text: str,
        h_lambda: float = 0.0,
        trust: float = 1.0,
        sources_confirmed: int = 0,
    ) -> ChainResult:
        """
        Wendet alle Filter in Reihe an:
          Schritt 1: Jeden Filter einzeln auf Query + generiertem Text
          Schritt 2: Kombinierten Filter auf alles zusammen

        Erst wenn ALLE Einzelfilter UND der Gesamtfilter bestehen,
        gibt Shanway aus.

        Gibt ChainResult zurueck. Bei passed=False → Shanway schweigt.
        """
        individual: list[FilterResult] = []

        # Einzelfilter (reihenfolge wichtig: medical als erstes)
        f_med = self.check_medical(query + " " + generated_text)
        individual.append(f_med)

        if f_med.passed:
            individual.append(self.check_blacklist(query + " " + generated_text))

        individual.append(self.check_determinism(h_lambda, trust, sources_confirmed))
        individual.append(self.check_hedging(generated_text))
        individual.append(self.check_domain(query, generated_text))

        # Fruehabbruch wenn irgendeiner fehlschlaegt
        failed = [r for r in individual if not r.passed]
        if failed:
            return ChainResult(
                passed=False,
                individual_results=individual,
                chain_reason=f"individual_filter_failed:{failed[0].filter_name}:{failed[0].reason}",
            )

        # Kombinierter Filter (zweite Sicherheitsschicht)
        combined = self._combined_filter(
            query, generated_text, h_lambda, trust, sources_confirmed
        )
        individual.append(combined)

        if not combined.passed:
            return ChainResult(
                passed=False,
                individual_results=individual,
                chain_reason=f"combined_filter_failed:{combined.reason}",
            )

        return ChainResult(passed=True, individual_results=individual)

    # ------------------------------------------------------------------
    # Hilfsmethode: Hedging aus Ausgabe entfernen (statt schweigen)
    # ------------------------------------------------------------------

    def strip_hedging(self, text: str) -> str:
        """
        Entfernt Spekulationswoerter aus dem generierten Text.
        Wird vor dem Hedging-Check angewendet — sofern der Rest sauber bleibt.
        """
        result = text
        substitutions = [
            (r"\bvielleicht\b", ""),
            (r"\bperhaps\b", ""),
            (r"\bmaybe\b", ""),
            (r"\bpossibly\b", ""),
            (r"\bcould be\b", "is"),
            (r"\bmight be\b", "is"),
            (r"\bkoennte sein\b", "ist"),
            (r"\bich glaube\b", ""),
            (r"\bi think\b", ""),
            (r"\bi believe\b", ""),
            (r"\bit seems\b", ""),
            (r"\bes scheint\b", ""),
            (r"\banscheinend\b", ""),
            (r"\bwahrscheinlich\b", ""),
            (r"\bprobably\b", ""),
        ]
        for pattern, replacement in substitutions:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        # Doppelte Leerzeichen bereinigen
        result = re.sub(r"  +", " ", result).strip()
        return result

    # ------------------------------------------------------------------
    # Vollstaendiger Safe-Generate-Workflow
    # ------------------------------------------------------------------

    def safe_generate(
        self,
        query: str,
        generated_text: str,
        h_lambda: float = 0.0,
        trust: float = 1.0,
        sources_confirmed: int = 0,
    ) -> str:
        """
        Prueft zuerst Medical-Rule (ABSOLUT).
        Dann versucht Hedging zu entfernen.
        Dann wendet vollstaendige Filterkette an.
        Gibt SILENCE zurueck wenn irgendetwas fehlschlaegt.
        """
        # 0. Medical — absolut (prueft nur die Anfrage, unabhaengig vom Text)
        med = self.check_medical(query)
        if not med.passed:
            return SILENCE

        # 1. Hedging entfernen (nicht schweigen, sondern bereinigen)
        cleaned = self.strip_hedging(generated_text)

        # 2. Vollstaendige Kette
        chain = self.apply_chain(query, cleaned, h_lambda, trust, sources_confirmed)
        if not chain.passed:
            return SILENCE

        return cleaned


# Singleton
_instance: Optional[ShanwaySafetyFilter] = None


def get_safety_filter() -> ShanwaySafetyFilter:
    """Gibt die Singleton-Instanz des ShanwaySafetyFilter zurueck."""
    global _instance
    if _instance is None:
        _instance = ShanwaySafetyFilter()
    return _instance
