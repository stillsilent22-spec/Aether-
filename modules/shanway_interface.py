"""Bidirectional Shanway interface for preload, web context and privacy analysis."""

from __future__ import annotations

import json
import math
import re
import threading
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .browser_engine import BrowserEngine
from .bus_bridge import BusBridgeEvent, RustBusBridge
from .preload_optimizer import PreloadOptimizer
from .privacy_anchor_builder import PrivacyAnchorBuilder
from .shanway import ShanwayEngine
from .shanway_response_builder import ShanwayResponseBuilder, ShanwayStructuredResponse
from .telemetry_classifier import TelemetryClassifier, TelemetryVerdict

SCIENTIFIC_WHITELIST = {
    "arxiv.org",
    "pubmed.ncbi.nlm.nih.gov",
    "ncbi.nlm.nih.gov",
    "semanticscholar.org",
    "nature.com",
    "science.org",
    "sciencemag.org",
    "springer.com",
    "springerlink.com",
    "wiley.com",
    "jstor.org",
    "who.int",
    "cdc.gov",
    "nih.gov",
    "europa.eu",
    "bmj.com",
    "thelancet.com",
    "cell.com",
    "pnas.org",
    "acs.org",
    "ieee.org",
    "acm.org",
    "wikipedia.org",
}
GENERAL_BLACKLIST = {
    "bild.de", "bild.com",
    "bunte.de", "gala.de", "ok-magazin.de",
    "buzzfeed.com", "buzzfeed.de",
    "heftig.co",
    "watson.de",
    "reddit.com", "reddit.de",
    "twitter.com", "x.com",
    "facebook.com", "fb.com",
    "instagram.com",
    "tiktok.com",
    "pinterest.com",
    "tumblr.com",
    "quora.com",
    "medium.com",
    "rt.com", "rt.de",
    "sputniknews.com",
    "epochtimes.de",
    "compact-magazin.com",
}
GENERAL_QUERY_MARKERS = {
    "rezept",
    "wie",
    "was ist",
    "erklaere",
    "erkläre",
    "anleitung",
}
SCIENTIFIC_QUERY_MARKERS = {
    "studie",
    "forschung",
    "paper",
    "wissenschaft",
    "klinisch",
    "medizin",
    "biologie",
    "physik",
    "chemie",
    "astronomie",
    "geologie",
    "psychologie",
}


def _token_set(text: str) -> set[str]:
    return {token for token in str(text or "").lower().split() if token}


@dataclass
class ShanwayInterfaceResult:
    assessment: Any
    preload_recommendations: list[dict[str, Any]]
    web_context: dict[str, Any]
    library_context: dict[str, Any]
    ttd_push_status: str
    ttd_push_count: int
    bus_events_received: list[dict[str, Any]]
    interface_log: list[str]

    def to_payload(self) -> dict[str, Any]:
        return {
            "assessment": self.assessment.to_payload() if hasattr(self.assessment, "to_payload") else {},
            "preload_recommendations": [dict(item) for item in list(self.preload_recommendations or [])],
            "web_context": dict(self.web_context or {}),
            "library_context": dict(self.library_context or {}),
            "ttd_push_status": str(self.ttd_push_status),
            "ttd_push_count": int(self.ttd_push_count),
            "bus_events_received": [dict(item) for item in list(self.bus_events_received or [])],
            "interface_log": list(self.interface_log or []),
        }

    def summary(self) -> str:
        return (
            f"Shanway {getattr(self.assessment, 'classification', 'unknown')} | "
            f"preloads {len(self.preload_recommendations)} | "
            f"web {self.web_context.get('consistency', 'none')} | "
            f"bus {len(self.bus_events_received)}"
        )


@dataclass
class PrivacyAnalysisResult:
    verdicts: list[TelemetryVerdict]
    confirmed_count: int
    suspected_count: int
    top_threat: TelemetryVerdict | None
    vault_anchors_saved: list[str]
    shanway_assessment: Any
    structured_response: ShanwayStructuredResponse
    log_weight_total: float
    snapshot_ts: str


class ShanwayInterface:
    """Routes Shanway analysis through preload, bus and privacy helpers."""

    def __init__(
        self,
        shanway_engine: ShanwayEngine,
        preload_optimizer: PreloadOptimizer,
        browser_engine: BrowserEngine | None = None,
        bus_bridge: RustBusBridge | None = None,
        vault_analysis_path: str = "data/aelab_vault/vault_analysis.json",
        public_library_path: str = "data/public_anchor_library",
        settings_path: str = "data/settings.json",
        pseudonym: str = "aether_local",
        auto_push_ttd: bool = False,
        telemetry_classifier: TelemetryClassifier | None = None,
        privacy_anchor_builder: PrivacyAnchorBuilder | None = None,
        response_builder: ShanwayResponseBuilder | None = None,
    ) -> None:
        self.shanway_engine = shanway_engine
        self.preload_optimizer = preload_optimizer
        self.browser_engine = browser_engine
        self.bus_bridge = bus_bridge
        self.vault_analysis_path = Path(vault_analysis_path)
        self.public_library_path = Path(public_library_path)
        self.settings_path = Path(settings_path)
        self.pseudonym = str(pseudonym)
        self.auto_push_ttd = bool(auto_push_ttd)
        self.telemetry_classifier = telemetry_classifier or TelemetryClassifier()
        self.privacy_anchor_builder = privacy_anchor_builder or PrivacyAnchorBuilder()
        self.response_builder = response_builder or ShanwayResponseBuilder()
        self._interface_log: list[str] = []
        self._analysis_engine: Any | None = None
        self._analysis_lock = threading.RLock()

    def analyze_and_route(self, text: str, **kwargs: Any) -> ShanwayInterfaceResult:
        assessment = self.shanway_engine.detect_asymmetry(text, **kwargs)
        ttd_push_status = "disabled"
        ttd_push_count = 0
        candidates = [dict(item) for item in list(getattr(assessment, "ttd_candidates", []) or []) if isinstance(item, dict)]
        if candidates and self.auto_push_ttd:
            holder: dict[str, Any] = {"status": "error", "count": 0}

            def _runner() -> None:
                status, count = self._push_ttd_candidates(candidates)
                holder["status"] = status
                holder["count"] = count

            thread = threading.Thread(target=_runner, daemon=True, name="ShanwayTTDPush")
            thread.start()
            thread.join(timeout=2.0)
            ttd_push_status = str(holder.get("status", "error"))
            ttd_push_count = int(holder.get("count", 0) or 0)

        preload_recs = self.preload_optimizer.recommend_preloads(top_n=3)
        system_load = float(kwargs.get("system_load", getattr(assessment, "observer_process_cpu", 0.0) or 0.0))
        if system_load > 90.0:
            web_context = {
                "ok": False,
                "reason": "skipped_due_to_load",
                "source_count": 0,
                "sources_used": 0,
                "source_symmetry": 0.0,
                "consistency": "none",
                "summary": "",
                "providers": [],
                "outlier_discarded": False,
                "vault_abgleich": "unbekannt",
                "vault_detail": "Nur Vault-Analyse aktiv, Browser-Abfragen uebersprungen",
            }
        elif self.browser_engine is not None and self.shanway_engine.should_request_web_context(text):
            web_context = self._fetch_multi_source_web_context(text, assessment=assessment)
        else:
            web_context = {
                "ok": False,
                "reason": "not_requested",
                "source_count": 0,
                "sources_used": 0,
                "source_symmetry": 0.0,
                "consistency": "none",
                "summary": "",
                "providers": [],
                "outlier_discarded": False,
                "vault_abgleich": "unbekannt",
                "vault_detail": "Kein zusaetzlicher Web-Kontext angefordert",
            }
        if bool(web_context.get("ok", False)) and str(web_context.get("summary", "") or "").strip():
            assessment = self.shanway_engine.detect_asymmetry(
                str(web_context.get("summary", "") or ""),
                coherence_score=float(web_context.get("source_symmetry", 0.0) or 0.0) * 100.0,
                source_label=f"web://{web_context.get('query_route', 'general')}",
            )
        library_context = self._enrich_from_public_library(assessment)
        bus_events_received: list[dict[str, Any]] = []
        if self.bus_bridge is not None and self.bus_bridge.available():
            bus_events_received = self.bus_bridge.recent_events(seconds=60.0)
        return ShanwayInterfaceResult(
            assessment=assessment,
            preload_recommendations=preload_recs,
            web_context=web_context,
            library_context=library_context,
            ttd_push_status=ttd_push_status if candidates else ("disabled" if not self.auto_push_ttd else "skipped"),
            ttd_push_count=int(ttd_push_count),
            bus_events_received=bus_events_received,
            interface_log=list(self._interface_log[-24:]),
        )

    def analyze(self, text: str, **kwargs: Any) -> ShanwayInterfaceResult:
        """Alias fuer den Shanway-Backend-Einstieg aus CLI und GUI."""
        return self.analyze_and_route(text, **kwargs)

    def _get_analysis_engine(self) -> Any:
        """Initialisiert die bestehende AnalysisEngine lazy fuer Seiten-Byteanalysen."""
        if self._analysis_engine is not None:
            return self._analysis_engine
        with self._analysis_lock:
            if self._analysis_engine is not None:
                return self._analysis_engine
            from .analysis_engine import AnalysisEngine
            from .blockchain_interface import AetherChain
            from .session_engine import SessionContext

            self._analysis_engine = AnalysisEngine(
                session_context=SessionContext(),
                chain=AetherChain(endpoint="local://shanway-web"),
            )
        return self._analysis_engine

    def analyze_privacy_snapshot(self, snapshot: dict[str, Any]) -> PrivacyAnalysisResult:
        verdicts = self.telemetry_classifier.classify_snapshot(snapshot)
        lines = [
            f"{item.entity_type}:{item.entity_name}:{item.classification}:{item.telemetry_score:.3f}"
            for item in verdicts[:12]
        ]
        summary = " | ".join(lines) or "privacy snapshot clean"
        assessment = self.shanway_engine.detect_asymmetry(summary, source_label="privacy_snapshot")
        interface_result = ShanwayInterfaceResult(
            assessment=assessment,
            preload_recommendations=self.preload_optimizer.recommend_preloads(top_n=3),
            web_context={"ok": False, "reason": "privacy_local_only", "consistency": "none", "source_symmetry": 0.0},
            library_context={"vault_abgleich": "unbekannt", "detail": "Privacy-Snapshot lokal"},
            ttd_push_status="disabled",
            ttd_push_count=0,
            bus_events_received=[],
            interface_log=list(self._interface_log[-24:]),
        )
        structured = self.response_builder.build(
            assessment,
            interface_result,
            raw_answer=self.shanway_engine.render_response(assessment),
        )
        session_id = str(snapshot.get("session_id", getattr(self.privacy_anchor_builder.session_engine, "session_id", "privacy_local")) or "privacy_local")
        saved = self.privacy_anchor_builder.build_and_save_all(verdicts, session_id=session_id)
        weights = [float(item.log_weight) for item in verdicts]
        total_weight = sum(weights)
        log_weight_total = math.log(1.0 + total_weight) / math.log(2.0 + float(len(verdicts))) if verdicts else 0.0
        confirmed = sum(1 for item in verdicts if item.classification == "CONFIRMED")
        suspected = sum(1 for item in verdicts if item.classification == "SUSPECTED")
        top_threat = verdicts[0] if verdicts else None
        return PrivacyAnalysisResult(
            verdicts=verdicts,
            confirmed_count=confirmed,
            suspected_count=suspected,
            top_threat=top_threat,
            vault_anchors_saved=saved,
            shanway_assessment=assessment,
            structured_response=structured,
            log_weight_total=round(float(log_weight_total), 12),
            snapshot_ts=str(snapshot.get("snapshot_ts", "")),
        )

    def _fetch_multi_source_web_context(self, query: str, assessment: Any | None = None) -> dict[str, Any]:
        cleaned_query = " ".join(str(query or "").split()).strip()
        if not cleaned_query:
            return {"ok": False, "reason": "insufficient_sources"}

        route = self._detect_query_route(cleaned_query)
        if route == "direct":
            candidates = self._prepare_direct_candidates(cleaned_query)
            required_consensus = 3
        else:
            search_payload = BrowserEngine.fetch_search_results(cleaned_query, provider="duckduckgo", timeout=6.0)
            raw_results = [dict(item) for item in list(search_payload.get("results", []) or [])][:10]
            candidates = self._prepare_search_candidates(raw_results, route)
            required_consensus = 4
        if not candidates:
            return {"ok": False, "reason": "insufficient_sources", "query_route": route}

        max_pages = 4 if route == "direct" else 7
        selected = candidates[:max_pages]
        fetched_pages = self._fetch_page_batch(selected, route)
        ok_pages = [page for page in fetched_pages if bool(page.get("ok", False))]
        if route == "scientific":
            scientific_count = sum(1 for page in ok_pages if bool(page.get("scientific_domain", False)))
            if scientific_count < 3:
                return {
                    "ok": False,
                    "reason": "insufficient_scientific_sources",
                    "query_route": route,
                    "source_count": len(fetched_pages),
                    "sources_used": 0,
                    "source_symmetry": 0.0,
                    "consistency": "low",
                    "summary": "",
                    "providers": ["duckduckgo"],
                    "outlier_discarded": False,
                    "vault_abgleich": "unbekannt",
                    "vault_detail": "Weniger als 3 wissenschaftliche Quellen verfuegbar",
                    "pages": fetched_pages,
                    "warnings": self._page_warnings(fetched_pages),
                }

        summaries = [str(page.get("summary", "") or "") for page in ok_pages if str(page.get("summary", "") or "").strip()]
        merged_all = self._merged_summary(summaries)
        consensus_pages: list[dict[str, Any]] = []
        outlier_discarded = False
        for page in ok_pages:
            summary = str(page.get("summary", "") or "")
            overlap = self._pair_overlap(summary, merged_all)
            eligible = bool(page.get("consensus_eligible", True)) and float(page.get("trust_score", 0.0) or 0.0) >= 0.35
            if overlap >= 0.08 and eligible:
                page["consensus_overlap"] = round(float(overlap), 12)
                consensus_pages.append(page)
            else:
                outlier_discarded = True
        consensus_summaries = [str(page.get("summary", "") or "") for page in consensus_pages]
        symmetry = self._source_symmetry(consensus_summaries if consensus_summaries else summaries)
        if len(consensus_pages) >= required_consensus and symmetry >= 0.55:
            consistency = "high"
        elif len(consensus_pages) >= required_consensus and symmetry >= 0.25:
            consistency = "medium"
        else:
            consistency = "low"
        merged_summary = self._merged_summary(consensus_summaries)
        vault_abgleich, vault_detail = self._vault_compare(assessment, merged_summary)
        warnings = self._page_warnings(fetched_pages)
        return {
            "ok": bool(len(consensus_pages) >= required_consensus and consistency != "low" and bool(merged_summary.strip())),
            "reason": "" if len(consensus_pages) >= required_consensus and consistency != "low" else "no_consensus",
            "query_route": route,
            "source_count": len(fetched_pages),
            "sources_used": len(consensus_pages),
            "source_symmetry": round(float(symmetry), 12),
            "consistency": consistency,
            "summary": merged_summary,
            "verified_context": merged_summary,
            "providers": ["duckduckgo"],
            "outlier_discarded": outlier_discarded,
            "vault_abgleich": vault_abgleich,
            "vault_detail": vault_detail,
            "pages": fetched_pages,
            "warnings": warnings,
            "consensus_count": len(consensus_pages),
            "required_consensus": int(required_consensus),
        }

    @staticmethod
    def _looks_like_direct_url(query: str) -> bool:
        """Erkennt direkte URLs oder hostartige Einzeleingaben fuer den Vergleichspfad."""
        cleaned = str(query or "").strip()
        if re.match(r"(?i)^https?://", cleaned):
            return True
        if " " in cleaned or "." not in cleaned:
            return False
        parsed = urlparse(f"https://{cleaned}")
        return bool(parsed.netloc and "." in parsed.netloc)

    @classmethod
    def _detect_query_route(cls, query: str) -> str:
        """Leitet Query-Routing fuer allgemeine, wissenschaftliche und direkte Anfragen ab."""
        cleaned = str(query or "").strip().lower()
        if cls._looks_like_direct_url(cleaned):
            return "direct"
        if any(marker in cleaned for marker in SCIENTIFIC_QUERY_MARKERS):
            return "scientific"
        if any(marker in cleaned for marker in GENERAL_QUERY_MARKERS):
            return "general"
        return "general"

    @staticmethod
    def _domain_from_url(url: str) -> str:
        """Extrahiert die Lowercase-Domain fuer Filter- und Trust-Entscheidungen."""
        parsed = urlparse(str(url or ""))
        domain = str(parsed.netloc or "").lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain

    @classmethod
    def _matches_domain_set(cls, domain: str, domain_set: set[str]) -> bool:
        """Prueft Domains inklusive Subdomains robust gegen eine definierte Menge."""
        normalized = str(domain or "").lower().strip()
        if not normalized:
            return False
        return any(normalized == item or normalized.endswith(f".{item}") for item in domain_set)

    @classmethod
    def _is_blacklisted_domain(cls, domain: str) -> bool:
        """Blockiert generelle Blacklist-Domains fuer alle Query-Typen."""
        normalized = str(domain or "").lower().strip()
        if normalized.endswith(".edu") or normalized.endswith(".gov"):
            return False
        return cls._matches_domain_set(normalized, GENERAL_BLACKLIST)

    @classmethod
    def _is_scientific_domain(cls, domain: str) -> bool:
        """Erlaubt wissenschaftliche Quellen ueber Whitelist sowie .edu/.gov."""
        normalized = str(domain or "").lower().strip()
        return (
            normalized.endswith(".edu")
            or normalized.endswith(".gov")
            or cls._matches_domain_set(normalized, SCIENTIFIC_WHITELIST)
        )

    def _prepare_search_candidates(self, raw_results: list[dict[str, Any]], route: str) -> list[dict[str, Any]]:
        """Filtert und sortiert DuckDuckGo-Ergebnisse vor dem eigentlichen Seitenfetch."""
        candidates: list[dict[str, Any]] = []
        for raw in list(raw_results or []):
            url = str(raw.get("url", "") or "").strip()
            domain = self._domain_from_url(url)
            if not url or not domain or self._is_blacklisted_domain(domain):
                continue
            scientific_domain = self._is_scientific_domain(domain)
            if route == "scientific" and not scientific_domain:
                continue
            snippet_probe = BrowserEngine.inspect_text_excerpt(
                str(raw.get("snippet", "") or ""),
                title=str(raw.get("title", "") or ""),
                url=url,
            )
            candidates.append(
                {
                    "url": url,
                    "domain": domain,
                    "title": str(raw.get("title", "") or ""),
                    "snippet": str(raw.get("snippet", "") or ""),
                    "rank": int(raw.get("rank", len(candidates) + 1) or len(candidates) + 1),
                    "scientific_domain": bool(scientific_domain),
                    "snippet_ai_score": float(snippet_probe.get("ai_generation_score", 0.0) or 0.0),
                    "snippet_ai_verdict": str(snippet_probe.get("ai_verdict", "human") or "human"),
                }
            )
        return sorted(
            candidates,
            key=lambda item: (
                0 if bool(item.get("scientific_domain", False)) else 1,
                float(item.get("snippet_ai_score", 0.0) or 0.0),
                int(item.get("rank", 0) or 0),
            ),
        )

    def _prepare_direct_candidates(self, query: str) -> list[dict[str, Any]]:
        """Fuehrt den Direktfetch plus drei Vergleichsseiten aus DuckDuckGo auf."""
        direct_url = str(query or "").strip()
        if not re.match(r"(?i)^https?://", direct_url):
            direct_url = f"https://{direct_url}"
        direct_domain = self._domain_from_url(direct_url)
        if not direct_domain or self._is_blacklisted_domain(direct_domain):
            return []
        comparison_query = str(urlparse(direct_url).netloc or direct_url)
        search_payload = BrowserEngine.fetch_search_results(comparison_query, provider="duckduckgo", timeout=6.0)
        comparisons = self._prepare_search_candidates(
            [dict(item) for item in list(search_payload.get("results", []) or [])][:10],
            route="general",
        )
        deduped: list[dict[str, Any]] = [
            {
                "url": direct_url,
                "domain": direct_domain,
                "title": direct_domain,
                "snippet": "",
                "rank": 0,
                "scientific_domain": self._is_scientific_domain(direct_domain),
                "snippet_ai_score": 0.0,
                "snippet_ai_verdict": "human",
            }
        ]
        for candidate in comparisons:
            if str(candidate.get("url", "") or "") == direct_url:
                continue
            deduped.append(candidate)
            if len(deduped) >= 4:
                break
        return deduped

    def _fetch_page_batch(self, candidates: list[dict[str, Any]], route: str) -> list[dict[str, Any]]:
        """Laedt Kandidatenseiten parallel und bewertet sie mit Browser- und AnalysisEngine-Pipeline."""
        results: list[dict[str, Any] | None] = [None] * len(candidates)

        def _runner(index: int, candidate: dict[str, Any]) -> None:
            results[index] = self._fetch_single_page(candidate, route)

        threads: list[threading.Thread] = []
        for index, candidate in enumerate(candidates):
            thread = threading.Thread(
                target=_runner,
                args=(index, dict(candidate)),
                daemon=True,
                name=f"ShanwayPageFetch-{index}",
            )
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join(timeout=12.0)
        return [dict(item) for item in results if isinstance(item, dict)]

    def _fetch_single_page(self, candidate: dict[str, Any], route: str) -> dict[str, Any]:
        """Analysiert genau eine Zielseite strukturell und bereitet sie fuer Konsensbildung auf."""
        url = str(candidate.get("url", "") or "")
        domain = str(candidate.get("domain", self._domain_from_url(url)) or "")
        probe = BrowserEngine.inspect_url(url, timeout=6.0, max_bytes=524288)
        page = {
            "url": url,
            "domain": domain,
            "title": str(candidate.get("title", "") or ""),
            "snippet": str(candidate.get("snippet", "") or ""),
            "rank": int(candidate.get("rank", 0) or 0),
            "scientific_domain": bool(candidate.get("scientific_domain", False)),
            "ok": bool(probe.get("ok", False)),
            "summary": str(probe.get("summary", "") or ""),
            "ai_generation_score": float(probe.get("ai_generation_score", 0.0) or 0.0),
            "ai_signals": [str(item) for item in list(probe.get("ai_signals", []) or []) if str(item).strip()],
            "ai_verdict": str(probe.get("ai_verdict", "human") or "human"),
            "risk_label": str(probe.get("risk_label", "") or ""),
            "error": str(probe.get("error", "") or ""),
            "consensus_eligible": True,
        }
        if not bool(probe.get("ok", False)):
            page["consensus_eligible"] = False
            return page
        try:
            with self._analysis_lock:
                fingerprint = self._get_analysis_engine().analyze_bytes(
                    bytes(probe.get("raw_bytes", b"") or b""),
                    source_label=url,
                    source_type="text_corpus" if str(probe.get("category", "") or "") in {"html", "text"} else "memory",
                )
            trust_score = self._derive_page_trust(fingerprint, page)
            page.update(
                {
                    "trust_score": round(float(trust_score), 12),
                    "coherence_score": float(getattr(fingerprint, "coherence_score", 0.0) or 0.0),
                    "resonance_score": float(getattr(fingerprint, "resonance_score", 0.0) or 0.0),
                    "ethics_score": float(getattr(fingerprint, "ethics_score", 0.0) or 0.0),
                    "integrity_state": str(getattr(fingerprint, "integrity_state", "") or ""),
                    "verdict": str(getattr(fingerprint, "verdict", "") or ""),
                }
            )
        except Exception as exc:
            page["trust_score"] = 0.0
            page["consensus_eligible"] = False
            page["error"] = str(exc)
            return page
        if route == "scientific" and str(page.get("ai_verdict", "human")) == "ai":
            page["consensus_eligible"] = False
            page["discard_reason"] = "scientific_ai_discarded"
        elif float(page.get("ai_generation_score", 0.0) or 0.0) > 0.70:
            page["consensus_eligible"] = False
            page["discard_reason"] = "ai_not_counted_for_consensus"
        return page

    def _derive_page_trust(self, fingerprint: Any, page: dict[str, Any]) -> float:
        """Leitet einen normierten Seitentrust aus bestehenden Pipeline-Metriken ab."""
        trust = (
            (0.25 * float(getattr(fingerprint, "symmetry_score", 0.0) or 0.0))
            + (0.25 * (float(getattr(fingerprint, "coherence_score", 0.0) or 0.0) / 100.0))
            + (0.20 * (float(getattr(fingerprint, "resonance_score", 0.0) or 0.0) / 100.0))
            + (0.20 * (float(getattr(fingerprint, "ethics_score", 0.0) or 0.0) / 100.0))
            + (0.10 * float(getattr(fingerprint, "observer_knowledge_ratio", 0.0) or 0.0))
        )
        if bool(page.get("scientific_domain", False)) and self._matches_domain_set(str(page.get("domain", "") or ""), {"wikipedia.org"}):
            trust -= 0.20
        if str(page.get("ai_verdict", "human") or "human") == "ai":
            trust -= 0.40
        return max(0.0, min(1.0, float(trust)))

    @staticmethod
    def _page_warnings(pages: list[dict[str, Any]]) -> list[str]:
        """Formuliert auditierbare KI-Warnungen fuer markierte Quellen."""
        signal_labels = {
            "typische_ki_phrasen": "typische KI-Phrasen",
            "zu_glatte_struktur": "zu glatte Struktur",
            "kein_autor": "kein Autor",
            "uebermaessige_listenstruktur": "uebermaessige Listenstruktur",
            "entropie_zu_gleichmaessig": "Entropie zu gleichmaessig",
            "sehr_hohe_lesbarkeit": "sehr hohe Lesbarkeit",
            "generische_sprache": "generische Sprache",
            "title_clickbait": "clickbait Titelmuster",
            "title_generic": "generischer Titel",
            "title_ai_common": "explizite KI-Markierung",
            "channel_generic": "generischer Kanalname",
            "channel_new": "sehr neuer Kanal",
            "channel_bulk": "ungewoehnlich hohe Upload-Frequenz",
            "channel_ai_graph": "KI-Kanal-Cluster",
        }
        warnings: list[str] = []
        for page in list(pages or []):
            ai_score = float(page.get("ai_generation_score", 0.0) or 0.0)
            if ai_score < 0.45:
                continue
            signals = ", ".join(
                signal_labels.get(str(item), str(item))
                for item in list(page.get("ai_signals", []) or [])[:4]
            )
            warnings.append(
                "[WARNUNG: Diese Quelle zeigt KI-generierte Inhalte]\n"
                f"[STRUKTURSIGNAL: ai_score={ai_score:.2f}, Signale: {signals or 'keine'}]"
            )
        return warnings

    @staticmethod
    def _pair_overlap(left: str, right: str) -> float:
        tokens_left = _token_set(left)
        tokens_right = _token_set(right)
        union = tokens_left | tokens_right
        if not union:
            return 0.0
        return float(len(tokens_left & tokens_right)) / float(len(union))

    def _source_symmetry(self, summaries: list[str]) -> float:
        if len(summaries) < 2:
            return 0.0
        scores = [self._pair_overlap(left, right) for left, right in combinations(summaries, 2)]
        return sum(scores) / len(scores) if scores else 0.0

    @staticmethod
    def _merged_summary(summaries: list[str]) -> str:
        if not summaries:
            return ""
        token_lists = [_token_set(text) for text in summaries]
        threshold = max(1, math.ceil(len(token_lists) / 2.0))
        counts: dict[str, int] = {}
        for tokens in token_lists:
            for token in tokens:
                counts[token] = counts.get(token, 0) + 1
        keep = {token for token, count in counts.items() if count >= threshold}
        ordered = [token for token in str(summaries[0] or "").split() if token.lower() in keep]
        merged = " ".join(ordered[:80]).strip()
        return merged or str(summaries[0] or "")[:800]

    def _vault_compare(self, assessment: Any | None, summary: str) -> tuple[str, str]:
        if assessment is None:
            return "unbekannt", "Kein Assessment fuer Vault-Abgleich"
        summary_tokens = _token_set(summary)
        known_tokens = _token_set(" ".join(list(getattr(assessment, "structural_siblings", []) or [])))
        known_tokens |= _token_set(" ".join(list(getattr(assessment, "shared_geometry", []) or [])))
        if not summary_tokens or not known_tokens:
            return "unbekannt", "Zu wenig stabile Token fuer Vault-Abgleich"
        overlap = float(len(summary_tokens & known_tokens)) / float(max(1, len(summary_tokens | known_tokens)))
        if overlap > 0.20:
            return "kompatibel", f"Token-Ueberlappung {overlap:.2f} mit bekannten Strukturen"
        contradiction_tokens = {"widerspruch", "contradiction", "false", "mismatch"}
        if summary_tokens & contradiction_tokens:
            return "widerspruechlich", "Explizite Widerspruchssignale im Web-Kontext"
        return "unbekannt", f"Token-Ueberlappung {overlap:.2f} unter Schwellwert"

    def _enrich_from_public_library(self, assessment: Any) -> dict[str, Any]:
        local = {
            str(item).lower()
            for item in list(getattr(assessment, "structural_siblings", []) or [])
            + list(getattr(assessment, "shared_geometry", []) or [])
            if str(item).strip()
        }
        library: set[str] = set()
        for file_path in sorted(self.public_library_path.rglob("*")):
            if not file_path.is_file():
                continue
            try:
                library.update(token.lower() for token in file_path.read_text(encoding="utf-8", errors="ignore").split())
            except Exception:
                continue
        shared = local & library
        denominator = max(1, max(len(local), len(library)))
        similarity = math.log(1.0 + float(len(shared))) / math.log(1.0 + float(denominator))
        return {
            "shared_count": int(len(shared)),
            "similarity": round(float(similarity), 12),
            "matches": sorted(shared)[:12],
            "vault_abgleich": "kompatibel" if similarity > 0.20 else "unbekannt",
            "detail": f"Oeffentliche Bibliothek teilt {len(shared)} Struktur-Tokens",
        }

    def _push_ttd_candidates(self, candidates: list[dict[str, Any]]) -> tuple[str, int]:
        accepted = [
            {
                "hash": str(item.get("hash", "") or ""),
                "delta_stability": float(item.get("delta_stability", 0.0) or 0.0),
                "symmetry": float(item.get("symmetry", 0.0) or 0.0),
                "residual": float(item.get("residual", 0.0) or 0.0),
            }
            for item in list(candidates or [])
            if float(item.get("delta_stability", 0.0) or 0.0) >= 0.70
        ][:5]
        if not accepted:
            return "skipped", 0
        target = Path("data") / "public_ttd_candidates.jsonl"
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with target.open("a", encoding="utf-8") as handle:
                for item in accepted:
                    handle.write(json.dumps(item, ensure_ascii=True, sort_keys=True) + "\n")
            return "pushed", len(accepted)
        except Exception:
            return "error", 0

    def on_bus_event(self, event: BusBridgeEvent | dict[str, Any]) -> None:
        raw = event.to_dict() if hasattr(event, "to_dict") else dict(event or {})
        event_type = str(raw.get("event_type", "") or "")
        payload = dict(raw.get("payload", {}) or {})
        if event_type == "WorkflowAnchorHit":
            self.preload_optimizer.note_anchor_hit(
                str(payload.get("anchor_hash", "") or ""),
                float(payload.get("confidence", 0.0) or 0.0),
            )
        elif event_type == "ShanwayUserMessage":
            self._interface_log.append(str(payload.get("message", "") or ""))
        elif event_type == "OfflineCachePrepared":
            self.preload_optimizer.record_history(
                {
                    "kind": "offline_cache",
                    "activities": list(payload.get("activities", []) or []),
                    "outcome": {"coverage_improved": int(payload.get("anchor_count", 0) or 0) > 0},
                }
            )
        elif event_type == "CrossProgramVramReuse":
            self._interface_log.append(
                f"VRAM reuse {payload.get('source_program', '')} -> {payload.get('target_program', '')}"
            )
        self._interface_log = self._interface_log[-64:]
