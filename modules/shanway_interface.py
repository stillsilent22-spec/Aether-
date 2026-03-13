"""Bidirectional Shanway interface for preload, web context and privacy analysis."""

from __future__ import annotations

import json
import math
import threading
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any

from .browser_engine import BrowserEngine
from .bus_bridge import BusBridgeEvent, RustBusBridge
from .preload_optimizer import PreloadOptimizer
from .privacy_anchor_builder import PrivacyAnchorBuilder
from .shanway import ShanwayEngine
from .shanway_response_builder import ShanwayResponseBuilder, ShanwayStructuredResponse
from .telemetry_classifier import TelemetryClassifier, TelemetryVerdict


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
        providers = ["duckduckgo", "bing", "brave"]
        results: list[dict[str, Any]] = []
        for provider in providers:
            result = self._fetch_provider_context(query, provider=provider)
            if result.get("ok"):
                results.append(result)
        if len(results) < 2:
            return {"ok": False, "reason": "insufficient_sources"}

        summaries = [str(item.get("summary", "") or "") for item in results]
        per_source_scores: list[tuple[int, float]] = []
        for index, summary in enumerate(summaries):
            peers = [text for idx, text in enumerate(summaries) if idx != index]
            scores = [self._pair_overlap(summary, other) for other in peers] or [0.0]
            per_source_scores.append((index, sum(scores) / len(scores)))
        outlier_discarded = False
        if len(results) >= 3:
            lowest_index, lowest_score = min(per_source_scores, key=lambda item: (item[1], item[0]))
            if lowest_score < 0.15:
                outlier_discarded = True
                results = [item for idx, item in enumerate(results) if idx != lowest_index]
                summaries = [str(item.get("summary", "") or "") for item in results]
        symmetry = self._source_symmetry(summaries)
        if symmetry >= 0.55:
            consistency = "high"
        elif symmetry >= 0.25:
            consistency = "medium"
        else:
            consistency = "low"
        merged_summary = self._merged_summary(summaries)
        vault_abgleich, vault_detail = self._vault_compare(assessment, merged_summary)
        return {
            "ok": True,
            "source_count": len(providers),
            "sources_used": len(results),
            "source_symmetry": round(float(symmetry), 12),
            "consistency": consistency,
            "summary": merged_summary,
            "providers": [str(item.get("provider", "") or "") for item in results],
            "outlier_discarded": outlier_discarded,
            "vault_abgleich": vault_abgleich,
            "vault_detail": vault_detail,
        }

    def _fetch_provider_context(self, query: str, provider: str) -> dict[str, Any]:
        normalized = str(provider or "duckduckgo").lower()
        if normalized == "duckduckgo":
            return BrowserEngine.fetch_search_context(query, provider="duckduckgo", timeout=6.0)
        if normalized == "bing":
            q = BrowserEngine.build_search_url(query, provider="bing").split("q=", 1)[-1]
            return self._fetch_manual("bing", f"https://www.bing.com/search?q={q}")
        if normalized == "brave":
            q = BrowserEngine.build_search_url(query).split("?q=", 1)[-1]
            return self._fetch_manual("brave", f"https://search.brave.com/search?q={q}")
        return {"ok": False, "provider": normalized, "summary": "", "error": "unsupported_provider"}

    @staticmethod
    def _fetch_manual(provider: str, url: str) -> dict[str, Any]:
        try:
            raw_html = BrowserEngine.download_text(url, timeout=6.0)
            summary = BrowserEngine.strip_html_text(raw_html, limit_chars=1200)
            return {
                "ok": bool(summary),
                "provider": provider,
                "query": "",
                "url": url,
                "summary": summary,
                "search_url": url,
                "error": "" if summary else "empty_summary",
            }
        except Exception as exc:
            return {"ok": False, "provider": provider, "summary": "", "error": str(exc), "url": ""}

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
