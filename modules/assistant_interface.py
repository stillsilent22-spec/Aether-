"""Lokale Assistant-Schnittstelle ohne externe Netz- oder Browserpfade."""

from __future__ import annotations

import json
import math
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .assistant import AssistantEngine
from .assistant_response_builder import AssistantResponseBuilder, AssistantStructuredResponse
from .bus_bridge import BusBridgeEvent, RustBusBridge
from .preload_optimizer import PreloadOptimizer
from .privacy_anchor_builder import PrivacyAnchorBuilder
from .telemetry_classifier import TelemetryClassifier, TelemetryVerdict


@dataclass
class AssistantInterfaceResult:
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
            f"Assistant {getattr(self.assessment, 'classification', 'unknown')} | "
            f"preloads {len(self.preload_recommendations)} | local-only | "
            f"bus {len(self.bus_events_received)}"
        )


@dataclass
class PrivacyAnalysisResult:
    verdicts: list[TelemetryVerdict]
    confirmed_count: int
    suspected_count: int
    top_threat: TelemetryVerdict | None
    vault_anchors_saved: list[str]
    assistant_assessment: Any
    structured_response: AssistantStructuredResponse
    log_weight_total: float
    snapshot_ts: str


class AssistantInterface:
    """Fuehrt Assistant-Auswertung strikt lokal aus."""

    def __init__(
        self,
        assistant_engine: AssistantEngine,
        preload_optimizer: PreloadOptimizer,
        bus_bridge: RustBusBridge | None = None,
        vault_analysis_path: str = "data/aelab_vault/vault_analysis.json",
        public_library_path: str = "data/public_anchor_library",
        settings_path: str = "data/settings.json",
        pseudonym: str = "aether_local",
        auto_push_ttd: bool = False,
        telemetry_classifier: TelemetryClassifier | None = None,
        privacy_anchor_builder: PrivacyAnchorBuilder | None = None,
        response_builder: AssistantResponseBuilder | None = None,
    ) -> None:
        self.assistant_engine = assistant_engine
        self.preload_optimizer = preload_optimizer
        self.bus_bridge = bus_bridge
        self.vault_analysis_path = Path(vault_analysis_path)
        self.public_library_path = Path(public_library_path)
        self.settings_path = Path(settings_path)
        self.pseudonym = str(pseudonym)
        self.auto_push_ttd = bool(auto_push_ttd)
        self.telemetry_classifier = telemetry_classifier or TelemetryClassifier()
        self.privacy_anchor_builder = privacy_anchor_builder or PrivacyAnchorBuilder()
        self.response_builder = response_builder or AssistantResponseBuilder()
        self._interface_log: list[str] = []
        self._lock = threading.RLock()

    def analyze_and_route(self, text: str, **kwargs: Any) -> AssistantInterfaceResult:
        assessment = self.assistant_engine.detect_asymmetry(text, **kwargs)
        ttd_push_status = "disabled"
        ttd_push_count = 0
        candidates = [
            dict(item)
            for item in list(getattr(assessment, "ttd_candidates", []) or [])
            if isinstance(item, dict)
        ]
        if candidates and self.auto_push_ttd:
            ttd_push_status, ttd_push_count = self._push_ttd_candidates(candidates)

        library_context = self._enrich_from_public_library(assessment)
        bus_events_received: list[dict[str, Any]] = []
        if self.bus_bridge is not None and self.bus_bridge.available():
            bus_events_received = self.bus_bridge.recent_events(seconds=60.0)

        return AssistantInterfaceResult(
            assessment=assessment,
            preload_recommendations=self.preload_optimizer.recommend_preloads(top_n=3),
            web_context={
                "ok": False,
                "reason": "disabled_non_core",
                "source_count": 0,
                "sources_used": 0,
                "source_symmetry": 0.0,
                "consistency": "none",
                "summary": "",
                "providers": [],
                "outlier_discarded": False,
                "vault_abgleich": "unbekannt",
                "vault_detail": "Externe Inhalte sind in diesem Modus deaktiviert.",
            },
            library_context=library_context,
            ttd_push_status=ttd_push_status if candidates else ("disabled" if not self.auto_push_ttd else "skipped"),
            ttd_push_count=int(ttd_push_count),
            bus_events_received=bus_events_received,
            interface_log=list(self._interface_log[-24:]),
        )

    def analyze(self, text: str, **kwargs: Any) -> AssistantInterfaceResult:
        return self.analyze_and_route(text, **kwargs)

    def analyze_privacy_snapshot(self, snapshot: dict[str, Any]) -> PrivacyAnalysisResult:
        verdicts = self.telemetry_classifier.classify_snapshot(snapshot)
        lines = [
            f"{item.entity_type}:{item.entity_name}:{item.classification}:{item.telemetry_score:.3f}"
            for item in verdicts[:12]
        ]
        summary = " | ".join(lines) or "privacy snapshot clean"
        assessment = self.assistant_engine.detect_asymmetry(summary, source_label="privacy_snapshot")
        interface_result = AssistantInterfaceResult(
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
            raw_answer=self.assistant_engine.render_response(assessment),
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
            assistant_assessment=assessment,
            structured_response=structured,
            log_weight_total=round(float(log_weight_total), 12),
            snapshot_ts=str(snapshot.get("snapshot_ts", "")),
        )

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
        elif event_type == "AssistantUserMessage":
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
