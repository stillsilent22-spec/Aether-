from __future__ import annotations

import logging
logger = logging.getLogger(__name__)
import hashlib
import json
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from modules.consensus_engine import get_invariance_score, submit_candidate

_log = logging.getLogger(__name__)
_LAST_ESTIMATED_SAVING_LOCK = threading.Lock()
_LAST_ESTIMATED_SAVING: float = 0.0


def _set_last_estimated_saving(value: float) -> None:
    global _LAST_ESTIMATED_SAVING
    normalized = float(max(0.0, min(1.0, float(value))))
    with _LAST_ESTIMATED_SAVING_LOCK:
        _LAST_ESTIMATED_SAVING = normalized


def get_last_estimated_saving() -> float:
    """Liefert die zuletzt beobachtete globale Einsparung aus dem aktiven Observer-Lauf."""
    with _LAST_ESTIMATED_SAVING_LOCK:
        return float(_LAST_ESTIMATED_SAVING)


@dataclass
class SoftwareFrame:
    """Beschreibt einen beobachteten Software-Frame in komprimierter Form."""

    timestamp_ms: int
    source_process: str
    raw_hash: str
    region_hashes: List[str]
    entropy: float
    symmetry: float


@dataclass
class InvariantAnchor:
    """Repraesentiert einen stabil beobachteten Regionenanker fuer den Schwarm."""

    region_id: str
    ttd_hash: str
    stability_count: int
    first_seen_ms: int
    last_seen_ms: int
    software_context: str


@dataclass
class LocalDelta:
    """Repraesentiert lokale Veraenderungen zwischen zwei aufeinanderfolgenden Frames."""

    frame_a_hash: str
    frame_b_hash: str
    changed_regions: List[str]
    xor_patches: Dict[str, bytes]
    topographic_map: Dict[str, str]
    timestamp_ms: int


def hash_region(data: bytes, x: int, y: int, w: int, h: int) -> str:
    """Berechnet den deterministischen SHA-256-Hash eines Bildausschnitts."""
    try:
        payload = b"|".join([
            bytes(data),
            str(int(x)).encode("utf-8"),
            str(int(y)).encode("utf-8"),
            str(int(w)).encode("utf-8"),
            str(int(h)).encode("utf-8"),
        ])
        return hashlib.sha256(payload).hexdigest()
    except Exception as err:
        _log.warning("hash_region failed: %s", err)
        return hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# Adaptiver Setpoint-Controller (deterministisch + auditierbar)
#
# Formel reagiert NUR auf bereits gemessene Werte — keine Vorhersagen.
# Jeder Threshold-Wechsel kann anhand der Eingangswerte vollständig
# rekonstruiert werden (deterministische Auditierbarkeit).
#
# Terme:
#   shannon_term   : weit vom Shannon-Limit → mehr teilen (threshold sinkt)
#   coverage_term  : viel bereits bekannt   → selektiver teilen (threshold steigt)
#   delta_term     : System in Flux         → noch nicht teilen (threshold steigt)
#   bpj_slope_term : Effizienz fällt        → neue AlgoTokens nötig (threshold sinkt)
#
# Bounds: [THRESHOLD_MIN=0.50, THRESHOLD_MAX=0.98]
# ---------------------------------------------------------------------------

_THRESHOLD_BASE: float = 0.85
_THRESHOLD_MIN: float = 0.50
_THRESHOLD_MAX: float = 0.98

# AELab-Evolution triggern wenn delta_ratio diesen Setpoint überschreitet.
AE_EVOLUTION_SETPOINT: float = 0.40


def compute_adaptive_threshold(
    shannon_gap_pct: float,
    anchor_coverage: float,
    delta_ratio: float,
    bpj_slope: float = 0.0,
    network_metrics: Optional[Dict[str, Any]] = None,
) -> float:
    """Berechnet den adaptiven share_threshold deterministisch aus Systemmetriken.

    network_metrics (aus P2PLayer.aggregate_network_metrics()) hat Vorrang vor
    lokalen Werten — Netz-Median ist robuster gegen lokale Ausreißer.
    Fehlende Netz-Felder fallen auf den übergebenen lokalen Wert zurück.
    Keine Vorhersagen: reagiert nur auf bereits gemessene Werte.

    Args:
        shannon_gap_pct  : lokaler Abstand zum Shannon-Limit [0..100]
        anchor_coverage  : lokaler Anchor-Abdeckungsgrad     [0..1]
        delta_ratio      : lokale delta_ratio                [0..1]
        bpj_slope        : lokale bits_per_joule-Steigung
        network_metrics  : Dict aus aggregate_network_metrics() — Netz-Mediane

    Rückgabe: threshold in [_THRESHOLD_MIN, _THRESHOLD_MAX]
    """
    nm = network_metrics or {}
    # Netz-Median hat Vorrang; lokaler Wert ist Fallback
    g_raw = nm.get("shannon_gap_pct", shannon_gap_pct)
    c_raw = nm.get("anchor_coverage", anchor_coverage)
    d_raw = nm.get("delta_ratio", delta_ratio)
    s_raw = nm.get("bpj_slope", bpj_slope)

    g = max(0.0, min(100.0, float(g_raw))) / 100.0
    c = max(0.0, min(1.0, float(c_raw)))
    d = max(0.0, min(1.0, float(d_raw)))
    s = float(s_raw)

    shannon_term   = -0.10 * g                               # weit vom Limit → mehr teilen
    coverage_term  = +0.08 * c                               # hohe Abdeckung → selektiver
    delta_term     = +0.06 * d                               # hoher Delta → warten
    bpj_slope_term = -0.05 * max(0.0, min(1.0, -s / 1000.0))  # fallende Effizienz → mehr teilen

    raw = _THRESHOLD_BASE + shannon_term + coverage_term + delta_term + bpj_slope_term
    return float(max(_THRESHOLD_MIN, min(_THRESHOLD_MAX, raw)))


class InvariantObserver:
    """Beobachtet Frames, trennt Invarianten von Deltas und meldet stabile Regionen dem Schwarm."""

    def __init__(
        self,
        node_id: str,
        consensus_db: str = "data/consensus.db",
        stability_threshold: int = 5,
        share_threshold: float = 0.85,
    ) -> None:
        self.node_id = str(node_id)
        self.consensus_db = str(consensus_db)
        self.stability_threshold = max(1, int(stability_threshold))
        self.share_threshold = float(max(0.0, min(1.0, share_threshold)))
        self._last_frame: Optional[SoftwareFrame] = None
        self._stable_counts: Dict[str, int] = {}
        self._anchors: Dict[str, InvariantAnchor] = {}
        self._region_ttd: Dict[str, str] = {}
        self._emitted_region_versions: Dict[str, str] = {}
        self._stable_region_total = 0
        self._observed_region_total = 0
        self._last_estimated_saving: float = 0.0
        # Audit-Trail für Threshold-Änderungen (deterministisch nachvollziehbar)
        self._threshold_audit_path: Optional[str] = None

    def set_threshold_audit_path(self, path: str) -> None:
        """Setzt den Pfad für das Threshold-Audit-Log (JSONL)."""
        self._threshold_audit_path = str(path)

    def update_share_threshold(
        self,
        shannon_gap_pct: float,
        anchor_coverage: float,
        delta_ratio: float,
        bpj_slope: float = 0.0,
        network_metrics: Optional[Dict[str, Any]] = None,
    ) -> float:
        """Berechnet und setzt share_threshold adaptiv. Schreibt jeden Wechsel ins Audit-Log.

        network_metrics (aus P2PLayer.aggregate_network_metrics()) — wenn vorhanden,
        werden Netz-Mediane bevorzugt. Lokale Werte dienen als Fallback.
        Determinismus: gleiche Inputs → gleicher Threshold, immer.
        Keine Vorhersagen: reagiert nur auf bereits gemessene Metriken.
        """
        new_threshold = compute_adaptive_threshold(
            shannon_gap_pct=shannon_gap_pct,
            anchor_coverage=anchor_coverage,
            delta_ratio=delta_ratio,
            bpj_slope=bpj_slope,
            network_metrics=network_metrics,
        )
        old_threshold = self.share_threshold
        changed = abs(new_threshold - old_threshold) > 1e-6
        self.share_threshold = new_threshold

        if self._threshold_audit_path and changed:
            nm = network_metrics or {}
            entry = {
                "ts": int(time.time() * 1000),
                "node_id": self.node_id,
                "threshold_old": round(old_threshold, 6),
                "threshold_new": round(new_threshold, 6),
                "source": "network" if nm else "local",
                "network_peer_count": int(nm.get("peer_count", 0)),
                "inputs_effective": {
                    "shannon_gap_pct": round(float(nm.get("shannon_gap_pct", shannon_gap_pct)), 4),
                    "anchor_coverage": round(float(nm.get("anchor_coverage", anchor_coverage)), 4),
                    "delta_ratio":     round(float(nm.get("delta_ratio", delta_ratio)), 4),
                    "bpj_slope":       round(float(nm.get("bpj_slope", bpj_slope)), 4),
                },
            }
            try:
                with open(self._threshold_audit_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n")
            except Exception as err:
                _log.warning("threshold audit write failed: %s", err)

        return new_threshold

    def _region_id(self, process_name: str, index: int) -> str:
        """Leitet aus Prozessname und Region-Index eine stabile Region-ID ab."""
        x = int(index % 16)
        y = int(index // 16)
        return f"{process_name}:region:{x}:{y}"

    def _xor_patch(self, left: str, right: str) -> bytes:
        """Erzeugt einen lokalen XOR-Patch aus zwei Hash-Reprasentationen."""
        left_bytes = str(left or "").encode("utf-8")
        right_bytes = str(right or "").encode("utf-8")
        size = max(len(left_bytes), len(right_bytes))
        left_bytes = left_bytes.ljust(size, b"\x00")
        right_bytes = right_bytes.ljust(size, b"\x00")
        return bytes(a ^ b for a, b in zip(left_bytes, right_bytes))

    def observe_frame(self, frame: SoftwareFrame) -> Tuple[List[InvariantAnchor], Optional[LocalDelta]]:
        """Vergleicht einen Frame mit dem letzten Zustand und trennt neue Anker von lokalen Deltas."""
        try:
            if self._last_frame is None:
                self._last_frame = frame
                self._observed_region_total += len(frame.region_hashes)
                self._last_estimated_saving = self.estimate_transmission_saving()
                _set_last_estimated_saving(self._last_estimated_saving)
                return [], None

            previous = self._last_frame
            new_anchors: List[InvariantAnchor] = []
            changed_regions: List[str] = []
            xor_patches: Dict[str, bytes] = {}
            topographic_map: Dict[str, str] = {}

            self._observed_region_total += len(frame.region_hashes)

            for index, region_hash in enumerate(frame.region_hashes):
                region_id = self._region_id(frame.source_process, index)
                previous_hash = previous.region_hashes[index] if index < len(previous.region_hashes) else None
                ttd_hash = hashlib.sha256(
                    f"{frame.source_process}|{region_id}|{region_hash}".encode("utf-8")
                ).hexdigest()

                if previous_hash is None:
                    self._stable_counts[region_id] = 1
                    self._region_ttd[region_id] = ttd_hash
                    topographic_map[region_id] = "new"
                    continue

                if str(previous_hash) == str(region_hash):
                    self._stable_counts[region_id] = self._stable_counts.get(region_id, 1) + 1
                    self._region_ttd[region_id] = ttd_hash
                    self._stable_region_total += 1
                    topographic_map[region_id] = "stable"
                    if self._stable_counts[region_id] >= self.stability_threshold:
                        anchor = self._anchors.get(region_id)
                        if anchor is None:
                            anchor = InvariantAnchor(
                                region_id=region_id,
                                ttd_hash=ttd_hash,
                                stability_count=self._stable_counts[region_id],
                                first_seen_ms=previous.timestamp_ms,
                                last_seen_ms=frame.timestamp_ms,
                                software_context=frame.source_process,
                            )
                        else:
                            anchor.ttd_hash = ttd_hash
                            anchor.stability_count = self._stable_counts[region_id]
                            anchor.last_seen_ms = frame.timestamp_ms
                        self._anchors[region_id] = anchor
                        submit_candidate(
                            ttd_hash=ttd_hash,
                            anchor_type="invariant_region",
                            node_id=self.node_id,
                            metrics={
                                "entropy": float(frame.entropy),
                                "symmetry": float(frame.symmetry),
                                "stability_count": int(anchor.stability_count),
                            },
                            software_context=frame.source_process,
                            db_path=self.consensus_db,
                        )
                        emitted_version = self._emitted_region_versions.get(region_id, "")
                        if emitted_version != ttd_hash:
                            self._emitted_region_versions[region_id] = ttd_hash
                            new_anchors.append(anchor)
                else:
                    self._stable_counts[region_id] = 1
                    self._region_ttd[region_id] = ttd_hash
                    changed_regions.append(region_id)
                    xor_patches[region_id] = self._xor_patch(str(previous_hash), str(region_hash))
                    topographic_map[region_id] = "drift"

            delta = LocalDelta(
                frame_a_hash=str(previous.raw_hash),
                frame_b_hash=str(frame.raw_hash),
                changed_regions=changed_regions,
                xor_patches=xor_patches,
                topographic_map=topographic_map,
                timestamp_ms=int(frame.timestamp_ms),
            )
            self._last_frame = frame
            self._last_estimated_saving = self.estimate_transmission_saving()
            _set_last_estimated_saving(self._last_estimated_saving)
            return new_anchors, delta
        except Exception as err:
            _log.warning("observe_frame failed: %s", err)
            self._last_frame = frame
            _set_last_estimated_saving(self._last_estimated_saving)
            return [], None

    def get_shareable_anchors(self) -> List[InvariantAnchor]:
        """Liefert nur hinreichend stabile und im Konsens bestaetigte Invarianten."""
        try:
            shareable: List[InvariantAnchor] = []
            for anchor in self._anchors.values():
                if anchor.stability_count < self.stability_threshold:
                    continue
                score = get_invariance_score(anchor.ttd_hash, db_path=self.consensus_db)
                if score >= self.share_threshold:
                    shareable.append(anchor)
            return shareable
        except Exception as err:
            _log.warning("get_shareable_anchors failed: %s", err)
            return []

    def reconstruct_from_anchors(
        self,
        known_anchors: List[InvariantAnchor],
        delta: LocalDelta,
    ) -> Dict[str, str]:
        """Ordnet pro Region zu, ob Rekonstruktion aus Ankern, Delta oder gar nicht moeglich ist."""
        try:
            known_region_ids = {anchor.region_id for anchor in list(known_anchors or [])}
            reconstructed: Dict[str, str] = {}
            for region_id in sorted(set(delta.topographic_map.keys()) | set(known_region_ids)):
                if region_id in known_region_ids:
                    reconstructed[region_id] = "reconstructed"
                elif region_id in delta.xor_patches:
                    reconstructed[region_id] = "delta_applied"
                else:
                    reconstructed[region_id] = "unknown"
            return reconstructed
        except Exception as err:
            _log.warning("reconstruct_from_anchors failed: %s", err)
            return {}

    def estimate_transmission_saving(self) -> float:
        """Schaetzt die Einsparung durch stabile Invarianten ueber alle beobachteten Regionen."""
        try:
            if self._observed_region_total <= 0:
                return 0.0
            return float(max(0.0, min(1.0, float(self._stable_region_total) / float(self._observed_region_total))))
        except Exception as err:
            _log.warning("estimate_transmission_saving failed: %s", err)
            return 0.0