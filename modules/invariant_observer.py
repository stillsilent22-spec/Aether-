from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from modules.consensus_engine import get_invariance_score, submit_candidate


_LAST_ESTIMATED_SAVING = 0.0


def _set_last_estimated_saving(value: float) -> None:
    """Aktualisiert den letzten global beobachteten Einsparungswert."""
    global _LAST_ESTIMATED_SAVING
    _LAST_ESTIMATED_SAVING = float(max(0.0, min(1.0, value)))


def get_last_estimated_saving() -> float:
    """Liefert den zuletzt beobachteten Einsparungswert des InvariantObserver."""
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
        print(f"[AETHERNET] hash_region failed: {err}")
        return hashlib.sha256(b"").hexdigest()


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
                _set_last_estimated_saving(self.estimate_transmission_saving())
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
            _set_last_estimated_saving(self.estimate_transmission_saving())
            return new_anchors, delta
        except Exception as err:
            print(f"[AETHERNET] observe_frame failed: {err}")
            self._last_frame = frame
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
            print(f"[AETHERNET] get_shareable_anchors failed: {err}")
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
            print(f"[AETHERNET] reconstruct_from_anchors failed: {err}")
            return {}

    def estimate_transmission_saving(self) -> float:
        """Schaetzt die Einsparung durch stabile Invarianten ueber alle beobachteten Regionen."""
        try:
            if self._observed_region_total <= 0:
                return 0.0
            return float(max(0.0, min(1.0, float(self._stable_region_total) / float(self._observed_region_total))))
        except Exception as err:
            print(f"[AETHERNET] estimate_transmission_saving failed: {err}")
            return 0.0