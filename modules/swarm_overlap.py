from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""Structural domain-overlap detection for Aether Swarm.

Compares local anchor fingerprint metrics against peer-supplied candidate
metrics to identify structural overlaps within user-defined domain tags.
When an overlap is found and consent is active, an event is appended to
data/interbus/swarm_overlap_events.json for the Rust shell to poll.

Privacy guarantees:
  - Only non-invertible metric vectors (mean, std, entropy) are compared.
  - Raw pixel/frame data is never accessed by this module.
  - Domain tags are set exclusively by the user in data/domain_tags.json.
  - Consent is checked before any comparison or write operation.
  - remote_node_pubkey serves solely as an anonymous contact handle.

Data flow:
  1. User writes domain tags to data/domain_tags.json (list of strings).
  2. Peer nodes expose candidate metric vectors via
     data/interbus/swarm_peer_candidates.json (populated by the P2P layer).
  3. detect_and_publish_overlaps() compares local metrics to candidates.
  4. New events are written to data/interbus/swarm_overlap_events.json.
  5. The Rust shell polls that file on Tick and shows requests in the Chat tab.
"""


import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

INTERBUS_DIR = ROOT / "data" / "interbus"
OVERLAP_EVENTS_PATH = INTERBUS_DIR / "swarm_overlap_events.json"
DOMAIN_TAGS_PATH = ROOT / "data" / "domain_tags.json"
DB_PATH = ROOT / "data" / "swarm_metrics.db"
PEER_CANDIDATES_PATH = INTERBUS_DIR / "swarm_peer_candidates.json"

# Cosine similarity threshold: above this value → structural overlap detected.
SIMILARITY_THRESHOLD = 0.80

# Maximum events to keep in the events file (oldest removed first).
MAX_EVENTS = 50

_overlap_lock = threading.Lock()


# --------------------------------------------------------------------------- #
#   Helpers                                                                   #
# --------------------------------------------------------------------------- #

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _epoch_week() -> str:
    now = datetime.now(timezone.utc)
    week = now.isocalendar()[1]
    return f"KW{week:02d}-{now.year}"


# Vollständiger Φ-Vektor (9 Dimensionen) — signal-agnostisch
# Reihenfolge muss auf beiden Seiten (lokal + Peer) identisch sein.
_PHI_KEYS: List[str] = [
    "entropy_approx",      # H_S  Shannon
    "boltzmann_entropy",   # H_B  Boltzmann (orthogonal)
    "zipf_alpha",          # α_Z  Zipf Rank-Frequenz
    "benford_score",       # β_F  Benford Erstziffer
    "periodicity",         # ρ_P  Fourier Periodizität
    "katz_dimension",      # D_K  Katz Fraktaldimension
    "perm_entropy",        # H_P  Permutations-Entropie
    "delta_ratio",         # Δ_C  Delta-Konvergenz
    "noether_consistency", # K_N  Noether Symmetrie
]


def _extract_phi(row: Dict[str, Any]) -> List[float]:
    """Extrahiert den 9D Φ-Vektor aus einer DB-Zeile oder Gossip-Kandidat.

    Fehlende Werte werden auf 0.0 gesetzt — Vergleich bleibt möglich,
    Gewichtung dieser Dimension fällt automatisch raus (Cosinus).
    """
    extras: Dict[str, Any] = {}
    raw_extras = row.get("extras")
    if isinstance(raw_extras, str):
        try:
            extras = json.loads(raw_extras)
        except Exception:
            pass
    elif isinstance(raw_extras, dict):
        extras = raw_extras

    phi: List[float] = []
    for key in _PHI_KEYS:
        # Direkt in row, dann in extras
        val = row.get(key, extras.get(key, 0.0))
        try:
            phi.append(float(val))
        except Exception:
            phi.append(0.0)
    return phi


def _cosine_similarity(
    a: Tuple[float, ...],
    b: Tuple[float, ...],
) -> float:
    """Cosinus-Ähnlichkeit auf N-dimensionalen Vektoren."""
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = sum(x * x for x in a) ** 0.5
    mag_b = sum(x * x for x in b) ** 0.5
    if mag_a < 1e-9 or mag_b < 1e-9:
        return 0.0
    return dot / (mag_a * mag_b)


# --------------------------------------------------------------------------- #
#   I/O helpers                                                               #
# --------------------------------------------------------------------------- #

def load_domain_tags() -> List[str]:
    """Return the user-defined domain tags from data/domain_tags.json.

    Expected format: a JSON list of strings, e.g. ``["biology", "finance"]``.
    Returns an empty list if the file does not exist or is malformed.
    """
    try:
        if DOMAIN_TAGS_PATH.is_file():
            raw = json.loads(DOMAIN_TAGS_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                return [str(t).strip().lower() for t in raw if t]
    except Exception as e:
        logger.warning(f"[swarm_overlap] Fehler: {e}")
        pass
    return []


def _read_local_metrics(limit: int = 100) -> List[Dict[str, Any]]:
    """Read recent anchor fingerprint metrics from the local swarm_metrics.db.

    Only «changed» and «new» frames are returned — «stable» frames carry no
    structural information beyond their first occurrence.
    """
    if not DB_PATH.is_file():
        return []
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=3.0)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT fingerprint, mean_val, std_val, entropy_approx, extras
            FROM frame_metrics
            WHERE delta_marker != 'stable'
            ORDER BY ts DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows if r["fingerprint"]]
    except Exception as e:
        return []


def _load_peer_candidates() -> List[Dict[str, Any]]:
    """Load remote peer candidate metric vectors from the interbus exchange file.

    Each entry must contain: ``fingerprint``, ``phi`` (list of 9 floats),
    ``remote_node_pubkey``, ``source_label`` (user-defined name).
    Legacy entries with ``mean_val``/``std_val``/``entropy_approx`` are still accepted.

    This file is populated by the P2P exchange layer. When no P2P layer is
    active it remains absent and detection silently returns 0.
    """
    try:
        if PEER_CANDIDATES_PATH.is_file():
            raw = json.loads(PEER_CANDIDATES_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                return raw
    except Exception as e:
        logger.warning(f"[swarm_overlap] Fehler: {e}")
        pass
    return []


def _read_existing_events() -> List[Dict[str, Any]]:
    with _overlap_lock:
        try:
            if OVERLAP_EVENTS_PATH.is_file():
                raw = json.loads(OVERLAP_EVENTS_PATH.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    return raw
        except Exception as e:
            logger.warning(f"[swarm_overlap] Fehler: {e}")
            pass
    return []


def _write_events(events: List[Dict[str, Any]]) -> None:
    with _overlap_lock:
        INTERBUS_DIR.mkdir(parents=True, exist_ok=True)
        # Trim to MAX_EVENTS (keep newest)
        trimmed = events[-MAX_EVENTS:]
        OVERLAP_EVENTS_PATH.write_text(
            json.dumps(trimmed, indent=2, ensure_ascii=True),
            encoding="utf-8",
        )


# --------------------------------------------------------------------------- #
#   Public API                                                                #
# --------------------------------------------------------------------------- #

def detect_and_publish_overlaps(threshold: float = SIMILARITY_THRESHOLD) -> int:
    """Compare local anchor Φ-vectors to peer candidates and publish overlap events.

    Comparison is signal-agnostic (9D Φ-vector). No domain filter — the structural
    distance alone decides. The function is a no-op (returns 0) when:
    - Swarm consent is not active.
    - No peer candidates are available.

    Returns:
        Number of new overlap events written to disk.
    """
    from modules.swarm_consent import has_consent
    if not has_consent():
        return 0

    local_metrics = _read_local_metrics()
    if not local_metrics:
        return 0

    peer_candidates = _load_peer_candidates()
    if not peer_candidates:
        return 0

    existing = _read_existing_events()
    # Short-hash keys already reported — avoid duplicate events.
    existing_keys: Set[str] = {e.get("anchor_hash_a", "") for e in existing}

    new_events: List[Dict[str, Any]] = []
    epoch = _epoch_week()

    for local in local_metrics:
        local_fp: str = str(local.get("fingerprint", ""))
        if not local_fp:
            continue
        short_hash = local_fp[:16]
        if short_hash in existing_keys:
            continue  # already reported for this anchor

        # Vollständiger 9D Φ-Vektor — signal-agnostisch
        phi_local = _extract_phi(local)

        for candidate in peer_candidates:
            # Φ aus Kandidat extrahieren (neu: phi-Liste; legacy: einzelne Felder)
            raw_phi = candidate.get("phi")
            if isinstance(raw_phi, list) and len(raw_phi) == len(_PHI_KEYS):
                phi_cand = [float(v) for v in raw_phi]
            else:
                phi_cand = _extract_phi(candidate)

            score = _cosine_similarity(tuple(phi_local), tuple(phi_cand))
            if score < threshold:
                continue  # strukturell zu verschieden

            remote_pubkey = str(candidate.get("remote_node_pubkey", ""))
            # Nutzer-vergebene Label beider Seiten — das ist alles was angezeigt wird
            local_label = str(local.get("source_label", "") or "").strip()
            remote_label = str(candidate.get("source_label", "") or "").strip()
            new_events.append({
                "anchor_hash_a":    short_hash,
                "local_label":      local_label,
                "remote_label":     remote_label,
                "structural_score": round(score, 4),
                "phi_dimensions":   len([v for v in phi_local if v != 0.0]),
                "epoch_week":       epoch,
                "remote_node_pubkey": remote_pubkey,
                "detected_at":      _utc_now(),
            })
            # Eine Kontaktanfrage pro lokalem Anker maximal.
            existing_keys.add(short_hash)
            break

    if new_events:
        _write_events(existing + new_events)

    return len(new_events)
