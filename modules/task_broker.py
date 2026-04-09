"""
task_broker.py — Swarm Computation Delegation Engine

Schwache Knoten (Vista-PC, Android, Raspberry Pi) können rechenintensive
Aufgaben an stärkere Swarm-Mitglieder auslagern:

  1. TaskRequest-Broadcast:  "Ich brauche Invarianten-Analyse für Chunk-Klasse X"
  2. TaskBid:                Fähiger Peer bietet Ausführung an
  3. TaskAccept:             Auftraggeber wählt das beste Angebot
  4. TaskResult:             Executor liefert strukturelle Fingerprints zurück

Privatsphäre: Task-Payloads sind IMMER nur der 9-Invarianten-Vektor Φ.
Nie: Rohdaten, Pixeldaten, Dateiinhalte, Sessions oder Keys.

Persistenz:
  data/interbus/task_queue.json   — ausstehende eigene Tasks (survives restart)
  data/interbus/task_results.json — Abschluss-Statistik / Contribution-Zähler

Integration: Gossip-Pakete via swarm_p2p.publish_fingerprints() transportieren
  msg["task_requests"] = [TaskRequest.to_dict(), ...]
  msg["task_bids"]     = [TaskBid.to_dict(), ...]
  msg["task_results"]  = [TaskResult.to_dict(), ...]
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
TASK_QUEUE_PATH   = ROOT / "data" / "interbus" / "task_queue.json"
TASK_RESULTS_PATH = ROOT / "data" / "interbus" / "task_results.json"

# Task-Typen — Erweiterbar; jeder Typ hat eigene CPU/RAM-Anforderungen
TASK_INVARIANT_ANALYSIS = "invariant_analysis"   # 9-Invarianten-Vektor berechnen
TASK_VAULT_EVOLVE        = "vault_evolve"         # GA-Evolution für neuen Vault-Baum
TASK_FRAME_DELTA         = "frame_delta"          # XOR-Delta eines Frames kodieren
TASK_PREDICTION_TRAIN    = "prediction_train"     # Vorhersage-Modell verfeinern

# Mindest-Capability-Score zum Akzeptieren fremder Tasks
MIN_SCORE_TO_ACCEPT = 50   # Standard-Tier

# TTL für Task-Requests im Gossip
TASK_TTL_SECONDS = 300


# --------------------------------------------------------------------------- #
#  Datenstrukturen                                                             #
# --------------------------------------------------------------------------- #

@dataclass
class TaskRequest:
    """Broadcast: Knoten kündigt Rechenaufgabe für den Schwarm an."""
    task_id:           str
    task_type:         str            # TASK_* Konstante
    payload_fingerprint: str          # SHA256 des Invarianten-Vektors (kein Inhalt)
    invariant_vector:  List[float]    # 9-Invarianten-Vektor Φ (strukturell, kein Inhalt)
    requirements:      List[str]      # Benötigte Probes: ["numpy", "scipy"]
    bounty_priority:   int            # 0–10; höher = dringender
    requester_node_id: str
    expires_ts:        float          # Unix-Timestamp
    chunk_class:       str = "generic"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema":               "aether.task.request.v1",
            "task_id":              self.task_id,
            "task_type":            self.task_type,
            "payload_fingerprint":  self.payload_fingerprint,
            "invariant_vector":     [round(v, 6) for v in self.invariant_vector],
            "requirements":         self.requirements,
            "bounty_priority":      self.bounty_priority,
            "requester_node_id":    self.requester_node_id,
            "expires_ts":           self.expires_ts,
            "chunk_class":          self.chunk_class,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TaskRequest":
        return cls(
            task_id=str(d["task_id"]),
            task_type=str(d["task_type"]),
            payload_fingerprint=str(d["payload_fingerprint"]),
            invariant_vector=[float(v) for v in d.get("invariant_vector", [])],
            requirements=list(d.get("requirements", [])),
            bounty_priority=int(d.get("bounty_priority", 0)),
            requester_node_id=str(d["requester_node_id"]),
            expires_ts=float(d["expires_ts"]),
            chunk_class=str(d.get("chunk_class", "generic")),
        )


@dataclass
class TaskBid:
    """Response: Fähiger Peer bietet Ausführung an."""
    bid_id:               str
    task_id:              str
    bidder_node_id:       str
    capability_score_pct: float   # Eigener Capability-Score des Bieters
    eta_seconds:          float   # Geschätzte Ausführungszeit
    bidder_relay_url:     str = ""
    bidder_ygg_addr:      str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema":               "aether.task.bid.v1",
            "bid_id":               self.bid_id,
            "task_id":              self.task_id,
            "bidder_node_id":       self.bidder_node_id,
            "capability_score_pct": round(self.capability_score_pct, 1),
            "eta_seconds":          round(self.eta_seconds, 1),
            "bidder_relay_url":     self.bidder_relay_url,
            "bidder_ygg_addr":      self.bidder_ygg_addr,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TaskBid":
        return cls(
            bid_id=str(d["bid_id"]),
            task_id=str(d["task_id"]),
            bidder_node_id=str(d["bidder_node_id"]),
            capability_score_pct=float(d.get("capability_score_pct", 0.0)),
            eta_seconds=float(d.get("eta_seconds", 60.0)),
            bidder_relay_url=str(d.get("bidder_relay_url", "")),
            bidder_ygg_addr=str(d.get("bidder_ygg_addr", "")),
        )


@dataclass
class TaskResult:
    """Delivery: Executor liefert Ergebnis als strukturelle Fingerprints."""
    task_id:              str
    executor_node_id:     str
    result_fingerprints:  List[str]   # SHA256-Hashes der abgeleiteten Strukturanker
    compression_achieved: float        # Verhältnis zu naivem Ansatz (niedriger = besser)
    algo_token_id:        str = ""     # Optional: benutzter/generierter AlgoToken
    ts:                   float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema":               "aether.task.result.v1",
            "task_id":              self.task_id,
            "executor_node_id":     self.executor_node_id,
            "result_fingerprints":  self.result_fingerprints[:64],
            "compression_achieved": round(self.compression_achieved, 4),
            "algo_token_id":        self.algo_token_id,
            "ts":                   self.ts,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TaskResult":
        return cls(
            task_id=str(d["task_id"]),
            executor_node_id=str(d["executor_node_id"]),
            result_fingerprints=list(d.get("result_fingerprints", [])),
            compression_achieved=float(d.get("compression_achieved", 1.0)),
            algo_token_id=str(d.get("algo_token_id", "")),
            ts=float(d.get("ts", time.time())),
        )


# --------------------------------------------------------------------------- #
#  Kern-Engine                                                                 #
# --------------------------------------------------------------------------- #

class TaskBroker:
    """Verwaltet ausgehende Task-Requests und eingehende Bids/Results.

    Singleton pro Prozess — TaskBroker.instance() verwenden.
    Thread-sicher. Persistente Queue überlebt Neustarts.

    REQUESTER-SEITE:
      create_task_request(...)        → erzeugt + registriert Task
      get_pending_requests_to_broadcast() → fürs Gossip-Paket
      receive_bid(bid_data)           → verarbeitet eingehende Gebote
      receive_result(result_data)     → verarbeitet fertiges Ergebnis
      get_best_bid(task_id)           → wählt bestes Gebot
      get_result(task_id)             → holt fertiges Ergebnis

    EXECUTOR-SEITE:
      receive_remote_request(req_data) → speichert fremden Task
      get_executable_requests(...)    → Tasks die wir ausführen können
      build_bid_for(req, ...)         → Gebot erstellen
      execute_task(req, ...)          → Task lokal ausführen
    """

    _instance: Optional["TaskBroker"] = None
    _instance_lock = threading.Lock()

    @classmethod
    def instance(cls) -> "TaskBroker":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._my_requests:    Dict[str, TaskRequest]        = {}
        self._incoming_bids:  Dict[str, List[TaskBid]]      = {}
        self._results:        Dict[str, TaskResult]          = {}
        self._remote_requests: List[TaskRequest]             = []
        self._completed_count: int = 0
        self._load_persistent()

    # ── Persistenz ────────────────────────────────────────────────────────── #

    def _load_persistent(self) -> None:
        try:
            if TASK_QUEUE_PATH.is_file():
                data = json.loads(TASK_QUEUE_PATH.read_text(encoding="utf-8"))
                now = time.time()
                for d in data.get("pending", []):
                    try:
                        req = TaskRequest.from_dict(d)
                        if req.expires_ts > now:
                            self._my_requests[req.task_id] = req
                    except Exception:
                        pass
            if TASK_RESULTS_PATH.is_file():
                data = json.loads(TASK_RESULTS_PATH.read_text(encoding="utf-8"))
                self._completed_count = int(data.get("completed_count", 0))
        except Exception as exc:
            logger.debug(f"[task_broker] load_persistent: {exc}")

    def _save_persistent(self) -> None:
        try:
            TASK_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
            now = time.time()
            pending = [r.to_dict() for r in self._my_requests.values()
                       if r.expires_ts > now]
            TASK_QUEUE_PATH.write_text(
                json.dumps({"schema": "aether.task_queue.v1", "pending": pending},
                           ensure_ascii=True, indent=2),
                encoding="utf-8",
            )
            TASK_RESULTS_PATH.write_text(
                json.dumps({"schema": "aether.task_results.v1",
                            "completed_count": self._completed_count},
                           ensure_ascii=True, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.debug(f"[task_broker] save_persistent: {exc}")

    # ── Requester-Seite ───────────────────────────────────────────────────── #

    def create_task_request(
        self,
        task_type: str,
        invariant_vector: List[float],
        *,
        requirements: Optional[List[str]] = None,
        bounty_priority: int = 5,
        requester_node_id: str = "",
        chunk_class: str = "generic",
        ttl: float = TASK_TTL_SECONDS,
    ) -> TaskRequest:
        """Erzeugt und registriert einen neuen Task-Request für den Broadcast."""
        phi = [float(v) for v in invariant_vector[:9]]
        payload_fp = hashlib.sha256(
            json.dumps([round(v, 6) for v in phi], separators=(",", ":")).encode()
        ).hexdigest()
        task_id = "task-" + uuid.uuid4().hex[:16]
        req = TaskRequest(
            task_id=task_id,
            task_type=task_type,
            payload_fingerprint=payload_fp,
            invariant_vector=phi,
            requirements=requirements or [],
            bounty_priority=max(0, min(10, bounty_priority)),
            requester_node_id=requester_node_id,
            expires_ts=time.time() + ttl,
            chunk_class=chunk_class,
        )
        with self._lock:
            self._my_requests[task_id] = req
            self._save_persistent()
        logger.info(f"[task_broker] Task erzeugt: {task_id[:16]}... "
                    f"type={task_type} prio={bounty_priority}")
        return req

    def get_pending_requests_to_broadcast(self) -> List[Dict[str, Any]]:
        """Gibt ausstehende eigene Tasks für das nächste Gossip-Paket zurück."""
        now = time.time()
        with self._lock:
            return [
                r.to_dict() for r in self._my_requests.values()
                if r.expires_ts > now and r.bounty_priority >= 3
            ][:4]  # max 4 pro Gossip-Paket

    def receive_bid(self, bid_data: Dict[str, Any]) -> None:
        """Verarbeitet ein eingehendes Gebot eines Peers."""
        try:
            bid = TaskBid.from_dict(bid_data)
        except Exception:
            return
        with self._lock:
            if bid.task_id not in self._my_requests:
                return
            self._incoming_bids.setdefault(bid.task_id, []).append(bid)
        logger.info(f"[task_broker] Bid für {bid.task_id[:16]}... "
                    f"von {bid.bidder_node_id[:16]}... "
                    f"cap={bid.capability_score_pct:.0f}% eta={bid.eta_seconds:.0f}s")

    def receive_result(self, result_data: Dict[str, Any]) -> Optional[TaskResult]:
        """Verarbeitet ein fertiges Ergebnis. Gibt TaskResult zurück wenn eigener Task."""
        try:
            result = TaskResult.from_dict(result_data)
        except Exception:
            return None
        with self._lock:
            if result.task_id not in self._my_requests:
                return None
            self._results[result.task_id] = result
            del self._my_requests[result.task_id]
            self._save_persistent()
        logger.info(f"[task_broker] Ergebnis für {result.task_id[:16]}... "
                    f"von {result.executor_node_id[:16]}... "
                    f"compression={result.compression_achieved:.3f} "
                    f"fps={len(result.result_fingerprints)}")
        # Ergebnis-Fingerprints in lokales Wissen kristallisieren
        try:
            from modules.offline_learning import OfflineLearner
            OfflineLearner.instance().on_task_result(
                result.result_fingerprints, task_type=result.task_id
            )
        except Exception:
            pass
        return result

    def get_result(self, task_id: str) -> Optional[TaskResult]:
        with self._lock:
            return self._results.get(task_id)

    def get_best_bid(self, task_id: str) -> Optional[TaskBid]:
        """Bestes Gebot (höchster Capability-Score, bereinigt um ETA)."""
        with self._lock:
            bids = self._incoming_bids.get(task_id, [])
            if not bids:
                return None
            return max(bids, key=lambda b: b.capability_score_pct - b.eta_seconds * 0.01)

    # ── Executor-Seite ────────────────────────────────────────────────────── #

    def receive_remote_request(self, request_data: Dict[str, Any]) -> Optional[TaskRequest]:
        """Speichert eingehenden fremden Task-Request.
        Gibt None zurück wenn abgelaufen oder fehlerhaft.
        """
        try:
            req = TaskRequest.from_dict(request_data)
        except Exception:
            return None
        if req.expires_ts < time.time():
            return None
        with self._lock:
            self._remote_requests.append(req)
            if len(self._remote_requests) > 32:
                self._remote_requests = self._remote_requests[-32:]
        return req

    def get_executable_requests(
        self,
        local_capabilities: List[str],
        local_score_pct: float,
    ) -> List[TaskRequest]:
        """Gibt fremde Tasks zurück die dieser Knoten ausführen kann.

        Ein Task ist ausführbar wenn:
        - Eigener Capability-Score >= MIN_SCORE_TO_ACCEPT (50%)
        - Alle benötigten Probes lokal vorhanden
        - Task noch nicht abgelaufen
        """
        if local_score_pct < MIN_SCORE_TO_ACCEPT:
            return []
        now = time.time()
        cap_set = set(local_capabilities)
        with self._lock:
            return [
                r for r in self._remote_requests
                if r.expires_ts > now and set(r.requirements).issubset(cap_set)
            ]

    def build_bid_for(
        self,
        request: TaskRequest,
        local_node_id: str,
        local_score_pct: float,
        relay_url: str = "",
        ygg_addr: str = "",
    ) -> TaskBid:
        """Erstellt ein Gebot für einen ausführbaren Task."""
        base_eta = {
            TASK_INVARIANT_ANALYSIS: 2.0,
            TASK_VAULT_EVOLVE:        10.0,
            TASK_FRAME_DELTA:         5.0,
            TASK_PREDICTION_TRAIN:    30.0,
        }.get(request.task_type, 15.0)
        # Niedrigerer Score = langsamer = höhere ETA
        eta = base_eta * max(1.0, 100.0 / max(1.0, local_score_pct))
        return TaskBid(
            bid_id="bid-" + uuid.uuid4().hex[:12],
            task_id=request.task_id,
            bidder_node_id=local_node_id,
            capability_score_pct=local_score_pct,
            eta_seconds=eta,
            bidder_relay_url=relay_url,
            bidder_ygg_addr=ygg_addr,
        )

    def execute_task(
        self,
        request: TaskRequest,
        executor_node_id: str,
        local_score_pct: float,
    ) -> Optional[TaskResult]:
        """Führt einen Task lokal aus und gibt das Ergebnis zurück.

        Aktuell: Ableitung struktureller Fingerprints aus dem Φ-Vektor.
        Privatsphäre: Ergebnis sind IMMER nur strukturelle Fingerprints,
        niemals Rohdaten oder Inhalte.
        """
        try:
            start = time.time()
            result_fps = _compute_structural_fingerprints(
                request.invariant_vector,
                request.task_type,
                request.chunk_class,
            )
            elapsed = time.time() - start
            raw_size = max(1, len(request.invariant_vector)) * 8 * 64
            compression = len(result_fps) * 64 / raw_size
            with self._lock:
                self._completed_count += 1
                self._save_persistent()
            logger.info(f"[task_broker] Task {request.task_id[:16]}... "
                        f"ausgeführt in {elapsed:.2f}s, "
                        f"{len(result_fps)} Output-Fingerprints")
            return TaskResult(
                task_id=request.task_id,
                executor_node_id=executor_node_id,
                result_fingerprints=result_fps,
                compression_achieved=compression,
                ts=time.time(),
            )
        except Exception as exc:
            logger.warning(f"[task_broker] execute_task fehlgeschlagen: {exc}")
            return None

    def get_contribution_count(self) -> int:
        """Wie viele Tasks hat dieser Knoten bisher für andere ausgeführt?
        Wird für den Contribution-Index in capability_score.py verwendet.
        """
        with self._lock:
            return self._completed_count

    def get_bids_to_broadcast(self, local_node_id: str, local_score_pct: float,
                               local_caps: List[str]) -> List[Dict[str, Any]]:
        """Erstellt Gebote für ausführbare fremde Tasks (für Gossip-Paket)."""
        bids = []
        for req in self.get_executable_requests(local_caps, local_score_pct):
            bid = self.build_bid_for(req, local_node_id, local_score_pct)
            bids.append(bid.to_dict())
        return bids[:4]  # max 4 Gebote pro Gossip-Paket


# --------------------------------------------------------------------------- #
#  Interne Berechnung                                                          #
# --------------------------------------------------------------------------- #

def _compute_structural_fingerprints(
    invariant_vector: List[float],
    task_type: str,
    chunk_class: str,
) -> List[str]:
    """Leitet strukturelle Fingerprints aus einem Invarianten-Vektor ab.

    Das ist die Kernberechnung die schwache Knoten an starke auslagern.
    Input:  9-Invarianten-Vektor Φ = (H_S, H_B, α_Z, β_F, ρ_P, D_K, H_P, Δ_C, K_N)
    Output: Liste von SHA256-Fingerprints die ableitbare Strukturanker repräsentieren
    Privatsphäre: Keine Rohdaten an irgendeiner Stelle.
    """
    fps: List[str] = []

    # Primär-Fingerprint: SHA256 des vollständigen Φ-Vektors
    phi_str = json.dumps([round(v, 6) for v in invariant_vector[:9]],
                         separators=(",", ":"))
    fps.append(hashlib.sha256(
        f"{task_type}:{chunk_class}:{phi_str}".encode()
    ).hexdigest())

    # Dimensionale Fingerprints: jede Invarianten-Dimension einzeln analysiert
    inv_names = [
        "h_shannon", "h_boltzmann", "alpha_zipf", "beta_benford",
        "rho_fourier", "D_katz", "H_perm", "delta_conv", "K_noether",
    ]
    for name, val in zip(inv_names, invariant_vector[:9]):
        # Quantisierung auf 4 signifikante Bits → struktureller Bucket
        if 0.0 <= val <= 1.0:
            bucket = int(val * 16)
        else:
            bucket = int(abs(val) * 4) % 64
        fps.append(hashlib.sha256(
            f"{name}:{bucket}:{chunk_class}:{task_type}".encode()
        ).hexdigest())

    # Paarweise Korrelations-Fingerprints für die wichtigsten Invariantenpaare
    pairs = [(0, 2), (0, 4), (2, 5), (6, 7)]  # (Shannon,Zipf), (Shannon,Fourier), etc.
    for i, j in pairs:
        if i < len(invariant_vector) and j < len(invariant_vector):
            v_i = round(invariant_vector[i], 4)
            v_j = round(invariant_vector[j], 4)
            fps.append(hashlib.sha256(
                f"pair:{inv_names[i]}:{v_i}:{inv_names[j]}:{v_j}:{chunk_class}".encode()
            ).hexdigest())

    return fps[:16]  # max 16 Output-Fingerprints pro Task
