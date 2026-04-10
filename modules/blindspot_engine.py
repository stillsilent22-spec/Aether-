"""
blindspot_engine.py — Gödelsche Selbstreferenz und evolutionärer Wachstums-Loop
================================================================================

KERNIDEE: Ein System das seine eigenen Schwächen kennt, kommuniziert und
überwindet ist stabiler als eines das sie ignoriert.

Gödels Unvollständigkeitssatz übersetzt auf Knoten-Ebene:
  Kein Knoten kann alles von sich selbst wissen — aber er kann seine
  Blindstellen benennen, andere um Hilfe bitten, und die empfangene Hilfe
  dauerhaft in sein eigenes Wissen integrieren (unabhängiges Lernen).

Drei Ebenen:

1. SELBSTERKENNUNG (nie aufhörender Monitoring-Loop):
   - Capability-Gaps: "Mir fehlt NumPy / Yggdrasil / die Rust-Shell"
   - Compute-Limits: "Ich kann Task Typ X nicht ausführen — zu schwach"
   - Wissens-Gaps: "Ich habe keinen Anker für Chunk-Klasse Y"
   - Bootstrap-Gaps: "Ich bin neu — was brauche ich für den nächsten Tier?"
   - Permanente Gaps: Wenn Berechnungen komplett unlösbar sind → Blindspot melden

2. SWARM-KOMMUNIKATION (via Gossip):
   - Gaps werden als "blindspot_signals" in Gossip-Pakete eingebettet
   - Peers die eine Lösung haben antworten mit "blindspot_hints"
   - Kein Handshake nötig — Gossip überträgt beides passiv

3. UNABHÄNGIGES LERNEN (Gödel-Boost):
   - Empfangene Hints werden in den lokalen OfflineLearner kristallisiert
   - Gelöste Gaps werden zu "known_strengths" — der Knoten kann nun anderen helfen
   - Der Loop hört NIE auf: neue Stärken decken neue Blindstellen auf (Rekursion)
   - Ziel: nicht nur der Schwarm wird besser, jeder Teilnehmer wird unabhängig besser

Persistenz:
  data/interbus/blindspot_state.json — aktuelle Gaps + resolved History
  data/interbus/peer_blindspots.json — was andere Peers gemeldet haben (wir können helfen)
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
BLINDSPOT_STATE_PATH  = ROOT / "data" / "interbus" / "blindspot_state.json"
PEER_BLINDSPOTS_PATH  = ROOT / "data" / "interbus" / "peer_blindspots.json"

# Nach wie vielen Sekunden ein ungelöster Gap erneut gebroadcastet wird
REBROADCAST_INTERVAL_SEC = 300

# Maximal gemeldete Gaps pro Gossip-Paket (Bandbreite schonen)
MAX_GAPS_PER_GOSSIP = 6

# Maximal gespeicherte gelöste Gaps in der History
MAX_RESOLVED_HISTORY = 256

# Wie oft der Monitoring-Tick läuft (Sekunden)
MONITOR_INTERVAL_SEC = 60


# --------------------------------------------------------------------------- #
#  Gap-Typen                                                                  #
# --------------------------------------------------------------------------- #

GAP_MISSING_MODULE   = "missing_module"    # Python/Rust-Abhängigkeit fehlt
GAP_COMPUTE_LIMIT    = "compute_limit"     # Zu schwach für Task-Typ X
GAP_KNOWLEDGE_GAP    = "knowledge_gap"     # Kein Anker / Prior für Chunk-Klasse
GAP_BOOTSTRAP_GAP    = "bootstrap_gap"     # Neuer Knoten: fehlt Wissen für nächsten Tier
GAP_PROGRESSION_STEP = "progression_step"  # Weiß was fehlt um nächsten Tier zu erreichen
GAP_UNSOLVABLE       = "unsolvable"        # Komplett unlösbar ohne Hilfe (echter Blindspot)


@dataclass
class BlindspotSignal:
    """Ein strukturierter Blindspot — exportierbar als Gossip-Feld."""
    signal_id:    str
    domain:       str   # z.B. "rust_shell", "yggdrasil", "invariant_analysis", "vault_evolution"
    gap_type:     str   # GAP_* Konstante
    description:  str   # Menschenlesbar
    priority:     int   # 0–10; 10 = kritisch
    created_ts:   float
    last_broadcast_ts: float = 0.0
    hint_count:   int = 0       # Wie viele Hints wurden empfangen?
    resolved:     bool = False
    resolved_ts:  float = 0.0
    resolved_by:  str = ""      # peer_node_id der geholfen hat (leer = selbst gelöst)
    metadata:     Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema":             "aether.blindspot.signal.v1",
            "signal_id":          self.signal_id,
            "domain":             self.domain,
            "gap_type":           self.gap_type,
            "description":        self.description,
            "priority":           self.priority,
            "created_ts":         round(self.created_ts, 3),
            "last_broadcast_ts":  round(self.last_broadcast_ts, 3),
            "hint_count":         self.hint_count,
            "resolved":           self.resolved,
            "resolved_ts":        round(self.resolved_ts, 3),
            "resolved_by":        self.resolved_by,
            "metadata":           self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "BlindspotSignal":
        return cls(
            signal_id=str(d.get("signal_id", "")),
            domain=str(d.get("domain", "")),
            gap_type=str(d.get("gap_type", GAP_KNOWLEDGE_GAP)),
            description=str(d.get("description", "")),
            priority=int(d.get("priority", 5)),
            created_ts=float(d.get("created_ts", time.time())),
            last_broadcast_ts=float(d.get("last_broadcast_ts", 0.0)),
            hint_count=int(d.get("hint_count", 0)),
            resolved=bool(d.get("resolved", False)),
            resolved_ts=float(d.get("resolved_ts", 0.0)),
            resolved_by=str(d.get("resolved_by", "")),
            metadata=dict(d.get("metadata", {})),
        )


@dataclass
class BlindspotHint:
    """Antwort eines Peers auf einen Gap-Signal — direkt kristallisierbar."""
    hint_id:         str
    signal_id:       str         # Welchen Gap beantwortet dieser Hint?
    from_peer:       str         # node_id des helfenden Peers
    domain:          str
    hint_type:       str         # "instruction", "anchor_data", "algo_token", "knowledge_pack"
    payload_hash:    str         # SHA256 des Hint-Inhalts (kein Rohinhalt)
    instructions:    str         # Menschenlesbare Anweisung (z.B. "pip install numpy")
    fingerprints:    List[str]   # Strukturelle Fingerprints zum Kristallisieren
    priority_boost:  float       # Wie stark hilft dieser Hint? 0.0–1.0
    ts:              float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema":         "aether.blindspot.hint.v1",
            "hint_id":        self.hint_id,
            "signal_id":      self.signal_id,
            "from_peer":      self.from_peer,
            "domain":         self.domain,
            "hint_type":      self.hint_type,
            "payload_hash":   self.payload_hash,
            "instructions":   self.instructions,
            "fingerprints":   self.fingerprints[:32],
            "priority_boost": round(self.priority_boost, 4),
            "ts":             round(self.ts, 3),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "BlindspotHint":
        return cls(
            hint_id=str(d.get("hint_id", "")),
            signal_id=str(d.get("signal_id", "")),
            from_peer=str(d.get("from_peer", "")),
            domain=str(d.get("domain", "")),
            hint_type=str(d.get("hint_type", "instruction")),
            payload_hash=str(d.get("payload_hash", "")),
            instructions=str(d.get("instructions", "")),
            fingerprints=list(d.get("fingerprints", [])),
            priority_boost=float(d.get("priority_boost", 0.5)),
            ts=float(d.get("ts", time.time())),
        )


# --------------------------------------------------------------------------- #
#  BlindspotEngine                                                             #
# --------------------------------------------------------------------------- #

class BlindspotEngine:
    """Gödelsche Selbstreferenz-Engine für Aether-Knoten.

    Singleton pro Prozess — BlindspotEngine.instance() verwenden.
    Thread-sicher.

    Lifecycle:
      1. start() — Monitoring-Loop starten
      2. tick() — Einmalig manuell auslösen (wird auch von start() genutzt)
      3. get_signals_for_broadcast() — ausstehende Gaps für Gossip-Einbettung
      4. absorb_peer_hints(hints, peer_id) — empfangene Hints kristallisieren
      5. absorb_peer_gaps(peer_id, gaps) — Gaps anderer Peers speichern
      6. get_evolutionary_status() — Gesundheit + Wachstum des Knotens messen
    """

    _instance: Optional["BlindspotEngine"] = None
    _instance_lock = threading.Lock()

    @classmethod
    def instance(cls) -> "BlindspotEngine":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self) -> None:
        self._lock             = threading.Lock()
        self._active_gaps:     Dict[str, BlindspotSignal] = {}   # signal_id → signal
        self._resolved_history: List[BlindspotSignal]     = []
        self._known_strengths:  Dict[str, float]          = {}   # domain → confidence 0–1
        self._peer_gaps:        Dict[str, List[Dict]]     = {}   # peer_id → list of gap dicts
        self._hints_received:   int                       = 0
        self._gaps_resolved:    int                       = 0
        self._is_running        = False
        self._stop_event        = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._load_state()

    # ── Lifecycle ─────────────────────────────────────────────────────────── #

    def start(self) -> None:
        """Startet den kontinuierlichen Monitoring-Loop (daemon-Thread)."""
        with self._lock:
            if self._is_running:
                return
            self._is_running = True
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="blindspot-engine",
        )
        self._monitor_thread.start()
        logger.info("[blindspot] Monitoring-Loop gestartet.")

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            self._is_running = False

    def _monitor_loop(self) -> None:
        """Läuft dauerhaft — erkennt neue Gaps, entfernt gelöste."""
        while not self._stop_event.is_set():
            try:
                self.tick()
            except Exception as exc:
                logger.debug(f"[blindspot] monitor_loop tick: {exc}")
            self._stop_event.wait(MONITOR_INTERVAL_SEC)

    # ── Kern-Tick ─────────────────────────────────────────────────────────── #

    def tick(self) -> Dict[str, Any]:
        """Einen vollständigen Monitoring-Zyklus durchführen.

        Erkennt automatisch:
        - Fehlende Capabilities aus capability_score.json
        - Compute-Limits aus task_broker (Tasks ohne Bids)
        - Wissens-Gaps aus knowledge_snapshot
        - Bootstrap-Gaps für neue/schwache Knoten

        Gibt Zusammenfassung zurück.
        """
        new_gaps: List[str] = []
        resolved: List[str] = []

        new_gaps += self._check_capability_gaps()
        new_gaps += self._check_compute_limits()
        new_gaps += self._check_knowledge_gaps()
        new_gaps += self._check_bootstrap_gaps()
        resolved += self._auto_resolve_gaps()

        self._save_state()

        return {
            "new_gaps":      new_gaps,
            "resolved":      resolved,
            "active_count":  len(self._active_gaps),
            "total_resolved": self._gaps_resolved,
            "hints_received": self._hints_received,
            "known_strengths": len(self._known_strengths),
        }

    # ── Gap-Erkennung ─────────────────────────────────────────────────────── #

    def _check_capability_gaps(self) -> List[str]:
        """Liest capability_score.json und meldet fehlende Proben als Gaps."""
        new = []
        try:
            path = ROOT / "data" / "interbus" / "capability_score.json"
            if not path.is_file():
                return new
            data = json.loads(path.read_text(encoding="utf-8"))
            probes: Dict[str, Any] = data.get("probes", {})
            next_goal = str(data.get("next_goal", ""))
            stage_index = int(data.get("stage_index", 0))

            for probe_name, probe_data in probes.items():
                if not isinstance(probe_data, dict):
                    continue
                if probe_data.get("ok"):
                    # Probe OK → Stärke registrieren, zugehörigen Gap schließen
                    self._mark_strength(probe_name, 1.0)
                    self._auto_resolve_by_domain(probe_name)
                    continue

                # Probe fehlt → Gap registrieren
                domain = probe_name
                description = (
                    probe_data.get("note") or
                    probe_data.get("error") or
                    "Probe nicht verfügbar: " + probe_name
                )
                priority = 8 if stage_index <= 1 else 6
                sig_id = "cap-" + hashlib.sha256(domain.encode()).hexdigest()[:16]
                if sig_id not in self._active_gaps:
                    self.register_gap(
                        domain=domain,
                        gap_type=GAP_MISSING_MODULE,
                        description=str(description),
                        priority=priority,
                        signal_id=sig_id,
                        metadata={"next_goal": next_goal, "stage_index": stage_index},
                    )
                    new.append(sig_id)
        except Exception as exc:
            logger.debug(f"[blindspot] _check_capability_gaps: {exc}")
        return new

    def _check_compute_limits(self) -> List[str]:
        """Prüft TaskBroker: Tasks ohne Bids nach Timeout → Compute-Limit-Gap."""
        new = []
        try:
            from modules.task_broker import TaskBroker as _TB
            broker = _TB.instance()
            pending = broker.get_pending_requests_to_broadcast()
            now = time.time()
            for req_dict in pending:
                task_id = str(req_dict.get("task_id", ""))
                task_type = str(req_dict.get("task_type", ""))
                expires = float(req_dict.get("expires_ts", 0))
                created_approx = expires - 300.0  # TTL ist 300s
                # Wenn Task älter als 120s und noch keine Bids → Compute-Limit-Gap
                if (now - created_approx) > 120:
                    sig_id = "compute-" + hashlib.sha256(task_type.encode()).hexdigest()[:16]
                    if sig_id not in self._active_gaps:
                        self.register_gap(
                            domain=task_type,
                            gap_type=GAP_COMPUTE_LIMIT,
                            description=(
                                "Task " + task_type + " hat keine Bids erhalten — "
                                "kein Peer stark genug oder kein Peer erreichbar."
                            ),
                            priority=7,
                            signal_id=sig_id,
                            metadata={"task_id": task_id},
                        )
                        new.append(sig_id)
        except Exception as exc:
            logger.debug(f"[blindspot] _check_compute_limits: {exc}")
        return new

    def _check_knowledge_gaps(self) -> List[str]:
        """Prüft knowledge_snapshot: leere oder schwache Einträge → Knowledge-Gap."""
        new = []
        try:
            path = ROOT / "data" / "interbus" / "knowledge_snapshot.json"
            if not path.is_file():
                return new
            data = json.loads(path.read_text(encoding="utf-8"))
            stats = data.get("prediction_stats", {})
            total_obs = int(stats.get("total_observations", 0))
            prefetch_acc = float(stats.get("prefetch_accuracy", 0.0))
            algo_tokens = list(data.get("algo_tokens_top10", []))

            # Kein Wissen vorhanden = Wissens-Gap
            if total_obs < 10:
                sig_id = "knowledge-bootstrap"
                if sig_id not in self._active_gaps:
                    self.register_gap(
                        domain="knowledge_bootstrap",
                        gap_type=GAP_KNOWLEDGE_GAP,
                        description=(
                            "Zu wenige Beobachtungen (" + str(total_obs) + ") — "
                            "Knoten hat noch kaum eigene Analyse-Erfahrung. "
                            "Peers können Genesis-Priors teilen."
                        ),
                        priority=6,
                        signal_id=sig_id,
                        metadata={"total_observations": total_obs},
                    )
                    new.append(sig_id)
            elif total_obs >= 50:
                self._auto_resolve_by_domain("knowledge_bootstrap")

            # Schwache Vorhersage = Wissens-Gap
            if total_obs > 10 and prefetch_acc < 0.3:
                sig_id = "knowledge-prefetch-weak"
                if sig_id not in self._active_gaps:
                    self.register_gap(
                        domain="prefetch_accuracy",
                        gap_type=GAP_KNOWLEDGE_GAP,
                        description=(
                            "Prefetch-Genauigkeit zu schwach ("
                            + str(round(prefetch_acc * 100, 1)) + "%) — "
                            "Peers mit besseren Vorhersagen können Hints teilen."
                        ),
                        priority=4,
                        signal_id=sig_id,
                        metadata={"prefetch_accuracy": prefetch_acc},
                    )
                    new.append(sig_id)
            elif prefetch_acc >= 0.5:
                self._auto_resolve_by_domain("prefetch_accuracy")

            # Kein AlgoToken = Algorithmen-Gap
            if not algo_tokens:
                sig_id = "knowledge-no-algotokens"
                if sig_id not in self._active_gaps:
                    self.register_gap(
                        domain="algo_tokens",
                        gap_type=GAP_KNOWLEDGE_GAP,
                        description=(
                            "Keine AlgoTokens vorhanden — "
                            "Peers können bessere Kompressions-Algorithmen teilen."
                        ),
                        priority=5,
                        signal_id=sig_id,
                    )
                    new.append(sig_id)
            elif len(algo_tokens) >= 2:
                self._auto_resolve_by_domain("algo_tokens")

        except Exception as exc:
            logger.debug(f"[blindspot] _check_knowledge_gaps: {exc}")
        return new

    def _check_bootstrap_gaps(self) -> List[str]:
        """Prüft ob der Knoten neu ist und welche Schritte für den nächsten Tier fehlen."""
        new = []
        try:
            cap_path = ROOT / "data" / "interbus" / "capability_score.json"
            if not cap_path.is_file():
                return new
            data = json.loads(cap_path.read_text(encoding="utf-8"))
            stage_index = int(data.get("stage_index", 0))
            next_goal = str(data.get("next_goal", ""))
            score_pct = int(data.get("percent_int", 0))

            if stage_index <= 1 and score_pct < 50:
                sig_id = "bootstrap-new-node"
                if sig_id not in self._active_gaps:
                    self.register_gap(
                        domain="node_bootstrap",
                        gap_type=GAP_BOOTSTRAP_GAP,
                        description=(
                            "Neuer/schwacher Knoten (Score " + str(score_pct) + "%) — "
                            "braucht Unterstützung um vollwertiger Swarm-Teilnehmer zu werden. "
                            "Nächstes Ziel: " + (next_goal or "Capability-Score erhöhen.")
                        ),
                        priority=9,
                        signal_id=sig_id,
                        metadata={
                            "score_pct": score_pct,
                            "stage_index": stage_index,
                            "next_goal": next_goal,
                        },
                    )
                    new.append(sig_id)
            elif score_pct >= 60:
                self._auto_resolve_by_domain("node_bootstrap")

            # Progression-Step: Knoten weiß was er braucht für den nächsten Tier
            if next_goal and stage_index >= 1 and score_pct < 90:
                sig_id = "progression-" + hashlib.sha256(next_goal.encode()).hexdigest()[:12]
                if sig_id not in self._active_gaps:
                    self.register_gap(
                        domain="progression_path",
                        gap_type=GAP_PROGRESSION_STEP,
                        description="Progression-Schritt bekannt: " + next_goal,
                        priority=5,
                        signal_id=sig_id,
                        metadata={"next_goal": next_goal, "stage_index": stage_index},
                    )
                    new.append(sig_id)
        except Exception as exc:
            logger.debug(f"[blindspot] _check_bootstrap_gaps: {exc}")
        return new

    # ── Manuelle Gap-Registrierung ─────────────────────────────────────────── #

    def register_gap(
        self,
        domain: str,
        gap_type: str,
        description: str,
        priority: int = 5,
        signal_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> BlindspotSignal:
        """Registriert einen neuen Gap. Idempotent per signal_id.

        Kann von jedem Modul aufgerufen werden wenn es an eine Grenze stößt.
        Z.B.: analyse_capsule wenn kein Anker für Chunk-Klasse existiert.
        """
        if signal_id is None:
            raw = domain + "|" + gap_type + "|" + description[:64]
            signal_id = "gap-" + hashlib.sha256(raw.encode()).hexdigest()[:16]
        with self._lock:
            if signal_id in self._active_gaps:
                return self._active_gaps[signal_id]
            sig = BlindspotSignal(
                signal_id=signal_id,
                domain=str(domain),
                gap_type=str(gap_type),
                description=str(description),
                priority=max(0, min(10, int(priority))),
                created_ts=time.time(),
                metadata=metadata or {},
            )
            self._active_gaps[signal_id] = sig
            logger.info(
                "[blindspot] Neuer Gap: domain=%s type=%s prio=%d",
                domain, gap_type, priority,
            )
        return sig

    def register_unsolvable(
        self,
        domain: str,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> BlindspotSignal:
        """Für den härtesten Fall: komplett unlösbar ohne externe Hilfe.

        Sendet Priority-10-Gap — maximale Dringlichkeit im Schwarm.
        """
        return self.register_gap(
            domain=domain,
            gap_type=GAP_UNSOLVABLE,
            description=description,
            priority=10,
            metadata=metadata,
        )

    # ── Hint-Absorption (Gödel-Boost) ─────────────────────────────────────── #

    def absorb_peer_hints(
        self,
        hints: List[Dict[str, Any]],
        peer_node_id: str,
    ) -> int:
        """Verarbeitet empfangene Hints eines Peers.

        Für jeden Hint:
        1. Sucht den passenden aktiven Gap
        2. Kristallisiert die Fingerprints via OfflineLearner (unabhängiges Lernen)
        3. Markiert den Gap als teilweise/vollständig gelöst
        4. Macht den Knoten zum potenziellen Helfer für denselben Gap → Stärke

        Gibt Anzahl verarbeiteter Hints zurück.
        """
        absorbed = 0
        for hint_data in hints:
            try:
                hint = BlindspotHint.from_dict(hint_data)
                sig_id = hint.signal_id

                # Fingerprints in OfflineLearner kristallisieren (unabhängiges Lernen)
                if hint.fingerprints:
                    try:
                        from modules.offline_learning import OfflineLearner
                        OfflineLearner.instance().on_task_result(
                            hint.fingerprints,
                            task_type="blindspot_hint:" + hint.domain,
                        )
                    except Exception as ol_exc:
                        logger.debug(f"[blindspot] offline_learner: {ol_exc}")

                with self._lock:
                    if sig_id in self._active_gaps:
                        sig = self._active_gaps[sig_id]
                        sig.hint_count += 1
                        # Nach genug hochwertigen Hints → Gap als gelöst markieren
                        if sig.hint_count >= 1 and hint.priority_boost >= 0.7:
                            self._resolve_gap(sig_id, resolved_by=peer_node_id)
                        elif sig.hint_count >= 3:
                            self._resolve_gap(sig_id, resolved_by=peer_node_id)
                    self._hints_received += 1

                # Stärke eintragen: wir kennen jetzt mehr über diese Domäne
                self._mark_strength(hint.domain, min(1.0, hint.priority_boost + 0.3))

                absorbed += 1
                logger.info(
                    "[blindspot] Hint absorbiert von %s: domain=%s boost=%.2f",
                    peer_node_id[:16],
                    hint.domain,
                    hint.priority_boost,
                )
            except Exception as exc:
                logger.debug(f"[blindspot] absorb_hint: {exc}")

        if absorbed > 0:
            self._save_state()
        return absorbed

    # ── Peer-Gaps speichern (wir können helfen) ───────────────────────────── #

    def absorb_peer_gaps(
        self,
        peer_node_id: str,
        peer_signals: List[Dict[str, Any]],
    ) -> int:
        """Speichert Gaps anderer Peers lokal.

        Diese Information wird von get_hints_for_broadcast() verwendet:
        Wenn wir in einer Domäne eine Stärke haben und ein Peer einen Gap
        in derselben Domäne meldet, generieren wir automatisch einen Hint.
        """
        if not peer_signals:
            return 0
        with self._lock:
            self._peer_gaps[peer_node_id] = [
                d for d in peer_signals if isinstance(d, dict)
            ][:MAX_GAPS_PER_GOSSIP]
        try:
            existing: Dict[str, Any] = {}
            if PEER_BLINDSPOTS_PATH.is_file():
                try:
                    existing = json.loads(PEER_BLINDSPOTS_PATH.read_text(encoding="utf-8"))
                except Exception:
                    existing = {}
            existing[peer_node_id] = {
                "ts": time.time(),
                "signals": peer_signals[:MAX_GAPS_PER_GOSSIP],
            }
            # Maximal 200 Peers behalten
            if len(existing) > 200:
                oldest = sorted(existing.items(), key=lambda kv: kv[1].get("ts", 0))
                for k, _ in oldest[:len(existing) - 200]:
                    del existing[k]
            PEER_BLINDSPOTS_PATH.parent.mkdir(parents=True, exist_ok=True)
            PEER_BLINDSPOTS_PATH.write_text(
                json.dumps(existing, ensure_ascii=True, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.debug(f"[blindspot] absorb_peer_gaps save: {exc}")
        return len(peer_signals)

    # ── Gossip-Integration ────────────────────────────────────────────────── #

    def get_signals_for_broadcast(self) -> List[Dict[str, Any]]:
        """Gibt aktive ungelöste Gaps für das nächste Gossip-Paket zurück.

        Priorisiert: hohe Priorität zuerst, dann älteste (rebroadcast-interval aware).
        Max MAX_GAPS_PER_GOSSIP Einträge.
        """
        now = time.time()
        with self._lock:
            candidates = [
                sig for sig in self._active_gaps.values()
                if not sig.resolved
                and (now - sig.last_broadcast_ts) >= REBROADCAST_INTERVAL_SEC
            ]
        # Sortiert: Priorität absteigend, dann älteste zuerst
        candidates.sort(key=lambda s: (-s.priority, s.last_broadcast_ts))
        result = []
        with self._lock:
            for sig in candidates[:MAX_GAPS_PER_GOSSIP]:
                sig.last_broadcast_ts = now
                result.append(sig.to_dict())
        return result

    def get_hints_for_broadcast(self, local_node_id: str = "") -> List[Dict[str, Any]]:
        """Generiert Hints für Peers deren Gaps wir lösen können.

        Prüft: Haben wir eine Stärke in einer Domäne, für die ein Peer einen Gap hat?
        Falls ja → automatischer Hint mit passendem Inhalt.
        """
        hints = []
        with self._lock:
            strengths_snapshot = dict(self._known_strengths)
            peer_gaps_snapshot = dict(self._peer_gaps)

        for peer_id, peer_gap_list in peer_gaps_snapshot.items():
            for gap_dict in peer_gap_list:
                domain = str(gap_dict.get("domain", ""))
                signal_id = str(gap_dict.get("signal_id", ""))
                gap_type = str(gap_dict.get("gap_type", ""))

                strength = strengths_snapshot.get(domain, 0.0)
                if strength < 0.5:
                    continue  # Wir können nicht helfen

                instruction = self._build_instruction(domain, gap_type, gap_dict)
                if not instruction:
                    continue

                hint_id = "hint-" + hashlib.sha256(
                    (signal_id + local_node_id).encode()
                ).hexdigest()[:16]

                hint = BlindspotHint(
                    hint_id=hint_id,
                    signal_id=signal_id,
                    from_peer=local_node_id,
                    domain=domain,
                    hint_type="instruction",
                    payload_hash=hashlib.sha256(instruction.encode()).hexdigest(),
                    instructions=instruction,
                    fingerprints=[],
                    priority_boost=float(min(1.0, strength)),
                )
                hints.append(hint.to_dict())

        return hints[:MAX_GAPS_PER_GOSSIP]

    def _build_instruction(
        self,
        domain: str,
        gap_type: str,
        gap_dict: Dict[str, Any],
    ) -> str:
        """Erzeugt eine menschenlesbare Hilfs-Anweisung für einen bekannten Gap-Typ."""
        instructions: Dict[str, str] = {
            # Python-Pakete
            "numpy":          "pip install numpy",
            "scipy":          "pip install scipy",
            "cryptography":   "pip install cryptography",
            "nacl":           "pip install PyNaCl",
            "requests":       "pip install requests",
            # System-Komponenten
            "yggdrasil":      "Yggdrasil installieren: https://yggdrasil-network.github.io/installation",
            "rust_binary":    "Rust-Shell bauen: cargo build --release (in aether-delta-engine/)",
            "rust_shell":     "Rust-Shell bauen: cargo build --release (in aether-delta-engine/)",
            # Bootstrap
            "node_bootstrap": "Aether starten und Gossip-Verbindung herstellen; Genesis-Priors werden automatisch übertragen.",
            "knowledge_bootstrap": "Warte auf ersten Gossip-Kontakt; Genesis-Invarianten werden als Priors injiziert.",
            # Algorithmen
            "algo_tokens":    "AlgoToken-Sharing aktiv — beim nächsten Gossip-Zyklus werden Tokens empfangen.",
            "prefetch_accuracy": "Mehr lokale Analyse-Durchläufe erhöhen Vorhersagegenauigkeit über Zeit.",
        }
        meta_goal = str(gap_dict.get("metadata", {}).get("next_goal", ""))
        base = instructions.get(domain, "")
        if not base and gap_type == GAP_PROGRESSION_STEP and meta_goal:
            base = "Progression-Schritt: " + meta_goal
        return base

    # ── Evolutionärer Status ──────────────────────────────────────────────── #

    def get_evolutionary_status(self) -> Dict[str, Any]:
        """Gibt aktuellen Wachstumsstatus zurück.

        Zeigt: wie viele Gaps waren vorhanden, gelöst, was sind unsere Stärken jetzt.
        Das ist der Gödel-Boost: Schwächen → Stärken → neue Blindstellen → Wachstum.
        """
        with self._lock:
            active = [s.to_dict() for s in self._active_gaps.values() if not s.resolved]
            strengths = dict(self._known_strengths)
            gaps_resolved = self._gaps_resolved
            hints_received = self._hints_received
            resolved_history_count = len(self._resolved_history)

        # Evolutionäre Reife: 0 = Stunde Null, 1.0 = alle bekannten Gaps gelöst
        total_seen = gaps_resolved + len(active)
        evolutionary_maturity = (
            round(gaps_resolved / total_seen, 3) if total_seen > 0 else 0.0
        )

        return {
            "schema":                "aether.blindspot.status.v1",
            "active_gaps":           len(active),
            "active_gap_details":    active,
            "gaps_resolved_total":   gaps_resolved,
            "hints_received_total":  hints_received,
            "known_strengths":       strengths,
            "strengths_count":       len(strengths),
            "evolutionary_maturity": evolutionary_maturity,
            "godel_label": (
                "Stunde-Null (keine Erfahrung)" if evolutionary_maturity == 0 else
                "Wächst (lernt aus Gaps)" if evolutionary_maturity < 0.5 else
                "Gödel-Reif (Stärken > Lücken)" if evolutionary_maturity < 0.9 else
                "Vollständig selbstreferenziell"
            ),
        }

    # ── Interne Hilfsmethoden ─────────────────────────────────────────────── #

    def _resolve_gap(self, signal_id: str, resolved_by: str = "") -> None:
        """Markiert einen Gap als gelöst. MUSS unter self._lock aufgerufen werden
        ODER ohne Lock wenn aus _auto_resolve_by_domain."""
        with self._lock:
            sig = self._active_gaps.pop(signal_id, None)
        if sig is None:
            return
        sig.resolved = True
        sig.resolved_ts = time.time()
        sig.resolved_by = resolved_by
        with self._lock:
            self._resolved_history.append(sig)
            if len(self._resolved_history) > MAX_RESOLVED_HISTORY:
                self._resolved_history.pop(0)
            self._gaps_resolved += 1
        logger.info(
            "[blindspot] Gap gelöst: domain=%s by=%s (total=%d)",
            sig.domain,
            resolved_by[:16] if resolved_by else "self",
            self._gaps_resolved,
        )

    def _auto_resolve_by_domain(self, domain: str) -> None:
        """Löst alle aktiven Gaps in einer Domäne wenn Stärke erreicht wurde."""
        to_resolve = []
        with self._lock:
            for sig_id, sig in list(self._active_gaps.items()):
                if sig.domain == domain and not sig.resolved:
                    to_resolve.append(sig_id)
        for sig_id in to_resolve:
            self._resolve_gap(sig_id)

    def _auto_resolve_gaps(self) -> List[str]:
        """Prüft alle aktiven Gaps ob sie durch neue Stärken lösbar sind."""
        resolved = []
        with self._lock:
            strengths = dict(self._known_strengths)
        for domain, confidence in strengths.items():
            if confidence >= 0.8:
                to_resolve = []
                with self._lock:
                    for sig_id, sig in list(self._active_gaps.items()):
                        if sig.domain == domain:
                            to_resolve.append(sig_id)
                for sig_id in to_resolve:
                    self._resolve_gap(sig_id)
                    resolved.append(sig_id)
        return resolved

    def _mark_strength(self, domain: str, confidence: float) -> None:
        """Registriert eine neue oder verbesserte Stärke."""
        with self._lock:
            existing = self._known_strengths.get(domain, 0.0)
            # Stärken wachsen, aber nie über 1.0
            self._known_strengths[domain] = min(1.0, max(existing, float(confidence)))

    # ── Persistenz ───────────────────────────────────────────────────────── #

    def _save_state(self) -> None:
        try:
            with self._lock:
                active = {k: v.to_dict() for k, v in self._active_gaps.items()}
                history = [s.to_dict() for s in self._resolved_history[-64:]]
                strengths = dict(self._known_strengths)
                stats = {
                    "gaps_resolved": self._gaps_resolved,
                    "hints_received": self._hints_received,
                }
            state = {
                "schema":             "aether.blindspot.state.v1",
                "ts":                 time.time(),
                "active_gaps":        active,
                "resolved_history":   history,
                "known_strengths":    strengths,
                "stats":              stats,
            }
            BLINDSPOT_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            BLINDSPOT_STATE_PATH.write_text(
                json.dumps(state, ensure_ascii=True, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.debug(f"[blindspot] _save_state: {exc}")

    def _load_state(self) -> None:
        try:
            if not BLINDSPOT_STATE_PATH.is_file():
                return
            state = json.loads(BLINDSPOT_STATE_PATH.read_text(encoding="utf-8"))
            if state.get("schema") != "aether.blindspot.state.v1":
                return
            for sig_dict in state.get("active_gaps", {}).values():
                try:
                    sig = BlindspotSignal.from_dict(sig_dict)
                    if not sig.resolved:
                        self._active_gaps[sig.signal_id] = sig
                except Exception:
                    pass
            for sig_dict in state.get("resolved_history", []):
                try:
                    self._resolved_history.append(BlindspotSignal.from_dict(sig_dict))
                except Exception:
                    pass
            self._known_strengths = {
                k: float(v)
                for k, v in state.get("known_strengths", {}).items()
                if isinstance(v, (int, float))
            }
            stats = state.get("stats", {})
            self._gaps_resolved = int(stats.get("gaps_resolved", 0))
            self._hints_received = int(stats.get("hints_received", 0))
            logger.info(
                "[blindspot] State geladen: %d aktive Gaps, %d Stärken",
                len(self._active_gaps),
                len(self._known_strengths),
            )
        except Exception as exc:
            logger.debug(f"[blindspot] _load_state: {exc}")
