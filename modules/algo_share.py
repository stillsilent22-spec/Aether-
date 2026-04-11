"""
algo_share.py
Teilt Expression Trees als strukturelle Algorithmen — nie Daten, nie Deltas.

Anwendungsfälle:
  - Swarm-Nodes tauschen effektive Trees für bestimmte Datenklassen
  - Gaming: Spieler teilen Kompressions-Algorithmen als handelbare Assets
  - Forschung: reproduzierbare strukturelle Beschreibungen ohne Inhalte

Ein AlgoToken ist:
  - tree_signature: SHA256 des Trees (Fingerprint)
  - invariant_profile: welche mathematischen Invarianten der Tree nutzt
  - fitness_score: wie gut der Tree Strukturen beschreibt (lossless-Rate)
  - domain_hint: für welche Datenklasse der Tree optimiert wurde
  - NIEMALS: Rohdaten, Delta, session_key, persönliche Dateien
"""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class AlgoToken:
    """
    Handelbares/teilbares Strukturbeschreibungs-Token.
    Enthält nur den Algorithmus, nie die Daten.
    """
    token_id: str              # SHA256(tree_signature + domain_hint)
    tree_signature: str        # SHA256 des Expression Trees
    invariant_profile: List[str]  # welche Invarianten genutzt werden (z.B. ["pi", "phi", "2^k"])
    fitness_score: float       # lossless-Rate des Trees [0,1]
    domain_hint: str           # "text", "binary", "audio", "generic"
    cascade_version: str
    node_count: int
    depth: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "tree_signature": self.tree_signature,
            "invariant_profile": self.invariant_profile,
            "fitness_score": round(self.fitness_score, 4),
            "domain_hint": self.domain_hint,
            "cascade_version": self.cascade_version,
            "node_count": self.node_count,
            "depth": self.depth,
        }

    def canonical_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True,
                          sort_keys=True, separators=(",", ":"))


def build_algo_token(aelab_result: Dict[str, Any], domain_hint: str = "generic") -> Optional[AlgoToken]:
    """
    Baut einen AlgoToken aus einem aelab_engine.analyze()-Ergebnis.
    Gibt None zurück wenn commit_allowed=False (Tree nicht gut genug zum Teilen).
    """
    from modules.unified_cascade import CASCADE_VERSION

    if not aelab_result.get("commit_allowed", False):
        return None

    tree_sig = str(aelab_result.get("signature", ""))
    if not tree_sig:
        return None

    # Invarianten-Profil aus has_anchor und Signatur ableiten
    invariant_profile: List[str] = []
    if aelab_result.get("has_anchor", False):
        invariant_profile = ["mathematical_anchor"]

    token_id = hashlib.sha256(
        f"{tree_sig}|{domain_hint}".encode()
    ).hexdigest()

    return AlgoToken(
        token_id=token_id,
        tree_signature=tree_sig,
        invariant_profile=invariant_profile,
        fitness_score=float(aelab_result.get("lossless", 0.0)),
        domain_hint=domain_hint,
        cascade_version=CASCADE_VERSION,
        node_count=int(aelab_result.get("nodes", 0)),
        depth=int(aelab_result.get("depth", 0)),
    )


def verify_algo_token(token: AlgoToken) -> bool:
    """
    Prüft ob ein empfangener AlgoToken strukturell valide ist.
    Kein Inhalt, keine Daten — nur Struktur-Integrität.
    """
    expected_id = hashlib.sha256(
        f"{token.tree_signature}|{token.domain_hint}".encode()
    ).hexdigest()
    return (
        token.token_id == expected_id
        and 0.0 <= token.fitness_score <= 1.0
        and len(token.tree_signature) == 64  # SHA256 hex
        and bool(token.cascade_version)
    )


# --------------------------------------------------------------------------- #
#  AutoPropagator — automatische Weitergabe verbesserter Algorithmen          #
# --------------------------------------------------------------------------- #

import threading
import time
from pathlib import Path

_ALGO_STORE_PATH = Path(__file__).resolve().parent.parent / "data" / "swarm" / "algo_tokens.json"


class AutoPropagator:
    """Überwacht die lokale Vault-Effizienz und gibt verbesserte AlgoTokens
    automatisch via Gossip weiter, sobald eine signifikante Verbesserung eintritt.

    Logik:
      - Nach jeder Vault-Session: emit_if_improved(vault_stats) aufrufen
      - Wenn hit_ratio > letzter Wert + MIN_IMPROVEMENT_DELTA: neues Token emittieren
      - Token wird im nächsten Gossip-Paket als "algo_token" mitgeschickt

    Empfang:
      - receive_algo_token(token_dict): speichert empfangenes Token lokal
      - get_best_token_for_gossip(): gibt bestes bekanntes Token zurück

    Privatsphäre: AlgoTokens enthalten NUR tree_signature + Fitness-Score.
    Niemals: Rohdaten, Inhalte, Nutzerinfos.
    """

    _instance: Optional["AutoPropagator"] = None
    _instance_lock = threading.Lock()

    @classmethod
    def instance(cls) -> "AutoPropagator":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    # Mindest-Verbesserung der Hit-Rate bevor ein Token weitergegeben wird
    MIN_IMPROVEMENT_DELTA = 0.05   # 5 Prozentpunkte
    # Mindest-Fitness-Score für das Teilen
    MIN_FITNESS_TO_SHARE = 0.30

    # Anzahl unabhängiger Beobachtungen bis ein Token als Quorum-bestätigt gilt.
    # Zählt nach Nachrichteneingang — kein Peer-Tracking, peer-identitätsblind.
    QUORUM_CONFIRMATION_THRESHOLD = 3

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_hit_ratio: float = 0.0
        self._share_count: int = 0
        # Bekannte Token: token_id → AlgoToken-Dict (eigene + empfangene)
        self._known_tokens: Dict[str, Dict[str, Any]] = {}
        # Bestes eigenes Token für den nächsten Gossip
        self._pending_token: Optional[Dict[str, Any]] = None
        # Zählt wie oft jedes Token im Netz gesehen wurde (flüchtig, kein Peer-ID).
        # Erreicht ein Token den Schwellwert, wird es als Quorum-bestätigt markiert.
        # Sinn: je mehr unabhängige Knoten ein Token teilen, desto repräsentativer.
        self._token_seen_count: Dict[str, int] = {}
        self._load_persistent()

    def _load_persistent(self) -> None:
        try:
            if _ALGO_STORE_PATH.is_file():
                data = json.loads(_ALGO_STORE_PATH.read_text(encoding="utf-8"))
                self._known_tokens = {
                    k: v for k, v in data.get("tokens", {}).items()
                    if isinstance(v, dict)
                }
                self._share_count = int(data.get("share_count", 0))
                # Persist quorum counters across restarts so hard-won quorum
                # confirmation is not lost on nodes that restart frequently
                # (e.g. gaming nodes that reboot between sessions).
                self._token_seen_count = {
                    k: int(v)
                    for k, v in data.get("seen_counts", {}).items()
                    if isinstance(v, (int, float))
                }
        except Exception:
            pass

    def _save_persistent(self) -> None:
        try:
            _ALGO_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
            _ALGO_STORE_PATH.write_text(
                json.dumps({
                    "schema":      "aether.algo_store.v1",
                    "tokens":      self._known_tokens,
                    "share_count": self._share_count,
                    "seen_counts": self._token_seen_count,
                }, ensure_ascii=True, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def emit_if_improved(self, vault_stats: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Prüft ob die Vault-Effizienz sich genug verbessert hat zum Teilen.

        Wird nach jeder Vault-Session aufgerufen.
        vault_stats erwartet:
            "hit_ratio":        float  (0.0–1.0)
            "fitness_score":    float  (0.0–1.0)
            "tree_signature":   str    (SHA256)
            "invariant_profile": list
            "domain_hint":      str
            "node_count":       int
            "depth":            int

        Gibt AlgoToken-Dict zurück wenn emittiert, sonst None.
        """
        hit_ratio    = float(vault_stats.get("hit_ratio",     0.0))
        fitness      = float(vault_stats.get("fitness_score", 0.0))
        tree_sig     = str(vault_stats.get("tree_signature",  ""))
        domain_hint  = str(vault_stats.get("domain_hint",     "generic"))

        if not tree_sig or fitness < self.MIN_FITNESS_TO_SHARE:
            return None

        with self._lock:
            improvement = hit_ratio - self._last_hit_ratio
            if improvement < self.MIN_IMPROVEMENT_DELTA:
                return None

            try:
                from modules.unified_cascade import CASCADE_VERSION
            except ImportError:
                CASCADE_VERSION = "unknown"

            token_id = hashlib.sha256(f"{tree_sig}|{domain_hint}".encode()).hexdigest()

            # Log-skalierte Fitness für legacy-Hardware-Tiers (Weber-Fechner-Gesetz):
            #   Kleine Verbesserungen auf schwacher Hardware zählen proportional
            #   gleich viel wie große Verbesserungen auf starker Hardware.
            try:
                from modules.math_utils import log_scale_fitness, tier_from_fitness
                log_fit = round(log_scale_fitness(fitness), 4)
                min_tier = tier_from_fitness(fitness)
            except Exception:
                log_fit = round(fitness, 4)
                min_tier = 0

            token_dict: Dict[str, Any] = {
                "token_id":         token_id,
                "tree_signature":   tree_sig,
                "invariant_profile": vault_stats.get("invariant_profile", []),
                "fitness_score":    round(fitness, 4),
                "log_fitness":      log_fit,
                "min_tier":         min_tier,
                "domain_hint":      domain_hint,
                "cascade_version":  CASCADE_VERSION,
                "node_count":       int(vault_stats.get("node_count", 0)),
                "depth":            int(vault_stats.get("depth", 0)),
                "hit_ratio":        round(hit_ratio, 4),
                "emitted_ts":       time.time(),
            }
            self._known_tokens[token_id] = token_dict
            self._pending_token = token_dict
            self._last_hit_ratio = hit_ratio
            self._share_count += 1
            self._save_persistent()

        return token_dict

    def receive_algo_token(self, token_data: Dict[str, Any]) -> bool:
        """Speichert ein empfangenes AlgoToken (aus Gossip eines Peers).

        Prüft Integrität, speichert lokal.
        Gibt True zurück wenn gültig und neu, False wenn bekannt oder ungültig.
        """
        if not isinstance(token_data, dict):
            return False
        token_id    = str(token_data.get("token_id",     ""))
        tree_sig    = str(token_data.get("tree_signature", ""))
        domain_hint = str(token_data.get("domain_hint",  "generic"))

        if not token_id or not tree_sig or len(tree_sig) != 64:
            return False

        expected_id = hashlib.sha256(f"{tree_sig}|{domain_hint}".encode()).hexdigest()
        if token_id != expected_id:
            return False   # Integritätsfehler

        with self._lock:
            # Sichtbarkeits-Zähler: kein Peer-Bezug — nur wie oft taucht dieses
            # Token im Netz auf.  Jeder Knoten zählt unabhängig.  Kein Schutz
            # gegen einen Knoten der dasselbe Token mehrfach sendet — dafür ist
            # der Rate-Limiter in gossip_toxicity_filter.py zuständig.
            count = self._token_seen_count.get(token_id, 0) + 1
            self._token_seen_count[token_id] = count
            quorum_now = (count >= self.QUORUM_CONFIRMATION_THRESHOLD)

            if token_id in self._known_tokens:
                # Bereits bekannt — aber Quorum-Status könnte sich jetzt ändern
                if quorum_now and not self._known_tokens[token_id].get("quorum_confirmed"):
                    self._known_tokens[token_id]["quorum_confirmed"] = True
                    self._save_persistent()
                return False   # nicht neu

            if quorum_now:
                token_data = dict(token_data)
                token_data["quorum_confirmed"] = True

            self._known_tokens[token_id] = token_data
            # Re-Gossip: sofort als pending setzen → nächster Gossip-Zyklus leitet ihn weiter
            self._pending_token = token_data
            self._save_persistent()
        return True

    def get_tokens_for_domain(self, domain_hint: str) -> List["AlgoToken"]:
        """Gibt alle bekannten AlgoTokens für eine Datenklasse zurück (eigene + empfangene).

        Wird von task_broker._find_simplified_algo_token() genutzt um den einfachsten
        bekannten Lösungsweg für eine chunk_class zu finden.
        """
        result: List[AlgoToken] = []
        with self._lock:
            for token_dict in self._known_tokens.values():
                if token_dict.get("domain_hint", "generic") != domain_hint:
                    continue
                try:
                    result.append(AlgoToken(
                        token_id=str(token_dict["token_id"]),
                        tree_signature=str(token_dict["tree_signature"]),
                        invariant_profile=list(token_dict.get("invariant_profile", [])),
                        fitness_score=float(token_dict.get("fitness_score", 0.0)),
                        domain_hint=str(token_dict.get("domain_hint", "generic")),
                        cascade_version=str(token_dict.get("cascade_version", "unknown")),
                        node_count=int(token_dict.get("node_count", 0)),
                        depth=int(token_dict.get("depth", 0)),
                    ))
                except Exception:
                    pass
        return result

    def get_best_token_for_gossip(self) -> Optional[Dict[str, Any]]:
        """Gibt das beste verfügbare AlgoToken für den nächsten Gossip-Paket zurück.

        Priorisierung (gleich für alle — kein Peer-Bezug):
          1. eigenes pending_token (frischeste eigene Verbesserung)
          2. Quorum-bestätigtes Token mit höchstem fitness_score
             (≥3 unabhängige Knoten haben dasselbe Token geteilt → höhere
              Repräsentativität, kein einzelner Peer wird bevorzugt)
          3. Bestes bekanntes Token nach fitness_score (Fallback)

        Setzt pending_token zurück nach dem Abruf.
        """
        with self._lock:
            if self._pending_token is not None:
                token = self._pending_token
                self._pending_token = None
                return token
            if not self._known_tokens:
                return None
            # Quorum-bestätigte Tokens bevorzugen — sie repräsentieren
            # kollektives Swarm-Wissen, unabhängig davon wer sie gesendet hat
            quorum_tokens = [
                t for t in self._known_tokens.values()
                if t.get("quorum_confirmed")
            ]
            if quorum_tokens:
                return max(quorum_tokens, key=lambda t: float(t.get("fitness_score", 0.0)))
            return max(self._known_tokens.values(),
                       key=lambda t: float(t.get("fitness_score", 0.0)))

    def get_share_count(self) -> int:
        """Wie viele AlgoTokens hat dieser Knoten bisher weitergegeben?"""
        with self._lock:
            return self._share_count

    def get_known_token_count(self) -> int:
        """Wie viele AlgoTokens kennt dieser Knoten (eigene + empfangene)?"""
        with self._lock:
            return len(self._known_tokens)

    def get_best_token_for_tier(
        self,
        tier: int,
        domain_hint: str = "generic",
    ) -> Optional[Dict[str, Any]]:
        """Bestes AlgoToken für eine gegebene Hardware-Stufe (0–4).

        Legacy-Knoten (tier 0–1) erhalten nur Tokens deren min_tier ≤ ihrer Stufe —
        so bekommen schwache Knoten keine Tokens die sie nicht verarbeiten können.
        Ranking nutzt log_scale_fitness damit kleine Verbesserungen auf schwacher
        Hardware fair bewertet werden (Weber-Fechner-Gesetz).
        """
        try:
            from modules.math_utils import log_scale_fitness
        except Exception:
            log_scale_fitness = lambda f, t=0: f  # type: ignore[assignment]

        with self._lock:
            candidates = [
                t for t in self._known_tokens.values()
                if t.get("domain_hint", "generic") == domain_hint
                and int(t.get("min_tier", 0)) <= tier
            ]
            if not candidates:
                # Fallback: ignoriere domain_hint, behalte tier-Filter
                candidates = [
                    t for t in self._known_tokens.values()
                    if int(t.get("min_tier", 0)) <= tier
                ]
            if not candidates:
                return None
            return max(
                candidates,
                key=lambda t: log_scale_fitness(float(t.get("fitness_score", 0.0)), tier),
            )


# Alias für Kompatibilität mit task_broker._find_simplified_algo_token
AlgoTokenStore = AutoPropagator
