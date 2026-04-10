from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""
P2P Sync Layer for Aether Swarm (opt-in).

Device-lock enforcement in receive_gossip():
  - One account per device: a device_fingerprint may only have ONE node_id.
  - One device per account: a node_id may only come from ONE device_fingerprint.
  Peers violating either rule are silently dropped.
Provides pluggable peer-to-peer fingerprint and metadata exchange.
Built on top of the existing AethernetTransport — no extra dependencies.

Features:
        - PeerID: derived from node's Ed25519 public key (not IP-based)
        - Signed fingerprint gossip: publish only SHA256 fingerprints + aggregated metrics
        - DHT-style peer discovery: extends existing LAN UDP beacon
        - Local leader election: simple highest-PeerID leader rule for local networks
        - Encrypted channels: reuses AethernetTransport Ed25519 signing (Noise-equivalent)

Privacy guarantees:
    - Share ONLY: fingerprints, aggregated metrics, anonymous node_id
    - NEVER share: raw frames, pixel data, application content

Opt-in via settings.json. Bootstrap enables swarm_p2p by default for fresh nodes.
"""


import hashlib
import json
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# lan_beacon und yggdrasil_install werden lazy geladen:
# - lan_beacon wird nur gebraucht wenn LAN-P2P aktiv ist (Tier ≥2)
# - yggdrasil_install wird nur gebraucht wenn Yggdrasil auto-manage aktiv ist (Tier ≥3)
# So startet ein Relay-Bridge-Node (Win9x, ARM nano) sofort ohne diese Module zu laden.

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SETTINGS_PATH = ROOT / "data" / "settings.json"
INTERBUS_DIR = ROOT / "data" / "interbus"
P2P_GOSSIP_PATH = INTERBUS_DIR / "p2p_gossip.json"
LOCAL_NODE_JSON_PATH = ROOT / "data" / "swarm" / "node.json"
NODE_DISCOVERY_DIR = ROOT / "data" / "swarm" / "nodes"
RELAY_POOL_PATH = ROOT / "data" / "swarm" / "relay_pool.json"

DEFAULT_P2P: Dict[str, Any] = {
    "enabled": True,
    "gossip_interval_seconds": 30.0,
    "max_fingerprints_per_gossip": 20,
    "leader_election_enabled": True,
    "peer_ttl_seconds": 120.0,
    "discovery_nodes_dir": "data/swarm/nodes",
    "auto_manage_yggdrasil": True,
    "yggdrasil_config_path": "data/yggdrasil.conf",
    "peer_retry_interval_seconds": 300.0,
    # genesis_yggdrasil_addr: Yggdrasil-Overlay-IPv6 des Genesis-Knotens.
    # Kein echter IP-Leak — Yggdrasil-Adressen sind kryptografische Overlay-Adressen.
    # Neue Knoten tragen hier die vom Genesis-Node mitgeteilte Adresse ein:
    #   "swarm_p2p": { "genesis_yggdrasil_addr": "200:xxxx:...:xxxx" }
    # Auf dem Genesis-Node selbst wird das Feld automatisch aus genesis_node.key befüllt.
    "genesis_yggdrasil_addr": "",
    # relay_url (legacy, single) + relay_urls (Liste, bevorzugt).
    # Knoten lernen automatisch neue Relays aus dem Gossip dazu.
    "relay_url": "",
    "relay_urls": [],
}

# ---------------------------------------------------------------------------
# Relay-Pool — mehrere Relay-Kandidaten, erster der antwortet gewinnt.
# Knoten lernen neue Relays aus Gossip-Paketen anderer Peers.
# ---------------------------------------------------------------------------
_relay_pool_lock = threading.Lock()


def _load_relay_pool(config: Dict[str, Any]) -> List[str]:
    """Liest alle bekannten Relay-URLs zusammen:
    1. config["relay_urls"] (Liste aus settings.json)
    2. config["relay_url"]  (veraltetes Einzel-Feld, rückwärtskompatibel)
    3. data/swarm/relay_pool.json (gelerntes aus Gossip)
    Dedupliziert, leer-Strings entfernt.
    """
    pool: List[str] = []
    # Aus Config
    for url in config.get("relay_urls") or []:
        u = str(url).strip()
        if u:
            pool.append(u)
    single = str(config.get("relay_url", "") or "").strip()
    if single:
        pool.append(single)
    # Aus persistiertem Pool
    try:
        if RELAY_POOL_PATH.is_file():
            data = json.loads(RELAY_POOL_PATH.read_text(encoding="utf-8"))
            for url in data.get("urls", []):
                u = str(url).strip()
                if u:
                    pool.append(u)
    except Exception:
        pass
    # Deduplizieren, Reihenfolge erhalten
    seen: set = set()
    result: List[str] = []
    for u in pool:
        if u not in seen:
            seen.add(u)
            result.append(u)
    return result


def _save_relay_pool(urls: List[str]) -> None:
    """Speichert den aktuellen Relay-Pool persistent."""
    try:
        RELAY_POOL_PATH.parent.mkdir(parents=True, exist_ok=True)
        RELAY_POOL_PATH.write_text(
            json.dumps({"schema": "aether.relay_pool.v1", "urls": urls[:64]},
                       ensure_ascii=True, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


def _pick_live_relay(pool: List[str], timeout: float = 5.0) -> str:
    """Gibt die erste erreichbare Relay-URL zurück, leerer String wenn keine antwortet.

    Probiert HEAD /gossip/latest — wenn der Relay-HTTP-Server antwortet,
    ist er online. Kein Yggdrasil, kein LAN nötig.
    """
    import urllib.request as _ureq
    import urllib.error as _uerr
    for url in pool:
        try:
            u = url.rstrip("/") + "/gossip/latest"
            req = _ureq.Request(u, method="HEAD")
            with _ureq.urlopen(req, timeout=timeout) as resp:
                if 200 <= resp.status < 500:  # 404 auch ok — Server ist da
                    return url
        except Exception:
            continue
    return ""


def _extend_relay_pool_from_gossip(config: Dict[str, Any], new_url: str) -> None:
    """Fügt eine neue, aus Gossip gelernte Relay-URL zum persistierten Pool hinzu."""
    if not new_url:
        return
    new_url = new_url.strip()
    if not new_url.startswith(("http://", "https://")):
        return
    with _relay_pool_lock:
        pool = _load_relay_pool(config)
        if new_url in pool:
            return
        pool.append(new_url)
        _save_relay_pool(pool)


# ---------------------------------------------------------------------------
# Shared metric bridges — keine Circular-Imports
#
# set_pipeline_metrics()    : Pipeline schreibt Metriken nach jeder Analyse
# get_last_network_metrics(): Observer-Engine liest Netz-Mediane nach Gossip
# ---------------------------------------------------------------------------
_pipeline_metrics_lock = threading.Lock()
_PIPELINE_METRICS: Dict[str, Any] = {}
_LAST_NETWORK_METRICS: Dict[str, Any] = {}


def set_pipeline_metrics(metrics: Dict[str, Any]) -> None:
    """Pipeline schreibt aktuelle Metriken (delta_ratio, h_lambda …) nach jeder Analyse.
    Wird von _do_gossip() in das nächste Gossip-Paket eingebettet.
    """
    with _pipeline_metrics_lock:
        _PIPELINE_METRICS.update({
            k: v for k, v in metrics.items()
            if k in ("delta_ratio", "h_lambda", "shannon_gap_pct",
                     "anchor_coverage", "bits_per_joule", "bpj_slope", "trust_score")
            and v is not None
        })


def get_last_network_metrics() -> Dict[str, Any]:
    """Observer-Engine liest die zuletzt aggregierten Netz-Mediane.
    Leer bis zur ersten vollständigen Gossip-Runde.
    """
    with _pipeline_metrics_lock:
        return dict(_LAST_NETWORK_METRICS)

# --------------------------------------------------------------------------- #
#  Genesis-Node Identität                                                     #
# --------------------------------------------------------------------------- #

# Kein hardcodierter GENESIS_NODE_YGG_ADDR im Source-Code.
# Die Adresse wird ausschliesslich zur Laufzeit aus genesis_node.key abgeleitet.
# Nicht-Genesis-Knoten haben keinen Key → kennen die Adresse nicht → kein Tracking.
GENESIS_KEY_PATH: Path = ROOT / "data" / "keys" / "genesis_node.key"
_genesis_ygg_addr_cache: str = ""
_genesis_ygg_addr_lock = threading.Lock()


def _get_genesis_ygg_addr() -> str:
    """Leitet die Genesis-Yggdrasil-Adresse zur Laufzeit aus dem lokalen Key ab.

    Gibt "" zurück wenn kein genesis_node.key vorhanden (Nicht-Genesis-Knoten).
    Ergebnis wird gecacht — kein wiederholter Disk-Read nach erstem Aufruf.
    Die Adresse steht nie im Source-Code oder in einem Repo-Commit.
    """
    global _genesis_ygg_addr_cache
    with _genesis_ygg_addr_lock:
        if _genesis_ygg_addr_cache:
            return _genesis_ygg_addr_cache
        try:
            if not GENESIS_KEY_PATH.is_file():
                return ""
            raw = GENESIS_KEY_PATH.read_bytes()
            if len(raw) != 32:
                return ""
            from modules.yggdrasil_addr import derive_yggdrasil_address
            _genesis_ygg_addr_cache = derive_yggdrasil_address(raw)
            return _genesis_ygg_addr_cache
        except Exception:
            return ""


def _local_genesis_claim_is_verified() -> bool:
    """True nur wenn die lokale Genesis-Identitaet vollstaendig an Manifest+Hardware+Ygg gebunden ist."""
    try:
        import hmac as _hmac

        from modules.device_lock import _DEVICE_LOCK_PATH, compute_device_fingerprint
        from modules.identity_claim import (
            load_trusted_publishers,
            matches_manifest_genesis_identity,
            public_key_b64_from_pem,
        )

        if not GENESIS_KEY_PATH.is_file() or not _DEVICE_LOCK_PATH.is_file():
            return False
        raw = GENESIS_KEY_PATH.read_bytes()
        if len(raw) != 32:
            return False
        local_ygg_addr = _get_genesis_ygg_addr()
        if not local_ygg_addr or not LOCAL_NODE_JSON_PATH.is_file() or not SETTINGS_PATH.is_file():
            return False

        node_payload = json.loads(LOCAL_NODE_JSON_PATH.read_text(encoding="utf-8"))
        settings_payload = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        device_lock = json.loads(_DEVICE_LOCK_PATH.read_text(encoding="utf-8"))

        node_id = str(node_payload.get("node_id", "") or "").strip()
        node_ygg = str(node_payload.get("yggdrasil_addr", "") or "").strip()
        username = str(
            settings_payload.get("account_username", node_payload.get("account_username", "")) or ""
        ).strip()
        node_identity_lock = str(node_payload.get("account_identity_lock", "") or "").strip()
        settings_identity_lock = str(settings_payload.get("account_identity_lock", "") or "").strip()
        public_key_pem = str(node_payload.get("public_key_pem", "") or "").strip()
        stored_node = str(device_lock.get("node_id", "") or "").strip()
        stored_fp = str(device_lock.get("device_fingerprint", "") or "").strip()
        current_fp = compute_device_fingerprint()
        if not all([node_id, node_ygg, username, node_identity_lock, settings_identity_lock, public_key_pem, stored_node, stored_fp, current_fp]):
            return False
        if not _hmac.compare_digest(node_id, stored_node):
            return False
        if not _hmac.compare_digest(stored_fp, current_fp):
            return False
        if not _hmac.compare_digest(node_identity_lock, settings_identity_lock):
            return False
        if not _hmac.compare_digest(node_ygg.lower(), local_ygg_addr.lower()):
            return False
        manifest = load_trusted_publishers(ROOT)
        return matches_manifest_genesis_identity(
            manifest,
            username=username,
            node_id=node_id,
            public_key_b64=public_key_b64_from_pem(public_key_pem),
            device_fingerprint=current_fp,
            yggdrasil_addr=local_ygg_addr,
            identity_lock=node_identity_lock,
        )
    except Exception:
        return False


def _check_is_genesis_node() -> bool:
    """Prüft ob DIESER Knoten der Genesis-Node ist.

    True nur wenn genesis_node.key existiert, die lokale Yggdrasil-Adresse
    ableitbar ist UND der lokale Claim zum Manifest-/Hardware-/Username-Lock passt.
    """
    return _local_genesis_claim_is_verified()


# --------------------------------------------------------------------------- #
#  Hardware-Capability Gate                                                   #
# --------------------------------------------------------------------------- #

def _collect_node_capabilities() -> Dict[str, Any]:
    """Liest capability_score.json und baut einen kompakten Blind-Spot-Bericht.

    Wird in jeden Gossip-Paket eingebettet → alle Peers können sehen wer was fehlt.
    Kein PII, keine Inhaltsdaten — nur Systemfähigkeits-Flags.

    Rückgabe:
        {
          "score_pct": 62,
          "stage": "Standard",
          "stage_index": 2,
          "have": ["python_runtime", "cryptography", ...],
          "missing": ["yggdrasil", "numpy", "rust_binary"],
          "emergent_network_role": "relay-bridge-candidate",
          "symbiont_role": "relay-compatible-symbiont",
        }
    """
    try:
        path = ROOT / "data" / "interbus" / "capability_score.json"
        if not path.is_file():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        probes: Dict[str, Any] = data.get("probes", {})
        have = [k for k, v in probes.items() if isinstance(v, dict) and v.get("ok")]
        missing = [k for k, v in probes.items() if isinstance(v, dict) and not v.get("ok")]
        return {
            "score_pct":            int(data.get("percent_int", 0)),
            "stage":                str(data.get("stage", "")),
            "stage_index":          int(data.get("stage_index", 0)),
            "have":                 have,
            "missing":              missing,
            "emergent_network_role": str(data.get("emergent_network_role", "")),
            "symbiont_role":        str(data.get("symbiont_role", "")),
            "next_goal":            str(data.get("next_goal", "")),
            # Contribution-Index — zeigt wer Rechenzeit für andere bereitstellt
            "contribution_index":   int(data.get("contribution_index", 0)),
            "contribution_stage":   str(data.get("contribution_stage", "")),
            "tasks_completed":      int(data.get("tasks_completed", 0)),
        }
    except Exception as e:
        logger.warning(f"[swarm_p2p] _collect_node_capabilities failed: {e}")
        return {}


# Wie oft der Tier-Watchdog (Booster) neu prüft, bevor er aufgibt.
BOOST_CHECK_INTERVAL_SEC: int = 90
BOOST_MAX_TRIES: int = 10

# Genesis-Invarianten: physikalisch belegte Naturwerte als Prior für neue Knoten.
# Quelle: Benford (naturl. Daten), Zipf (Sprache/Web, Piantadosi 2014),
#         Mandelbrot (fraktale Selbstähnlichkeit), Fourier (circadianisches 24h-Muster).
# Werden einmalig beim StealthBeacon-Start eingeschrieben und von
# invariant_detector.load_genesis_prior() als Fallback-Prior geladen wenn
# noch keine eigenen Messungen vorliegen.
GENESIS_INVARIANTS: Dict[str, Any] = {
    "schema": "aether.invariant.genesis.v1",
    "source": "genesis_prior",
    "note": (
        "Eingeimpfte Basisinvarianten fuer neue / schwache Knoten. "
        "Werden durch eigene Messungen ueberschrieben sobald ausreichend Daten vorliegen."
    ),
    "invariant_strength": 0.72,  # Startwert — nicht zu hoch, damit echte Messungen dominieren
    "fourier": {
        "detected": True,
        "period": 24.0,           # Circadianische Periode: 24 Einheiten (Tages-Zyklus)
        "source": "prior",
    },
    "benford": {
        "benford_conformance": 0.85,   # Typisch fuer echte Natur-/Messdaten
        "chi_squared": 4.1,
        "source": "prior",
    },
    "zipf": {
        "alpha": 1.07,             # Klassischer Zipf-Exponent (Sprache, Web, Anchors)
        "r_squared": 0.94,
        "interpretation": "classic_zipf: standard rank-frequency",
        "source": "prior",
    },
    "mandelbrot": {
        "beta": 1.40,              # Fraktale Selbstähnlichkeit (Menger-ähnlich)
        "r_squared": 0.88,
        "interpretation": "power_law: moderate locality",
        "source": "prior",
    },
    "recommendation": (
        "• Genesis-Prior aktiv: preload top 20% Anchors "
        "| Fractal-Cache-Struktur empfohlen "
        "| Sync-Zyklus ~24 Einheiten"
    ),
}

def _read_hw_capability() -> Dict[str, Any]:
    """Liest data/interbus/hw_capability.json (geschrieben von hardware::write_capability_json).

    Gibt ein Dict mit mindestens diesen Keys zurück:
        tier_rank (int 0-4), lan_beacon (bool), lan_p2p (bool),
        yggdrasil (bool), dht (bool), network_tier (str), os_platform (str)
    Schlägt nie fehl — Defaults entsprechen LocalOnly (konservativste Annahme).
    """
    _default = {
        "tier_rank": 0, "network_tier": "LocalOnly", "os_platform": "Unknown",
        "lan_beacon": False, "lan_p2p": False, "yggdrasil": False, "dht": False,
        "runtime": "",
        "shell_capable": True,
        "progressive_network_unlock": False,
    }
    try:
        hw_path = ROOT / "data" / "interbus" / "hw_capability.json"
        if hw_path.is_file():
            data = json.loads(hw_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                _default.update({k: data[k] for k in _default if k in data})
    except Exception as e:
        logger.warning(f"[swarm_p2p] hw_capability read failed: {e}")
    return _default


def _read_capability_score() -> Dict[str, Any]:
    """Liest data/interbus/capability_score.json für Lern-/Aufstiegsstatus.

    Diese Daten ersetzen NICHT das native Hardware-Tier. Sie beschreiben nur,
    wie weit der Knoten logisch bereits gekommen ist.
    """
    default = {
        "stage": "Basis-Daemon",
        "stage_index": 0,
        "shell_ready": False,
        "overlay_ready": False,
        "full_member_ready": False,
        "swarm_learning_active": False,
        "startup_mode": "full",
        "progression_track": "full-runtime",
        "base_progression_mode": "vault-first",
        "progression_mode": "vault-first",
        "next_goal": "",
        "network_end_goal": "YggdrasilP2P",
        "overlay_path": "native-yggdrasil",
        "relay_bridge_required": False,
        "symbiont_role": "overlay-peer",
        "emergent_network_role": "visibility-staging",
        "aethernet_goal_message": "LAN ist nur Zwischenstufe; Ziel ist echte Aufnahme ins P2P-Aethernet.",
    }
    try:
        path = ROOT / "data" / "interbus" / "capability_score.json"
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                default.update({k: data[k] for k in default if k in data})
    except Exception as e:
        logger.warning(f"[swarm_p2p] capability_score read failed: {e}")
    return default


def _progression_hint(cap: Dict[str, Any]) -> str:
    mode = str(cap.get("base_progression_mode", cap.get("progression_mode", "vault-first")) or "vault-first")
    next_goal = str(cap.get("next_goal", "") or "").strip()
    network_goal = str(cap.get("network_end_goal", "YggdrasilP2P") or "YggdrasilP2P")
    overlay_path = str(cap.get("overlay_path", "native-yggdrasil") or "native-yggdrasil")
    symbiont_role = str(cap.get("symbiont_role", "overlay-peer") or "overlay-peer")
    goal_message = str(cap.get("aethernet_goal_message", "") or "").strip()
    if mode == "full-member":
        return "Knoten ist logisch bereits voll im Aethernet angekommen."
    if mode == "overlay-ready":
        return "Shell/Yggdrasil sind bereit; jetzt folgt der Uebergang in das echte Overlay-Aethernet."
    if mode == "shell-ready":
        return "Rust-Shell ist lokal bereit; naechster Schritt ist Overlay-Kompatibilitaet statt dauerhaftem LAN-Inselbetrieb."
    if mode == "lan-p2p-ready":
        return "LAN-P2P ist nur die Zwischenstufe; Ziel bleibt Overlay-/Relay-Aufnahme ins Aethernet."
    if mode == "lan-beacon-ready":
        return "Sichtbarkeit ist nur die erste Stufe; naechstes Ziel ist symbiotischer P2P-Anschluss ans Aethernet."
    if overlay_path == "relay-bridge":
        return f"Knoten arbeitet als {symbiont_role}; Relay-Bruecke statt LAN-Endstation. Ziel: {network_goal}."
    if overlay_path == "ultra-legacy-bootstrap":
        return "Ultra-Legacy lokal aktiv; Ziel ist spaeterer Headless-/Relay-Anschluss ans Aethernet."
    if goal_message:
        return goal_message
    if next_goal:
        return next_goal
    return "Vault-first aktiv: lokale Invarianten und minimale Sichtbarkeit kommen zuerst."


def _base_progression_mode(cap: Dict[str, Any]) -> str:
    return str(cap.get("base_progression_mode", cap.get("progression_mode", "vault-first")) or "vault-first")


def _tier_features_from_rank(rank: int) -> Dict[str, Any]:
    normalized = max(0, min(4, int(rank)))
    mapping = {
        0: ("LocalOnly", False, False, False, False),
        1: ("LanBeacon", True, False, False, False),
        2: ("LanP2P", True, True, False, False),
        3: ("YggdrasilP2P", True, True, True, False),
        4: ("FullDht", True, True, True, True),
    }
    label, lan_beacon, lan_p2p, yggdrasil, dht = mapping[normalized]
    return {
        "effective_network_tier": label,
        "effective_tier_rank": normalized,
        "lan_beacon": lan_beacon,
        "lan_p2p": lan_p2p,
        "yggdrasil": yggdrasil,
        "dht": dht,
        "vault_bootstrap_only": normalized <= 1,
    }


def _effective_swarm_scope(hw: Dict[str, Any], cap: Dict[str, Any]) -> Dict[str, Any]:
    """Combine native hardware ceiling with current learning/readiness state.

    The hardware tier defines the maximum possible scope on this machine.
    Capability/readiness decides how much of that scope is currently unlocked.
    """
    native_rank = max(0, min(4, int(hw.get("native_tier_rank", hw.get("tier_rank", 0)) or 0)))
    native_label = str(hw.get("native_network_tier", hw.get("network_tier", "LocalOnly")) or "LocalOnly")
    runtime = str(hw.get("runtime", "") or "")
    shell_capable = bool(hw.get("shell_capable", runtime != "headless-python"))
    progressive_unlock = bool(hw.get("progressive_network_unlock", not shell_capable))
    startup_mode = str(cap.get("startup_mode", "full") or "full")
    progression_track = str(cap.get("progression_track", "full-runtime") or "full-runtime")
    base_mode = _base_progression_mode(cap)
    network_end_goal = str(cap.get("network_end_goal", native_label) or native_label)
    overlay_path = str(cap.get("overlay_path", "native-yggdrasil") or "native-yggdrasil")
    relay_bridge_required = bool(cap.get("relay_bridge_required", False))
    symbiont_role = str(cap.get("symbiont_role", "overlay-peer") or "overlay-peer")
    emergent_network_role = str(cap.get("emergent_network_role", "visibility-staging") or "visibility-staging")
    aethernet_goal_message = str(cap.get("aethernet_goal_message", "") or "")

    if shell_capable and not progressive_unlock:
        scope = _tier_features_from_rank(native_rank)
        scope.update(
            {
                "native_network_tier": native_label,
                "native_tier_rank": native_rank,
                "startup_mode": startup_mode,
                "progression_track": progression_track,
                "base_progression_mode": base_mode,
                "progression_mode": str(cap.get("progression_mode", "vault-first") or "vault-first"),
                "next_goal": str(cap.get("next_goal", "") or ""),
                "shell_capable": shell_capable,
                "progressive_network_unlock": progressive_unlock,
                "network_end_goal": network_end_goal,
                "overlay_path": overlay_path,
                "relay_bridge_required": relay_bridge_required,
                "symbiont_role": symbiont_role,
                "emergent_network_role": emergent_network_role,
                "aethernet_goal_message": aethernet_goal_message,
            }
        )
        return scope

    if native_rank <= 0:
        desired_rank = 0
    else:
        desired_rank = 1
        progression_mode = base_mode
        stage_index = int(cap.get("stage_index", 0) or 0)
        if progression_mode in {"lan-p2p-ready", "shell-ready", "overlay-ready", "full-member"} or stage_index >= 2 or bool(cap.get("shell_ready", False)):
            desired_rank = max(desired_rank, 2)
        if progression_mode in {"overlay-ready", "full-member"} or bool(cap.get("overlay_ready", False)):
            desired_rank = max(desired_rank, 3)
        if progression_mode == "full-member" or bool(cap.get("full_member_ready", False)):
            desired_rank = max(desired_rank, 4)

    effective_rank = min(native_rank, desired_rank)
    scope = _tier_features_from_rank(effective_rank)
    scope.update(
        {
            "native_network_tier": native_label,
            "native_tier_rank": native_rank,
            "startup_mode": startup_mode,
            "progression_track": progression_track,
            "base_progression_mode": base_mode,
            "progression_mode": str(cap.get("progression_mode", "vault-first") or "vault-first"),
            "next_goal": str(cap.get("next_goal", "") or ""),
            "shell_capable": shell_capable,
            "progressive_network_unlock": progressive_unlock,
            "network_end_goal": network_end_goal,
            "overlay_path": overlay_path,
            "relay_bridge_required": relay_bridge_required,
            "symbiont_role": symbiont_role,
            "emergent_network_role": emergent_network_role,
            "aethernet_goal_message": aethernet_goal_message,
        }
    )
    return scope


def _booster_interval_seconds(initial_rank: int) -> int:
    if initial_rank <= 0:
        return BOOST_CHECK_INTERVAL_SEC * 2
    if initial_rank == 1:
        return int(BOOST_CHECK_INTERVAL_SEC * 1.5)
    return BOOST_CHECK_INTERVAL_SEC


# --------------------------------------------------------------------------- #
#  PeerID                                                                     #
# --------------------------------------------------------------------------- #

def derive_peer_id(public_key_path: Optional[str] = None) -> str:
    """Derive PeerID from Ed25519 public key (deterministic, anonymous)."""
    try:
        if public_key_path is None:
            public_key_path = str(ROOT / "data" / "keys" / "node_public.key")
        key_bytes = Path(public_key_path).read_bytes()
        return "peer-" + hashlib.sha256(key_bytes).hexdigest()[:32]
    except Exception as e:
        # Fallback: generate stable random PeerID stored locally
        pid_path = ROOT / "data" / "peer_id.txt"
        if pid_path.is_file():
            return pid_path.read_text(encoding="utf-8").strip()
        pid = "peer-" + uuid.uuid4().hex[:32]
        pid_path.parent.mkdir(parents=True, exist_ok=True)
        pid_path.write_text(pid, encoding="utf-8")
        return pid


# --------------------------------------------------------------------------- #
#  Leader election (simple highest-PeerID rule)                              #
# --------------------------------------------------------------------------- #

class LeaderElection:
    """Simple deterministic leader election: highest PeerID among known peers."""

    def __init__(self, local_peer_id: str) -> None:
        self._local_peer_id = local_peer_id
        self._known_peers: Dict[str, float] = {}  # peer_id -> last_seen_ts
        self._lock = threading.Lock()
        self._ttl = DEFAULT_P2P["peer_ttl_seconds"]

    def register_peer(self, peer_id: str) -> None:
        with self._lock:
            self._known_peers[peer_id] = time.monotonic()

    def evict_stale(self) -> None:
        now = time.monotonic()
        with self._lock:
            stale = [p for p, ts in self._known_peers.items() if now - ts > self._ttl]
            for p in stale:
                del self._known_peers[p]

    def is_leader(self) -> bool:
        """Return True if local node is the current leader (highest PeerID)."""
        self.evict_stale()
        with self._lock:
            all_peers = list(self._known_peers.keys()) + [self._local_peer_id]
        return self._local_peer_id >= max(all_peers)

    def current_leader(self) -> str:
        self.evict_stale()
        with self._lock:
            all_peers = list(self._known_peers.keys()) + [self._local_peer_id]
        return max(all_peers)

    def peer_count(self) -> int:
        self.evict_stale()
        with self._lock:
            return len(self._known_peers)


# --------------------------------------------------------------------------- #
#  Gossip message                                                             #
# --------------------------------------------------------------------------- #

def _build_gossip_message(
    peer_id: str,
    fingerprints: List[str],
    metrics_summary: Dict[str, Any],
    is_leader: bool,
    is_genesis_node: bool = False,
) -> Dict[str, Any]:
    """Build a gossip message containing ONLY fingerprints and aggregated metrics."""
    msg: Dict[str, Any] = {
        "schema": "aether.swarm.p2p.gossip.v1",
        "peer_id": peer_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "is_leader": is_leader,
        "fingerprints": fingerprints[:DEFAULT_P2P["max_fingerprints_per_gossip"]],
        "metrics_summary": metrics_summary,
        # Raw frames, pixel data, application content: NEVER included
    }
    # is_genesis_node wird nur gesetzt wenn genesis_node.key lokal vorhanden ist.
    # is_genesis_node wird im Gossip mitgeschickt — Empfänger gleichen die
    # ygg_addr des Absenders gegen die erste gelernte Genesis-Adresse ab.
    # Nicht-Genesis-Knoten kennen diese Adresse erst nach erstem Kontakt.
    if is_genesis_node:
        msg["is_genesis_node"] = True
    return msg


def _load_local_account_claim() -> Dict[str, Any]:
    try:
        if not LOCAL_NODE_JSON_PATH.is_file():
            return {}
        payload = json.loads(LOCAL_NODE_JSON_PATH.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return {}
        return {
            "account_username": str(payload.get("account_username", "") or "").strip(),
            "account_identity_lock": str(payload.get("account_identity_lock", "") or "").strip(),
            "ygg_addr": str(
                payload.get("ygg_addr", payload.get("yggdrasil_addr", "")) or ""
            ).strip(),
            "network_entry_id": str(payload.get("network_entry_id", "") or "").strip(),
            "native_ygg_bound": bool(payload.get("native_ygg_bound", False)),
        }
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
#  P2PLayer                                                                   #
# --------------------------------------------------------------------------- #

class P2PLayer:
    """Opt-in P2P fingerprint exchange layer."""

    def __init__(
        self,
        node_id: str,
        aethernet_transport: Any = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._node_id = node_id
        self._transport = aethernet_transport
        self._config = dict(DEFAULT_P2P)
        if config:
            self._config.update(config)

        # Load local device_fingerprint for inclusion in gossip messages
        try:
            from modules.device_lock import get_local_fingerprint
            self._device_fingerprint: str = get_local_fingerprint() or ""
        except ImportError:
            self._device_fingerprint = ""
        self._account_username: str = ""
        self._account_identity_lock: str = ""
        self._local_ygg_addr: str = ""
        self._network_entry_id: str = ""
        self._native_ygg_bound: bool = False
        self._refresh_local_account_claim()

        self._peer_id = derive_peer_id()
        self._leader_election = LeaderElection(self._peer_id)
        self._stop_event = threading.Event()
        self._gossip_thread: Optional[threading.Thread] = None
        self._received_gossip: List[Dict[str, Any]] = []
        self._received_lock = threading.Lock()
        self._discovered_peer_addrs: List[str] = []
        self._discovered_relay_addrs: List[str] = []
        # addr -> monotonic timestamp of last connection attempt
        self._bootstrapped_peer_addrs: Dict[str, float] = {}
        self._started_yggdrasil = False
        # Tier-Watchdog (Startbooster): läuft wenn Hardware zu schwach für vollständiges P2P.
        self._booster_active: bool = False
        self._booster_thread: Optional[threading.Thread] = None
        # Genesis-Node-Status: True nur auf dem Knoten des Erstellers.
        self._is_genesis_node: bool = _check_is_genesis_node()
        if self._is_genesis_node:
            logger.info("[P2P] Genesis-Node-Key gefunden — dieser Knoten ist der Genesis-Node.")
        # Peer-Capability-Verzeichnis: node_id → node_capabilities aus Gossip
        # Ermöglicht get_swarm_capability_gaps() — welche Probes fehlen im Schwarm?
        self._peer_capabilities: Dict[str, Dict[str, Any]] = {}

    @property
    def enabled(self) -> bool:
        return bool(self._config.get("enabled", False))

    @property
    def peer_id(self) -> str:
        return self._peer_id

    def _refresh_local_account_claim(self) -> None:
        claim = _load_local_account_claim()
        self._account_username = str(claim.get("account_username", "") or "").strip()
        self._account_identity_lock = str(claim.get("account_identity_lock", "") or "").strip()
        self._local_ygg_addr = str(claim.get("ygg_addr", "") or "").strip()
        self._network_entry_id = str(claim.get("network_entry_id", "") or "").strip()
        self._native_ygg_bound = bool(claim.get("native_ygg_bound", False))

    def _is_consented(self) -> bool:
        """Prueft ob Swarm-Teilnahme aktiv ist (opt-out Modell).

        Liest data/swarm_consent.json. Standard ist True — kein File = Teilnahme aktiv.
        Abschalten nur explizit über 'Swarm deaktivieren' im SwarmOps-Tab oder
        durch revoked=true in der JSON.
        Genesis-Nodes koennen consent_ok=true im Bootstrap setzen.
        """
        consent_path = ROOT / "data" / "swarm_consent.json"
        try:
            if consent_path.is_file():
                data = json.loads(consent_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    if "consented" in data:
                        return bool(data.get("consented"))
                    if "consent_ok" in data:
                        return bool(data.get("consent_ok"))
                    if "approved" in data:
                        return bool(data.get("approved"))
                    # Explizites Revoke respektieren
                    if bool(data.get("revoked", False)):
                        return False
        except Exception as e:
            logger.warning(f"[swarm_p2p] Stiller Fehler: {e}")
            pass
        # Default-on: kein File = Consent gilt als erteilt (opt-out Modell)
        return True

    def start(self) -> None:
        if not self.enabled:
            print("[P2P] Disabled. Set swarm_p2p.enabled=true to activate.")
            return
        # --- Consent check: Default-on, revoke jederzeit moeglich ---
        if not self._is_consented():
            print("[P2P] Consent widerrufen in swarm_consent.json — Swarm-Teilnahme abgebrochen.")
            return
        # --- Offline-Resilienz: Knowledge-Snapshot sofort laden (Knoten nicht Stunde-Null) ---
        try:
            from modules.offline_learning import OfflineLearner as _OL
            _OL.instance()  # __init__ lädt Snapshot automatisch
            logger.debug("[P2P] OfflineLearner initialisiert, Knowledge-Snapshot geladen.")
        except Exception as _ol_exc:
            logger.debug(f"[P2P] OfflineLearner: {_ol_exc}")
        # --- Hardware-Capability Gate ---
        hw = _read_hw_capability()
        cap = _read_capability_score()
        scope = _effective_swarm_scope(hw, cap)
        effective_rank = int(scope.get("effective_tier_rank", 0))
        if effective_rank < 1:
            if not self._booster_active:
                relay_pool = _load_relay_pool(self._config)
                if relay_pool and scope.get("relay_bridge_required", False):
                    # Relay-Bridge-Modus: Pool durchsuchen, ersten erreichbaren Relay nehmen.
                    # Beim Start sofort Bootstrap: Peer-Liste + Relay-Pool vom Relay holen.
                    active_relay = _pick_live_relay(relay_pool)
                    if active_relay and self._transport is not None:
                        boot = getattr(self._transport, "bootstrap_from_relay", None)
                        if callable(boot):
                            n = boot(active_relay)
                            logger.info(f"[P2P] Bootstrap via {active_relay}: {n} Peers gelernt.")
                    print(
                        f"[P2P] LocalOnly + Relay-Pool ({len(relay_pool)} Kandida\u0074en) \u2192 Relay-Bridge-Gossip-Loop. "
                        f"Aktiv: {active_relay or '(noch keiner erreichbar)'} "
                        f"Native={scope.get('native_network_tier', '?')} "
                        f"({hw.get('os_platform', '?')}) {_progression_hint(cap)}"
                    )
                    self._start_stealth_beacon()
                    self._stop_event.clear()
                    self._gossip_thread = threading.Thread(
                        target=self._gossip_loop, daemon=True, name="swarm-p2p-relay-gossip"
                    )
                    self._gossip_thread.start()
                    self._start_tier_watchdog(initial_rank=effective_rank)
                else:
                    print(
                        f"[P2P] Effektiv LocalOnly | Native={scope.get('native_network_tier', '?')} "
                        f"({hw.get('os_platform', '?')}): "
                        f"Starte StealthBeacon + Tier-Watchdog. {_progression_hint(cap)}"
                    )
                    self._start_stealth_beacon()
                    self._start_tier_watchdog(initial_rank=effective_rank)
            return
        if scope.get("lan_beacon", False) and not scope.get("lan_p2p", False):
            if not self._booster_active:
                print(
                    f"[P2P] Effektiv {scope.get('effective_network_tier', '?')} | "
                    f"Native={scope.get('native_network_tier', '?')} "
                    f"({hw.get('os_platform', '?')}): Nur LAN-Beacon aktiv. "
                    f"Kein Gossip-/Leader-Overhead. {_progression_hint(cap)}"
                )
                self._start_stealth_beacon()
                self._start_tier_watchdog(initial_rank=effective_rank)
            return
        if not scope.get("lan_beacon", False):
            print("[P2P] LAN-Beacon nicht unterstützt (hw_capability) — P2P übersprungen.")
            return
        print(
            f"[P2P] Effektiv: {scope.get('effective_network_tier', '?')} | Native: {scope.get('native_network_tier', '?')} "
            f"({hw.get('os_platform', '?')}) — "
            f"LAN={scope.get('lan_p2p')}, Yggdrasil={scope.get('yggdrasil')}, DHT={scope.get('dht')} | "
            f"Stage={cap.get('stage', '?')} / {scope.get('progression_mode', 'vault-first')} | "
            f"Ziel={scope.get('network_end_goal', '?')} | Pfad={scope.get('overlay_path', '?')}"
        )
        self._ensure_yggdrasil_runtime(scope)
        from modules.lan_beacon import start as _start_lan_beacon
        _start_lan_beacon()
        discovery_dir = str(self._config.get("discovery_nodes_dir", "data/swarm/nodes") or "data/swarm/nodes")
        self._discovered_peer_addrs = self.discover_from_nodes_dir(discovery_dir)
        self._bootstrap_known_peers(self._discovered_peer_addrs)
        self._stop_event.clear()
        self._gossip_thread = threading.Thread(
            target=self._gossip_loop, daemon=True, name="swarm-p2p-gossip"
        )
        self._gossip_thread.start()
        print(
            f"[P2P] Layer started. PeerID={self._peer_id[:16]}… "
            f"Discovery={len(self._discovered_peer_addrs)} peers"
        )

    def stop(self) -> None:
        self._stop_event.set()
        self._booster_active = False  # Watchdog erkennt _stop_event und beendet sich
        # Letzten Knowledge-Snapshot schreiben bevor der Thread stirbt
        try:
            from modules.offline_learning import OfflineLearner as _OL
            ol = _OL.instance()
            ol.stop()
            ol.write_knowledge_snapshot()
        except Exception:
            pass
        if self._gossip_thread:
            self._gossip_thread.join(timeout=3.0)
        if self._started_yggdrasil:
            from modules.yggdrasil_install import stop_yggdrasil_subprocess as _stop_ygg
            _stop_ygg()
            self._started_yggdrasil = False

    # ---------------------------------------------------------------------- #
    #  Startbooster: StealthBeacon + Tier-Watchdog                           #
    # ---------------------------------------------------------------------- #

    def _start_stealth_beacon(self) -> None:
        """Minimaler LAN-UDP-Announce für LocalOnly-Geräte.

        Kein Gossip, kein Leader-Overhead — nur passiv im LAN ankündigen.
        Damit ist das Gerät im Netz sichtbar, auch wenn es keinen P2P-Gossip
        leisten kann (z.B. RPi Zero, Win9x-Emulation, <256 MB RAM).
        Impft zusätzlich die Genesis-Invarianten ein (idempotent: überschreibt
        keine bereits vorhandenen eigenen Messungen).
        """
        self._seed_genesis_invariants()
        try:
            from modules.lan_beacon import start as _start_lan_beacon
            _start_lan_beacon()
            print("[P2P] StealthBeacon aktiv — LAN-Announce ohne Gossip-Overhead.")
        except Exception as e:
            logger.warning(f"[P2P] StealthBeacon fehlgeschlagen: {e}")

    def _seed_genesis_invariants(self) -> None:
        """Schreibt GENESIS_INVARIANTS nach data/interbus/genesis_invariants.json.

        Idempotent: schreibt nur wenn die Datei noch nicht existiert ODER wenn
        sie noch keinen source='measured'-Eintrag enthält (d.h. noch kein
        eigenes Messergebnis vorhanden). Eigene Messungen werden nie überschrieben.
        """
        out_path = ROOT / "data" / "interbus" / "genesis_invariants.json"
        try:
            if out_path.is_file():
                existing = json.loads(out_path.read_text(encoding="utf-8"))
                if isinstance(existing, dict) and existing.get("source") == "measured":
                    logger.debug("[P2P] genesis_invariants.json enthält eigene Messung — Prior nicht überschrieben.")
                    return
            INTERBUS_DIR.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps(GENESIS_INVARIANTS, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            print("[P2P] Genesis-Invarianten eingeimpft — Knoten hat Ausgangsbasis (Benford 0.85 / Zipf α 1.07 / Mandelbrot β 1.40 / Fourier 24).")
        except Exception as e:
            logger.warning(f"[P2P] Genesis-Invarianten konnten nicht geschrieben werden: {e}")

    def _start_tier_watchdog(self, initial_rank: int, try_count: int = 0) -> None:
        """Startet einen One-Shot-Watchdog-Thread.

        Jeder Thread läuft genau einmal: schläft BOOST_CHECK_INTERVAL_SEC,
        prüft den Tier einmal und beendet sich dann. Kein interner Loop —
        so können nie mehrere Watchdogs gleichzeitig aktiv sein.
        Kein Upgrade → neuer One-Shot wird nach dem Ablauf gestartet.
        """
        if self._booster_active:
            return  # Bereits ein One-Shot aktiv — keinen zweiten starten
        if try_count >= BOOST_MAX_TRIES:
            print(
                f"[P2P-Booster] {BOOST_MAX_TRIES} Checks ohne Tier-Upgrade — "
                "Watchdog beendet. Gerät bleibt auf StealthBeacon."
            )
            return
        interval_sec = _booster_interval_seconds(initial_rank)
        self._booster_active = True
        self._booster_thread = threading.Thread(
            target=self._tier_watchdog_once,
            args=(initial_rank, try_count, interval_sec),
            daemon=True,
            name=f"swarm-p2p-booster-{try_count}",
        )
        self._booster_thread.start()
        print(
            f"[P2P-Booster] One-Shot #{try_count + 1}/{BOOST_MAX_TRIES} gestartet — "
            f"prüft in {interval_sec}s auf Tier-Upgrade."
        )

    def _tier_watchdog_once(self, initial_rank: int, try_count: int, interval_sec: int) -> None:
        """One-Shot-Watchdog: schläft 90s, prüft einmal, beendet sich dann.

        Kein Loop — nach der Prüfung ist dieser Thread fertig.
        Bei fehlendem Upgrade startet _start_tier_watchdog() einen neuen
        One-Shot (try_count + 1). Maximal ein Thread gleichzeitig aktiv.
        """
        stopped = self._stop_event.wait(timeout=interval_sec)
        self._booster_active = False  # Thread läuft ab — Gate freigeben
        if stopped:
            return  # stop() gerufen — keine Fortsetzung
        hw = _read_hw_capability()
        cap = _read_capability_score()
        scope = _effective_swarm_scope(hw, cap)
        new_rank = int(scope.get("effective_tier_rank", 0))
        print(
            f"[P2P-Booster] Check {try_count + 1}/{BOOST_MAX_TRIES}: "
            f"Effektiv={scope.get('effective_network_tier', '?')} (Rank {new_rank}, Start-Rank {initial_rank}) | "
            f"Native={scope.get('native_network_tier', '?')} | Stage={cap.get('stage', '?')} / {scope.get('progression_mode', 'vault-first')}"
        )
        if new_rank > initial_rank:
            logger.info(
                f"[P2P-Booster] Tier-Upgrade erkannt: {initial_rank} → {new_rank} "
                f"({scope.get('effective_network_tier')}). Starte P2P..."
            )
            self.start()  # Normaler Start — _booster_active ist bereits False
        else:
            # Kein Upgrade — Yggdrasil-Install versuchen wenn AE-Progression es erlaubt
            if scope.get("relay_bridge_required", False):
                self._try_install_yggdrasil_if_ready(cap)
            # Neuen One-Shot planen (nächster try_count)
            self._start_tier_watchdog(initial_rank, try_count + 1)

    def _try_install_yggdrasil_if_ready(self, cap: Dict[str, Any]) -> None:
        """Versucht Yggdrasil herunterzuladen wenn AE-Progression es erlaubt.

        Bedingungen:
          - Yggdrasil noch nicht installiert (kein Binary in bin/)
          - Capability-Score >= 25% (Knoten hat genug gelernt + Overhead reduziert)
          - Genug freier Speicher (>= 50 MB)

        Nachfolge-Check des Tier-Watchdogs erkennt das neue Binary automatisch
        und triggert den Tier-Upgrade auf YggdrasilP2P im nächsten One-Shot.
        """
        try:
            from modules.yggdrasil_install import is_yggdrasil_available, install_yggdrasil
            if is_yggdrasil_available():
                return  # Bereits installiert
            cap_score = float(cap.get("capability_percent", 0.0) or 0.0)
            if cap_score < 25.0:
                logger.debug(
                    "[P2P-Booster] Yggdrasil-Install aufgeschoben: "
                    f"Capability {cap_score:.0f}% < 25%"
                )
                return
            try:
                import shutil as _shutil
                free_mb = _shutil.disk_usage(".").free / (1024 * 1024)
                if free_mb < 50:
                    logger.debug(
                        f"[P2P-Booster] Yggdrasil-Install aufgeschoben: "
                        f"nur {free_mb:.0f} MB frei"
                    )
                    return
            except Exception:
                pass
            print(
                f"[P2P-Booster] AE-Progression ({cap_score:.0f}%) erlaubt Yggdrasil-Install — "
                "starte Download für Tier-Upgrade auf YggdrasilP2P..."
            )
            install_yggdrasil()
            print("[P2P-Booster] Yggdrasil installiert — nächster Watchdog-Check erkennt Tier-Upgrade.")
        except Exception as exc:
            print(f"[P2P-Booster] Yggdrasil-Install fehlgeschlagen (wird erneut versucht): {exc}")

    def is_leader(self) -> bool:
        return self._leader_election.is_leader()

    def current_leader(self) -> str:
        return self._leader_election.current_leader()

    def publish_fingerprints(
        self,
        fingerprints: List[str],
        metrics_summary: Optional[Dict[str, Any]] = None,
        node_capabilities: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Publish fingerprints to known peers via AethernetTransport."""
        if not self.enabled:
            return False
        if not fingerprints:
            return False
        msg = _build_gossip_message(
            peer_id=self._peer_id,
            fingerprints=fingerprints,
            metrics_summary=metrics_summary or {},
            is_leader=self.is_leader(),
            is_genesis_node=self._is_genesis_node,
        )
        # Include device identity fields for swarm-level device-lock enforcement
        msg["node_id"] = self._node_id
        if self._device_fingerprint:
            msg["device_fingerprint"] = self._device_fingerprint
        self._refresh_local_account_claim()
        if self._account_username:
            msg["account_username"] = self._account_username
        if self._account_identity_lock:
            msg["account_identity_lock"] = self._account_identity_lock
        if self._local_ygg_addr:
            msg["ygg_addr"] = self._local_ygg_addr
        if self._network_entry_id:
            msg["network_entry_id"] = self._network_entry_id
        if self._native_ygg_bound:
            msg["native_ygg_bound"] = True
        # Blind-Spot-Bericht: welche Capabilities fehlen diesem Knoten?
        # Andere Knoten können sehen wer noch Yggdrasil, NumPy, etc. braucht.
        caps = node_capabilities if node_capabilities is not None else _collect_node_capabilities()
        if caps:
            msg["node_capabilities"] = caps

        # Computation Delegation: ausstehende eigene Tasks broadcasten
        # Schwache Knoten fragen starke Knoten um Hilfe — via Gossip
        try:
            from modules.task_broker import TaskBroker as _TB
            _task_reqs = _TB.instance().get_pending_requests_to_broadcast()
            if _task_reqs:
                msg["task_requests"] = _task_reqs
            # Gebote für fremde Tasks mitschicken (wir können diese Tasks ausführen)
            _local_caps_list = caps.get("have", []) if caps else []
            _local_score = float(caps.get("score_pct", 0)) if caps else 0.0
            _bids = _TB.instance().get_bids_to_broadcast(
                self._node_id, _local_score, _local_caps_list
            )
            if _bids:
                msg["task_bids"] = _bids
        except Exception as _te:
            logger.debug(f"[swarm_p2p] task_broker embed: {_te}")

        # Prefetch-Hints: unsere Vorhersagen mit dem Schwarm teilen
        # Vista-Klasse-Knoten wärmen ihren Vault bevor die Anfrage kommt
        try:
            from modules.prediction_engine import PredictionEngine as _PE
            _hints = _PE.instance().get_prefetch_hints_for_gossip()
            if _hints:
                msg["prefetch_hints"] = _hints
        except Exception as _pe:
            logger.debug(f"[swarm_p2p] prediction_engine embed: {_pe}")

        # Auto-Propagation verbesserter Algorithmen
        # Wenn die lokale Vault-Effizienz gestiegen ist → bestes AlgoToken teilen
        try:
            from modules.algo_share import AutoPropagator as _AP
            _token = _AP.instance().get_best_token_for_gossip()
            if _token:
                msg["algo_token"] = _token
        except Exception as _ae:
            logger.debug(f"[swarm_p2p] algo_share embed: {_ae}")

        # Φ-Vektor-Snapshot: aktuelle Anker als Vergleichskandidaten anbieten.
        # Empfehlende Knoten können sie dann mit ihren lokalen Φs vergleichen.
        try:
            from modules.swarm_persist import open_swarm_metrics_db
            _phi_snapshot: List[Dict[str, Any]] = []
            with open_swarm_metrics_db() as _db:
                _rows = _db.execute(
                    "SELECT fingerprint, mean_val, std_val, entropy_approx, extras "
                    "FROM frame_metrics WHERE delta_marker != 'stable' "
                    "ORDER BY ts DESC LIMIT 10"
                ).fetchall()
            for _r in _rows:
                _extras: Dict[str, Any] = {}
                try:
                    _extras = json.loads(_r[4] or "{}")
                except Exception:
                    pass
                _phi: List[float] = [
                    float(_r[3]),                         # entropy_approx  → H_S
                    float(_extras.get("boltzmann_entropy", 0.0)),  # H_B
                    float(_extras.get("zipf_alpha", 0.0)),         # α_Z
                    float(_extras.get("benford_score", 0.0)),      # β_F
                    float(_extras.get("periodicity", 0.0)),        # ρ_P
                    float(_extras.get("katz_dimension", 0.0)),     # D_K
                    float(_extras.get("perm_entropy", 0.0)),       # H_P
                    float(_extras.get("delta_ratio", 0.0)),        # Δ_C
                    float(_extras.get("noether_consistency", 0.0)),# K_N
                ]
                _phi_snapshot.append({
                    "fingerprint": _r[0],
                    "phi": _phi,
                    "source_label": _extras.get("source_label", ""),
                    "remote_node_pubkey": self._peer_id,
                })
            if _phi_snapshot:
                msg["phi_candidates"] = _phi_snapshot
        except Exception as _phi_err:
            logger.debug(f"[swarm_p2p] phi_snapshot embed: {_phi_err}")

        # Write gossip to local interbus for external readers
        try:
            INTERBUS_DIR.mkdir(parents=True, exist_ok=True)
            P2P_GOSSIP_PATH.write_text(
                json.dumps(msg, ensure_ascii=True, indent=2), encoding="utf-8"
            )
        except Exception as e:
            logger.warning(f"[swarm_p2p] Stiller Fehler: {e}")
            pass
        # Send via AethernetTransport if available
        if self._transport is not None:
            try:
                # Pool-Modus: mehrere Relay-Kandidaten, erster der antwortet gewinnt.
                relay_pool = _load_relay_pool(self._config)
                if relay_pool:
                    cap = _read_capability_score()
                    hw = _read_hw_capability()
                    scope = _effective_swarm_scope(hw, cap)
                    # known_relay_urls aus Pool in Gossip einbauen → andere Knoten lernen das Netz
                    msg["known_relay_urls"] = relay_pool[:16]
                    if scope.get("relay_bridge_required", False):
                        # Relay-Bridge-Modus: Pool durchsuchen, ersten erreichbaren nutzen.
                        active_relay = _pick_live_relay(relay_pool)
                        if active_relay:
                            relay_gossip_push = getattr(self._transport, "relay_gossip_push", None)
                            if callable(relay_gossip_push):
                                relay_gossip_push(active_relay, msg)
                            relay_gossip_pull = getattr(self._transport, "relay_gossip_pull", None)
                            if callable(relay_gossip_pull):
                                for remote_msg in relay_gossip_pull(active_relay):
                                    self.receive_gossip(remote_msg)
                        else:
                            logger.debug("[P2P] Kein erreichbarer Relay im Pool — warte auf nächsten Gossip-Cycle.")
                    else:
                        # Vollknoten: ersten LAN-erreichbaren Relay nehmen
                        active_relay = relay_pool[0] if relay_pool else ""
                        if active_relay:
                            self._transport.relay_push(active_relay)
                return True
            except Exception as err:
                print(f"[P2P] relay_push failed: {err}")
        return True  # Local write succeeded

    def receive_gossip(self, msg: Dict[str, Any]) -> None:
        """Process incoming gossip message from a peer."""
        if not isinstance(msg, dict):
            return
        schema = str(msg.get("schema", ""))
        if schema != "aether.swarm.p2p.gossip.v1":
            return
        peer_id = str(msg.get("peer_id", "")).strip()

        # Device-lock enforcement: one account per device, one device per account
        incoming_node_id = str(msg.get("node_id", "") or "").strip()
        incoming_device_fp = str(msg.get("device_fingerprint", "") or "").strip()
        incoming_username = str(msg.get("account_username", "") or "").strip()
        incoming_ygg_addr = str(msg.get("ygg_addr", msg.get("yggdrasil_addr", "")) or "").strip()
        incoming_identity_lock = str(msg.get("account_identity_lock", "") or "").strip()
        incoming_network_entry_id = str(msg.get("network_entry_id", "") or "").strip()
        if incoming_node_id and incoming_device_fp and (
            incoming_username or incoming_ygg_addr or incoming_identity_lock or incoming_network_entry_id
        ):
            try:
                from modules.device_lock import peer_account_allowed as _peer_account_allowed

                if not _peer_account_allowed(
                    incoming_node_id,
                    incoming_device_fp,
                    account_username=incoming_username,
                    yggdrasil_addr=incoming_ygg_addr,
                    identity_lock=incoming_identity_lock,
                    network_entry_id=incoming_network_entry_id,
                ):
                    logger.warning(
                        f"[swarm_p2p] Peer verworfen (identity-lock): "
                        f"node={incoming_node_id[:16]}... fp={incoming_device_fp[:16]}..."
                    )
                    return
            except ImportError:
                pass
        elif incoming_node_id and incoming_device_fp:
            try:
                from modules.device_lock import peer_allowed as _peer_allowed

                if not _peer_allowed(incoming_node_id, incoming_device_fp):
                    logger.warning(
                        f"[swarm_p2p] Peer verworfen (device-lock): "
                        f"node={incoming_node_id[:16]}... fp={incoming_device_fp[:16]}..."
                    )
                    return
            except ImportError:
                pass

        # Spoofing-Schutz: Peer behauptet Genesis-Node zu sein → Adresse prüfen.
        # Nur der Genesis-Knoten selbst kennt die korrekte Adresse (aus Key).
        # Nicht-Genesis-Knoten lernen sie beim ersten echten Kontakt und prüfen danach.
        if msg.get("is_genesis_node") and not self._is_genesis_node:
            known_genesis_addr = _get_genesis_ygg_addr() or str(
                self._config.get("genesis_yggdrasil_addr", "") or ""
            ).strip()
            if incoming_ygg_addr and known_genesis_addr and incoming_ygg_addr.lower() != known_genesis_addr.lower():
                logger.warning(
                    f"[P2P] Spoofing-Versuch abgewehrt: Peer {peer_id[:16]}... "
                    f"behauptet Genesis-Node, aber Adresse stimmt nicht."
                )
                return
            try:
                from modules.identity_claim import (
                    load_trusted_publishers,
                    matches_manifest_genesis_identity,
                )

                manifest = load_trusted_publishers(ROOT)
                if not matches_manifest_genesis_identity(
                    manifest,
                    username=incoming_username,
                    node_id=incoming_node_id,
                    device_fingerprint=incoming_device_fp,
                    yggdrasil_addr=incoming_ygg_addr,
                    identity_lock=incoming_identity_lock,
                ):
                    logger.warning(
                        f"[P2P] Spoofing-Versuch abgewehrt: Peer {peer_id[:16]}... "
                        f"behauptet Genesis-Node ohne passenden Manifest-Lock."
                    )
                    return
            except ImportError:
                return

        if peer_id and peer_id != self._peer_id:
            self._leader_election.register_peer(peer_id)

        # Lerne neue Relay-URLs aus dem Gossip — so wächst das Verzeichnis von selbst.
        # Jeder Knoten der antwortet ist potenziell ein Relay für andere.
        for rurl in list(msg.get("known_relay_urls") or []):
            _extend_relay_pool_from_gossip(self._config, str(rurl))
        # Falls der Transport verfügbar ist: auch dort persistieren
        if self._transport is not None:
            learn = getattr(self._transport, "_learn_relay_url", None)
            if callable(learn):
                for rurl in list(msg.get("known_relay_urls") or []):
                    learn(str(rurl))
            # Absender-Peer in nodes_dir persistieren → nach Neustart erreichbar,
            # auch wenn der Genesis-Knoten schon offline ist.
            # Nur wenn node_id + ygg_addr vorhanden (Yggdrasil-Knoten).
            if incoming_node_id and incoming_ygg_addr:
                save_gossip_peer = getattr(self._transport, "_save_gossip_peer", None)
                if callable(save_gossip_peer):
                    save_gossip_peer({
                        "node_id": incoming_node_id,
                        "yggdrasil_addr": incoming_ygg_addr,
                        "peer_id": peer_id,
                        "account_username": incoming_username,
                    })

        with self._received_lock:
            self._received_gossip.append(msg)
            # Keep last 100 gossip messages
            if len(self._received_gossip) > 100:
                self._received_gossip = self._received_gossip[-100:]
            # Capability-Bericht des Peers speichern — für get_swarm_capability_gaps()
            incoming_caps = msg.get("node_capabilities")
            if isinstance(incoming_caps, dict) and incoming_node_id:
                self._peer_capabilities[incoming_node_id] = incoming_caps

        # Computation Delegation: fremde Task-Requests und Bids verarbeiten
        for req_data in list(msg.get("task_requests") or []):
            try:
                from modules.task_broker import TaskBroker as _TB
                _TB.instance().receive_remote_request(req_data)
            except Exception as _te:
                logger.debug(f"[swarm_p2p] task_request recv: {_te}")
        for bid_data in list(msg.get("task_bids") or []):
            try:
                from modules.task_broker import TaskBroker as _TB
                _TB.instance().receive_bid(bid_data)
            except Exception as _te:
                logger.debug(f"[swarm_p2p] task_bid recv: {_te}")
        for result_data in list(msg.get("task_results") or []):
            try:
                from modules.task_broker import TaskBroker as _TB
                _TB.instance().receive_result(result_data)
            except Exception as _te:
                logger.debug(f"[swarm_p2p] task_result recv: {_te}")

        # Prefetch-Hints: kollektive Vorhersagen absorbieren
        # Jeder Peer der spielt macht UNSERE Vorhersage besser
        _prefetch_hints = list(msg.get("prefetch_hints") or [])
        if _prefetch_hints:
            try:
                from modules.prediction_engine import PredictionEngine as _PE
                _n = _PE.instance().absorb_gossip_hints(_prefetch_hints)
                if _n > 0:
                    logger.debug(f"[P2P] {_n} Prefetch-Hints von {peer_id[:16]}... absorbiert")
            except Exception as _pe:
                logger.debug(f"[swarm_p2p] prediction_engine absorb: {_pe}")

        # Auto-Propagation: empfangenes AlgoToken speichern
        _algo_token = msg.get("algo_token")
        if isinstance(_algo_token, dict):
            try:
                from modules.algo_share import AutoPropagator as _AP
                if _AP.instance().receive_algo_token(_algo_token):
                    logger.info(f"[P2P] Neues AlgoToken von {peer_id[:16]}... gespeichert "
                                f"(fitness={_algo_token.get('fitness_score', '?')})")
            except Exception as _ae:
                logger.debug(f"[swarm_p2p] algo_token recv: {_ae}")

        # Φ-Kandidaten: empfangene Peer-Anker in swarm_peer_candidates.json mergen.
        # swarm_overlap.py liest diese Datei und vergleicht dann lokal via 9D Cosinus.
        _phi_cands = list(msg.get("phi_candidates") or [])
        if _phi_cands:
            try:
                _PEER_CAND_PATH = INTERBUS_DIR / "swarm_peer_candidates.json"
                _cand_lock = threading.Lock()  # thread-safe innerhalb dieses Blocks
                INTERBUS_DIR.mkdir(parents=True, exist_ok=True)
                _existing_cands: List[Dict[str, Any]] = []
                if _PEER_CAND_PATH.is_file():
                    try:
                        _existing_cands = json.loads(
                            _PEER_CAND_PATH.read_text(encoding="utf-8")
                        )
                        if not isinstance(_existing_cands, list):
                            _existing_cands = []
                    except Exception:
                        _existing_cands = []
                # Bestehende Fingerprints dieses Peers überschreiben (neueste Daten)
                _sender_pubkey = str(msg.get("peer_id", incoming_node_id or ""))
                _filtered = [c for c in _existing_cands
                             if c.get("remote_node_pubkey") != _sender_pubkey]
                for _cand in _phi_cands:
                    if isinstance(_cand, dict) and isinstance(_cand.get("phi"), list):
                        _cand["remote_node_pubkey"] = _sender_pubkey
                        _filtered.append(_cand)
                # Maximal 500 Kandidaten halten (neueste behalten)
                _filtered = _filtered[-500:]
                _PEER_CAND_PATH.write_text(
                    json.dumps(_filtered, ensure_ascii=True, indent=2),
                    encoding="utf-8",
                )
                logger.debug(f"[P2P] {len(_phi_cands)} Φ-Kandidaten von "
                             f"{_sender_pubkey[:16]}... gespeichert")
            except Exception as _ce:
                logger.debug(f"[swarm_p2p] phi_candidates recv: {_ce}")

    def get_received_fingerprints(self, limit: int = 100) -> List[str]:
        """Return all unique fingerprints received from peers."""
        seen: set[str] = set()
        result: List[str] = []
        with self._received_lock:
            for msg in reversed(self._received_gossip):
                for fp in msg.get("fingerprints", []):
                    if fp not in seen:
                        seen.add(fp)
                        result.append(fp)
                        if len(result) >= limit:
                            return result
        return result

    def aggregate_network_metrics(self) -> Dict[str, Any]:
        """Aggregiert Netz-Mediane aus empfangenen Gossip-Metriken aller Peers.

        Sicherheit: Pro node_id wird nur das NEUESTE Gossip-Paket verwendet.
        Ein einzelner Knoten kann den Median nicht durch Flooding dominieren.

        Gibt nur Felder zurück die in mindestens einem Gossip-Paket vorhanden sind.
        Leere oder ungültige Werte werden ignoriert — keine Vorhersagen, keine Imputationen.
        Enthält 'peer_count' = Anzahl eindeutiger Peers die eingeflossen sind.
        """
        keys_float = ["delta_ratio", "entropy", "shannon_gap_pct",
                      "anchor_coverage", "bits_per_joule", "bpj_slope",
                      "h_lambda", "trust_score"]

        # ── Nur neuestes Paket pro node_id verwenden (Flooding-Schutz) ────────
        latest_per_peer: Dict[str, Dict] = {}
        with self._received_lock:
            for msg in self._received_gossip:
                nid = msg.get("node_id")
                if not nid or not isinstance(nid, str):
                    continue
                # _received_gossip ist chronologisch → spätere Einträge überschreiben frühere
                summary = msg.get("metrics_summary")
                if isinstance(summary, dict):
                    latest_per_peer[nid] = summary

        buckets: Dict[str, List[float]] = {k: [] for k in keys_float}
        for summary in latest_per_peer.values():
            for key in keys_float:
                raw = summary.get(key)
                if raw is None:
                    continue
                try:
                    v = float(raw)
                    if not (v != v):  # NaN guard
                        buckets[key].append(v)
                except (TypeError, ValueError):
                    continue

        peer_count = len(latest_per_peer)
        result: Dict[str, Any] = {"peer_count": peer_count}
        for key, values in buckets.items():
            if not values:
                continue
            sorted_v = sorted(values)
            n = len(sorted_v)
            mid = n // 2
            # Median (robuster als Mittelwert gegen Ausreißer)
            median = sorted_v[mid] if n % 2 else (sorted_v[mid - 1] + sorted_v[mid]) / 2.0
            result[key] = round(median, 6)
        return result

    def get_swarm_capability_gaps(self) -> Dict[str, Any]:
        """Gibt einen Schwarm-weiten Blind-Spot-Bericht zurück.

        Zeigt welche Capabilities im Netz fehlverbreitet sind:
        - "missing_counts": wie viele Peers haben welche Probe NICHT?
        - "have_counts": wie viele Peers haben welche Probe?
        - "peers_by_stage": wie viele Peers sind in welcher Tier-Stufe?
        - "avg_score_pct": Durchschnitt des Capability-Scores im Netz
        - "total_peers_reporting": wie viele Peers haben Capability-Daten geschickt

        Diese Information kann z.B. im GUI angezeigt werden: "3 von 7 Peers
        brauchen noch Yggdrasil — 2 brauchen noch NumPy".
        """
        with self._received_lock:
            caps_snapshot = dict(self._peer_capabilities)

        total = len(caps_snapshot)
        if total == 0:
            return {"total_peers_reporting": 0}

        missing_counts: Dict[str, int] = {}
        have_counts: Dict[str, int] = {}
        stage_counts: Dict[str, int] = {}
        score_sum = 0
        score_n = 0

        for node_id, caps in caps_snapshot.items():
            for probe in caps.get("missing", []):
                missing_counts[probe] = missing_counts.get(probe, 0) + 1
            for probe in caps.get("have", []):
                have_counts[probe] = have_counts.get(probe, 0) + 1
            stage = str(caps.get("stage", "Unbekannt"))
            stage_counts[stage] = stage_counts.get(stage, 0) + 1
            pct = caps.get("score_pct")
            if isinstance(pct, (int, float)):
                score_sum += float(pct)
                score_n += 1

        # Sortiert nach Häufigkeit des Fehlens — die dringendste Lücke zuerst
        top_missing = sorted(missing_counts.items(), key=lambda x: -x[1])

        return {
            "total_peers_reporting": total,
            "missing_counts": dict(top_missing),
            "have_counts": have_counts,
            "peers_by_stage": stage_counts,
            "avg_score_pct": round(score_sum / score_n, 1) if score_n else 0,
        }

    def status(self) -> Dict[str, Any]:
        hw = _read_hw_capability()
        cap = _read_capability_score()
        scope = _effective_swarm_scope(hw, cap)
        return {
            "enabled": self.enabled,
            "peer_id": self._peer_id,
            "is_leader": self.is_leader(),
            "leader": self.current_leader(),
            "peer_count": self._leader_election.peer_count(),
            "received_gossip_count": len(self._received_gossip),
            "discovered_peer_count": len(self._discovered_peer_addrs),
            "discovered_relay_count": len(self._discovered_relay_addrs),
            "native_network_tier": scope.get("native_network_tier", "LocalOnly"),
            "effective_network_tier": scope.get("effective_network_tier", "LocalOnly"),
            "network_end_goal": scope.get("network_end_goal", "YggdrasilP2P"),
            "overlay_path": scope.get("overlay_path", "native-yggdrasil"),
            "relay_bridge_required": scope.get("relay_bridge_required", False),
            "symbiont_role": scope.get("symbiont_role", "overlay-peer"),
            "emergent_network_role": scope.get("emergent_network_role", "visibility-staging"),
            "progression_mode": scope.get("progression_mode", "vault-first"),
        }

    def discover_from_nodes_dir(self, nodes_dir: str = "data/swarm/nodes") -> List[str]:
        """Liest alle node.json und gibt Relay-Nodes zuerst zurueck.

        Der in DEFAULT_P2P konfigurierte genesis_yggdrasil_addr wird immer als
        erstes Relay zurueck gegeben (falls er nicht die eigene Adresse ist).
        """
        path = Path(nodes_dir)
        if not path.is_absolute():
            path = ROOT / path

        own_node_id = str(self._node_id or "")
        try:
            if LOCAL_NODE_JSON_PATH.is_file():
                local_payload = json.loads(LOCAL_NODE_JSON_PATH.read_text(encoding="utf-8"))
                if isinstance(local_payload, dict):
                    own_node_id = str(local_payload.get("node_id", own_node_id) or own_node_id)
        except Exception as e:
            logger.warning(f"[swarm_p2p] Stiller Fehler: {e}")
            pass

        relay_addrs: List[str] = []
        peer_addrs: List[str] = []
        seen: set[str] = set()

        # --- Builtin genesis seed: always try first unless it's ourselves ---
        own_ygg = ""
        try:
            if LOCAL_NODE_JSON_PATH.is_file():
                _lp = json.loads(LOCAL_NODE_JSON_PATH.read_text(encoding="utf-8"))
                own_ygg = str(_lp.get("yggdrasil_addr", "") or "")
        except Exception as e:
            logger.warning(f"[swarm_p2p] Stiller Fehler: {e}")
            pass
        genesis_seed = str(self._config.get("genesis_yggdrasil_addr", "") or "").strip()
        # Auf dem Genesis-Node selbst: Adresse aus Key ableiten wenn nicht konfiguriert
        if not genesis_seed:
            genesis_seed = _get_genesis_ygg_addr()
        if genesis_seed and genesis_seed != own_ygg:
            seen.add(genesis_seed)
            relay_addrs.append(genesis_seed)

        if not path.is_dir():
            self._discovered_relay_addrs = list(relay_addrs)
            return relay_addrs + peer_addrs
        for node_path in sorted(path.glob("*.json")):
            try:
                payload = json.loads(node_path.read_text(encoding="utf-8"))
            except Exception as e:
                continue
            if not isinstance(payload, dict):
                continue
            node_id = str(payload.get("node_id", "") or "")
            if own_node_id and node_id == own_node_id:
                continue
            address = payload.get("yggdrasil_addr")
            if address is None:
                continue
            address_str = str(address).strip()
            if not address_str or address_str in seen:
                continue
            seen.add(address_str)
            if bool(payload.get("relay", False)):
                relay_addrs.append(address_str)
            else:
                peer_addrs.append(address_str)

        self._discovered_relay_addrs = list(relay_addrs)
        return relay_addrs + peer_addrs

    def _bootstrap_known_peers(self, addresses: List[str]) -> None:
        """Connect to peers. Retries unconfirmed peers every peer_retry_interval_seconds."""
        if not addresses or self._transport is None:
            return
        now = time.monotonic()
        retry_interval = float(self._config.get("peer_retry_interval_seconds", 300.0))
        active_peer_ids = set(self._leader_election._known_peers.keys())
        has_active_peers = bool(active_peer_ids)

        to_try: List[str] = []
        for address in addresses:
            last_attempt = self._bootstrapped_peer_addrs.get(address, -1.0)
            if last_attempt < 0:
                # Never tried
                to_try.append(address)
            elif not has_active_peers and now - last_attempt >= retry_interval:
                # No confirmed peers yet — keep retrying every retry_interval
                to_try.append(address)

        if not to_try:
            return
        try:
            bootstrap = getattr(self._transport, "bootstrap_peers", None)
            if callable(bootstrap):
                bootstrap(list(to_try))
                for address in to_try:
                    self._bootstrapped_peer_addrs[address] = now
                return
            connect_peers = getattr(self._transport, "connect_peers", None)
            if callable(connect_peers):
                connect_peers(list(to_try))
                for address in to_try:
                    self._bootstrapped_peer_addrs[address] = now
                return
            connect_peer = getattr(self._transport, "connect_peer", None)
            if callable(connect_peer):
                for address in to_try:
                    connect_peer(address)
                    self._bootstrapped_peer_addrs[address] = now
        except Exception as err:
            print(f"[P2P] discovery bootstrap failed: {err}")

    def _refresh_discovery(self) -> None:
        discovery_dir = str(self._config.get("discovery_nodes_dir", "data/swarm/nodes") or "data/swarm/nodes")
        discovered = self.discover_from_nodes_dir(discovery_dir)
        if discovered:
            self._discovered_peer_addrs = list(discovered)
            self._bootstrap_known_peers(discovered)

    def _ensure_yggdrasil_runtime(self, hw: Optional[Dict[str, Any]] = None) -> None:
        if not bool(self._config.get("auto_manage_yggdrasil", True)):
            return
        # Hardware-Gate: Yggdrasil nur starten wenn Hardware es unterstützt
        if hw is None:
            hw = _read_hw_capability()
        if not hw.get("yggdrasil", False):
            logger.info(
                f"[swarm_p2p] Yggdrasil übersprungen: "
                f"Tier {hw.get('network_tier', '?')} unterstützt kein Yggdrasil-P2P."
            )
            return
        from modules.yggdrasil_install import (
            is_yggdrasil_managed_running as _ygg_running,
            start_yggdrasil_subprocess as _ygg_start,
        )
        if _ygg_running():
            self._started_yggdrasil = False
            return
        config_path = str(self._config.get("yggdrasil_config_path", "data/yggdrasil.conf") or "data/yggdrasil.conf")
        _ygg_start(config_path=config_path)
        self._started_yggdrasil = True

    def _gossip_loop(self) -> None:
        interval = float(self._config.get("gossip_interval_seconds", 30.0))
        # Offline-Learner beim Start des Loops hochfahren
        try:
            from modules.offline_learning import OfflineLearner as _OL
            _OL.instance().start_background_loop()
        except Exception:
            pass
        while not self._stop_event.is_set():
            try:
                self._do_gossip()
            except Exception as err:
                print(f"[P2P] gossip error: {err}")
            self._stop_event.wait(timeout=interval)

    def _do_gossip(self) -> None:
        """Collect recent fingerprints from DB and publish."""
        self._refresh_discovery()
        try:
            from modules.swarm_persist import get_fingerprint_stats, _connect, DEFAULT_DB_PATH, _db_lock
            with _db_lock:
                conn = _connect(DEFAULT_DB_PATH)
                try:
                    rows = conn.execute(
                        "SELECT fingerprint FROM fingerprints ORDER BY last_seen_ts DESC LIMIT ?",
                        (DEFAULT_P2P["max_fingerprints_per_gossip"],)
                    ).fetchall()
                finally:
                    conn.close()
            fps = [r[0] for r in rows]
            stats = get_fingerprint_stats()
            # Pipeline-Metriken einbetten (delta_ratio, h_lambda etc.)
            with _pipeline_metrics_lock:
                stats.update(_PIPELINE_METRICS)
            self.publish_fingerprints(
                fps,
                metrics_summary=stats,
                node_capabilities=_collect_node_capabilities(),
            )
            # Netz-Mediane aggregieren und für Observer-Engine bereitstellen
            net = self.aggregate_network_metrics()
            if net.get("peer_count", 0) > 0:
                with _pipeline_metrics_lock:
                    _LAST_NETWORK_METRICS.clear()
                    _LAST_NETWORK_METRICS.update(net)
            # Offline-Learner: Gossip war erfolgreich
            try:
                from modules.offline_learning import OfflineLearner as _OL
                _OL.instance().on_gossip_success()
            except Exception:
                pass
        except Exception as err:
            print(f"[P2P] _do_gossip error: {err}")
            # Offline-Learner: Gossip ist fehlgeschlagen
            try:
                from modules.offline_learning import OfflineLearner as _OL
                _OL.instance().on_gossip_failure()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
#  Factory                                                                    #
# --------------------------------------------------------------------------- #

def make_p2p_layer(
    node_id: str,
    aethernet_transport: Any = None,
) -> P2PLayer:
    """Create P2PLayer from settings.json config."""
    try:
        if SETTINGS_PATH.is_file():
            raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            config = raw.get("swarm_p2p", {})
        else:
            config = {}
    except Exception as e:
        config = {}
    return P2PLayer(node_id=node_id, aethernet_transport=aethernet_transport, config=config)
