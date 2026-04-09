from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""device_lock.py — Hardware-Bindung und Ein-Account-pro-Geraet-Durchsetzung.

Sicherheitsgarantien:
  1. Ein Konto pro Geraet: Jede Aether-Installation erzeugt EINEN privaten
     Schlussel, der durch den Hardware-Fingerprint gebunden ist.
     Wird der private Schluessel auf ein anderes Geraet kopiert, scheitert
     der Fingerprint-Vergleich beim naechsten Start und Aether verweigert
     den Betrieb.

  2. Ein Konto pro Netzwerk: Die Swarm-Schicht lehnt es ab, dasselbe
     node_id von ZWEI verschiedenen device_fingerprints zu akzeptieren.
     Genauso: Ein device_fingerprint darf nur EINE node_id registrieren.

  3. Datenschutz: Der Hardware-Fingerprint ist ein SHA-256-Hash aus stabilen,
     nicht-biometrischen System-IDs. Rohdaten (Seriennummern etc.) verlassen
     das Geraet nie. Der Hash ist lokal gespeichert und nicht umkehrbar.

Durchsetzungspunkte:
  - session_guard.require_session() prueft device_lock.verify_binding()
  - swarm_p2p.SwarmP2P.*_peer() prueft device_lock.peer_allowed()
  - device_fingerprint wird in node.json publiziert (fuer Swarm-Pruefung)
"""

import hashlib
import hmac
import json
import platform
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
_DEVICE_LOCK_PATH = ROOT / "data" / "device_lock.json"
_SETTINGS_PATH = ROOT / "data" / "settings.json"
_SWARM_LOCK_PATH = ROOT / "data" / "swarm" / "device_registry.json"

_FINGERPRINT_SALT = b"aether/v1/device-lock/fingerprint"
_SCHEMA = "aether.device_lock.v1"


# ---------------------------------------------------------------------------
# Hardware-Fingerprint (privacy-preserving, non-invertible)
# ---------------------------------------------------------------------------

def _windows_machine_guid() -> str:
    """Liest die MachineGuid aus der Windows-Registry (stabil ueber Reboots)."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        )
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return str(guid).strip()
    except Exception:
        return ""


def _linux_machine_id() -> str:
    """Liest /etc/machine-id oder /var/lib/dbus/machine-id (stabil)."""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except Exception:
            continue
    return ""


def _macos_hw_uuid() -> str:
    """Liest die Hardware-UUID via ioreg (stabil auf macOS)."""
    try:
        import subprocess
        out = subprocess.check_output(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            timeout=3,
            text=True,
            stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            if "IOPlatformUUID" in line:
                parts = line.split('"')
                if len(parts) >= 4:
                    return parts[-2].strip()
    except Exception:
        pass
    return ""


def _collect_hardware_components() -> list[str]:
    """Sammelt stabile, nicht-biometrische Hardware-Identifikatoren."""
    components: list[str] = []

    system = platform.system().lower()
    if system.startswith("win"):
        guid = _windows_machine_guid()
        if guid:
            components.append(f"win-guid:{guid}")
    elif system.startswith("linux"):
        mid = _linux_machine_id()
        if mid:
            components.append(f"linux-mid:{mid}")
    elif system.startswith("darwin"):
        uuid = _macos_hw_uuid()
        if uuid:
            components.append(f"macos-uuid:{uuid}")

    # Fallback additions (less stable, but better than nothing)
    node = platform.node()
    if node:
        components.append(f"hostname:{node}")

    machine = platform.machine()
    if machine:
        components.append(f"arch:{machine}")

    # Python interpreter path as last resort (stable per installation)
    try:
        components.append(f"py:{Path(sys.executable).resolve()}")
    except Exception:
        pass

    return components


def compute_device_fingerprint() -> str:
    """Berechnet den Hardware-Fingerprint als SHA-256-Hex (64 Zeichen).

    Kombiniert stabile Hardware-IDs und hasht sie mit einem festen Salt.
    Nicht umkehrbar. Keine Rohdaten werden gespeichert oder uebertragen.
    """
    components = _collect_hardware_components()
    if not components:
        logger.warning("[device_lock] Keine Hardware-Komponenten gefunden — Fallback auf leeres Set.")
    raw = "|".join(sorted(components)).encode("utf-8")
    digest = hmac.new(_FINGERPRINT_SALT, raw, hashlib.sha256).digest()
    return hashlib.sha256(digest).hexdigest()


# ---------------------------------------------------------------------------
# Binding verwalten
# ---------------------------------------------------------------------------

def initialize_binding(node_id: str) -> str:
    """Erstellt und speichert die Device-Binding beim ersten Start.

    Wird einmalig waehrend des Bootstraps aufgerufen.
    Wirft ValueError wenn bereits eine Binding fuer einen ANDEREN node_id existiert.
    Gibt den device_fingerprint zurueck.
    """
    fingerprint = compute_device_fingerprint()
    if _DEVICE_LOCK_PATH.is_file():
        try:
            existing = json.loads(_DEVICE_LOCK_PATH.read_text(encoding="utf-8"))
            existing_node = str(existing.get("node_id", "")).strip()
            existing_fp = str(existing.get("device_fingerprint", "")).strip()
            if existing_node and not hmac.compare_digest(existing_node, str(node_id).strip()):
                raise ValueError(
                    f"[device_lock] Geraet bereits mit node '{existing_node[:16]}...' gebunden. "
                    f"Zweites Konto auf diesem Geraet ist nicht erlaubt."
                )
            if existing_fp and not hmac.compare_digest(existing_fp, fingerprint):
                # Fingerprint changed — might be a hardware change, warn but allow
                logger.warning("[device_lock] Hardware-Fingerprint hat sich geaendert. Binding wird erneuert.")
        except (json.JSONDecodeError, KeyError):
            pass  # Corrupt file — overwrite

    lock_data = {
        "schema": _SCHEMA,
        "node_id": str(node_id).strip(),
        "device_fingerprint": fingerprint,
    }
    _DEVICE_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    _DEVICE_LOCK_PATH.write_text(
        json.dumps(lock_data, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    logger.info(f"[device_lock] Binding erstellt: node={node_id[:16]}..., fp={fingerprint[:16]}...")
    return fingerprint


def verify_binding(node_id: str) -> None:
    """Prueft ob node_id und Hardware-Fingerprint zur gespeicherten Binding passen.

    Wirft DeviceLockError bei Verletzung (Key kopiert, zweites Konto etc.).
    Wird bei jedem Start aufgerufen.
    """
    fingerprint = compute_device_fingerprint()

    if not _DEVICE_LOCK_PATH.is_file():
        # No binding yet — create it (first run after update/migration)
        initialize_binding(node_id)
        return

    try:
        stored = json.loads(_DEVICE_LOCK_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        raise DeviceLockError(
            "device_lock.json nicht lesbar. Neuinstallation erforderlich."
        ) from e

    stored_node = str(stored.get("node_id", "")).strip()
    stored_fp = str(stored.get("device_fingerprint", "")).strip()

    # 1. Selbe node_id?
    if stored_node and not hmac.compare_digest(stored_node, str(node_id).strip()):
        raise DeviceLockError(
            f"Konto-Konflikt: Dieses Geraet ist an node '{stored_node[:16]}...' gebunden. "
            f"Zweites Konto ist nicht erlaubt."
        )

    # 2. Gleicher Hardware-Fingerprint?
    if stored_fp and not hmac.compare_digest(stored_fp, fingerprint):
        raise DeviceLockError(
            "Hardware-Fingerprint stimmt nicht ueberein. "
            "Dieser private Schluessel gehoert zu einem anderen Geraet. "
            "Uebertragung von Konten zwischen Geraeten ist nicht erlaubt."
        )


class DeviceLockError(Exception):
    """Wird ausgeloest wenn die Device-Binding verletzt wird."""
    pass


# ---------------------------------------------------------------------------
# Swarm-Level: Peer-Pruefung (1 node_id pro device_fingerprint)
# ---------------------------------------------------------------------------

def _normalize_swarm_identity_entries(raw_entries: object) -> dict[str, dict[str, str]]:
    normalized: dict[str, dict[str, str]] = {}
    if not isinstance(raw_entries, dict):
        return normalized
    for raw_node_id, raw_entry in raw_entries.items():
        node_id = str(raw_node_id or "").strip()
        if not node_id:
            continue
        if isinstance(raw_entry, str):
            normalized[node_id] = {
                "device_fingerprint": str(raw_entry or "").strip(),
                "account_username": "",
                "yggdrasil_addr": "",
                "network_entry_id": "",
                "identity_lock": "",
            }
            continue
        if isinstance(raw_entry, dict):
            normalized[node_id] = {
                "device_fingerprint": str(raw_entry.get("device_fingerprint", "") or "").strip(),
                "account_username": str(raw_entry.get("account_username", "") or "").strip(),
                "yggdrasil_addr": str(raw_entry.get("yggdrasil_addr", "") or "").strip(),
                "network_entry_id": str(raw_entry.get("network_entry_id", "") or "").strip(),
                "identity_lock": str(raw_entry.get("identity_lock", "") or "").strip(),
            }
    return normalized


def _load_swarm_device_registry() -> dict[str, dict[str, str]]:
    """Laedt die Swarm-weite Node-Identity-Registry."""
    if not _SWARM_LOCK_PATH.is_file():
        return {}
    try:
        data = json.loads(_SWARM_LOCK_PATH.read_text(encoding="utf-8"))
        return _normalize_swarm_identity_entries(data.get("entries", {}))
    except Exception:
        return {}


def _save_swarm_device_registry(entries: dict[str, dict[str, str]]) -> None:
    _SWARM_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    _SWARM_LOCK_PATH.write_text(
        json.dumps({"schema": _SCHEMA + ".swarm", "entries": entries}, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def peer_allowed(node_id: str, device_fingerprint: str) -> bool:
    """Prueft ob ein Peer im Swarm zugelassen werden darf.

    Ablehnungsgruende:
    - Selbe device_fingerprint mit anderem node_id (zweites Konto auf einem Geraet)
    - Selbe node_id von anderer device_fingerprint (Key-Kopie auf anderes Geraet)

    Gibt True zurueck und registriert den Peer wenn er zugelassen ist.
    Gibt False zurueck bei Verletzung (Peer wird abgelehnt).
    """
    node_id = str(node_id or "").strip()
    device_fingerprint = str(device_fingerprint or "").strip()
    if not node_id or not device_fingerprint:
        return True  # Unbekannte Peers (ohne fingerprint) passieren — alte Clients

    registry = _load_swarm_device_registry()

    # Check 1: Ist die node_id schon von einem ANDEREN Device gesehen worden?
    existing_entry = registry.get(node_id, {})
    existing_fp = str(existing_entry.get("device_fingerprint", "") or "").strip()
    if existing_fp and not hmac.compare_digest(existing_fp, device_fingerprint):
        logger.warning(
            f"[device_lock] ABGELEHNT: node_id={node_id[:16]}... taucht von zweitem Geraet auf "
            f"(fp_neu={device_fingerprint[:16]}..., fp_alt={existing_fp[:16]}...)"
        )
        return False

    # Check 2: Hat dieses Device bereits eine ANDERE node_id registriert?
    for registered_node, registered_entry in registry.items():
        registered_fp = str(registered_entry.get("device_fingerprint", "") or "").strip()
        if not registered_fp:
            continue
        if hmac.compare_digest(registered_fp, device_fingerprint):
            if not hmac.compare_digest(registered_node, node_id):
                logger.warning(
                    f"[device_lock] ABGELEHNT: device_fingerprint={device_fingerprint[:16]}... "
                    f"versucht zweiten Account (neu={node_id[:16]}..., alt={registered_node[:16]}...)"
                )
                return False

    # Alles ok — registrieren
    if node_id not in registry or not str(registry[node_id].get("device_fingerprint", "") or "").strip():
        entry = dict(registry.get(node_id, {}))
        entry["device_fingerprint"] = device_fingerprint
        entry.setdefault("account_username", "")
        entry.setdefault("yggdrasil_addr", "")
        entry.setdefault("network_entry_id", "")
        entry.setdefault("identity_lock", "")
        registry[node_id] = entry
        _save_swarm_device_registry(registry)

    return True


def peer_account_allowed(
    node_id: str,
    device_fingerprint: str,
    account_username: str = "",
    yggdrasil_addr: str = "",
    identity_lock: str = "",
    network_entry_id: str = "",
) -> bool:
    """Erweitert peer_allowed um Username-, Ygg-/Hardware- und DHT-Entry-Lock-Konsistenz.

    network_entry_id ist der DHT-Peer-ID des Knotens (Fallback wenn kein Yg-Addr).
    Beide Felder koennen alternativ als Netzwerk-Einstiegs-Identitaet dienen.
    """
    node_id = str(node_id or "").strip()
    device_fingerprint = str(device_fingerprint or "").strip()
    account_username = str(account_username or "").strip()
    yggdrasil_addr = str(yggdrasil_addr or "").strip()
    identity_lock = str(identity_lock or "").strip()
    network_entry_id = str(network_entry_id or "").strip()

    if not peer_allowed(node_id, device_fingerprint):
        return False

    if not node_id:
        return True

    registry = _load_swarm_device_registry()
    entry = dict(registry.get(node_id, {}))
    existing_username = str(entry.get("account_username", "") or "").strip()
    existing_ygg = str(entry.get("yggdrasil_addr", "") or "").strip()
    existing_lock = str(entry.get("identity_lock", "") or "").strip()
    existing_network_entry_id = str(entry.get("network_entry_id", "") or "").strip()

    if existing_username and account_username and existing_username.lower() != account_username.lower():
        logger.warning(
            f"[device_lock] ABGELEHNT: node_id={node_id[:16]}... versucht zweiten Usernamen "
            f"(neu={account_username}, alt={existing_username})"
        )
        return False

    if existing_ygg and yggdrasil_addr and existing_ygg.lower() != yggdrasil_addr.lower():
        logger.warning(
            f"[device_lock] ABGELEHNT: node_id={node_id[:16]}... meldet andere Yggdrasil-Adresse "
            f"(neu={yggdrasil_addr}, alt={existing_ygg})"
        )
        return False

    if existing_network_entry_id and network_entry_id and existing_network_entry_id.lower() != network_entry_id.lower():
        logger.warning(
            f"[device_lock] ABGELEHNT: node_id={node_id[:16]}... meldet andere AetherNet-DHT-Peer-ID "
            f"(neu={network_entry_id[:16]}, alt={existing_network_entry_id[:16]})"
        )
        return False

    if existing_lock and identity_lock and existing_lock != identity_lock:
        logger.warning(
            f"[device_lock] ABGELEHNT: node_id={node_id[:16]}... meldet anderen Identity-Lock"
        )
        return False

    if account_username:
        for registered_node, registered_entry in registry.items():
            if registered_node == node_id:
                continue
            registered_username = str(registered_entry.get("account_username", "") or "").strip()
            if not registered_username or registered_username.lower() != account_username.lower():
                continue
            registered_fp = str(registered_entry.get("device_fingerprint", "") or "").strip()
            registered_ygg = str(registered_entry.get("yggdrasil_addr", "") or "").strip()
            registered_lock = str(registered_entry.get("identity_lock", "") or "").strip()
            registered_network_entry_id = str(registered_entry.get("network_entry_id", "") or "").strip()
            if registered_fp and device_fingerprint and registered_fp != device_fingerprint:
                logger.warning(
                    f"[device_lock] ABGELEHNT: Username '{account_username}' ist bereits an eine andere Hardware gebunden."
                )
                return False
            if registered_ygg and yggdrasil_addr and registered_ygg.lower() != yggdrasil_addr.lower():
                logger.warning(
                    f"[device_lock] ABGELEHNT: Username '{account_username}' ist bereits an eine andere Yggdrasil-Identitaet gebunden."
                )
                return False
            if registered_network_entry_id and network_entry_id and registered_network_entry_id.lower() != network_entry_id.lower():
                logger.warning(
                    f"[device_lock] ABGELEHNT: Username '{account_username}' ist bereits an eine andere AetherNet-DHT-Peer-ID gebunden."
                )
                return False
            if registered_lock and identity_lock and registered_lock != identity_lock:
                logger.warning(
                    f"[device_lock] ABGELEHNT: Username '{account_username}' ist bereits an einen anderen Identity-Lock gebunden."
                )
                return False
            if registered_node != node_id:
                logger.warning(
                    f"[device_lock] ABGELEHNT: Username '{account_username}' ist bereits an node '{registered_node[:16]}...' gebunden."
                )
                return False

    if account_username:
        entry["account_username"] = account_username
    if yggdrasil_addr:
        entry["yggdrasil_addr"] = yggdrasil_addr
    if network_entry_id:
        entry["network_entry_id"] = network_entry_id
    if identity_lock:
        entry["identity_lock"] = identity_lock
    entry["device_fingerprint"] = device_fingerprint
    registry[node_id] = entry
    _save_swarm_device_registry(registry)
    return True


def get_local_fingerprint() -> Optional[str]:
    """Gibt den gespeicherten lokalen Device-Fingerprint zurueck (oder None)."""
    if not _DEVICE_LOCK_PATH.is_file():
        return None
    try:
        data = json.loads(_DEVICE_LOCK_PATH.read_text(encoding="utf-8"))
        return str(data.get("device_fingerprint", "") or "").strip() or None
    except Exception:
        return None
