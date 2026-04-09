from __future__ import annotations

import logging
logger = logging.getLogger(__name__)
"""capability_score.py — Aether OS Readiness / Emergent OS Progress.

Probes every subsystem at startup (or on demand) and assigns a score 0–100.
The score fills a progress bar in the Aether UI — when it reaches 100 % the
full Aether OS mode is unlocked.

Each probe is guarded by a broad try/except so a failing probe never crashes
the host process.  The result is written to::

    data/interbus/capability_score.json

The Rust shell (iced_shell.rs) reads that file every tick and shows the value
as a progress bar in the Home tab.

Architecture tiers (based on accumulated score):
  0 – 24 %   Basis-Daemon    — gossip + LAN-beacon only, no GUI needed
  25 – 49 %  Minimal Node    — swarm + local analysis, no heavy deps
  50 – 74 %  Standard        — full Python backend operational
  75 – 99 %  Aether OS       — Rust GUI + all subsystems loaded
  100 %      Aether OS [Aktiv] — all probes green, vault + peers confirmed
"""

import importlib.util
import json
import os
import platform
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Constants ────────────────────────────────────────────────────────────────

SCORE_PATH = Path("data") / "interbus" / "capability_score.json"
STARTUP_ROUTE_PATH = Path("data") / "interbus" / "startup_route.json"
HW_CAPABILITY_PATH = Path("data") / "interbus" / "hw_capability.json"

STAGES = [
    (0,   "Basis-Daemon"),
    (25,  "Minimal Node"),
    (50,  "Standard"),
    (75,  "Aether OS"),
    (100, "Aether OS [Aktiv]"),
]

# Contribution-Stufen — wachsen unbegrenzt über 100% hinaus.
# contribution_index = (abgeschlossene Tasks) + (geteilte AlgoTokens × 2) + (Vorhersage-Obs. / 100)
CONTRIBUTION_STAGES = [
    (0,    "Aether OS [Aktiv]"),
    (10,   "Netz-Beitragender"),
    (50,   "Symbiont [Aktiv]"),
    (200,  "Katalysator [Aktiv]"),
    (1000, "Netz-Architekt [Aktiv]"),
]


# ── Probe result ────────────────────────────────────────────────────────────

@dataclass
class Probe:
    key: str
    label: str
    weight: int  # max points this probe can contribute
    earned: int = 0
    ok: bool = False
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "weight": self.weight,
            "earned": self.earned,
            "note": self.note,
        }


def _load_startup_route() -> Dict[str, Any]:
    try:
        if not STARTUP_ROUTE_PATH.exists():
            return {}
        payload = json.loads(STARTUP_ROUTE_PATH.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _load_hw_capability() -> Dict[str, Any]:
    try:
        if not HW_CAPABILITY_PATH.exists():
            return {}
        payload = json.loads(HW_CAPABILITY_PATH.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _network_emergence_metadata(
    startup_route: Dict[str, Any],
    hw_capability: Dict[str, Any],
    base_mode: str,
    shell_ready: bool,
    overlay_ready: bool,
    full_member_ready: bool,
) -> Dict[str, Any]:
    startup_mode = str(startup_route.get("mode", "full") or "full")
    native_rank = max(0, min(4, int(hw_capability.get("native_tier_rank", hw_capability.get("tier_rank", 0)) or 0)))
    native_label = str(hw_capability.get("native_network_tier", hw_capability.get("network_tier", "LocalOnly")) or "LocalOnly")

    if native_rank >= 4:
        network_end_goal = "FullDht"
        overlay_path = "native-yggdrasil-dht"
        relay_bridge_required = False
        symbiont_role = "dht-seed"
    elif native_rank >= 3:
        network_end_goal = "YggdrasilP2P"
        overlay_path = "native-yggdrasil"
        relay_bridge_required = False
        symbiont_role = "overlay-peer"
    elif startup_mode == "ultra_legacy":
        network_end_goal = "RelayBridgeToAethernet"
        overlay_path = "ultra-legacy-bootstrap"
        relay_bridge_required = True
        symbiont_role = "local-symbiont"
    elif native_rank >= 1:
        network_end_goal = "RelayBridgeToAethernet"
        overlay_path = "relay-bridge"
        relay_bridge_required = True
        symbiont_role = "relay-compatible-symbiont"
    else:
        network_end_goal = "AethernetCompatibility"
        overlay_path = "local-bootstrap"
        relay_bridge_required = True
        symbiont_role = "local-symbiont"

    emergent_network_role = "local-bootstrap"
    if full_member_ready:
        if network_end_goal == "FullDht":
            emergent_network_role = "full-dht-candidate"
        elif overlay_path.startswith("native-yggdrasil"):
            emergent_network_role = "overlay-full-member"
        else:
            emergent_network_role = "relay-full-member"
    elif overlay_ready or overlay_path.startswith("native-yggdrasil"):
        emergent_network_role = "overlay-candidate"
    elif base_mode in {"lan-p2p-ready", "shell-ready"}:
        emergent_network_role = "relay-bridge-candidate" if relay_bridge_required else "lan-to-overlay-candidate"
    elif base_mode == "lan-beacon-ready":
        emergent_network_role = "visibility-staging"

    aethernet_goal_message = "LAN ist nur Zwischenstufe; Ziel ist echte Aufnahme ins P2P-Aethernet."
    if network_end_goal == "FullDht":
        aethernet_goal_message = "Ziel ist FullDht: Yggdrasil-Overlay plus emergente DHT-Rolle, sobald genug Mitglieder und Reichweite vorhanden sind."
    elif network_end_goal == "YggdrasilP2P":
        aethernet_goal_message = "Ziel ist YggdrasilP2P: LAN dient nur als Vorstufe, danach traegt der Knoten nativ im Overlay-Aethernet."
    elif relay_bridge_required:
        aethernet_goal_message = "LAN ist nicht das Endziel; der Knoten bleibt symbiotisch Aethernet-kompatibel und wird ueber Relay-/Overlay-Bruecken ins groessere Netz eingebunden."

    return {
        "native_network_tier": native_label,
        "native_tier_rank": native_rank,
        "network_end_goal": network_end_goal,
        "overlay_path": overlay_path,
        "relay_bridge_required": relay_bridge_required,
        "symbiont_role": symbiont_role,
        "emergent_network_role": emergent_network_role,
        "aethernet_goal_message": aethernet_goal_message,
    }


# ── Individual probe functions ───────────────────────────────────────────────

def _probe_python_runtime() -> Probe:
    p = Probe("python_runtime", "Python Runtime", weight=5)
    try:
        major, minor = sys.version_info.major, sys.version_info.minor
        if major >= 3 and minor >= 8:
            p.ok = True
            p.earned = 5
            p.note = f"Python {major}.{minor}.{sys.version_info.micro}"
        elif major >= 3 and minor >= 6:
            # Works for daemon_headless.py — partial credit
            p.ok = True
            p.earned = 3
            p.note = f"Python {major}.{minor} (3.8+ empfohlen)"
        else:
            p.note = f"Python {major}.{minor} — zu alt für volles Aether"
    except Exception as exc:
        p.note = str(exc)
    return p


def _probe_rust_binary() -> Probe:
    """Volles Rust-Binary = 10 Pkt. Headless-Daemon als Ersatz = 5 Pkt.
    So bekommt auch ein alter PC, der keinen Rust-Build starten kann,
    wenigstens Teilpunkte statt null."""
    p = Probe("rust_binary", "Rust / Headless-Binary", weight=10)
    try:
        candidates = [
            Path("bin") / "aether-cli",
            Path("bin") / "aether-cli.exe",
            Path("target") / "release" / "aether-cli",
            Path("target") / "release" / "aether-cli.exe",
            Path("target") / "release" / "aether_iced",
            Path("target") / "release" / "aether_iced.exe",
        ]
        found = [c for c in candidates if c.exists()]
        if found:
            p.ok = True
            p.earned = 10
            p.note = str(found[0])
        elif Path("daemon_headless.py").exists():
            # Alter PC ohne Rust-Toolchain kann trotzdem teilnehmen
            p.ok = True
            p.earned = 5
            p.note = "daemon_headless.py vorhanden — Headless-Modus aktiv"
        else:
            p.note = "Kein Rust-Binary und kein Headless-Daemon gefunden"
    except Exception as exc:
        p.note = str(exc)
    return p


def _probe_gpu_display() -> Probe:
    p = Probe("gpu_display", "GPU / Display", weight=10)
    try:
        if sys.platform.startswith("win"):
            # On Windows, a display is always available unless running as a service
            import ctypes  # stdlib
            user32 = ctypes.windll.user32  # type: ignore[attr-defined]
            w = user32.GetSystemMetrics(0)
            if w > 0:
                p.ok = True
                p.earned = 10
                p.note = f"Windows display {w}px breit"
            else:
                p.earned = 5
                p.note = "Windows ohne Anzeige (Headless/Service)"
        elif sys.platform == "darwin":
            p.ok = True
            p.earned = 10
            p.note = "macOS — Display angenommen"
        else:
            # Linux: check DISPLAY or WAYLAND_DISPLAY
            display = os.environ.get("DISPLAY", "") or os.environ.get("WAYLAND_DISPLAY", "")
            if display:
                p.ok = True
                p.earned = 10
                p.note = f"Display: {display}"
            else:
                p.earned = 3
                p.note = "Kein DISPLAY/WAYLAND_DISPLAY — Headless-Modus"
    except Exception as exc:
        p.earned = 3
        p.note = f"Display-Erkennung fehlgeschlagen: {exc}"
    return p


def _probe_yggdrasil() -> Probe:
    p = Probe("yggdrasil", "Yggdrasil Overlay", weight=10)
    try:
        candidates = [
            Path("bin") / "yggdrasil",
            Path("bin") / "yggdrasil.exe",
            Path("/usr/bin/yggdrasil"),
            Path("/usr/local/bin/yggdrasil"),
        ]
        found = [c for c in candidates if c.exists()]
        if found:
            p.ok = True
            p.earned = 10
            p.note = str(found[0])
            return p

        # Check running process
        try:
            import psutil  # type: ignore
            names = {proc.name().lower() for proc in psutil.process_iter(["name"])}
            if "yggdrasil" in names or "yggdrasil.exe" in names:
                p.ok = True
                p.earned = 10
                p.note = "Yggdrasil läuft als Prozess"
                return p
        except Exception as e:
            logger.warning(f"[capability_score] Fehler: {e}")
            pass

        # Config exists means it was already set up
        if (Path("data") / "yggdrasil.conf").exists():
            p.earned = 5
            p.note = "yggdrasil.conf vorhanden, Binary fehlt noch"
        else:
            p.note = "Yggdrasil nicht installiert"
    except Exception as exc:
        p.note = str(exc)
    return p


def _probe_network() -> Probe:
    p = Probe("network", "Netzwerk (Genesis)", weight=5)
    try:
        import socket
        # Try connecting to genesis Yggdrasil address or a public DNS
        # Using a non-routable test target (port 80 on 1.1.1.1) with 1s timeout
        with socket.create_connection(("1.1.1.1", 80), timeout=1.5):
            p.ok = True
            p.earned = 5
            p.note = "Internet erreichbar"
    except OSError as e:
        # Try LAN fallback — even localhost reachable counts
        try:
            import socket as _s
            with _s.create_connection(("127.0.0.1", 80), timeout=0.3):
                p.earned = 3
                p.note = "Nur Localhost erreichbar"
        except OSError as e:
            p.note = "Kein Netzwerk erkannt"
    except Exception as exc:
        p.note = str(exc)
    return p


def _probe_module(key: str, label: str, import_name: str, weight: int) -> Probe:
    p = Probe(key, label, weight=weight)
    try:
        if importlib.util.find_spec(import_name) is not None:
            p.ok = True
            p.earned = weight
            p.note = "vorhanden"
        else:
            p.note = f"{import_name} nicht installiert"
    except Exception as exc:
        p.note = str(exc)
    return p


def _probe_swarm_consent() -> Probe:
    p = Probe("swarm_consent", "Swarm Opt-in", weight=5)
    try:
        consent_path = Path("data") / "swarm_consent.json"
        if consent_path.exists():
            data = json.loads(consent_path.read_text(encoding="utf-8"))
            if data.get("consented", False):
                p.ok = True
                p.earned = 5
                p.note = f"Zugestimmt von: {data.get('source', 'unbekannt')}"
            else:
                p.note = "Swarm-Teilnahme abgelehnt (opt-out)"
        else:
            p.note = "Keine Einwilligung vorhanden — Standard: opt-out"
    except Exception as exc:
        p.note = str(exc)
    return p


def _probe_vault() -> Probe:
    p = Probe("vault", "Lokaler Vault", weight=10)
    try:
        vault_path = Path("data") / "vault"
        if vault_path.is_dir():
            entries = list(vault_path.rglob("*"))
            count = sum(1 for e in entries if e.is_file())
            if count > 0:
                p.ok = True
                p.earned = 10
                p.note = f"{count} Vault-Einträge"
            else:
                p.earned = 5
                p.note = "Vault-Verzeichnis leer"
        else:
            p.note = "Vault noch nicht initialisiert"
    except Exception as exc:
        p.note = str(exc)
    return p


def _probe_peers() -> Probe:
    p = Probe("peers", "Swarm Peers bekannt", weight=5)
    try:
        nodes_path = Path("data") / "swarm" / "nodes"
        local_node_path = Path("data") / "swarm" / "node.json"
        paths = list(nodes_path.glob("*.json")) if nodes_path.is_dir() else []
        if local_node_path.is_file():
            paths.append(local_node_path)
        if paths:
            p.ok = True
            p.earned = 5
            p.note = f"{len(paths)} Peer-Dateien im Swarm-Verzeichnis"
        else:
            p.note = "Noch keine Peers bekannt"
    except Exception as exc:
        p.note = str(exc)
    return p


def _probe_disk_space() -> Probe:
    p = Probe("disk_space", "Freier Speicher", weight=5)
    try:
        import shutil
        stat = shutil.disk_usage(Path("data") if Path("data").exists() else Path("."))
        free_mb = stat.free / (1024 * 1024)
        if free_mb >= 1024:
            p.ok = True
            p.earned = 5
            p.note = f"{free_mb / 1024:.1f} GB frei"
        elif free_mb >= 500:
            p.earned = 3
            p.note = f"{free_mb:.0f} MB frei (knapp)"
        else:
            p.note = f"Nur {free_mb:.0f} MB frei — zu wenig"
    except Exception as exc:
        p.note = str(exc)
    return p


def _probe_ram() -> Probe:
    p = Probe("ram", "Arbeitsspeicher", weight=5)
    try:
        import psutil  # type: ignore
        mem = psutil.virtual_memory()
        available_mb = mem.available / (1024 * 1024)
        if available_mb >= 512:
            p.ok = True
            p.earned = 5
            p.note = f"{available_mb / 1024:.2f} GB verfügbar"
        elif available_mb >= 256:
            p.earned = 3
            p.note = f"{available_mb:.0f} MB — eingeschränkter Betrieb"
        else:
            p.note = f"Nur {available_mb:.0f} MB — sehr knapp"
    except ImportError as e:
        # psutil not available — use platform heuristic
        try:
            if sys.platform.startswith("linux"):
                info = Path("/proc/meminfo").read_text(encoding="utf-8")
                for line in info.splitlines():
                    if line.startswith("MemAvailable:"):
                        kb = int(line.split()[1])
                        mb = kb // 1024
                        if mb >= 512:
                            p.ok = True
                            p.earned = 5
                            p.note = f"{mb // 1024} GB verfügbar (proc)"
                        elif mb >= 256:
                            p.earned = 3
                            p.note = f"{mb} MB (proc, eingeschränkt)"
                        else:
                            p.note = f"{mb} MB (proc, sehr knapp)"
                        break
                else:
                    p.earned = 3
                    p.note = "RAM unbekannt (psutil fehlt, proc gelesen)"
            else:
                p.earned = 3
                p.note = "RAM unbekannt (psutil nicht verfügbar)"
        except Exception as e:
            p.earned = 3
            p.note = "RAM-Erkennung ohne psutil fehlgeschlagen"
    except Exception as exc:
        p.note = str(exc)
    return p


def _probe_data_writable() -> Probe:
    p = Probe("data_writable", "Schreibzugriff data/", weight=5)
    try:
        data_dir = Path("data")
        data_dir.mkdir(parents=True, exist_ok=True)
        test_file = data_dir / ".aether_write_test"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink()
        p.ok = True
        p.earned = 5
        p.note = "data/ beschreibbar"
    except Exception as exc:
        p.note = f"data/ nicht beschreibbar: {exc}"
    return p


def _probe_swarm_invariants() -> Probe:
    """Misst, wie viele Invarianten / Konsens-Ereignisse der Schwarm
    bereits mit diesem Knoten geteilt hat.  Steigt kontinuierlich an —
    auch auf sehr alter Hardware — weil die Punkte aus kollektivem
    Wissen kommen, nicht aus lokaler Rechenpower.

    Gewicht: 15 Punkte (höchste Einzelgewichtung).
    Schwellen:
      ≥ 1   Konsens-Ereignis  →  3 Pkt  (Basis-Teilnahme)
      ≥ 5                     →  6 Pkt
      ≥ 20                    →  9 Pkt
      ≥ 50                    → 12 Pkt
      ≥ 100                   → 15 Pkt  (vollständig synced)
    """
    p = Probe("swarm_invariants", "Geteilte Invarianten (Schwarm)", weight=15)
    try:
        # Primärquelle: backend_state.json (geschrieben von Python-Backend)
        bs_path = Path("data") / "interbus" / "backend_state.json"
        consensus_count = 0
        pack_count = 0
        if bs_path.exists():
            data = json.loads(bs_path.read_text(encoding="utf-8"))
            consensus_count = int(data.get("swarm_consensus_count", 0))
            pack_count      = int(data.get("swarm_pack_count", 0))

        # Fallback: Anzahl lokaler Swarm-Pack-Dateien zählen
        if consensus_count == 0 and pack_count == 0:
            packs_dir = Path("data") / "swarm" / "packs"
            if packs_dir.is_dir():
                pack_count = sum(1 for _ in packs_dir.rglob("*.json"))

        total = max(consensus_count, pack_count)

        if total >= 100:
            p.ok = True
            p.earned = 15
            p.note = f"{total} Invarianten — vollständig synced"
        elif total >= 50:
            p.ok = True
            p.earned = 12
            p.note = f"{total} Invarianten geteilt"
        elif total >= 20:
            p.earned = 9
            p.note = f"{total} Invarianten geteilt"
        elif total >= 5:
            p.earned = 6
            p.note = f"{total} Invarianten geteilt"
        elif total >= 1:
            p.earned = 3
            p.note = f"{total} Invariante — Schwarm-Kontakt hergestellt"
        else:
            p.note = "Noch keine geteilten Invarianten (Schwarm noch nicht aktiv)"
    except Exception as exc:
        p.note = str(exc)
    return p


def _probe_swarm_reachable_peers() -> Probe:
    """Zählt aktiv erreichbare Peers — wächst mit jedem neuen Knoten,
    der sich mit diesem Gerät verbindet.  Auch ein alter PC kann hier
    maximale Punktzahl erreichen, wenn genug Peers aktiv sind.

    Gewicht: 10 Punkte.
    Schwellen:
      ≥ 1 Peer  →  3 Pkt
      ≥ 3       →  6 Pkt
      ≥ 5       →  8 Pkt
      ≥ 10      → 10 Pkt
    """
    p = Probe("swarm_reachable_peers", "Erreichbare Peers (aktiv)", weight=10)
    try:
        reachable = 0
        bs_path = Path("data") / "interbus" / "backend_state.json"
        if bs_path.exists():
            data = json.loads(bs_path.read_text(encoding="utf-8"))
            reachable = int(data.get("swarm_reachable_node_count", 0))

        if reachable >= 10:
            p.ok = True
            p.earned = 10
            p.note = f"{reachable} Peers erreichbar"
        elif reachable >= 5:
            p.ok = True
            p.earned = 8
            p.note = f"{reachable} Peers erreichbar"
        elif reachable >= 3:
            p.earned = 6
            p.note = f"{reachable} Peers erreichbar"
        elif reachable >= 1:
            p.earned = 3
            p.note = f"{reachable} Peer erreichbar — erster Kontakt"
        else:
            p.note = "Keine Peers erreichbar"
    except Exception as exc:
        p.note = str(exc)
    return p


# ── Score computation ────────────────────────────────────────────────────────

def _stage(percent: int) -> Tuple[str, int]:
    """Return (stage_label, stage_index) for a given integer percent 0–100."""
    idx = 0
    label = STAGES[0][1]
    for threshold, name in STAGES:
        if percent >= threshold:
            label = name
            idx = STAGES.index((threshold, name))
    return label, idx


def _progression_metadata(probes: Dict[str, Probe], stage_index: int, startup_route: Dict[str, Any]) -> Dict[str, Any]:
    """Leitet die praktische Aethernet-Aufstiegslogik aus den Probe-Ergebnissen ab.

    Trennt klar zwischen:
      - lokaler Shell-Reife,
      - Overlay-/Yggdrasil-Reife,
      - vollwertiger Mitgliedschaft im verteilten Netz.

    WICHTIG: Diese Marker beschreiben nur die erreichte Reife. Die native
    Hardware-/OS-Grenze bleibt separat im hw_capability-Tier verankert.
    """
    python_probe = probes.get("python_runtime")
    rust_probe = probes.get("rust_binary")
    gpu_probe = probes.get("gpu_display")
    ygg_probe = probes.get("yggdrasil")
    network_probe = probes.get("network")
    invariants_probe = probes.get("swarm_invariants")
    peers_probe = probes.get("swarm_reachable_peers")
    startup_mode = str(startup_route.get("mode", "full") or "full")
    startup_reason = str(startup_route.get("reason", "default_full_runtime") or "default_full_runtime")
    requirements_profile = str(startup_route.get("requirements_profile", startup_mode) or startup_mode)
    recommended_entrypoint = str(startup_route.get("recommended_entrypoint", "start.py") or "start.py")
    hw_capability = _load_hw_capability()

    shell_ready = bool(
        python_probe and python_probe.earned >= 3
        and rust_probe and rust_probe.earned >= 10
        and gpu_probe and gpu_probe.earned >= 8
    )
    overlay_ready = bool(
        ygg_probe and ygg_probe.earned >= 10
        and network_probe and network_probe.earned >= 3
    )
    swarm_learning_active = bool(
        invariants_probe and invariants_probe.earned > 0
        or peers_probe and peers_probe.earned > 0
    )
    full_member_ready = bool(
        overlay_ready
        and stage_index >= 3
        and invariants_probe and invariants_probe.earned >= 6
        and peers_probe and peers_probe.earned >= 6
    )

    if full_member_ready:
        base_mode = "full-member"
        next_goal = "Volles Aethernet aktiv; Fokus auf Quorum, Relay und DHT-Stabilitaet."
    elif overlay_ready:
        base_mode = "overlay-ready"
        next_goal = "Shell und Yggdrasil sind bereit; mit mehr geteilten Invarianten folgt Vollmitgliedschaft."
    elif shell_ready:
        base_mode = "shell-ready"
        next_goal = "Rust-Shell ist lokal nutzbar; als Naechstes Yggdrasil/Overlay bereitstellen."
    elif stage_index >= 2:
        base_mode = "lan-p2p-ready"
        next_goal = "Lokaler und LAN-basierter Austausch ist tragfaehig; Shell oder Overlay koennen spaeter dazukommen."
    elif stage_index >= 1:
        base_mode = "lan-beacon-ready"
        next_goal = "Knoten ist sichtbar und lernt weiter; naechster Schritt ist leichter P2P-/Gossip-Betrieb."
    else:
        base_mode = "vault-first"
        next_goal = "Lokal lernen, Invarianten sammeln und schrittweise sichtbarer im Netz werden."

    progression_track = "full-runtime"
    progression_mode = base_mode
    fair_inclusion_path = False

    if startup_mode == "ultra_legacy":
        progression_track = "ultra-legacy"
        progression_mode = "ultra-legacy-local"
        fair_inclusion_path = True
        next_goal = "Ultra-Legacy-Pfad aktiv; lokal lernen, Vault pflegen und mit neuerer Laufzeit spaeter Headless oder LAN freischalten."
    elif startup_mode == "headless":
        progression_track = "legacy-headless"
        progression_mode = "legacy-headless-" + base_mode
        fair_inclusion_path = True
        if full_member_ready:
            next_goal = "Headless-Fairnesspfad aktiv; der Knoten traegt bereits voll zum Netz bei, auch ohne schweren UI-Stack."
        elif overlay_ready:
            next_goal = "Headless-Fairnesspfad aktiv; Overlay steht, mit mehr geteilten Invarianten folgt Vollmitgliedschaft."
        elif stage_index >= 2:
            next_goal = "Headless-Fairnesspfad aktiv; LAN/P2P steht, jetzt ueber AE/Vault weiter Invarianten und Peer-Reichweite aufbauen."
        else:
            next_goal = "Headless-Fairnesspfad aktiv; lokal lernen, Vault staerken und Schritt fuer Schritt sichtbarer im Netz werden."
    elif startup_mode == "android":
        progression_track = "android"
        progression_mode = "android-" + base_mode

    emergence = _network_emergence_metadata(
        startup_route,
        hw_capability,
        base_mode,
        shell_ready,
        overlay_ready,
        full_member_ready,
    )

    return {
        "shell_ready": shell_ready,
        "overlay_ready": overlay_ready,
        "full_member_ready": full_member_ready,
        "swarm_learning_active": swarm_learning_active,
        "startup_mode": startup_mode,
        "startup_reason": startup_reason,
        "requirements_profile": requirements_profile,
        "recommended_entrypoint": recommended_entrypoint,
        "progression_track": progression_track,
        "base_progression_mode": base_mode,
        "progression_mode": progression_mode,
        "next_goal": next_goal,
        "fair_inclusion_path": fair_inclusion_path,
        "native_network_tier": emergence["native_network_tier"],
        "native_tier_rank": emergence["native_tier_rank"],
        "network_end_goal": emergence["network_end_goal"],
        "overlay_path": emergence["overlay_path"],
        "relay_bridge_required": emergence["relay_bridge_required"],
        "symbiont_role": emergence["symbiont_role"],
        "emergent_network_role": emergence["emergent_network_role"],
        "aethernet_goal_message": emergence["aethernet_goal_message"],
    }


def _compute_contribution_index() -> Dict[str, Any]:
    """Berechnet den Contribution-Index — wächst unbegrenzt über 100% hinaus.

    Quellen:
      - Abgeschlossene Swarm-Tasks (task_broker.py / task_results.json)
      - Geteilte AlgoTokens (algo_share.py / algo_tokens.json)
      - Vorhersage-Beobachtungen (prediction_engine.py / chunk_transitions.json)

    Skala: keine Obergrenze. Wächst kontinuierlich mit jedem Beitrag.
    """
    tasks_completed = 0
    algo_shares = 0
    prediction_obs = 0
    prefetch_accuracy = 0.0

    try:
        p = Path("data") / "interbus" / "task_results.json"
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            tasks_completed = int(data.get("completed_count", 0))
    except Exception:
        pass

    try:
        p = Path("data") / "swarm" / "algo_tokens.json"
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            algo_shares = int(data.get("share_count", 0))
    except Exception:
        pass

    try:
        p = Path("data") / "interbus" / "chunk_transitions.json"
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            prediction_obs = int(data.get("total_observations", 0))
            hits   = int(data.get("prefetch_hits",   0))
            misses = int(data.get("prefetch_misses", 0))
            total  = hits + misses
            if total > 0:
                prefetch_accuracy = hits / total
    except Exception:
        pass

    # Gewichtete Summe: Tasks sind am wertvollsten (schwer), Observations leicht
    index = tasks_completed + (algo_shares * 2) + (prediction_obs // 100)

    # Contribution-Stufe bestimmen
    contribution_stage = CONTRIBUTION_STAGES[0][1]
    for threshold, label in CONTRIBUTION_STAGES:
        if index >= threshold:
            contribution_stage = label

    return {
        "contribution_index":   index,
        "contribution_stage":   contribution_stage,
        "tasks_completed":      tasks_completed,
        "algo_shares":          algo_shares,
        "prediction_obs":       prediction_obs,
        "prefetch_accuracy":    round(prefetch_accuracy, 3),
    }


def run_probes() -> Dict[str, Any]:
    """Execute all probes and return the consolidated capability report.

    Gewichtungsphilosophie
    ─────────────────────
    Hardware-Probes  (Rust-Binary, GPU, Yggdrasil) sind fest —
    ein alter PC verliert dort Punkte, die er nicht zurückgewinnen kann.

    Schwarm-Probes (swarm_invariants, swarm_reachable_peers) sind dynamisch —
    sie steigen mit jedem Knoten der Invarianten teilt.  Dadurch kann
    ein Raspberry Pi Zero mit 15 echten Peers trotzdem 90 %+ erreichen.
    """
    probes: List[Probe] = [
        _probe_python_runtime(),          # 5  — fest
        _probe_rust_binary(),             # 10 — fest (5 Pkt. mit Headless-Daemon)
        _probe_gpu_display(),             # 10 — fest
        _probe_yggdrasil(),               # 10 — fest
        _probe_network(),                 # 5  — fest
        _probe_module("psutil",       "psutil",         "psutil",       5),
        _probe_module("numpy",        "NumPy",          "numpy",        5),
        _probe_module("scipy",        "SciPy",          "scipy",        5),
        _probe_module("cryptography", "cryptography",   "cryptography", 10),
        _probe_swarm_consent(),           # 5  — fest (Opt-in)
        _probe_vault(),                   # 10 — fest
        _probe_peers(),                   # 5  — fest (Peer-Dateien vorhanden)
        _probe_disk_space(),              # 5  — fest
        _probe_ram(),                     # 5  — fest
        _probe_data_writable(),           # 5  — fest
        # ── Dynamische Schwarm-Probes (wachsen mit geteilten Invarianten) ──
        _probe_swarm_invariants(),        # 15 — dynamisch, steigt mit Konsens-Ereignissen
        _probe_swarm_reachable_peers(),   # 10 — dynamisch, steigt mit aktiven Peers
    ]

    total_weight = sum(pr.weight for pr in probes)
    total_earned = sum(pr.earned for pr in probes)

    # Normalise to 100
    if total_weight > 0:
        percent = round((total_earned / total_weight) * 100)
    else:
        percent = 0
    percent = max(0, min(100, percent))

    stage_label, stage_index = _stage(percent)
    startup_route = _load_startup_route()
    progression = _progression_metadata({pr.key: pr for pr in probes}, stage_index, startup_route)
    contribution = _compute_contribution_index()

    return {
        "score":       total_earned,
        "max_score":   total_weight,
        "percent":     percent / 100.0,   # float 0.0–1.0 for Rust progress bar
        "percent_int": percent,
        "stage":       stage_label,
        "stage_index": stage_index,
        "shell_ready": progression["shell_ready"],
        "overlay_ready": progression["overlay_ready"],
        "full_member_ready": progression["full_member_ready"],
        "swarm_learning_active": progression["swarm_learning_active"],
        "startup_mode": progression["startup_mode"],
        "startup_reason": progression["startup_reason"],
        "requirements_profile": progression["requirements_profile"],
        "recommended_entrypoint": progression["recommended_entrypoint"],
        "progression_track": progression["progression_track"],
        "base_progression_mode": progression["base_progression_mode"],
        "progression_mode": progression["progression_mode"],
        "next_goal": progression["next_goal"],
        "fair_inclusion_path": progression["fair_inclusion_path"],
        "native_network_tier": progression["native_network_tier"],
        "native_tier_rank": progression["native_tier_rank"],
        "network_end_goal": progression["network_end_goal"],
        "overlay_path": progression["overlay_path"],
        "relay_bridge_required": progression["relay_bridge_required"],
        "symbiont_role": progression["symbiont_role"],
        "emergent_network_role": progression["emergent_network_role"],
        "aethernet_goal_message": progression["aethernet_goal_message"],
        # Contribution-Index: wächst unbegrenzt über 100% hinaus
        "contribution_index":  contribution["contribution_index"],
        "contribution_stage":  contribution["contribution_stage"],
        "tasks_completed":     contribution["tasks_completed"],
        "algo_shares":         contribution["algo_shares"],
        "prediction_obs":      contribution["prediction_obs"],
        "prefetch_accuracy":   contribution["prefetch_accuracy"],
        "probes":      {pr.key: pr.to_dict() for pr in probes},
        "platform":    platform.system(),
        "python":      f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def write_score(result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Run probes (or use supplied result) and write to SCORE_PATH. Returns result."""
    if result is None:
        result = run_probes()
    try:
        SCORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        SCORE_PATH.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        # Never crash the host — logging only
        import logging
        logging.getLogger(__name__).warning("capability_score: write failed: %s", exc)
    return result


def probe_and_write() -> Dict[str, Any]:
    """Convenience entry point: run all probes and persist the result."""
    return write_score()


# ── CLI entry point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    result = probe_and_write()
    print(f"Aether OS Readiness: {result['percent_int']}% — {result['stage']}")
    for key, info in result["probes"].items():
        status = "✓" if info["ok"] else "✗"
        print(f"  {status} {key:20s}  {info['earned']:2d}/{info['weight']:2d}  {info['note']}")
