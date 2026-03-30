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

from __future__ import annotations

import importlib.util
import json
import os
import platform
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Constants ────────────────────────────────────────────────────────────────

SCORE_PATH = Path("data") / "interbus" / "capability_score.json"

STAGES = [
    (0,   "Basis-Daemon"),
    (25,  "Minimal Node"),
    (50,  "Standard"),
    (75,  "Aether OS"),
    (100, "Aether OS [Aktiv]"),
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "weight": self.weight,
            "earned": self.earned,
            "note": self.note,
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
        except Exception:
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
    except OSError:
        # Try LAN fallback — even localhost reachable counts
        try:
            import socket as _s
            with _s.create_connection(("127.0.0.1", 80), timeout=0.3):
                p.earned = 3
                p.note = "Nur Localhost erreichbar"
        except OSError:
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
        nodes_path = Path("data") / "nodes"
        swarm_path = Path("data") / "swarm"
        paths = list((nodes_path.glob("*.json") if nodes_path.is_dir() else [])) + \
                list((swarm_path.glob("*.json") if swarm_path.is_dir() else []))
        if paths:
            p.ok = True
            p.earned = 5
            p.note = f"{len(paths)} Peer-Dateien"
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
    except ImportError:
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
        except Exception:
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

def _stage(percent: int) -> tuple[str, int]:
    """Return (stage_label, stage_index) for a given integer percent 0–100."""
    idx = 0
    label = STAGES[0][1]
    for threshold, name in STAGES:
        if percent >= threshold:
            label = name
            idx = STAGES.index((threshold, name))
    return label, idx


def run_probes() -> dict[str, Any]:
    """Execute all probes and return the consolidated capability report.

    Gewichtungsphilosophie
    ─────────────────────
    Hardware-Probes  (Rust-Binary, GPU, Yggdrasil) sind fest —
    ein alter PC verliert dort Punkte, die er nicht zurückgewinnen kann.

    Schwarm-Probes (swarm_invariants, swarm_reachable_peers) sind dynamisch —
    sie steigen mit jedem Knoten der Invarianten teilt.  Dadurch kann
    ein Raspberry Pi Zero mit 15 echten Peers trotzdem 90 %+ erreichen.
    """
    probes: list[Probe] = [
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

    return {
        "score":       total_earned,
        "max_score":   total_weight,
        "percent":     percent / 100.0,   # float 0.0–1.0 for Rust progress bar
        "percent_int": percent,
        "stage":       stage_label,
        "stage_index": stage_index,
        "probes":      {pr.key: pr.to_dict() for pr in probes},
        "platform":    platform.system(),
        "python":      f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def write_score(result: dict[str, Any] | None = None) -> dict[str, Any]:
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


def probe_and_write() -> dict[str, Any]:
    """Convenience entry point: run all probes and persist the result."""
    return write_score()


# ── CLI entry point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    result = probe_and_write()
    print(f"Aether OS Readiness: {result['percent_int']}% — {result['stage']}")
    for key, info in result["probes"].items():
        status = "✓" if info["ok"] else "✗"
        print(f"  {status} {key:20s}  {info['earned']:2d}/{info['weight']:2d}  {info['note']}")
