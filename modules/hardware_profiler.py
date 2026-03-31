"""
Aether – Hardware-Profiler und Optimierungs-Engine für alte Hardware.

Erkennt:
  - CPU-Typ, Kerne, Frequenz
  - RAM-Größe
  - Festplattentyp (HDD / SSD / NVMe)
  - GPU / Grafikkarte
  - Betriebssystem-Version

Leitet daraus ab:
  - Ob das System als "alte Hardware" gilt
  - Welche spezifischen Optimierungsvorschläge sinnvoll sind

Privacy:
  - Keine Daten verlassen das Gerät.
  - Seriennummern und Geräteidentifier werden nicht erfasst.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import psutil
    _PSUTIL_OK = True
except Exception as e:
    psutil = None  # type: ignore
    _PSUTIL_OK = False

logger = logging.getLogger(__name__)

_IS_WIN = sys.platform.startswith("win")
_IS_LINUX = sys.platform.startswith("linux")
_IS_MAC = sys.platform == "darwin"


@dataclass
class HardwareProfile:
    """Strukturelles Hardwareprofil des aktuellen Systems."""

    cpu_name: str = ""
    cpu_cores_physical: int = 1
    cpu_cores_logical: int = 1
    cpu_freq_mhz: float = 0.0
    ram_total_mb: int = 0
    ram_available_mb: int = 0
    disk_type: str = "unknown"      # "HDD", "SSD", "NVMe", "unknown"
    disk_free_gb: float = 0.0
    gpu_name: str = ""
    os_name: str = ""
    os_version: str = ""
    aero_enabled: bool = False      # Windows Vista+ Transparenz-Effekte
    is_old_hardware: bool = False   # True wenn System als "alt" eingestuft

    # Schwellwerte für "alte Hardware":
    #   RAM < 2 GB, CPU < 2 GHz, HDD statt SSD
    OLD_RAM_MB = 2048
    OLD_CPU_GHZ = 2.0
    OLD_DISK = "HDD"

    def as_dict(self) -> dict[str, Any]:
        return {
            "cpu_name": self.cpu_name,
            "cpu_cores_physical": self.cpu_cores_physical,
            "cpu_cores_logical": self.cpu_cores_logical,
            "cpu_freq_mhz": self.cpu_freq_mhz,
            "ram_total_mb": self.ram_total_mb,
            "ram_available_mb": self.ram_available_mb,
            "disk_type": self.disk_type,
            "disk_free_gb": round(self.disk_free_gb, 1),
            "gpu_name": self.gpu_name,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "aero_enabled": self.aero_enabled,
            "is_old_hardware": self.is_old_hardware,
        }


@dataclass
class OptimizationSuggestion:
    """Ein konkreter, umsetzbarer Optimierungsvorschlag."""

    action_type: str           # z.B. "priority_lower", "service_disable", "visual_disable"
    target: str                # Prozessname, Service-ID oder "system"
    title_de: str = ""
    title_en: str = ""
    severity: str = "low"      # "low", "medium", "high"
    reversible: bool = True
    auto_applicable: bool = False   # Kann ohne Nutzereingabe angewandt werden
    rollback_data: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)

    def title(self, lang: str = "de") -> str:
        return self.title_de if lang.startswith("d") else self.title_en


class HardwareProfiler:
    """
    Erkennt Hardwareeigenschaften und stuft das System ein.

    Alle Methoden sind read-only (kein Schreiben in Systemdateien).
    """

    def __init__(self) -> None:
        self._cached: HardwareProfile | None = None
        self._cache_time: float = 0.0
        self._CACHE_TTL = 300.0   # 5 Minuten

    def profile(self, force: bool = False) -> HardwareProfile:
        """Erstellt oder gibt das gecachte Hardwareprofil zurück."""
        now = time.time()
        if not force and self._cached and (now - self._cache_time) < self._CACHE_TTL:
            return self._cached

        p = HardwareProfile()
        p.os_name = platform.system()
        p.os_version = platform.version()

        self._fill_cpu(p)
        self._fill_ram(p)
        self._fill_disk(p)
        self._fill_gpu(p)
        self._check_aero(p)
        self._classify(p)

        self._cached = p
        self._cache_time = now
        return p

    # ------------------------------------------------------------------
    # CPU
    # ------------------------------------------------------------------

    def _fill_cpu(self, p: HardwareProfile) -> None:
        try:
            p.cpu_name = platform.processor() or ""
        except Exception as e:
            logger.warning(f"[hardware_profiler] Fehler: {e}")
            pass

        if _PSUTIL_OK and psutil:
            try:
                p.cpu_cores_physical = psutil.cpu_count(logical=False) or 1
                p.cpu_cores_logical = psutil.cpu_count(logical=True) or 1
                freq = psutil.cpu_freq()
                if freq:
                    p.cpu_freq_mhz = float(freq.max or freq.current or 0)
            except Exception as e:
                logger.warning(f"[hardware_profiler] Fehler: {e}")
                pass

        # Fallback: /proc/cpuinfo (Linux)
        if _IS_LINUX and not p.cpu_freq_mhz:
            try:
                text = Path("/proc/cpuinfo").read_text()
                m = re.search(r"cpu MHz\s*:\s*([\d.]+)", text)
                if m:
                    p.cpu_freq_mhz = float(m.group(1))
                m2 = re.search(r"model name\s*:\s*(.+)", text)
                if m2 and not p.cpu_name:
                    p.cpu_name = m2.group(1).strip()
            except Exception as e:
                logger.warning(f"[hardware_profiler] Fehler: {e}")
                pass

    # ------------------------------------------------------------------
    # RAM
    # ------------------------------------------------------------------

    def _fill_ram(self, p: HardwareProfile) -> None:
        if _PSUTIL_OK and psutil:
            try:
                vm = psutil.virtual_memory()
                p.ram_total_mb = int(vm.total // (1024 * 1024))
                p.ram_available_mb = int(vm.available // (1024 * 1024))
            except Exception as e:
                logger.warning(f"[hardware_profiler] Fehler: {e}")
                pass

    # ------------------------------------------------------------------
    # Festplatte
    # ------------------------------------------------------------------

    def _fill_disk(self, p: HardwareProfile) -> None:
        if _PSUTIL_OK and psutil:
            try:
                du = psutil.disk_usage("/")
                p.disk_free_gb = float(du.free) / (1024 ** 3)
            except Exception as e:
                logger.warning(f"[hardware_profiler] Fehler: {e}")
                pass

        # Typ erkennen
        if _IS_WIN:
            p.disk_type = self._disk_type_windows()
        elif _IS_LINUX:
            p.disk_type = self._disk_type_linux()
        else:
            p.disk_type = "SSD"  # macOS: fast immer SSD

    def _disk_type_windows(self) -> str:
        """Ermittelt HDD/SSD per PowerShell (Media­type-Wert)."""
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-PhysicalDisk | Select-Object -First 1).MediaType"],
                stderr=subprocess.DEVNULL,
                timeout=5,
                text=True,
            ).strip().lower()
            if "ssd" in out:
                return "SSD"
            if "hdd" in out or "spinning" in out or "fixed" in out:
                return "HDD"
            if "nvme" in out:
                return "NVMe"
        except Exception as e:
            logger.warning(f"[hardware_profiler] Fehler: {e}")
            pass
        return "unknown"

    def _disk_type_linux(self) -> str:
        """Prüft Rotational-Flag in /sys/block."""
        try:
            for dev_path in Path("/sys/block").iterdir():
                rota = dev_path / "queue" / "rotational"
                if rota.exists():
                    val = rota.read_text().strip()
                    return "HDD" if val == "1" else "SSD"
        except Exception as e:
            logger.warning(f"[hardware_profiler] Fehler: {e}")
            pass
        return "unknown"

    # ------------------------------------------------------------------
    # GPU
    # ------------------------------------------------------------------

    def _fill_gpu(self, p: HardwareProfile) -> None:
        if _IS_WIN:
            try:
                out = subprocess.check_output(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-CimInstance Win32_VideoController | Select-Object -First 1).Name"],
                    stderr=subprocess.DEVNULL, timeout=5, text=True,
                ).strip()
                p.gpu_name = out
            except Exception as e:
                logger.warning(f"[hardware_profiler] Fehler: {e}")
                pass
        elif _IS_LINUX:
            try:
                out = subprocess.check_output(
                    ["lspci"], stderr=subprocess.DEVNULL, text=True, timeout=5
                )
                m = re.search(r"VGA[^\n]*?:\s*(.+)", out)
                if m:
                    p.gpu_name = m.group(1).strip()
            except Exception as e:
                logger.warning(f"[hardware_profiler] Fehler: {e}")
                pass
        elif _IS_MAC:
            try:
                out = subprocess.check_output(
                    ["system_profiler", "SPDisplaysDataType"],
                    stderr=subprocess.DEVNULL, text=True, timeout=10,
                )
                m = re.search(r"Chipset Model:\s*(.+)", out)
                if m:
                    p.gpu_name = m.group(1).strip()
            except Exception as e:
                logger.warning(f"[hardware_profiler] Fehler: {e}")
                pass

    # ------------------------------------------------------------------
    # Aero / visuelle Effekte (Windows)
    # ------------------------------------------------------------------

    def _check_aero(self, p: HardwareProfile) -> None:
        if not _IS_WIN:
            return
        try:
            import ctypes
            dwm = ctypes.windll.dwmapi
            enabled = ctypes.c_int(0)
            dwm.DwmIsCompositionEnabled(ctypes.byref(enabled))
            p.aero_enabled = bool(enabled.value)
        except Exception as e:
            p.aero_enabled = False

    # ------------------------------------------------------------------
    # Klassifikation
    # ------------------------------------------------------------------

    def _classify(self, p: HardwareProfile) -> None:
        old_flags = 0
        if p.ram_total_mb > 0 and p.ram_total_mb < HardwareProfile.OLD_RAM_MB:
            old_flags += 2
        if p.cpu_freq_mhz > 0 and p.cpu_freq_mhz < HardwareProfile.OLD_CPU_GHZ * 1000:
            old_flags += 2
        if p.disk_type == "HDD":
            old_flags += 1
        if p.cpu_cores_physical <= 2:
            old_flags += 1
        p.is_old_hardware = old_flags >= 2


class HardwareOptimizer:
    """
    Analysiert das laufende System und generiert konkrete
    Optimierungsvorschläge — speziell für alte Hardware.

    Alle Vorschläge sind umkehrbar (rollback_data wird mitgeliefert).
    Keine Aktion wird ohne Nutzerzustimmung ausgeführt.
    """

    # Dienste, die auf alten Systemen häufig unnötig CPU/RAM verbrauchen
    _KNOWN_BLOAT_SERVICES_WIN: dict[str, str] = {
        "SysMain":        "Superfetch/SysMain (belastet HDDs stark)",
        "WSearch":        "Windows-Suche (Indizierung)",
        "DiagTrack":      "Telemetrie-Dienst",
        "DoSvc":          "Delivery Optimization (Windows Update P2P)",
        "TabletInputService": "Tablet-Eingabe (auf Desktop irrelevant)",
        "Fax":            "Fax-Dienst",
        "RemoteRegistry": "Remote-Registry",
        "XblGameSave":    "Xbox Game Save",
        "XboxNetApiSvc":  "Xbox Netzwerk",
    }

    _KNOWN_BLOAT_PROCESSES: list[str] = [
        "OneDrive.exe", "MsMpEng.exe", "SearchIndexer.exe",
        "GameBarPresenceWriter.exe", "YourPhone.exe", "widgets.exe",
    ]

    def __init__(self, profiler: HardwareProfiler | None = None) -> None:
        self._profiler = profiler or HardwareProfiler()

    def analyze(self) -> list[OptimizationSuggestion]:
        """Gibt eine Liste priorisierter Optimierungsvorschläge zurück."""
        hw = self._profiler.profile()
        suggestions: list[OptimizationSuggestion] = []

        if not _PSUTIL_OK or psutil is None:
            return suggestions

        # -- 1. RAM-Auslastung --
        try:
            vm = psutil.virtual_memory()
            ram_pct = float(vm.percent)
            if ram_pct > 80:
                suggestions.append(OptimizationSuggestion(
                    action_type="memory_alert",
                    target="system",
                    title_de=f"RAM-Auslastung kritisch ({ram_pct:.0f}%) – Empfehlung: Nicht benötigte Programme schließen.",
                    title_en=f"RAM usage critical ({ram_pct:.0f}%) – Recommendation: close unused programs.",
                    severity="high",
                    reversible=False,
                    auto_applicable=False,
                ))
        except Exception as e:
            logger.warning(f"[hardware_profiler] Fehler: {e}")
            pass

        # -- 2. Bloat-Prozesse (hohe CPU-Last) --
        try:
            running = {p.name(): p for p in psutil.process_iter(["name", "cpu_percent", "pid"])}
            for bloat in self._KNOWN_BLOAT_PROCESSES:
                if bloat in running:
                    proc = running[bloat]
                    cpu = float(proc.cpu_percent(interval=0.1) or 0)
                    if cpu > 5:
                        suggestions.append(OptimizationSuggestion(
                            action_type="priority_lower",
                            target=bloat,
                            title_de=f"'{bloat}' belegt {cpu:.0f}% CPU. Soll ich die Priorität senken?",
                            title_en=f"'{bloat}' uses {cpu:.0f}% CPU. Should I lower its priority?",
                            severity="medium",
                            reversible=True,
                            auto_applicable=True,
                            rollback_data={"process": bloat, "prev_priority": "normal"},
                            details={"pid": proc.pid, "cpu_percent": cpu},
                        ))
        except Exception as e:
            logger.warning(f"[hardware_profiler] Fehler: {e}")
            pass

        # -- 3. Windows-Dienste (nur Windows) --
        if _IS_WIN:
            suggestions.extend(self._check_win_services(hw))

        # -- 4. HDD-Thrashing --
        if hw.disk_type == "HDD":
            try:
                di = psutil.disk_io_counters()
                # Zwei Messungen im Abstand von 1 Sekunde
                time.sleep(1.0)
                di2 = psutil.disk_io_counters()
                write_mb = (di2.write_bytes - di.write_bytes) / 1_000_000  # type: ignore[union-attr]
                read_mb = (di2.read_bytes - di.read_bytes) / 1_000_000    # type: ignore[union-attr]
                if write_mb + read_mb > 5:
                    suggestions.append(OptimizationSuggestion(
                        action_type="io_alert",
                        target="system",
                        title_de=f"Hohe Festplattenaktivität ({write_mb+read_mb:.1f} MB/s) auf HDD – verlangsamt das System erheblich.",
                        title_en=f"High disk activity ({write_mb+read_mb:.1f} MB/s) on HDD – slowing the system significantly.",
                        severity="high",
                        reversible=False,
                        auto_applicable=False,
                    ))
            except Exception as e:
                logger.warning(f"[hardware_profiler] Fehler: {e}")
                pass

        # -- 5. Aero / visuelle Effekte --
        if hw.aero_enabled and hw.is_old_hardware:
            suggestions.append(OptimizationSuggestion(
                action_type="visual_disable",
                target="aero",
                title_de="Visuelle Effekte (Aero/Transparenz) sind aktiv – belasten alte Hardware. Soll ich sie deaktivieren?",
                title_en="Visual effects (Aero/transparency) are active – heavy on old hardware. Should I disable them?",
                severity="medium",
                reversible=True,
                auto_applicable=False,
                rollback_data={"aero_state": True},
            ))

        # -- 6. Speicherfragmentierung (viele kleine Allokationen) --
        if hw.is_old_hardware:
            try:
                vm = psutil.virtual_memory()
                if vm.percent > 70 and hw.disk_type == "HDD":
                    suggestions.append(OptimizationSuggestion(
                        action_type="memory_fragmentation",
                        target="system",
                        title_de="Hohe Speicherauslastung auf altem System mit HDD. Empfehlung: Weniger Programme gleichzeitig öffnen.",
                        title_en="High memory usage on old system with HDD. Recommendation: open fewer programs at once.",
                        severity="medium",
                        reversible=False,
                        auto_applicable=False,
                    ))
            except Exception as e:
                logger.warning(f"[hardware_profiler] Fehler: {e}")
                pass

        return sorted(suggestions, key=lambda s: {"high": 0, "medium": 1, "low": 2}[s.severity])

    def _check_win_services(self, hw: HardwareProfile) -> list[OptimizationSuggestion]:
        """Prüft bekannte Windows-Bloat-Dienste."""
        suggestions: list[OptimizationSuggestion] = []
        if not _IS_WIN:
            return suggestions
        try:
            import winreg
            for svc_name, svc_desc in self._KNOWN_BLOAT_SERVICES_WIN.items():
                try:
                    key_path = f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}"
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
                        start_val, _ = winreg.QueryValueEx(k, "Start")
                        # Start=2 = Automatisch, Start=3 = Manuell, Start=4 = Deaktiviert
                        if int(start_val) in (2, 3):
                            suggestions.append(OptimizationSuggestion(
                                action_type="service_disable",
                                target=svc_name,
                                title_de=f"Dienst '{svc_desc}' ist aktiv – verbraucht Ressourcen auf diesem System. Soll ich ihn deaktivieren?",
                                title_en=f"Service '{svc_desc}' is running – consuming resources. Should I disable it?",
                                severity="low",
                                reversible=True,
                                auto_applicable=False,
                                rollback_data={"service": svc_name, "prev_start": int(start_val)},
                                details={"service_name": svc_name, "description": svc_desc},
                            ))
                except FileNotFoundError as e:
                    logger.warning(f"[hardware_profiler] Fehler: {e}")
                    pass
        except ImportError as e:
            logger.warning(f"[hardware_profiler] Fehler: {e}")
            pass
        return suggestions
