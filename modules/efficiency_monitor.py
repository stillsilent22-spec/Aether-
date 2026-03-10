"""Leichtgewichtiger CPU-/RAM-Monitor fuer lokale Low-Power-Analysen."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

try:
    import psutil
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    psutil = None


@dataclass
class EfficiencySnapshot:
    """Kompakter Laufzeitsnapshot fuer GUI und Selbsttests."""

    available: bool
    cpu_percent: float = 0.0
    ram_percent: float = 0.0
    ram_used_mb: float = 0.0
    process_rss_mb: float = 0.0
    threads: int = 0
    status: str = ""
    warning: str = ""
    missing_dependencies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert den Snapshot fuer Logs oder Payloads."""
        return {
            "available": bool(self.available),
            "cpu_percent": float(self.cpu_percent),
            "ram_percent": float(self.ram_percent),
            "ram_used_mb": float(self.ram_used_mb),
            "process_rss_mb": float(self.process_rss_mb),
            "threads": int(self.threads),
            "status": str(self.status),
            "warning": str(self.warning),
            "missing_dependencies": [str(item) for item in list(self.missing_dependencies)],
        }


class EfficiencyMonitor:
    """Liefert periodische Effizienzwerte ohne schwere Laufzeitkosten."""

    def __init__(self) -> None:
        self._available = psutil is not None
        self._process = psutil.Process() if self._available else None
        self._primed = False

    def sample(self, status: str = "") -> EfficiencySnapshot:
        """Nimmt einen Snapshot des aktuellen Systems und Python-Prozesses auf."""
        if not self._available or self._process is None:
            return EfficiencySnapshot(
                available=False,
                status=str(status or ""),
                warning="psutil fehlt - Effizienzmonitor inaktiv",
                missing_dependencies=["psutil"],
            )
        try:
            if not self._primed:
                psutil.cpu_percent(interval=None)
                self._process.cpu_percent(interval=None)
                self._primed = True
            cpu_percent = float(psutil.cpu_percent(interval=None))
            virtual_memory = psutil.virtual_memory()
            process_info = self._process.memory_info()
            threads = int(self._process.num_threads())
            warning = ""
            if float(virtual_memory.percent) >= 80.0:
                warning = "RAM hoch - Low-Power aktivieren?"
            return EfficiencySnapshot(
                available=True,
                cpu_percent=float(cpu_percent),
                ram_percent=float(virtual_memory.percent),
                ram_used_mb=float(virtual_memory.used) / (1024.0 * 1024.0),
                process_rss_mb=float(process_info.rss) / (1024.0 * 1024.0),
                threads=int(threads),
                status=str(status or ""),
                warning=str(warning),
                missing_dependencies=[],
            )
        except Exception as exc:
            return EfficiencySnapshot(
                available=False,
                status=str(status or ""),
                warning=f"Effizienzmonitor fehlgeschlagen: {exc}",
                missing_dependencies=[],
            )
