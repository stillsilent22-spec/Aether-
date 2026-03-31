import logging
logger = logging.getLogger(__name__)
"""pixel_coord_optimizer.py — MetaLayer OS Phase B: Pixel-Koordinatenpfad-Optimierung.

Analysiert den logischen Render-Pfad jedes Prozesses durch den DWM-Compositor
und schlägt Optimierungen vor (kürzere Hop-Sequenzen, Batch-Compositing).
Alle Pfade werden in einer CoordMatrix zusammengeführt.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any

try:
    import psutil
    _PSUTIL = True
except ImportError as e:
    _PSUTIL = False

try:
    import win32gui
    import win32process
    _WIN32 = True
except ImportError as e:
    _WIN32 = False

from modules.process_pixel_mapper import ProcessPixelMapper, ProcessPixelMap


# ── Konstanten ────────────────────────────────────────────────────────────────

# Schichten im logischen Render-Pfad (Windows DWM)
PATH_LAYERS_DEFAULT = [
    "application_surface",
    "dxgi_swap_chain",
    "dwm_visual_tree",
    "composition_batch",
    "flip_model",
    "display_driver",
    "physical_framebuffer",
]

OPTIMAL_HOP_COUNT = 3        # Beste bekannte Hop-Anzahl für direkte Prozesse
LATENCY_PER_HOP_MS = 0.35   # Typische DWM-Hop-Latenz in ms


# ── Datenklassen ──────────────────────────────────────────────────────────────

@dataclass
class PixelPath:
    """Logischer Render-Pfad eines Prozesses durch DWM-Schichten."""
    pid: int
    process_name: str
    timestamp: float
    path_layers: List[str] = field(default_factory=list)
    hop_count: int = 0
    estimated_latency_ms: float = 0.0
    is_optimal: bool = False
    optimization_potential: float = 0.0   # [0, 1]

    def to_dict(self) -> dict:
        return {
            "pid":                  self.pid,
            "process_name":         self.process_name,
            "timestamp":            self.timestamp,
            "path_layers":          self.path_layers,
            "hop_count":            self.hop_count,
            "estimated_latency_ms": round(self.estimated_latency_ms, 3),
            "is_optimal":           self.is_optimal,
            "optimization_potential": round(self.optimization_potential, 4),
        }


@dataclass
class CoordMatrixEntry:
    """Eintrag in der globalen Koordinatenmatrix."""
    pid: int
    process_name: str
    region: Dict[str, int]       # {left, top, width, height} — Screenregion
    score: float                 # Kombinierter Pfad-Score [0, 1]
    hop_count: int
    estimated_latency_ms: float

    def to_dict(self) -> dict:
        return {
            "pid":                  self.pid,
            "process_name":         self.process_name,
            "region":               self.region,
            "score":                round(self.score, 4),
            "hop_count":            self.hop_count,
            "estimated_latency_ms": round(self.estimated_latency_ms, 3),
        }


@dataclass
class CoordMatrix:
    """Gesamte Koordinatenmatrix aller analysierten Prozesse."""
    entries: List[CoordMatrixEntry] = field(default_factory=list)
    global_bottlenecks: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "entries":            [e.to_dict() for e in self.entries],
            "global_bottlenecks": self.global_bottlenecks,
            "timestamp":          self.timestamp,
        }


@dataclass
class PathOptimizationProposal:
    """Konkreter Optimierungsvorschlag für einen PixelPath."""
    pid: int
    process_name: str
    description: str
    potential_hop_reduction: int
    confidence: float

    def to_dict(self) -> dict:
        return {
            "pid":                    self.pid,
            "process_name":           self.process_name,
            "description":            self.description,
            "potential_hop_reduction": self.potential_hop_reduction,
            "confidence":             round(self.confidence, 4),
        }


# ── Hauptklasse ───────────────────────────────────────────────────────────────

class PixelCoordOptimizer:
    """
    Bestimmt und optimiert den Render-Koordinatenpfad für Benutzerprozesse.

    Da DWM-interne APIs nicht öffentlich sind, wird ein strukturelles Modell
    des Pfades aus beobachtbaren Fensterattributen abgeleitet.
    """

    def __init__(self) -> None:
        self._mapper = ProcessPixelMapper()
        self._path_cache: Dict[int, PixelPath] = {}

    # ── Öffentliche API ───────────────────────────────────────────────────────

    def analyze_render_path(self, pid: int, process_name: str = "") -> PixelPath:
        """Analysiert den vollständigen Render-Pfad eines Prozesses."""
        if not process_name and _PSUTIL:
            try:
                process_name = psutil.Process(pid).name()
            except Exception as e:
                process_name = "unknown"

        layers = list(PATH_LAYERS_DEFAULT)
        hop_count = self._estimate_hop_count(pid, layers)
        latency_ms = hop_count * LATENCY_PER_HOP_MS
        is_optimal = hop_count <= OPTIMAL_HOP_COUNT
        opt_potential = max(0.0, (hop_count - OPTIMAL_HOP_COUNT) / max(1, len(layers)))

        path = PixelPath(
            pid=pid,
            process_name=process_name,
            timestamp=time.time(),
            path_layers=layers,
            hop_count=hop_count,
            estimated_latency_ms=latency_ms,
            is_optimal=is_optimal,
            optimization_potential=min(1.0, opt_potential),
        )
        self._path_cache[pid] = path
        return path

    def find_shortest_path(self, pid: int, process_name: str = "") -> PixelPath:
        """
        Berechnet den theoretisch kürzestmöglichen Render-Pfad für einen Prozess.
        (Basis: Entfernung von Kompositing-Schichten, die für diesen Prozess unnötig sind.)
        """
        path = self.analyze_render_path(pid, process_name)
        # Ermittle entfernbare Schichten
        removable = self._find_removable_layers(pid, path.path_layers)
        optimal_layers = [l for l in path.path_layers if l not in removable]
        hop_count = len(optimal_layers)
        return PixelPath(
            pid=pid,
            process_name=path.process_name,
            timestamp=time.time(),
            path_layers=optimal_layers,
            hop_count=hop_count,
            estimated_latency_ms=hop_count * LATENCY_PER_HOP_MS,
            is_optimal=True,
            optimization_potential=0.0,
        )

    def compute_global_coord_matrix(
        self, all_pids: Optional[List[int]] = None
    ) -> CoordMatrix:
        """Erstellt eine CoordMatrix über alle angegebenen (oder alle User-)Prozesse."""
        entries: list[CoordMatrixEntry] = []
        bottlenecks: list[str] = []

        pids_to_scan: list[int]
        if all_pids is not None:
            pids_to_scan = list(all_pids)
        else:
            pids_to_scan = self._enumerate_user_pids()

        hop_counts: list[int] = []
        for pid in pids_to_scan:
            path = self.analyze_render_path(pid)
            pmap = self._mapper.map_process(pid)
            region = pmap.screen_region if pmap else {}
            score = self._path_score(path, pmap)
            entry = CoordMatrixEntry(
                pid=pid,
                process_name=path.process_name,
                region=region,
                score=score,
                hop_count=path.hop_count,
                estimated_latency_ms=path.estimated_latency_ms,
            )
            entries.append(entry)
            hop_counts.append(path.hop_count)

        # Globale Engpässe: Schichten mit überdurchschnittlich vielen Hops
        if hop_counts:
            mean_hops = sum(hop_counts) / len(hop_counts)
            high_hop_procs = [
                e.process_name for e in entries if e.hop_count > mean_hops + 1.5
            ]
            if high_hop_procs:
                bottlenecks.append(
                    f"Hohe Hop-Anzahl bei: {', '.join(set(high_hop_procs)[:5])}"
                )

        return CoordMatrix(entries=entries, global_bottlenecks=bottlenecks)

    def suggest_path_optimization(
        self, path: PixelPath
    ) -> list[PathOptimizationProposal]:
        """Leitet Optimierungsvorschläge aus einem PixelPath ab."""
        proposals: list[PathOptimizationProposal] = []
        if path.is_optimal:
            return proposals

        removable = self._find_removable_layers(path.pid, path.path_layers)
        for layer in removable:
            proposals.append(PathOptimizationProposal(
                pid=path.pid,
                process_name=path.process_name,
                description=f"Schicht '{layer}' ist für diesen Prozess nicht notwendig "
                            f"und kann übersprungen werden.",
                potential_hop_reduction=1,
                confidence=0.65,
            ))

        if path.hop_count > OPTIMAL_HOP_COUNT + 2:
            proposals.append(PathOptimizationProposal(
                pid=path.pid,
                process_name=path.process_name,
                description=(
                    f"Prozess hat {path.hop_count} Hops (Optimum: {OPTIMAL_HOP_COUNT}). "
                    "Flip-Model-Direktpfad prüfen."
                ),
                potential_hop_reduction=path.hop_count - OPTIMAL_HOP_COUNT,
                confidence=0.50,
            ))
        return proposals

    # ── Hilfsfunktionen ───────────────────────────────────────────────────────

    def _estimate_hop_count(self, pid: int, layers: list[str]) -> int:
        """
        Schätzt die tatsächliche Hop-Anzahl aus beobachtbaren Fensterattributen.
        Mehr Attribut-Flags → mehr DWM-Kompositing-Schichten aktiv.
        """
        base = len(layers)
        if not _WIN32:
            return base
        try:
            hwnd = self._find_hwnd(pid)
            if hwnd is None:
                return base
            ex_style = win32gui.GetWindowLong(hwnd, -20)  # GWL_EXSTYLE
            if ex_style & 0x00080000:   # WS_EX_LAYERED
                base -= 0
                # layered window: nutzt zusätzliche Compositing-Schicht
            cls = win32gui.GetClassName(hwnd)
            if "ApplicationFrameWindow" in cls:
                base += 1   # UWP: Zusatz-Kompositing via CoreWindow
            if ex_style & 0x00200000:   # WS_EX_NOREDIRECTIONBITMAP
                base -= 2   # Direkte Flip-Ausgabe → weniger Hops
        except Exception as e:
            logger.warning(f"[pixel_coord_optimizer] Fehler: {e}")
            pass
        return max(1, base)

    def _find_removable_layers(self, pid: int, layers: list[str]) -> list[str]:
        """Identifiziert Schichten, die für diesen Prozess nicht benötigt werden."""
        removable: list[str] = []
        if not _WIN32:
            return removable
        try:
            hwnd = self._find_hwnd(pid)
            if hwnd is None:
                return removable
            ex_style = win32gui.GetWindowLong(hwnd, -20)
            # flip_model kann übersprungen werden wenn NoRedirectionBitmap gesetzt
            if ex_style & 0x00200000 and "flip_model" in layers:
                removable.append("flip_model")
            # Composition-Batch unnötig wenn Prozess keine transparenten Bereiche hat
            if not (ex_style & 0x00080000) and "composition_batch" in layers:
                removable.append("composition_batch")
        except Exception as e:
            logger.warning(f"[pixel_coord_optimizer] Fehler: {e}")
            pass
        return removable

    def _path_score(
        self, path: PixelPath, pmap: Optional[ProcessPixelMap]
    ) -> float:
        """Kombinierter Pfad-Qualitätsscore [0, 1] — höher = besser optimiert."""
        hop_score = max(0.0, 1.0 - (path.hop_count - OPTIMAL_HOP_COUNT) / max(1, len(PATH_LAYERS_DEFAULT)))
        render_score = 1.0 - (pmap.render_cost_score if pmap else 0.5)
        return round((hop_score + render_score) / 2.0, 4)

    def _find_hwnd(self, pid: int) -> Optional[int]:
        if not _WIN32:
            return None
        found: list[int] = []
        def _cb(hwnd: int, _: Any) -> bool:
            if not win32gui.IsWindowVisible(hwnd):
                return True
            try:
                _, wpid = win32process.GetWindowThreadProcessId(hwnd)
                if wpid == pid:
                    rect = win32gui.GetWindowRect(hwnd)
                    if rect[2] - rect[0] > 0 and rect[3] - rect[1] > 0:
                        found.append(hwnd)
            except Exception as e:
                logger.warning(f"[pixel_coord_optimizer] Fehler: {e}")
                pass
            return True
        try:
            win32gui.EnumWindows(_cb, None)
        except Exception as e:
            logger.warning(f"[pixel_coord_optimizer] Fehler: {e}")
            pass
        return found[0] if found else None

    def _enumerate_user_pids(self) -> list[int]:
        if not _PSUTIL:
            return []
        SYSTEM_USERS = frozenset({"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"})
        pids = []
        for proc in psutil.process_iter(["pid", "username"]):
            try:
                info = proc.info
                username = str(info.get("username") or "")
                user_short = username.split("\\")[-1].upper()
                if user_short in SYSTEM_USERS:
                    continue
                pids.append(int(info["pid"]))
            except Exception as e:
                continue
        return pids
