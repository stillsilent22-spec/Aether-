"""process_pixel_mapper.py — MetaLayer OS Phase A: Process-to-Pixel Mapping.

Jedem Benutzerprozess wird seine Screen-Präsenz (Pixel-Region, Blockentropie,
Koordinatenpfad) zugeordnet. Keine Screenshot-Flut — nur das jeweilige
Prozessfenster wird per mss scoped erfasst, nie der gesamte Bildschirm.
"""
from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

try:
    import numpy as np
    _NUMPY = True
except ImportError:
    _NUMPY = False

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

try:
    import mss as _mss_mod
    _MSS = True
except ImportError:
    _MSS = False

try:
    import win32gui
    import win32process
    _WIN32 = True
except ImportError:
    _WIN32 = False

# ── Konstanten ────────────────────────────────────────────────────────────────

BLOCK_SIZE  = 8          # Pixel-Block-Rasterbreite (8×8 px)
MAX_BLOCKS  = 256        # Maximale Blöcke pro Fenster
SYSTEM_USERS = frozenset({"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"})


# ── Datenklassen ──────────────────────────────────────────────────────────────

@dataclass
class PixelBlock:
    """Strukturelles Merkmal eines 8×8-Pixelblocks."""
    block_id: int
    entropy: float          # Shannon-Entropie [0, 8]
    symmetry: float         # Achsensymmetrie [0, 1]
    pixel_hash: str         # SHA-256 des Blockbytes (kurz: [:12])
    coord_x: int            # Linke Kante des Blocks (Bildschirmkoordinaten)
    coord_y: int            # Obere Kante des Blocks (Bildschirmkoordinaten)

    def to_dict(self) -> dict:
        return {
            "block_id":   self.block_id,
            "entropy":    round(self.entropy, 5),
            "symmetry":   round(self.symmetry, 5),
            "pixel_hash": self.pixel_hash,
            "coord_x":    self.coord_x,
            "coord_y":    self.coord_y,
        }


@dataclass
class ProcessPixelMap:
    """Vollständiges Pixel-Profil eines Benutzerprozesses."""
    pid: int
    process_name: str
    timestamp: float
    screen_region: Dict[str, int]       # {left, top, width, height}
    pixel_blocks: List[PixelBlock] = field(default_factory=list)
    total_screen_coverage_pct: float = 0.0   # Anteil an Monitorauflösung
    render_cost_score: float = 0.0           # Proxy für GPU/Render-Last [0, 1]
    coord_path_score: float = 0.0            # DWM-Hop-Heuristik [0, 1]

    def to_dict(self) -> dict:
        return {
            "pid":                      self.pid,
            "process_name":             self.process_name,
            "timestamp":                self.timestamp,
            "screen_region":            self.screen_region,
            "pixel_blocks":             [b.to_dict() for b in self.pixel_blocks],
            "total_screen_coverage_pct": round(self.total_screen_coverage_pct, 4),
            "render_cost_score":        round(self.render_cost_score, 5),
            "coord_path_score":         round(self.coord_path_score, 5),
        }


# ── Hauptklasse ───────────────────────────────────────────────────────────────

class ProcessPixelMapper:
    """
    Ordnet jedem Benutzerprozess seine Screen-Pixel-Präsenz zu.

    Datenschutz: Kein Gesamt-Screenshot. Nur das explizite Prozessfenster
    wird erfasst. Keine Speicherung von Rohdaten über MAX_HISTORY Ticks.
    """

    MAX_HISTORY = 16

    def __init__(self) -> None:
        self._history: list[ProcessPixelMap] = []
        self._monitor_area: int = self._probe_monitor_area()

    # ── Öffentliche API ───────────────────────────────────────────────────────

    def map_process(self, pid: int, process_name: str = "") -> Optional[ProcessPixelMap]:
        """Erstellt ein ProcessPixelMap für einen einzelnen Prozess."""
        if not process_name and _PSUTIL:
            try:
                process_name = psutil.Process(pid).name()
            except Exception:
                process_name = "unknown"

        bbox = self._hwnd_to_bbox(pid)
        if bbox is None:
            # Kein sichtbares Fenster → minimales, leeres Profil zurückgeben
            return ProcessPixelMap(
                pid=pid,
                process_name=process_name,
                timestamp=time.time(),
                screen_region={},
                pixel_blocks=[],
                total_screen_coverage_pct=0.0,
                render_cost_score=0.0,
                coord_path_score=0.0,
            )

        raw = self._capture_region(bbox)
        blocks = self._compute_pixel_blocks(bbox, raw)
        coverage = self._coverage(bbox)
        render_cost = self._render_cost(blocks)
        hwnd = self._find_hwnd(pid)
        cps = self._coord_path_score(hwnd, pid) if hwnd else 0.0

        pmap = ProcessPixelMap(
            pid=pid,
            process_name=process_name,
            timestamp=time.time(),
            screen_region=bbox,
            pixel_blocks=blocks,
            total_screen_coverage_pct=coverage,
            render_cost_score=render_cost,
            coord_path_score=cps,
        )
        self._history.append(pmap)
        if len(self._history) > self.MAX_HISTORY:
            self._history.pop(0)
        return pmap

    def map_all_user_processes(self, max_count: int = 32) -> list[ProcessPixelMap]:
        """Erstellt ProcessPixelMaps für alle Benutzerprozesse mit sichtbarem Fenster."""
        results: list[ProcessPixelMap] = []
        if not _PSUTIL:
            return results
        seen: set[int] = set()
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                info = proc.info
                username = str(info.get("username") or "")
                user_short = username.split("\\")[-1].upper()
                if user_short in SYSTEM_USERS:
                    continue
                pid = int(info["pid"])
                if pid in seen:
                    continue
                seen.add(pid)
                pmap = self.map_process(pid, str(info.get("name") or ""))
                if pmap is not None:
                    results.append(pmap)
                if len(results) >= max_count:
                    break
            except Exception:
                continue
        return results

    def history_summary(self) -> dict:
        """Aggregierte Statistik der zuletzt gemappten Prozesse."""
        if not self._history:
            return {"count": 0}
        coverages = [m.total_screen_coverage_pct for m in self._history]
        return {
            "count":              len(self._history),
            "mean_coverage_pct":  round(sum(coverages) / len(coverages), 4),
            "max_coverage_pct":   round(max(coverages), 4),
        }

    # ── Fenster / Region ──────────────────────────────────────────────────────

    def _find_hwnd(self, pid: int) -> Optional[int]:
        """Gibt das primäre HWND eines Prozesses zurück (Windows only)."""
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
            except Exception:
                pass
            return True
        try:
            win32gui.EnumWindows(_cb, None)
        except Exception:
            pass
        return found[0] if found else None

    def _hwnd_to_bbox(self, pid: int) -> Optional[Dict[str, int]]:
        """Bestimmt die Bildschirm-BoundingBox des primären Fensters eines Prozesses."""
        if not _WIN32:
            return None
        hwnd = self._find_hwnd(pid)
        if hwnd is None:
            return None
        try:
            rect = win32gui.GetWindowRect(hwnd)
            left, top, right, bottom = rect
            width  = max(0, right - left)
            height = max(0, bottom - top)
            if width == 0 or height == 0:
                return None
            return {"left": left, "top": top, "width": width, "height": height}
        except Exception:
            return None

    # ── Pixel-Analyse ─────────────────────────────────────────────────────────

    def _capture_region(self, bbox: Dict[str, int]) -> bytes:
        """Scoped mss-Capture der angegebenen Region."""
        if not _MSS:
            return b""
        try:
            with _mss_mod.mss() as sct:
                monitor = {
                    "left":   int(bbox.get("left", 0)),
                    "top":    int(bbox.get("top", 0)),
                    "width":  max(1, int(bbox.get("width", 1))),
                    "height": max(1, int(bbox.get("height", 1))),
                }
                screenshot = sct.grab(monitor)
                return bytes(screenshot.raw)
        except Exception:
            return b""

    def _compute_pixel_blocks(
        self, bbox: Dict[str, int], raw: bytes
    ) -> list[PixelBlock]:
        """Zerlegt Rohdaten in 8×8-Blöcke und berechnet strukturelle Metriken."""
        blocks: list[PixelBlock] = []
        if not raw or not _NUMPY:
            return blocks

        import numpy as np

        width  = max(1, int(bbox.get("width", 1)))
        height = max(1, int(bbox.get("height", 1)))
        left   = int(bbox.get("left", 0))
        top    = int(bbox.get("top", 0))

        # raw ist BGRA (mss) oder RGB — 4 Bytes pro Pixel angenommen
        arr = np.frombuffer(raw, dtype=np.uint8)
        bytes_per_pixel = len(raw) // max(1, width * height)
        if bytes_per_pixel < 1:
            bytes_per_pixel = 4
        try:
            arr = arr.reshape((height, width, bytes_per_pixel))
        except ValueError:
            return blocks

        # Graustufen (Luma)
        if bytes_per_pixel >= 3:
            gray = (
                0.2126 * arr[:, :, 2].astype(np.float32)
                + 0.7152 * arr[:, :, 1].astype(np.float32)
                + 0.0722 * arr[:, :, 0].astype(np.float32)
            ).astype(np.uint8)
        else:
            gray = arr[:, :, 0].astype(np.uint8)

        block_id = 0
        for row in range(0, height - BLOCK_SIZE + 1, BLOCK_SIZE):
            for col in range(0, width - BLOCK_SIZE + 1, BLOCK_SIZE):
                if block_id >= MAX_BLOCKS:
                    break
                patch = gray[row : row + BLOCK_SIZE, col : col + BLOCK_SIZE].flatten()
                entropy  = float(_shannon_entropy_arr(patch))
                symmetry = float(_symmetry_arr(patch))
                phash    = hashlib.sha256(bytes(patch)).hexdigest()[:12]
                blocks.append(PixelBlock(
                    block_id = block_id,
                    entropy  = entropy,
                    symmetry = symmetry,
                    pixel_hash = phash,
                    coord_x  = left + col,
                    coord_y  = top  + row,
                ))
                block_id += 1
            else:
                continue
            break  # inner break propagated
        # outer loop — continue normally
        # (redo properly)
        blocks.clear()
        block_id = 0
        stop = False
        for row in range(0, height - BLOCK_SIZE + 1, BLOCK_SIZE):
            if stop:
                break
            for col in range(0, width - BLOCK_SIZE + 1, BLOCK_SIZE):
                if block_id >= MAX_BLOCKS:
                    stop = True
                    break
                patch = gray[row : row + BLOCK_SIZE, col : col + BLOCK_SIZE].flatten()
                entropy  = float(_shannon_entropy_arr(patch))
                symmetry = float(_symmetry_arr(patch))
                phash    = hashlib.sha256(bytes(patch)).hexdigest()[:12]
                blocks.append(PixelBlock(
                    block_id   = block_id,
                    entropy    = entropy,
                    symmetry   = symmetry,
                    pixel_hash = phash,
                    coord_x    = left + col,
                    coord_y    = top  + row,
                ))
                block_id += 1
        return blocks

    # ── Bewertungs-Hilfsfunktionen ────────────────────────────────────────────

    def _coord_path_score(self, hwnd: Optional[int], pid: int) -> float:
        """
        Schätzt die DWM-Koordinatenpfad-Komplexität (Hops zwischen Prozess
        und physischem Frame-Buffer).

        Heuristik (kein echter DWM-API-Aufruf da undokumentiert):
          - Basis-Score 0.5
          + 0.1 wenn Fenster layered (WS_EX_LAYERED)
          + 0.1 wenn Fenster composited-only (WS_EX_NOREDIRECTIONBITMAP)
          + 0.15 wenn kein Win32-Fenster (z.B. UWP/CoreWindow)
          + 0.05 wenn Prozess hohe CPU-Last → viele DWM-Redraw-Requests
        """
        if not _WIN32 or hwnd is None:
            return 0.5
        score = 0.5
        try:
            ex_style = win32gui.GetWindowLong(hwnd, -20)  # GWL_EXSTYLE
            if ex_style & 0x00080000:   # WS_EX_LAYERED
                score += 0.1
            if ex_style & 0x00200000:   # WS_EX_NOREDIRECTIONBITMAP
                score += 0.1
        except Exception:
            pass
        try:
            cls_name = win32gui.GetClassName(hwnd)
            if "ApplicationFrameWindow" in cls_name or "Windows.UI" in cls_name:
                score += 0.15
        except Exception:
            pass
        if _PSUTIL:
            try:
                cpu = psutil.Process(pid).cpu_percent(interval=None)
                score += min(0.15, cpu / 200.0)
            except Exception:
                pass
        return min(1.0, score)

    def _coverage(self, bbox: Dict[str, int]) -> float:
        """Prozentualer Anteil der Fenster-Fläche an der Hauptmonitor-Auflösung."""
        area = bbox.get("width", 0) * bbox.get("height", 0)
        return min(1.0, area / max(1, self._monitor_area))

    @staticmethod
    def _render_cost(blocks: list[PixelBlock]) -> float:
        """
        Normiertes Maß für Render-Last aus Block-Entropien.
        Hohe Entropie → wenig Komp-Potential → mehr Render-Arbeit.
        """
        if not blocks:
            return 0.0
        mean_entropy = sum(b.entropy for b in blocks) / len(blocks)
        return min(1.0, mean_entropy / 8.0)   # max Entropie = 8 bit

    @staticmethod
    def _probe_monitor_area() -> int:
        """Ermittelt die Hauptmonitor-Auflösung einmalig beim Start."""
        if _WIN32:
            try:
                import ctypes
                user32 = ctypes.windll.user32
                w = user32.GetSystemMetrics(0)
                h = user32.GetSystemMetrics(1)
                if w > 0 and h > 0:
                    return int(w) * int(h)
            except Exception:
                pass
        # Fallback: 1920×1080
        return 1920 * 1080


# ── Modul-interne Hilfsfunktionen (numpy-gestützt) ───────────────────────────

def _shannon_entropy_arr(arr: "np.ndarray") -> float:
    if not _NUMPY:
        return 0.0
    import numpy as np
    counts = np.bincount(arr.astype(np.uint8), minlength=256).astype(np.float64)
    total = float(arr.size)
    if total == 0:
        return 0.0
    probs = counts[counts > 0] / total
    return float(-np.sum(probs * np.log2(probs)))


def _symmetry_arr(arr: "np.ndarray") -> float:
    if arr.size < 2:
        return 1.0
    import numpy as np
    half = arr.size // 2
    return float(np.sum(arr[:half] == arr[-half:][::-1]) / half)
