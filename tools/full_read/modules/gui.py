"""Deterministische lokale Tkinter-GUI fuer Aether."""

from __future__ import annotations

import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Any

from .analysis_engine import AnalysisEngine, AetherFingerprint
from .log_system import LogSystem
from .preload_optimizer import PreloadOptimizer
from .registry import AetherRegistry, GENESIS_HASH
from .security_monitor import AetherSecurityMonitor
from .session_engine import SessionContext

APP_BG = "#0E141A"
APP_PANEL = "#121B22"
APP_BORDER = "#1F2A33"
APP_TEXT = "#E8ECEF"
APP_TEXT_MUTED = "#A7B0B7"
APP_ACCENT = "#2FA3B5"


class AetherGUI:
    """Schlanke Bedienoberflaeche fuer lokale deterministische Strukturpruefung."""

    def __init__(
        self,
        session_context: SessionContext,
        registry: AetherRegistry,
        log_system: LogSystem,
        analysis_engine: AnalysisEngine,
        security_monitor: AetherSecurityMonitor,
        renderer: Any | None = None,
        ae_vault: Any | None = None,
        ae_interpreter: Any | None = None,
    ) -> None:
        self.session_context = session_context
        self.registry = registry
        self.log_system = log_system
        self.analysis_engine = analysis_engine
        self.security_monitor = security_monitor
        self.renderer = renderer
        self.ae_vault = ae_vault
        self.ae_interpreter = ae_interpreter
        self.root: tk.Tk | None = None
        self.path_var: tk.StringVar | None = None
        self.status_var: tk.StringVar | None = None
        self.summary_var: tk.StringVar | None = None
        self.output_text: tk.Text | None = None
        self._latest_fingerprint: AetherFingerprint | None = None

    def _ensure_root(self) -> tk.Tk:
        if self.root is not None:
            return self.root
        self.root = tk.Tk()
        self.root.title("Aether - Deterministische Strukturanalyse")
        self.root.geometry("1080x760")
        self.root.minsize(900, 640)
        self.root.configure(bg=APP_BG)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.path_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Bereit fuer lokale Analyse.")
        self.summary_var = tk.StringVar(
            value=f"Session {self.session_context.session_id} | Nutzer {self.session_context.username} | Genesis {GENESIS_HASH[:12]}"
        )

        outer = tk.Frame(self.root, bg=APP_BG)
        outer.pack(fill="both", expand=True, padx=16, pady=16)

        header = tk.Frame(outer, bg=APP_PANEL, bd=1, relief="solid", highlightbackground=APP_BORDER)
        header.pack(fill="x", pady=(0, 12))
        tk.Label(
            header,
            text="Aether Core",
            bg=APP_PANEL,
            fg=APP_TEXT,
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w", padx=14, pady=(12, 4))
        tk.Label(
            header,
            textvariable=self.summary_var,
            bg=APP_PANEL,
            fg=APP_TEXT_MUTED,
            font=("Consolas", 10),
        ).pack(anchor="w", padx=14, pady=(0, 12))

        controls = tk.Frame(outer, bg=APP_BG)
        controls.pack(fill="x", pady=(0, 12))
        ttk.Entry(controls, textvariable=self.path_var).pack(side="left", fill="x", expand=True)
        ttk.Button(controls, text="Datei", command=self.open_file).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Analysieren", command=self.analyze_current_path).pack(side="left", padx=(8, 0))

        status = tk.Frame(outer, bg=APP_PANEL, bd=1, relief="solid", highlightbackground=APP_BORDER)
        status.pack(fill="x", pady=(0, 12))
        tk.Label(
            status,
            textvariable=self.status_var,
            bg=APP_PANEL,
            fg=APP_ACCENT,
            font=("Segoe UI", 10, "bold"),
            justify="left",
            wraplength=980,
        ).pack(anchor="w", padx=14, pady=12)

        self.output_text = tk.Text(
            outer,
            bg="#0B1115",
            fg=APP_TEXT,
            insertbackground=APP_TEXT,
            wrap="word",
            font=("Consolas", 10),
            relief="solid",
            bd=1,
        )
        self.output_text.pack(fill="both", expand=True)
        self.output_text.insert(
            "1.0",
            "Aether bleibt lokal: keine externen Inhalte, keine Live-Synthese, keine Echtzeit-Renderpfade.\n",
        )
        self.output_text.configure(state="disabled")
        return self.root

    def open_file(self) -> None:
        self._ensure_root()
        selected = filedialog.askopenfilename(title="Aether Datei waehlen")
        if selected and self.path_var is not None:
            self.path_var.set(selected)
            self._set_status(f"Datei gewaehlt: {selected}")

    def analyze_current_path(self) -> AetherFingerprint | None:
        path_value = str(self.path_var.get() if self.path_var is not None else "").strip()
        if not path_value:
            self._set_status("Keine Datei ausgewaehlt.")
            return None
        return self.analyze_path(path_value)

    def analyze_path(self, path_value: str) -> AetherFingerprint:
        source_path = Path(path_value)
        fingerprint = self.analysis_engine.analyze_file(source_path)
        self._latest_fingerprint = fingerprint
        self._render_result(source_path, fingerprint)
        self._set_status(f"Analyse abgeschlossen: {source_path.name}")
        return fingerprint

    def _render_result(
        self,
        source_path: Path,
        fingerprint: AetherFingerprint,
    ) -> None:
        payload = {
            "path": str(source_path),
            "file_hash": str(getattr(fingerprint, "file_hash", "") or ""),
            "scan_hash": str(getattr(fingerprint, "scan_hash", "") or ""),
            "symmetry_score": float(getattr(fingerprint, "symmetry_score", 0.0) or 0.0),
            "entropy_mean": float(getattr(fingerprint, "entropy_mean", 0.0) or 0.0),
            "coherence_score": float(getattr(fingerprint, "coherence_score", 0.0) or 0.0),
            "resonance_score": float(getattr(fingerprint, "resonance_score", 0.0) or 0.0),
            "ethics_score": float(getattr(fingerprint, "ethics_score", 0.0) or 0.0),
            "verdict": str(getattr(fingerprint, "verdict", "") or ""),
            "integrity_state": str(getattr(fingerprint, "integrity_state", "") or ""),
        }
        self._set_output(json.dumps(payload, ensure_ascii=False, indent=2))

    def _set_status(self, message: str) -> None:
        if self.status_var is not None:
            self.status_var.set(str(message))

    def _set_output(self, text: str) -> None:
        if self.output_text is None:
            return
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", text)
        self.output_text.configure(state="disabled")

    def run(self) -> None:
        self._ensure_root().mainloop()

    def _on_close(self) -> None:
        try:
            self.registry.close()
        except Exception:
            pass
        if self.root is not None:
            self.root.destroy()
            self.root = None


VeiraGUI = AetherGUI
