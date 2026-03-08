"""Tkinter-GUI fuer Vera Aether Core inklusive Aether-Theremin."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from uuid import uuid4

import cv2
from matplotlib import pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from PIL import Image, ImageTk

from .analysis_engine import AetherFingerprint, AnalysisEngine
from .audio_engine import AudioEngine
from .bayes_engine import BayesianBeliefEngine, BayesianBeliefSnapshot
from .agent_loop import AgentLoopEngine
from .browser_engine import BrowserEngine, BrowserSnapshot
from .chat_sync_engine import ChatRelayServer, ChatSyncClient, sync_error_text
from .conway_engine import ContinuousConway
from .device_profile import DeviceProfileEngine, RuntimePressure
from .dialog_engine import AssistantContext, StructuralDialogEngine, StructuralReply
from .embedding_engine import CrossDomainEmbeddingEngine
from .evolved_language import EvolvedLanguageEngine, EvolvedSentence
from .graph_engine import GraphFieldEngine, GraphFieldSnapshot
from .log_system import LogSystem
from .observer_engine import AnchorPoint, ObserverEngine
from .public_anchor import PublicBlockchainAnchor
from .reconstruction_engine import LosslessReconstructionEngine
from .registry import AetherRegistry, GENESIS_HASH, compute_chain_block_hash
from .security_monitor import AetherSecurityMonitor
from .session_engine import SessionContext
from .shanway import ShanwayAssessment, ShanwayEngine
from .symbol_grounding import SymbolGroundingLayer
from .spectrum_engine import SpectrumEngine
from .spacetime_renderer import RenderScene, SpacetimeRenderer
from .storage_gp import DualModeStorageEngine
from .theremin_engine import ThereminEngine, ThereminFrameState
from .vault_chain import AetherAugmentor
from .voxel_grid import VoxelGrid4D
from .ae_evolution_core import AEAlgorithmVault, AetherAnchorInterpreter
from .aelab_legacy import iter_legacy_dna_files, parse_legacy_dna_file

try:
    import speech_recognition as sr
except Exception:
    sr = None

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    TKDND_AVAILABLE = True
except Exception:
    DND_FILES = "DND_Files"
    TkinterDnD = None
    TKDND_AVAILABLE = False


class VeiraGUI:
    """Stellt die komplette Bedienoberflaeche fuer Analyse, Spektrum und Theremin bereit."""

    def __init__(
        self,
        session_context: SessionContext,
        registry: AetherRegistry,
        log_system: LogSystem,
        renderer: SpacetimeRenderer,
        audio_engine: AudioEngine,
        analysis_engine: AnalysisEngine,
        security_monitor: AetherSecurityMonitor,
        ae_vault: AEAlgorithmVault = None,
        ae_interpreter: AetherAnchorInterpreter = None,
    ) -> None:
        """Initialisiert Fenster, Widgets und Laufzeitabhaengigkeiten."""
        self.session_context = session_context
        self.registry = registry
        self.log_system = log_system
        self.renderer = renderer
        self.audio_engine = audio_engine
        self.analysis_engine = analysis_engine
        self.security_monitor = security_monitor
        self.spectrum_engine = SpectrumEngine(session_context=session_context)
        self.voxel_grid = VoxelGrid4D()
        self.observer_engine = ObserverEngine()
        self.bayes_engine = BayesianBeliefEngine()
        self.conway_engine = ContinuousConway()
        self.dialog_engine = StructuralDialogEngine(registry=registry)
        self.shanway_engine = ShanwayEngine()
        self.embedding_engine = CrossDomainEmbeddingEngine(session_context.seed)
        self.graph_engine = GraphFieldEngine()
        self.reconstruction_engine = LosslessReconstructionEngine()
        self.device_profile_engine = DeviceProfileEngine()
        self.device_profile = self.device_profile_engine.detect()
        self.browser_engine = BrowserEngine()
        self.chat_sync_client = ChatSyncClient()
        self.chat_relay_server = ChatRelayServer(str(Path("data") / "chat_relay_events.jsonl"))
        self.public_anchor = PublicBlockchainAnchor(str(Path("data") / "public_anchor_settings.json"))
        self.symbol_grounding = SymbolGroundingLayer(str(Path("data") / "symbol_grounding.json"))
        self.language_engine = EvolvedLanguageEngine(str(Path("data") / "evolved_language.json"), session_context.seed)
        self.storage_gp_engine = DualModeStorageEngine(session_context.seed)
        self.agent_loop = AgentLoopEngine()
        self.augmentor = AetherAugmentor(session_context, registry)
        self.theremin_engine = ThereminEngine(
            session_context=session_context,
            spectrum_engine=self.spectrum_engine,
            registry=registry,
            audio_engine=audio_engine,
        )
        self.ae_vault = ae_vault or AEAlgorithmVault()
        self.ae_interpreter = ae_interpreter or AetherAnchorInterpreter(self.ae_vault)

        self.root = TkinterDnD.Tk() if TKDND_AVAILABLE and TkinterDnD is not None else tk.Tk()
        self.root.title("Aether - Raumzeit-Analyse")
        self.root.geometry("1560x900")
        self.root.minsize(1260, 760)
        self.root.configure(bg="#0A0F2E")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.path_var = tk.StringVar(value="")
        self.loading_var = tk.StringVar(value="Bereit.")
        self.restore_status_var = tk.StringVar(value="Original-Open: kein Dateidatensatz")
        self.raw_storage_status_var = tk.StringVar(value="Dual-Mode: Delta-only")
        self.history_status_var = tk.StringVar(value="Historie: keine Eintraege")
        self.honeypot_var = tk.StringVar(value="Diagnostik: ruhig")
        self.state_var = tk.StringVar(value="Symmetrisches Feld - keine Anomalien erkannt")
        self.semantic_state_var = tk.StringVar(value="Semantik: --")
        self.beauty_state_var = tk.StringVar(value="Schoenheit: --")
        self.graph_region_var = tk.StringVar(value="Graph-Region: --")
        self.graph_phase_var = tk.StringVar(value="Graph-Phase: --")
        self.graph_attractor_var = tk.StringVar(value="Attraktoren: --")
        self.bayes_anchor_var = tk.StringVar(value="Bayes-Prior: --")
        self.bayes_phase_var = tk.StringVar(value="Bayes-Phase: --")
        self.bayes_pattern_var = tk.StringVar(value="Bayes-Muster: --")
        self.bayes_alarm_var = tk.StringVar(value="Bayes-Alarm: --")
        self.model_depth_var = tk.StringVar(value="Modelltiefe: --")
        self.delta_learning_var = tk.StringVar(value="Delta-Lernen: --")
        self.anomaly_memory_var = tk.StringVar(value="Immungedaechtnis: --")
        self.collective_status_var = tk.StringVar(value="Collective: 0 Snapshots | keine Priors aktiv")
        self.theremin_state_var = tk.StringVar(value="Theremin: inaktiv")
        self.wavelength_var = tk.StringVar(value="Dominante Wellenlaenge: -- nm")
        self.sensitivity_var = tk.DoubleVar(value=1.0)
        self.harmony_var = tk.DoubleVar(value=0.65)
        self.storage_layer_var = tk.StringVar(value="Raw Deltas")
        self.symmetry_monitor_var = tk.DoubleVar(value=0.0)
        self.coherence_monitor_var = tk.DoubleVar(value=0.0)
        self.resonance_monitor_var = tk.DoubleVar(value=0.0)
        self.integrity_score_var = tk.StringVar(value="0.0")
        self.integrity_text_var = tk.StringVar(value="Strukturell gesund")
        self.beauty_signature_var = tk.StringVar(value="Beauty 7D: --")
        self.observer_gap_var = tk.StringVar(value="H_lambda: --")
        self.ae_anchor_status_var = tk.StringVar(value="AELAB-Anker: --")
        self.ae_iteration_var = tk.StringVar(value="AELAB Iteration: idle")
        self.ae_stop_button_var = tk.StringVar(value="Stop Iterationen")
        self.header_key_var = tk.StringVar(value=f"KEY {self.augmentor.key_fingerprint}")
        self.header_user_var = tk.StringVar(
            value=f"USER {self.session_context.username} | ROLE {self.session_context.user_role.upper()}"
        )
        self.header_assistant_var = tk.StringVar(value="ASSIST Shanway")
        self.header_vault_var = tk.StringVar(value="VAULT 0")
        self.header_chain_var = tk.StringVar(value="F-CHAIN 0")
        self.header_anchor_var = tk.StringVar(value="ANCHOR Q0")
        self.header_alarm_var = tk.StringVar(value="ALARMS 0")
        self.header_named_var = tk.StringVar(value="NAMED 0 / TOTAL 0")
        self.header_ontology_var = tk.StringVar(value="")
        self.header_device_var = tk.StringVar(value=f"{self.device_profile.label} | {self.device_profile.detail}")
        self.header_security_var = tk.StringVar(
            value=(
                f"{self.session_context.security_mode} | "
                f"{self.session_context.trust_state} | "
                f"MAZE {self.session_context.maze_state}"
            )
        )
        self.browser_url_var = tk.StringVar(value="https://example.org")
        self.browser_lock_var = tk.StringVar(value="🔒")
        self.browser_ct_var = tk.StringVar(value="C(t): --")
        self.browser_d_var = tk.StringVar(value="D: --")
        self.browser_recon_var = tk.StringVar(value="RECON: ✗")
        self.browser_status_var = tk.StringVar(value="Shanway Browser bereit")
        self.browser_title_var = tk.StringVar(value="Kein Seitentitel")
        self.browser_dock_var = tk.BooleanVar(value=False)
        self.raw_storage_enabled_var = tk.BooleanVar(
            value=bool(getattr(self.session_context, "raw_storage_enabled", False))
        )
        self.camera_toggle_var = tk.BooleanVar(value=False)
        self.agent_toggle_var = tk.BooleanVar(value=False)
        self.camera_mirror_var = tk.BooleanVar(value=True)
        self.camera_theremin_var = tk.BooleanVar(value=False)
        self.metric_h0_var = tk.StringVar(value="--")
        self.metric_ht_var = tk.StringVar(value="--")
        self.metric_ct_var = tk.StringVar(value="--")
        self.metric_d_var = tk.StringVar(value="--")
        self.metric_phi_var = tk.StringVar(value="--")
        self.metric_freq_var = tk.StringVar(value="--")
        self.metric_detune_var = tk.StringVar(value="--")
        self.metric_prior_var = tk.StringVar(value="--")
        self.metric_anchor_count_var = tk.StringVar(value="0")
        self.metric_benford_var = tk.StringVar(value="--")
        self.metric_runtime_var = tk.StringVar(value="--")
        self.metric_recon_var = tk.StringVar(value="✗")
        self.metric_resolved_var = tk.StringVar(value="0")
        self.pattern_found_var = tk.StringVar(value="")
        self.recon_status_var = tk.StringVar(value="RECON: ✗")
        self.coherence_live_var = tk.DoubleVar(value=0.0)
        self.h_obs_live_var = tk.DoubleVar(value=0.0)
        self.voice_status_var = tk.StringVar(value="GP-Systemsprache | 100 Generationen | 100 Baeume | kein LLM")
        self.voice_sentence_vars = [tk.StringVar(value=""), tk.StringVar(value=""), tk.StringVar(value="")]
        self.chat_input_var = tk.StringVar(value="")
        self.chat_channel_var = tk.StringVar(value="# global")
        self.chat_status_var = tk.StringVar(value="Shanway bereit | lokal | ohne LLM")
        self.chat_reply_var = tk.StringVar(value="Shanway: --")
        self.chat_semantic_var = tk.StringVar(value="Semantik: -- | Schoenheit: --")
        self.chat_channel_note_var = tk.StringVar(value="Kanal: global | oeffentlich")
        self.shanway_corpus_var = tk.StringVar(value="Corpus: 0 de | 0 en")
        self.shanway_enabled_var = tk.BooleanVar(
            value=bool(getattr(self.session_context, "user_settings", {}).get("shanway_enabled", False))
        )
        self.shanway_browser_mode_var = tk.BooleanVar(value=False)
        self.shanway_sensitive_var = tk.StringVar(value="Shanway Guard: bereit")
        self.chat_sync_url_var = tk.StringVar(
            value=str(getattr(self.session_context, "user_settings", {}).get("chat_sync_url", "") or "")
        )
        self.chat_sync_port_var = tk.StringVar(
            value=str(getattr(self.session_context, "user_settings", {}).get("chat_sync_port", "8765") or "8765")
        )
        self.chat_sync_secret_var = tk.StringVar(value="")
        self.chat_sync_status_var = tk.StringVar(value="Mehrrechner-Sync: aus")
        self.security_key_var = tk.StringVar(
            value=(
                f"LIVE {self.session_context.live_session_fingerprint or 'LOCAL'} | "
                f"{'/'.join(getattr(self.session_context, 'login_algorithms', ('sha256', 'blake2b')))}"
            )
        )
        self.security_node_var = tk.StringVar(value=f"NODE {self.session_context.node_id[:16] or '--'}")
        self.security_trust_var = tk.StringVar(value=f"TRUST {self.session_context.trust_state}")
        self.security_maze_var = tk.StringVar(value=f"DIAG {self.session_context.maze_state}")
        self.security_summary_var = tk.StringVar(value=str(getattr(self.session_context, "security_summary", "")))
        self.security_mode_choice_var = tk.StringVar(value=str(getattr(self.session_context, "security_mode", "PROD")))

        self.analysis_thread: threading.Thread | None = None
        self.browser_analysis_thread: threading.Thread | None = None
        self.chat_sync_job: str | None = None
        self.chat_sync_connected = False
        self.chat_sync_last_url = ""
        self.chat_sync_polling = False
        self.spectrum_thread: threading.Thread | None = None
        self.csv_thread: threading.Thread | None = None
        self.speech_thread: threading.Thread | None = None
        self.chat_thread: threading.Thread | None = None
        self.shanway_corpus_thread: threading.Thread | None = None
        self.current_canvas: FigureCanvasTkAgg | None = None
        self.current_figure = None
        self.current_fingerprint: AetherFingerprint | None = None
        self.ae_anchor_text: tk.Text | None = None
        self.ae_stop_button: tk.Button | None = None
        self.animation_scene: RenderScene | None = None
        self.animation_job: str | None = None
        self.camera_capture: cv2.VideoCapture | None = None
        self.camera_job: str | None = None
        self.conway_job: str | None = None
        self.browser_poll_job: str | None = None
        self.browser_flash_job: str | None = None
        self.browser_host_sync_job: str | None = None
        self.camera_image_ref = None
        self.conway_image_ref = None
        self.current_h_obs = 0.0
        self.current_phi = 0.0
        self.last_observer_metrics = None
        self.last_reconstruction_verified = False
        self.last_file_anchors: list[AnchorPoint] = []
        self.vault_entries_cache: list[dict[str, object]] = []
        self.cluster_variances_cache: dict[str, float] = {}
        self._latest_agent_token = ""
        self._alarm_reset_job: str | None = None
        self._last_agent_resolved_count = 0
        self._language_job_id = 0
        self._browser_job_id = 0
        self._voice_card_refs: list[tk.Frame] = []
        self._browser_address_frames: list[tk.Frame] = []
        self._latest_file_record_id: int | None = None
        self._selected_vault_entry_id: int | None = None
        self._selected_chain_block_id: int | None = None
        self.history_entries_cache: list[dict[str, object]] = []
        self.history_index = -1
        self._vault_line_map: dict[int, dict[str, object]] = {}
        self._chain_line_map: dict[int, dict[str, object]] = {}
        self._previous_theremin_anchors: list[AnchorPoint] = []
        self._runtime_pressure: RuntimePressure | None = None
        self._runtime_delay_scale = 1.0
        self._runtime_fps_scale = 1.0
        self._last_runtime_loop = ""
        self._last_runtime_sample_at = 0.0
        self._last_named_total = self.symbol_grounding.named_counts()
        self._last_ontology_complete = self.symbol_grounding.ontology_complete()
        self._known_opposite_pairs = {
            tuple(sorted(pair)) for pair in self.symbol_grounding.opposite_pairs()
        }
        self._last_graph_snapshot: GraphFieldSnapshot | None = None
        self._last_bayes_snapshot: BayesianBeliefSnapshot | None = None
        self._last_pattern_cluster = None
        self._last_similarity_best = 0.0
        self._model_depth_report: dict[str, object] = {}
        self._delta_learning_curve: dict[str, object] = {}
        self._anomaly_memory_cache: list[dict[str, object]] = []
        self._delta_ratio_series: list[float] = []
        self.learning_curve_canvas: tk.Canvas | None = None
        self.anomaly_memory_label: tk.Label | None = None
        self.chat_channels_cache: list[dict[str, object]] = []
        self.chat_channel_map: dict[str, dict[str, object]] = {}
        self._last_dual_storage_decision: dict[str, object] = {}
        self._updating_security_mode = False

        self._configure_styles()
        self.renderer.set_storage_layer(self.storage_layer_var.get())
        self.session_context.generate_honeypots()
        self._build_layout()
        self._apply_collective_feedback()
        self._apply_security_snapshot()
        self._refresh_shanway_corpus_status()
        self._render_placeholder()
        self._refresh_recent_logs()
        self._refresh_restore_status()
        self._refresh_history_cache()
        self._setup_drag_and_drop()
        self._build_augment_window()
        self._refresh_augment_views()
        self._refresh_chat_channels()
        self._refresh_chat_view()
        self._prime_language_panel()
        self._apply_raw_storage_mode_label(bool(self.raw_storage_enabled_var.get()))
        if self.device_profile.low_end:
            self.loading_var.set(
                f"{self.device_profile.label}: Alle Funktionen bleiben aktiv, die Darstellung laeuft nur gedrosselt."
            )
        self.root.after(1200, self._bootstrap_public_anchor_cycle)

    @staticmethod
    def _ae_anchor_preview(anchors: list[dict[str, object]], limit: int = 3) -> str:
        """Verdichtet AELAB-Anker fuer interne Texte."""
        parts: list[str] = []
        for anchor in list(anchors)[: max(1, int(limit))]:
            anchor_type = str(anchor.get("type_label", anchor.get("type", ""))).strip()
            origin = str(anchor.get("origin", "")).strip()
            if anchor_type and origin:
                parts.append(f"{anchor_type} via {origin}")
            elif anchor_type:
                parts.append(anchor_type)
        return " | ".join(parts)

    @staticmethod
    def _ae_guard_preview(summary: dict[str, object]) -> str:
        """Verdichtet die AE-Kontrollschicht fuer sichtbare Statuszeilen."""
        noether = float(summary.get("noether_mean", 0.0) or 0.0) * 100.0
        dual = float(summary.get("dual_path_mean", 0.0) or 0.0) * 100.0
        uncertainty = float(summary.get("heisenberg_mean", 0.0) or 0.0) * 100.0
        ready = int(summary.get("main_ready", 0) or 0)
        quarantined = int(summary.get("quarantined_total", 0) or 0)
        return f"Λ {noether:.0f}% | Δ {dual:.0f}% | U {uncertainty:.0f}% | M {ready} | Q {quarantined}"

    @staticmethod
    def _ae_constant_display_label(raw_label: str) -> str:
        """Mappt interne Konstantenlabels auf lesbare UI-Namen."""
        mapping = {
            "PI": "pi",
            "E": "e",
            "PHI": "phi",
            "LOG2": "log2",
        }
        return str(mapping.get(str(raw_label or "").upper(), str(raw_label or "emergent").lower()))

    @staticmethod
    def _ae_probe_payload_from_fingerprint(fingerprint: AetherFingerprint) -> dict[str, object]:
        """Verdichtet einen Fingerprint zu einem stabilen AELAB-Eingabepayload."""
        return {
            "source_type": str(getattr(fingerprint, "source_type", "file")),
            "source_label": str(getattr(fingerprint, "source_label", "")),
            "file_hash": str(getattr(fingerprint, "file_hash", "")),
            "integrity_state": str(getattr(fingerprint, "integrity_state", "")),
            "integrity_text": str(getattr(fingerprint, "integrity_text", "")),
            "ethics_score": float(getattr(fingerprint, "ethics_score", 0.0) or 0.0),
            "entropy_mean": float(getattr(fingerprint, "entropy_mean", 0.0) or 0.0),
            "periodicity": int(getattr(fingerprint, "periodicity", 0) or 0),
            "delta_ratio": float(getattr(fingerprint, "delta_ratio", 0.0) or 0.0),
            "beauty_signature": dict(getattr(fingerprint, "beauty_signature", {}) or {}),
            "observer_mutual_info": float(getattr(fingerprint, "observer_mutual_info", 0.0) or 0.0),
            "observer_knowledge_ratio": float(getattr(fingerprint, "observer_knowledge_ratio", 0.0) or 0.0),
            "h_lambda": float(getattr(fingerprint, "h_lambda", 0.0) or 0.0),
            "observer_state": str(getattr(fingerprint, "observer_state", "")),
        }

    def _resolve_ae_anchor_entries(self, fingerprint: AetherFingerprint | None) -> list[dict[str, object]]:
        """Liest normalisierte AE-Anker aus einem Fingerprint."""
        if fingerprint is None:
            return []
        summary = dict(getattr(fingerprint, "ae_lab_summary", {}) or {})
        return [dict(item) for item in list(summary.get("anchors", []) or []) if isinstance(item, dict)]

    def _build_ae_anchor_stars(self, anchors: list[dict[str, object]]) -> list[dict[str, object]]:
        """Mappt AE-Anker auf getrennte Sternpunkte fuer Renderer und AV-Schicht."""
        nearest_seed = {"PI": 3, "E": 7, "PHI": 11, "LOG2": 13}
        stars: list[dict[str, object]] = []
        for index, anchor in enumerate(list(anchors)[:24]):
            value = float(anchor.get("value", 0.0) or 0.0)
            deviation = float(anchor.get("deviation", 0.0) or 0.0)
            nearest = str(anchor.get("nearest_constant", "PI") or "PI")
            seed = int(nearest_seed.get(nearest, 5))
            x_norm = max(0.0, min(1.0, (((index * 3) + seed) % 16) / 15.0))
            y_norm = max(0.0, min(1.0, (((index * 2) + (seed * 2)) % 16) / 15.0))
            confidence = max(0.45, min(0.98, 1.0 - min(1.0, deviation / 0.25)))
            pulse_scale = 1.45 if str(anchor.get("type_label", "")) == "EMERGENT" else 1.0
            stars.append(
                {
                    "x": float(x_norm),
                    "y": float(y_norm),
                    "z": float(max(0.62, min(0.98, 0.74 + (0.22 * confidence)))),
                    "t_norm": float((index % 8) / 7.0 if index > 0 else 0.0),
                    "base_frequency": float(max(110.0, min(3520.0, abs(value) * 110.0))),
                    "volume": float(0.78 + (0.16 * confidence)),
                    "reverb_depth": 0.12,
                    "confidence": float(confidence),
                    "pulse_scale": float(pulse_scale),
                    "type_label": str(anchor.get("type_label", "EMERGENT")),
                }
            )
        return stars

    def _refresh_ae_anchor_panel(self, anchors: list[dict[str, object]]) -> None:
        """Aktualisiert das sichtbare AELAB-Anchor-Panel."""
        if self.ae_anchor_text is None:
            return
        self.ae_anchor_text.configure(state="normal")
        self.ae_anchor_text.delete("1.0", tk.END)
        self.ae_anchor_text.tag_config("emergent", foreground="#F2C14E")
        self.ae_anchor_text.tag_config("constant", foreground="#9FD6FF")
        if not anchors:
            self.ae_anchor_status_var.set("AELAB-Anker: keine aktiven Konstantenanker")
            self.ae_anchor_text.insert("1.0", "Keine AE-Anker im aktuellen Kontext.\n")
            self.ae_anchor_text.configure(state="disabled")
            return
        self.ae_anchor_status_var.set(
            f"AELAB-Anker {len(anchors)} | {self._ae_anchor_preview(list(anchors), limit=2) or 'aktiv'}"
        )
        for anchor in list(anchors)[:12]:
            nearest_label = self._ae_constant_display_label(str(anchor.get("nearest_constant", "PI")))
            line = (
                f"#{int(anchor.get('index', 0)):02d} "
                f"{float(anchor.get('value', 0.0) or 0.0):.12f} | "
                f"{str(anchor.get('type_label', 'EMERGENT'))} | "
                f"{nearest_label} "
                f"D{float(anchor.get('deviation', 0.0) or 0.0):.6g}\n"
            )
            start = self.ae_anchor_text.index(tk.END)
            self.ae_anchor_text.insert(tk.END, line)
            end = self.ae_anchor_text.index(tk.END)
            if str(anchor.get("type_label", "")) == "EMERGENT":
                self.ae_anchor_text.tag_add("emergent", start, end)
            else:
                self.ae_anchor_text.tag_add("constant", start, end)
        self.ae_anchor_text.configure(state="disabled")

    def _set_ae_stop_button_state(self, button_text: str, enabled: bool) -> None:
        """Setzt den sichtbaren Zustand des AE-Stop-Buttons robust."""
        self.ae_stop_button_var.set(str(button_text))
        if self.ae_stop_button is None:
            return
        self.ae_stop_button.configure(
            state=("normal" if enabled else "disabled"),
            bg=("#AA2E25" if enabled else "#666666"),
            activebackground=("#7B241C" if enabled else "#666666"),
            cursor=("hand2" if enabled else "arrow"),
        )

    def _apply_ae_snapshot_to_current_fingerprint(self, snapshot: dict[str, object]) -> None:
        """Spiegelt einen aktuellen AE-Snapshot in den geladenen Fingerprint zurueck."""
        if self.current_fingerprint is None:
            return
        current_summary = dict(getattr(self.current_fingerprint, "ae_lab_summary", {}) or {})
        current_summary.update(
            {
                "main_vault_size": int(snapshot.get("main_vault_size", 0) or 0),
                "sub_vault_size": int(snapshot.get("sub_vault_size", 0) or 0),
                "anchor_count": int(snapshot.get("anchor_count", 0) or 0),
                "top_anchor_types": list(snapshot.get("top_anchor_types", [])),
                "top_origins": list(snapshot.get("top_origins", [])),
                "anchor_preview": self._ae_anchor_preview(list(snapshot.get("anchors", []))),
                "anchors": list(snapshot.get("anchors", [])),
                "dna_export_path": str(snapshot.get("dna_export_path", "")),
                "noether_mean": float(snapshot.get("noether_mean", 0.0) or 0.0),
                "heisenberg_mean": float(snapshot.get("heisenberg_mean", 0.0) or 0.0),
                "dual_path_mean": float(snapshot.get("dual_path_mean", 0.0) or 0.0),
                "posterior_mean": float(snapshot.get("posterior_mean", 0.0) or 0.0),
                "benford_mean": float(snapshot.get("benford_mean", 0.0) or 0.0),
                "main_ready": int(snapshot.get("main_ready", 0) or 0),
                "sub_only": int(snapshot.get("sub_only", 0) or 0),
                "rejected": int(snapshot.get("rejected", 0) or 0),
                "quarantined_total": int(snapshot.get("quarantined_total", 0) or 0),
                "iteration": int(snapshot.get("iteration", 0) or 0),
                "phase": str(snapshot.get("phase", "")),
                "stopped": bool(snapshot.get("stopped", False)),
            }
        )
        setattr(self.current_fingerprint, "ae_lab_summary", current_summary)
        setattr(
            self.current_fingerprint,
            "ae_lab_summary_text",
            (
                f"{int(current_summary.get('anchor_count', 0) or 0)} Anker | "
                f"{int(current_summary.get('main_vault_size', 0) or 0)} stabile Algorithmen | "
                f"{current_summary.get('anchor_preview', '') or 'keine dominanten AE-Anker'} | "
                f"{self._ae_guard_preview(current_summary)}"
            ),
        )
        setattr(
            self.current_fingerprint,
            "ae_anchor_stars",
            self._build_ae_anchor_stars(list(current_summary.get("anchors", []))),
        )
        self._update_scene_fingerprint(self.current_fingerprint)
        self._update_semantic_status(
            self.current_fingerprint,
            source_text=str(getattr(self.current_fingerprint, "source_label", "")),
        )
        self._refresh_augment_views()

    def _import_legacy_dna_file(
        self,
        file_path: str,
        sync_registry: bool = False,
    ) -> dict[str, object]:
        """Importiert eine einzelne alte DNA-Datei in Registry und neuen AE-Vault."""
        legacy = parse_legacy_dna_file(file_path)
        payload = legacy.to_payload()
        archive_path = self.ae_vault.archive_legacy_dna(
            source_path=str(file_path),
            bucket=str(legacy.bucket),
            legacy_id=str(legacy.legacy_id),
        )
        payload["archive_path"] = str(archive_path)
        record_id = self.registry.save_legacy_ae_dna_record(
            session_id=str(self.session_context.session_id),
            user_id=int(getattr(self.session_context, "user_id", 0) or 0),
            source_path=str(file_path),
            source_label=Path(file_path).name,
            bucket=str(legacy.bucket),
            dna_payload=payload,
            dna_text=str(legacy.dna_text),
        )
        candidate = self.ae_vault.integrate_legacy_dna(payload, bucket=str(legacy.bucket))
        candidate.params["dna_record_id"] = int(record_id)
        candidate.params["source_path"] = str(file_path)
        candidate.params["source_label"] = Path(file_path).name
        candidate.params["archive_path"] = str(archive_path)
        if sync_registry:
            self._sync_ae_vault_registry()
        return {
            "legacy": legacy,
            "payload": payload,
            "record_id": int(record_id),
            "archive_path": str(archive_path),
        }

    def _sync_ae_vault_registry(self) -> None:
        """Persistiert Main- und Sub-Vault additiv in die Registry."""
        try:
            self.registry.sync_ae_vault_state(
                session_id=str(self.session_context.session_id),
                user_id=int(getattr(self.session_context, "user_id", 0) or 0),
                ae_state=self.ae_vault.export_state(),
            )
        except Exception:
            return

    def _attest_fingerprint_with_anchors(self, fingerprint: AetherFingerprint, record_id: int | None = None) -> None:
        """Attestiert den Fingerprint erst nach AE-Anker-Anreicherung lokal auf der Fingerprint-Chain."""
        chain = getattr(self.analysis_engine, "chain", None)
        if chain is None or not getattr(chain, "connected", False):
            return
        if not fingerprint.submit_to_chain(chain):
            return
        if record_id is not None and int(record_id) > 0:
            self.registry.update_fingerprint_payload(
                int(record_id),
                {
                    "ae_lab_summary": dict(getattr(fingerprint, "ae_lab_summary", {}) or {}),
                    "local_chain_tx_hash": str(getattr(fingerprint, "local_chain_tx_hash", "")),
                    "local_chain_prev_hash": str(getattr(fingerprint, "local_chain_prev_hash", "")),
                    "local_chain_endpoint": str(getattr(fingerprint, "local_chain_endpoint", "")),
                    "local_chain_attested_at": str(getattr(fingerprint, "local_chain_attested_at", "")),
                },
            )

    def _stop_ae_evolution(self) -> None:
        """Fordert den fruehzeitigen Abbruch einer laufenden oder naechsten AE-Evolution an."""
        stop_info = dict(self.ae_vault.request_stop())
        iteration = int(stop_info.get("current_iteration", 0) or 0)
        phase = str(stop_info.get("phase", "idle") or "idle")
        probe = None
        anchors: list[dict[str, object]] = []
        if self.current_fingerprint is not None:
            probe = self._ae_probe_payload_from_fingerprint(self.current_fingerprint)
            anchors = list(
                dict(getattr(self.current_fingerprint, "ae_lab_summary", {}) or {}).get("anchors", []) or []
            )
        export_path = self.ae_vault.export_anchor_snapshot(anchors=anchors, data=probe)
        self.ae_iteration_var.set(
            f"AELAB gestoppt bei Iteration {iteration} | Phase {phase}"
            + (f" | DNA {Path(export_path).name}" if export_path else "")
        )
        self.loading_var.set(
            f"AE-Stop angefordert | Iteration {iteration} | Phase {phase}"
            + (f" | Export {Path(export_path).name}" if export_path else "")
        )
        self._set_ae_stop_button_state(f"Gestoppt (Iteration {iteration})", enabled=False)

    def _run_ae_lab(
        self,
        fingerprint: AetherFingerprint,
        anchors: list[AnchorPoint],
        graph_snapshot: GraphFieldSnapshot,
        bayes_snapshot: BayesianBeliefSnapshot,
        similarity_best: float,
        pattern,
        token_info: dict[str, object] | None,
        model_depth_report: dict[str, object],
        delta_learning_curve: dict[str, object],
        anomaly_memory: list[dict[str, object]],
    ) -> dict[str, object]:
        """Fuettert AELAB nur intern mit Anchors und Kontextdaten."""
        self._set_ae_stop_button_state("Stop Iterationen", enabled=True)
        self.ae_iteration_var.set("AELAB Iteration: laeuft")
        ae_payload = {
            "source_type": str(getattr(fingerprint, "source_type", "file")),
            "source_label": str(getattr(fingerprint, "source_label", "")),
            "file_hash": str(getattr(fingerprint, "file_hash", "")),
            "integrity_state": str(getattr(fingerprint, "integrity_state", "")),
            "integrity_text": str(getattr(fingerprint, "integrity_text", "")),
            "ethics_score": float(getattr(fingerprint, "ethics_score", 0.0) or 0.0),
            "entropy_mean": float(getattr(fingerprint, "entropy_mean", 0.0) or 0.0),
            "periodicity": int(getattr(fingerprint, "periodicity", 0) or 0),
            "delta_ratio": float(getattr(fingerprint, "delta_ratio", 0.0) or 0.0),
            "beauty_signature": dict(getattr(fingerprint, "beauty_signature", {}) or {}),
            "observer_mutual_info": float(getattr(fingerprint, "observer_mutual_info", 0.0) or 0.0),
            "observer_knowledge_ratio": float(getattr(fingerprint, "observer_knowledge_ratio", 0.0) or 0.0),
            "h_lambda": float(getattr(fingerprint, "h_lambda", 0.0) or 0.0),
            "observer_state": str(getattr(fingerprint, "observer_state", "")),
            "anchor_count": int(len(anchors)),
            "anchors": [
                {
                    "x": round(float(anchor.x), 4),
                    "y": round(float(anchor.y), 4),
                    "z": round(float(anchor.z), 4),
                    "tau": round(float(anchor.tau), 4),
                    "strength": round(float(anchor.strength), 5),
                    "confidence": round(float(anchor.confidence), 5),
                    "interference": round(float(anchor.interference), 5),
                    "label": str(anchor.interference_label),
                }
                for anchor in anchors[:24]
            ],
            "graph_phase_state": str(graph_snapshot.phase_state),
            "graph_region": str(graph_snapshot.region_label),
            "graph_attractor_score": float(graph_snapshot.attractor_score),
            "graph_stable_subgraphs": int(graph_snapshot.stable_subgraphs),
            "graph_interference_mean": float(graph_snapshot.interference_mean),
            "bayes_anchor_posterior": float(bayes_snapshot.anchor_posterior),
            "bayes_graph_phase": str(bayes_snapshot.graph_phase_label),
            "bayes_graph_confidence": float(bayes_snapshot.graph_phase_confidence),
            "bayes_pattern_posterior": float(bayes_snapshot.pattern_posterior),
            "bayes_interference_posterior": float(bayes_snapshot.interference_posterior),
            "bayes_alarm_posterior": float(bayes_snapshot.alarm_posterior),
            "pattern_label": str(getattr(pattern, "label", "")) if pattern is not None else "",
            "pattern_members": list(getattr(pattern, "members", []))[:6] if pattern is not None else [],
            "similarity_best": float(similarity_best),
            "token": str(token_info.get("token", "")) if token_info else "",
            "token_name": str(token_info.get("human_name", "")) if token_info else "",
            "model_depth_label": str(model_depth_report.get("depth_label", "")),
            "model_depth_score": float(model_depth_report.get("depth_score", 0.0) or 0.0),
            "delta_learning_label": str(delta_learning_curve.get("trend_label", "")),
            "delta_learning_ratio": float(delta_learning_curve.get("improvement_ratio", 0.0) or 0.0),
            "anomaly_memory": list(anomaly_memory[:3]),
            "security_mode": str(getattr(self.session_context, "security_mode", "PROD")),
            "trust_state": str(getattr(self.session_context, "trust_state", "TRUSTED")),
            "maze_state": str(getattr(self.session_context, "maze_state", "NONE")),
        }
        snapshot = dict(self.ae_vault.evolve(ae_payload) or self.ae_vault.snapshot(ae_payload, limit=12))
        ae_anchors = list(snapshot.get("anchors", []))
        summary = {
            "active": True,
            "main_vault_size": int(snapshot.get("main_vault_size", 0) or 0),
            "sub_vault_size": int(snapshot.get("sub_vault_size", 0) or 0),
            "anchor_count": int(snapshot.get("anchor_count", 0) or 0),
            "top_anchor_types": list(snapshot.get("top_anchor_types", [])),
            "top_origins": list(snapshot.get("top_origins", [])),
            "anchor_preview": self._ae_anchor_preview(ae_anchors),
            "anchors": ae_anchors,
            "dna_export_path": str(snapshot.get("dna_export_path", "")),
            "noether_mean": float(snapshot.get("noether_mean", 0.0) or 0.0),
            "heisenberg_mean": float(snapshot.get("heisenberg_mean", 0.0) or 0.0),
            "dual_path_mean": float(snapshot.get("dual_path_mean", 0.0) or 0.0),
            "posterior_mean": float(snapshot.get("posterior_mean", 0.0) or 0.0),
            "benford_mean": float(snapshot.get("benford_mean", 0.0) or 0.0),
            "main_ready": int(snapshot.get("main_ready", 0) or 0),
            "sub_only": int(snapshot.get("sub_only", 0) or 0),
            "rejected": int(snapshot.get("rejected", 0) or 0),
            "quarantined_total": int(snapshot.get("quarantined_total", 0) or 0),
            "iteration": int(snapshot.get("iteration", 0) or 0),
            "phase": str(snapshot.get("phase", "")),
            "stopped": bool(snapshot.get("stopped", False)),
        }
        setattr(fingerprint, "ae_lab_summary", dict(summary))
        setattr(fingerprint, "ae_anchor_stars", self._build_ae_anchor_stars(ae_anchors))
        setattr(fingerprint, "ae_lab_anchor_count", int(summary["anchor_count"]))
        setattr(
            fingerprint,
            "ae_lab_top_anchor_type",
            str(summary["top_anchor_types"][0]) if summary["top_anchor_types"] else "",
        )
        setattr(
            fingerprint,
            "ae_lab_summary_text",
            (
                f"{int(summary['anchor_count'])} Anker | "
                f"{int(summary['main_vault_size'])} stabile Algorithmen | "
                f"{summary['anchor_preview'] or 'keine dominanten AE-Anker'} | "
                f"{self._ae_guard_preview(summary)}"
            ),
        )
        if bool(summary.get("stopped", False)):
            self.ae_iteration_var.set(
                f"AELAB gestoppt bei Iteration {int(summary.get('iteration', 0) or 0)} | Phase {str(summary.get('phase', 'idle') or 'idle')}"
            )
            self._set_ae_stop_button_state(
                f"Gestoppt (Iteration {int(summary.get('iteration', 0) or 0)})",
                enabled=False,
            )
        else:
            self.ae_iteration_var.set(
                f"AELAB abgeschlossen | Iteration {int(summary.get('iteration', 0) or 0)} | Phase {str(summary.get('phase', 'idle') or 'idle')} | {self._ae_guard_preview(summary)}"
            )
            self._set_ae_stop_button_state("Stop Iterationen", enabled=True)
        self._refresh_ae_anchor_panel(ae_anchors)
        self._sync_ae_vault_registry()
        if ae_anchors and not self._is_text_silent_source(fingerprint):
            self.audio_engine.trigger_anchor_pings([float(anchor.get("value", 0.0) or 0.0) for anchor in ae_anchors])
        return summary

    def _is_text_silent_source(self, fingerprint: AetherFingerprint | None) -> bool:
        """Unterdrueckt Audio fuer rein textuelle Shanway-/Browser-Quellen."""
        source_type = str(getattr(fingerprint, "source_type", "") or "").strip().lower()
        return source_type in {
            "chat",
            "chat_private",
            "chat_group",
            "webpage",
            "text_file",
            "text_corpus",
        }

    def _configure_styles(self) -> None:
        """Konfiguriert ttk-Stile fuer den Integritaets-Monitor."""
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "Symmetry.Horizontal.TProgressbar",
            troughcolor="#1B2552",
            background="#2DE2E6",
            bordercolor="#1B2552",
            lightcolor="#2DE2E6",
            darkcolor="#2DE2E6",
            thickness=10,
        )
        style.configure(
            "Coherence.Horizontal.TProgressbar",
            troughcolor="#1B2552",
            background="#67D5B5",
            bordercolor="#1B2552",
            lightcolor="#67D5B5",
            darkcolor="#67D5B5",
            thickness=10,
        )
        style.configure(
            "Resonance.Horizontal.TProgressbar",
            troughcolor="#1B2552",
            background="#7AB6FF",
            bordercolor="#1B2552",
            lightcolor="#7AB6FF",
            darkcolor="#7AB6FF",
            thickness=10,
        )
        style.configure(
            "ObserverCoherence.Horizontal.TProgressbar",
            troughcolor="#14314F",
            background="#2DE2E6",
            bordercolor="#14314F",
            lightcolor="#2DE2E6",
            darkcolor="#67D5FF",
            thickness=8,
        )
        style.configure(
            "ObserverHobs.Horizontal.TProgressbar",
            troughcolor="#4F2A14",
            background="#FF8C42",
            bordercolor="#4F2A14",
            lightcolor="#FF8C42",
            darkcolor="#FFB347",
            thickness=8,
        )

    def _build_layout(self) -> None:
        """Erzeugt die dreigeteilte Hauptstruktur der Oberflaeche."""
        container = tk.Frame(self.root, bg="#0A0F2E")
        container.pack(fill="both", expand=True, padx=12, pady=12)
        container.columnconfigure(0, weight=0, minsize=340)
        container.columnconfigure(1, weight=1)
        container.columnconfigure(2, weight=0, minsize=440)
        container.rowconfigure(0, weight=1)

        self.left_frame = tk.Frame(container, bg="#111A4A", bd=1, relief="groove")
        self.center_frame = tk.Frame(container, bg="#050816", bd=1, relief="groove")
        self.right_frame = tk.Frame(container, bg="#111A4A", bd=1, relief="groove")
        self.left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.center_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 10))
        self.right_frame.grid(row=0, column=2, sticky="nsew")

        self._build_left_panel()
        self._build_center_panel()
        self._build_right_panel()

    def _build_center_panel(self) -> None:
        """Erzeugt die zentrale Szeneflaeche mit optionalem Browser-Dock."""
        self.center_pane = ttk.Panedwindow(self.center_frame, orient="vertical")
        self.center_pane.pack(fill="both", expand=True)

        self.scene_frame = tk.Frame(self.center_pane, bg="#050816", bd=0, relief="flat")
        self.center_pane.add(self.scene_frame, weight=5)

        self.browser_main_panel = tk.Frame(self.center_pane, bg="#081120", bd=1, relief="groove")
        self.browser_main_panel.pack_propagate(False)
        self.browser_main_controls = self._create_browser_controls(self.browser_main_panel, outer_bg="#081120")
        self.browser_main_status = self._create_browser_status_bar(self.browser_main_panel, bg="#081120")
        self.browser_host_frame = tk.Frame(self.browser_main_panel, bg="#050B14", bd=0, relief="flat")
        self.browser_host_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.browser_host_frame.bind("<Configure>", self._schedule_browser_host_sync)
        self.browser_host_hint = tk.Label(
            self.browser_host_frame,
            text="Companion-Browser aktiv. Diese Flaeche bleibt als Platzhalter erhalten.",
            bg="#050B14",
            fg="#7AB6FF",
            font=("Segoe UI", 10),
        )
        self.browser_host_hint.place(relx=0.5, rely=0.5, anchor="center")

    def _create_browser_controls(self, parent, outer_bg: str) -> tk.Frame:
        """Baut eine Browser-Toolbar mit gemeinsamem Navigationszustand."""
        controls = tk.Frame(parent, bg=outer_bg)
        controls.pack(fill="x", padx=8, pady=(8, 4))
        ttk.Button(controls, text="←", width=3, command=self._browser_back).pack(side="left")
        ttk.Button(controls, text="→", width=3, command=self._browser_forward).pack(side="left", padx=(4, 0))
        ttk.Button(controls, text="↺", width=3, command=self._browser_reload).pack(side="left", padx=(4, 6))
        ttk.Button(controls, text="Extern", command=self._browser_open_external).pack(side="left", padx=(0, 6))
        address_frame = tk.Frame(controls, bg="#0E6B2F", bd=1, relief="solid")
        address_frame.pack(side="left", fill="x", expand=True)
        self._browser_address_frames.append(address_frame)
        tk.Label(
            address_frame,
            textvariable=self.browser_lock_var,
            bg="#0E6B2F",
            fg="#F3FFF7",
            width=2,
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left", padx=(6, 2))
        entry = tk.Entry(
            address_frame,
            textvariable=self.browser_url_var,
            bg="#07111F",
            fg="#E7F4FF",
            insertbackground="#E7F4FF",
            relief="flat",
        )
        entry.pack(side="left", fill="x", expand=True, padx=(0, 6), pady=4)
        entry.bind("<Return>", lambda _event: self._browser_navigate())
        return controls

    def _create_browser_status_bar(self, parent, bg: str) -> tk.Frame:
        """Baut die schlanke Browser-Statusleiste."""
        status = tk.Frame(parent, bg=bg)
        status.pack(fill="x", padx=8, pady=(0, 6))
        tk.Label(status, textvariable=self.browser_ct_var, bg=bg, fg="#67D5FF", font=("Consolas", 9, "bold")).pack(side="left")
        tk.Label(status, textvariable=self.browser_d_var, bg=bg, fg="#F6E7A7", font=("Consolas", 9, "bold")).pack(side="left", padx=(12, 0))
        tk.Label(status, textvariable=self.browser_recon_var, bg=bg, fg="#FFB347", font=("Consolas", 9, "bold")).pack(side="left", padx=(12, 0))
        return status

    def _build_augment_window(self) -> None:
        """Erzeugt eingebettete Modul-Tabs im Hauptfenster; Voxel und Anker bleiben permanent sichtbar."""
        self.augment_window = self.root
        for child in self.right_frame.winfo_children():
            child.destroy()

        header = tk.Frame(self.right_frame, bg="#0B1B33", height=42)
        header.pack(fill="x", padx=8, pady=(8, 6))
        self.augment_header = header
        tk.Label(header, textvariable=self.header_user_var, bg="#0B1B33", fg="#9AD7C8", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 10))
        tk.Label(header, textvariable=self.header_anchor_var, bg="#0B1B33", fg="#F6E7A7", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 10))
        tk.Label(header, textvariable=self.header_chain_var, bg="#0B1B33", fg="#8BE0FF", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 10))
        tk.Label(header, textvariable=self.header_security_var, bg="#0B1B33", fg="#FFB347", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 10))
        ttk.Button(header, text="Settings", command=self._open_public_anchor_settings).pack(side="right", padx=(6, 10))
        ttk.Button(header, text="Anchor Flush", command=self._flush_public_anchor_queue).pack(side="right", padx=6)

        anchor_card = tk.Frame(self.right_frame, bg="#0D1930", bd=1, relief="groove")
        anchor_card.pack(fill="x", padx=8, pady=(0, 6))
        tk.Label(anchor_card, text="Anchor-Layer", bg="#0D1930", fg="#E7F4FF", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(10, 4))
        tk.Label(anchor_card, textvariable=self.ae_anchor_status_var, bg="#0D1930", fg="#F6E7A7", wraplength=400, justify="left", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(0, 2))
        tk.Label(anchor_card, textvariable=self.ae_iteration_var, bg="#0D1930", fg="#FFB347", wraplength=400, justify="left", font=("Segoe UI", 8)).pack(anchor="w", padx=10, pady=(0, 4))
        self.ae_anchor_text = tk.Text(anchor_card, height=7, bg="#07111F", fg="#D7E8FF", relief="flat", wrap="word", font=("Consolas", 8))
        self.ae_anchor_text.pack(fill="x", padx=10, pady=(0, 10))
        self.ae_anchor_text.configure(state="disabled")

        body = tk.Frame(self.right_frame, bg="#111A4A")
        body.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.right_notebook = ttk.Notebook(body)
        self.right_notebook.pack(fill="both", expand=True)
        self.right_notebook.bind("<<NotebookTabChanged>>", self._on_augment_tab_changed)
        node_tab = tk.Frame(self.right_notebook, bg="#111A4A")
        camera_tab = tk.Frame(self.right_notebook, bg="#0D1930")
        theremin_tab = tk.Frame(self.right_notebook, bg="#0D1930")
        shanway_tab = tk.Frame(self.right_notebook, bg="#0D1930")
        chat_tab = tk.Frame(self.right_notebook, bg="#0D1930")
        browser_tab = tk.Frame(self.right_notebook, bg="#0D1930")
        chain_tab = tk.Frame(self.right_notebook, bg="#0D1930")
        vault_tab = tk.Frame(self.right_notebook, bg="#0D1930")
        verify_tab = tk.Frame(self.right_notebook, bg="#0D1930")
        self.right_notebook.add(node_tab, text="NODE")
        self.right_notebook.add(camera_tab, text="KAMERA")
        self.right_notebook.add(theremin_tab, text="THEREMIN")
        self.right_notebook.add(shanway_tab, text="SHANWAY")
        self.right_notebook.add(chat_tab, text="CHATS")
        self.right_notebook.add(browser_tab, text="BROWSER")
        self.right_notebook.add(chain_tab, text="CHAIN")
        self.right_notebook.add(vault_tab, text="VAULT")
        self.right_notebook.add(verify_tab, text="VERIFY")

        tk.Label(node_tab, text="Node-Status", bg="#111A4A", fg="#E7F4FF", font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=12, pady=(12, 6))
        tk.Label(node_tab, text=f"Session-ID: {self.session_context.session_id[:8]}", bg="#111A4A", fg="#C7D7FF", font=("Segoe UI", 10)).pack(anchor="w", padx=12, pady=(0, 6))
        self.honeypot_label = tk.Label(node_tab, textvariable=self.honeypot_var, bg="#111A4A", fg="#7DE8A7", font=("Segoe UI", 10, "bold"), wraplength=400, justify="left")
        self.honeypot_label.pack(anchor="w", padx=12, pady=(0, 6))
        self.theremin_label = tk.Label(node_tab, textvariable=self.theremin_state_var, bg="#111A4A", fg="#8FD6FF", font=("Segoe UI", 10, "bold"), wraplength=400, justify="left")
        self.theremin_label.pack(anchor="w", padx=12, pady=(0, 8))
        tk.Label(node_tab, text=f"Nutzer: {self.session_context.username} | Rolle: {self.session_context.user_role}", bg="#111A4A", fg="#9AD7C8", font=("Segoe UI", 9, "bold"), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 2))
        tk.Label(node_tab, textvariable=self.security_key_var, bg="#111A4A", fg="#CFE8FF", font=("Consolas", 9, "bold"), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 8))
        tk.Label(node_tab, textvariable=self.security_node_var, bg="#111A4A", fg="#F2C14E", font=("Consolas", 9, "bold"), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 2))
        tk.Label(node_tab, textvariable=self.security_trust_var, bg="#111A4A", fg="#FFB347", font=("Segoe UI", 9, "bold"), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 2))
        tk.Label(node_tab, textvariable=self.security_maze_var, bg="#111A4A", fg="#E7F4FF", font=("Segoe UI", 9, "bold"), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 6))
        security_controls = tk.Frame(node_tab, bg="#111A4A")
        security_controls.pack(anchor="w", padx=12, pady=(0, 6), fill="x")
        tk.Label(security_controls, text="Mode", bg="#111A4A", fg="#C7D7FF", font=("Segoe UI", 9)).pack(side="left")
        ttk.Combobox(security_controls, textvariable=self.security_mode_choice_var, values=("PROD", "DEV"), width=8, state="readonly").pack(side="left", padx=(8, 8))
        ttk.Button(security_controls, text="Check", command=self._run_security_recheck).pack(side="left")
        ttk.Button(security_controls, text="Audit", command=self._open_security_audit).pack(side="left", padx=(8, 0))
        self.security_mode_choice_var.trace_add("write", lambda *_args: self._on_security_mode_changed())
        tk.Label(node_tab, textvariable=self.security_summary_var, bg="#111A4A", fg="#C7D7FF", font=("Segoe UI", 9), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 10))
        tk.Label(node_tab, textvariable=self.state_var, bg="#111A4A", fg="#C7D7FF", font=("Segoe UI", 10), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 8))
        tk.Label(node_tab, textvariable=self.semantic_state_var, bg="#111A4A", fg="#67D5FF", font=("Segoe UI", 9, "bold"), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 2))
        tk.Label(node_tab, textvariable=self.beauty_state_var, bg="#111A4A", fg="#F6E7A7", font=("Segoe UI", 9), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 8))
        tk.Label(node_tab, textvariable=self.beauty_signature_var, bg="#111A4A", fg="#F6E7A7", font=("Consolas", 9), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 2))
        tk.Label(node_tab, textvariable=self.observer_gap_var, bg="#111A4A", fg="#9AD7C8", font=("Consolas", 9, "bold"), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 8))
        tk.Label(node_tab, textvariable=self.graph_region_var, bg="#111A4A", fg="#7DE8A7", font=("Consolas", 9, "bold"), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 2))
        tk.Label(node_tab, textvariable=self.graph_phase_var, bg="#111A4A", fg="#FFB347", font=("Consolas", 9), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 2))
        tk.Label(node_tab, textvariable=self.graph_attractor_var, bg="#111A4A", fg="#CFE8FF", font=("Consolas", 9), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 8))
        tk.Label(node_tab, textvariable=self.bayes_anchor_var, bg="#111A4A", fg="#7DE8A7", font=("Consolas", 9), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 2))
        tk.Label(node_tab, textvariable=self.bayes_phase_var, bg="#111A4A", fg="#67D5FF", font=("Consolas", 9), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 2))
        tk.Label(node_tab, textvariable=self.bayes_pattern_var, bg="#111A4A", fg="#F6E7A7", font=("Consolas", 9), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 2))
        tk.Label(node_tab, textvariable=self.bayes_alarm_var, bg="#111A4A", fg="#FFB347", font=("Consolas", 9), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 8))
        tk.Label(node_tab, textvariable=self.model_depth_var, bg="#111A4A", fg="#7DE8A7", font=("Consolas", 9, "bold"), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 2))
        tk.Label(node_tab, textvariable=self.delta_learning_var, bg="#111A4A", fg="#67D5FF", font=("Consolas", 9), wraplength=400, justify="left").pack(anchor="w", padx=12, pady=(0, 2))
        self.learning_curve_canvas = tk.Canvas(node_tab, width=400, height=42, bg="#0C172B", highlightthickness=1, highlightbackground="#233A5A")
        self.learning_curve_canvas.pack(anchor="w", padx=12, pady=(0, 6))
        self.anomaly_memory_label = tk.Label(node_tab, textvariable=self.anomaly_memory_var, bg="#111A4A", fg="#F6E7A7", font=("Consolas", 9), wraplength=400, justify="left", cursor="hand2")
        self.anomaly_memory_label.pack(anchor="w", padx=12, pady=(0, 10))
        self.anomaly_memory_label.bind("<Button-1>", self._open_anomaly_memory)
        monitor = tk.Frame(node_tab, bg="#111A4A")
        monitor.pack(fill="x", padx=12, pady=(0, 12))
        self._create_integrity_row(monitor, label="Symmetrie", variable=self.symmetry_monitor_var, style_name="Symmetry.Horizontal.TProgressbar")
        self._create_integrity_row(monitor, label="Kohaerenz", variable=self.coherence_monitor_var, style_name="Coherence.Horizontal.TProgressbar")
        self._create_integrity_row(monitor, label="Resonanz", variable=self.resonance_monitor_var, style_name="Resonance.Horizontal.TProgressbar")
        score_row = tk.Frame(monitor, bg="#111A4A")
        score_row.pack(fill="x", pady=(6, 3))
        tk.Label(score_row, text="Ethik-Score", bg="#111A4A", fg="#E7F4FF", font=("Segoe UI", 10, "bold")).pack(side="left")
        self.integrity_score_label = tk.Label(score_row, textvariable=self.integrity_score_var, bg="#111A4A", fg="#2DE2E6", font=("Segoe UI", 18, "bold"))
        self.integrity_score_label.pack(side="right")
        self.integrity_text_label = tk.Label(monitor, textvariable=self.integrity_text_var, bg="#111A4A", fg="#2DE2E6", font=("Segoe UI", 10, "bold"), wraplength=400, justify="left")
        self.integrity_text_label.pack(anchor="w", pady=(1, 0))

        camera_controls = tk.Frame(camera_tab, bg="#0D1930")
        camera_controls.pack(fill="x", padx=10, pady=(10, 8))
        ttk.Checkbutton(camera_controls, text="Kamera", variable=self.camera_toggle_var, command=self._toggle_camera_feed).pack(side="left", padx=(0, 8))
        ttk.Checkbutton(camera_controls, text="Mirror", variable=self.camera_mirror_var).pack(side="left", padx=(0, 8))
        ttk.Checkbutton(camera_controls, text="Theremin", variable=self.camera_theremin_var, command=self._toggle_camera_theremin).pack(side="left")
        self.camera_canvas = tk.Canvas(camera_tab, width=400, height=240, bg="#040811", highlightthickness=0)
        self.camera_canvas.pack(fill="x", padx=10, pady=(0, 8))
        tk.Label(camera_tab, textvariable=self.recon_status_var, bg="#0D1930", fg="#E7F4FF", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10)
        metrics = tk.Frame(camera_tab, bg="#0D1930")
        metrics.pack(fill="x", padx=10, pady=(6, 8))
        for label, variable in [("H(0)", self.metric_h0_var), ("H(t)", self.metric_ht_var), ("C(t)", self.metric_ct_var), ("D", self.metric_d_var), ("Φ", self.metric_phi_var), ("FREQ", self.metric_freq_var), ("DETUNE", self.metric_detune_var), ("PRIOR ACC", self.metric_prior_var), ("ANCHORS", self.metric_anchor_count_var), ("BENFORD", self.metric_benford_var), ("LOAD", self.metric_runtime_var), ("RESOLVED", self.metric_resolved_var)]:
            row = tk.Frame(metrics, bg="#0D1930")
            row.pack(fill="x")
            tk.Label(row, text=label, bg="#0D1930", fg="#8FB5FF", font=("Consolas", 9)).pack(side="left")
            tk.Label(row, textvariable=variable, bg="#0D1930", fg="#E7F4FF", font=("Consolas", 9, "bold")).pack(side="right")
        tk.Label(camera_tab, text="Kohaerenz", bg="#0D1930", fg="#8FB5FF", font=("Segoe UI", 9)).pack(anchor="w", padx=10)
        ttk.Progressbar(camera_tab, maximum=100, variable=self.coherence_live_var, style="ObserverCoherence.Horizontal.TProgressbar").pack(fill="x", padx=10, pady=(2, 6))
        tk.Label(camera_tab, text="H_obs", bg="#0D1930", fg="#FFB347", font=("Segoe UI", 9)).pack(anchor="w", padx=10)
        ttk.Progressbar(camera_tab, maximum=100, variable=self.h_obs_live_var, style="ObserverHobs.Horizontal.TProgressbar").pack(fill="x", padx=10, pady=(2, 8))
        tk.Label(camera_tab, text="Conway-Feld", bg="#0D1930", fg="#E7F4FF", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(2, 6))
        self.conway_canvas = tk.Canvas(camera_tab, width=400, height=220, bg="#060B14", highlightthickness=0)
        self.conway_canvas.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        tk.Label(theremin_tab, textvariable=self.theremin_state_var, bg="#0D1930", fg="#8FD6FF", font=("Segoe UI", 10, "bold"), wraplength=400, justify="left").pack(anchor="w", padx=10, pady=(12, 6))
        theremin_row = tk.Frame(theremin_tab, bg="#0D1930")
        theremin_row.pack(fill="x", padx=10, pady=(0, 8))
        ttk.Button(theremin_row, text="Theremin aktivieren", command=self._start_theremin).pack(side="left", fill="x", expand=True, padx=(0, 4))
        ttk.Button(theremin_row, text="Theremin stoppen", command=self._stop_theremin).pack(side="left", fill="x", expand=True, padx=(4, 0))
        tk.Label(theremin_tab, textvariable=self.wavelength_var, bg="#0D1930", fg="#E7F4FF", font=("Segoe UI", 9, "bold"), wraplength=400, justify="left").pack(anchor="w", padx=10, pady=(0, 8))
        theremin_metrics = tk.Frame(theremin_tab, bg="#0D1930")
        theremin_metrics.pack(fill="x", padx=10, pady=(0, 10))
        for label, variable in [("Kohaerenz", self.metric_ct_var), ("Frequenz", self.metric_freq_var), ("Detune", self.metric_detune_var), ("Anker", self.metric_anchor_count_var), ("Prior", self.metric_prior_var), ("Benford", self.metric_benford_var), ("Runtime", self.metric_runtime_var)]:
            row = tk.Frame(theremin_metrics, bg="#0D1930")
            row.pack(fill="x")
            tk.Label(row, text=label, bg="#0D1930", fg="#8FB5FF", font=("Consolas", 9)).pack(side="left")
            tk.Label(row, textvariable=variable, bg="#0D1930", fg="#E7F4FF", font=("Consolas", 9, "bold")).pack(side="right")

        tk.Label(shanway_tab, text="Shanway", bg="#0D1930", fg="#E7F4FF", font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=10, pady=(12, 6))
        shanway_mode_row = tk.Frame(shanway_tab, bg="#0D1930")
        shanway_mode_row.pack(fill="x", padx=10, pady=(0, 6))
        ttk.Checkbutton(shanway_mode_row, text="Shanway aktiv", variable=self.shanway_enabled_var, command=self._on_shanway_toggle).pack(side="left", padx=(0, 8))
        ttk.Checkbutton(shanway_mode_row, text="Browser-Liveanalyse aus", variable=self.shanway_browser_mode_var, command=self._on_shanway_browser_toggle, state="disabled").pack(side="left")
        shanway_corpus_row = tk.Frame(shanway_tab, bg="#0D1930")
        shanway_corpus_row.pack(fill="x", padx=10, pady=(0, 8))
        ttk.Button(shanway_corpus_row, text="Corpus einlesen", command=self._import_shanway_corpus).pack(side="left")
        ttk.Button(shanway_corpus_row, text="Corpus-Ordner", command=self._open_shanway_corpus_dir).pack(side="left", padx=(6, 0))
        tk.Label(
            shanway_corpus_row,
            textvariable=self.shanway_corpus_var,
            bg="#0D1930",
            fg="#8FD6FF",
            font=("Consolas", 9, "bold"),
        ).pack(side="right")
        shanway_status_card = tk.Frame(shanway_tab, bg="#10223F", bd=0, relief="flat", highlightthickness=1, highlightbackground="#233A5A")
        shanway_status_card.pack(fill="x", padx=10, pady=(0, 8))
        tk.Label(shanway_status_card, textvariable=self.shanway_sensitive_var, bg="#10223F", fg="#F2C14E", wraplength=400, justify="left", font=("Segoe UI", 9)).pack(anchor="w", padx=10, pady=(10, 4))
        tk.Label(shanway_status_card, textvariable=self.chat_status_var, bg="#10223F", fg="#2DE2E6", wraplength=400, justify="left", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(0, 2))
        tk.Label(shanway_status_card, textvariable=self.chat_reply_var, bg="#10223F", fg="#F6E7A7", wraplength=400, justify="left", font=("Segoe UI", 9)).pack(anchor="w", padx=10, pady=(0, 2))
        tk.Label(shanway_status_card, textvariable=self.chat_semantic_var, bg="#10223F", fg="#9CB0CC", wraplength=400, justify="left", font=("Consolas", 9)).pack(anchor="w", padx=10, pady=(0, 10))
        tk.Label(shanway_tab, text="Privater Verlauf mit Shanway", bg="#0D1930", fg="#8FB5FF", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(0, 4))
        self.shanway_text = tk.Text(
            shanway_tab,
            bg="#07111F",
            fg="#D7E8FF",
            relief="flat",
            wrap="word",
            font=("Segoe UI", 10),
            height=14,
            padx=10,
            pady=10,
        )
        self.shanway_text.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self.shanway_text.configure(state="disabled")
        shanway_compose_card = tk.Frame(shanway_tab, bg="#10223F", bd=0, relief="flat", highlightthickness=1, highlightbackground="#233A5A")
        shanway_compose_card.pack(fill="x", padx=10, pady=(0, 8))
        tk.Label(
            shanway_compose_card,
            text="Hier direkt an Shanway schreiben. Ctrl+Enter sendet.",
            bg="#10223F",
            fg="#CFE8FF",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=10, pady=(10, 6))
        self.shanway_input_text = tk.Text(
            shanway_compose_card,
            bg="#0B1628",
            fg="#E7F4FF",
            insertbackground="#E7F4FF",
            relief="flat",
            wrap="word",
            font=("Segoe UI", 10),
            height=5,
            padx=10,
            pady=8,
        )
        self.shanway_input_text.pack(fill="x", padx=10, pady=(0, 8))
        self.shanway_input_text.bind("<Control-Return>", lambda _event: (self._send_private_shanway_message(), "break")[1])
        shanway_actions = tk.Frame(shanway_compose_card, bg="#10223F")
        shanway_actions.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(shanway_actions, text="An Shanway senden", command=self._send_private_shanway_message).pack(side="left")
        ttk.Button(
            shanway_actions,
            text="Leeren",
            command=lambda: self._clear_message_input("shanway"),
        ).pack(side="left", padx=(6, 0))
        self._build_voice_cards(shanway_tab)

        self.chain_text = tk.Text(chain_tab, bg="#07111F", fg="#D7E8FF", relief="flat", wrap="word", font=("Consolas", 9))
        self.chain_text.pack(fill="both", expand=True, padx=8, pady=(8, 6))
        self.chain_text.bind("<Button-1>", self._select_chain_entry)
        self.genesis_card = tk.Frame(
            chain_tab,
            bg="#30240A",
            bd=0,
            relief="flat",
            highlightthickness=2,
            highlightbackground="#F2C14E",
            highlightcolor="#F2C14E",
        )
        self.genesis_card.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(
            self.genesis_card,
            text="GENESIS · shared root · all instances",
            bg="#30240A",
            fg="#F6E7A7",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", padx=10, pady=(8, 2))
        self.genesis_text_var = tk.StringVar(value="")
        tk.Label(
            self.genesis_card,
            textvariable=self.genesis_text_var,
            bg="#30240A",
            fg="#F8F0CC",
            wraplength=340,
            justify="left",
            font=("Consolas", 9),
        ).pack(anchor="w", padx=10, pady=(0, 8))
        self.vault_text = tk.Text(vault_tab, bg="#07111F", fg="#D7E8FF", relief="flat", wrap="word", font=("Consolas", 9))
        self.vault_text.pack(fill="both", expand=True, padx=8, pady=(8, 6))
        self.vault_text.bind("<Button-1>", self._select_vault_entry)
        self.vault_text.bind("<Double-1>", self._rename_token_from_vault)
        self.verify_text = tk.Text(verify_tab, bg="#07111F", fg="#D7E8FF", relief="flat", wrap="word", font=("Consolas", 9))
        self.verify_text.pack(fill="both", expand=True, padx=8, pady=(8, 6))

        chat_header = tk.Frame(chat_tab, bg="#081120")
        chat_header.pack(fill="x", padx=8, pady=(8, 6))
        chat_channel_row = tk.Frame(chat_header, bg="#081120")
        chat_channel_row.pack(fill="x", padx=8, pady=(8, 4))
        tk.Label(
            chat_channel_row,
            text="Kanal",
            bg="#081120",
            fg="#9CB0CC",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(0, 6))
        self.chat_channel_combo = ttk.Combobox(
            chat_channel_row,
            textvariable=self.chat_channel_var,
            state="readonly",
            width=28,
        )
        self.chat_channel_combo.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.chat_channel_combo.bind("<<ComboboxSelected>>", self._on_chat_channel_changed)
        ttk.Button(chat_channel_row, text="Aktualisieren", command=self._refresh_chat_view).pack(side="left")
        chat_action_row = tk.Frame(chat_header, bg="#081120")
        chat_action_row.pack(fill="x", padx=8, pady=(0, 4))
        ttk.Button(chat_action_row, text="Direkt...", command=self._chat_open_private_dialog).pack(side="left", padx=(0, 4))
        ttk.Button(chat_action_row, text="Neue Gruppe", command=self._chat_create_group_dialog).pack(side="left", padx=(0, 4))
        ttk.Button(chat_action_row, text="Mitglied+", command=self._chat_add_group_member).pack(side="left", padx=(0, 4))
        ttk.Button(chat_action_row, text="Mitglied-", command=self._chat_remove_group_member).pack(side="left", padx=(0, 4))
        ttk.Button(chat_action_row, text="Shanway", command=self._chat_toggle_group_shanway).pack(side="left", padx=(0, 4))
        ttk.Button(chat_action_row, text="Verlassen", command=self._chat_leave_group).pack(side="left")
        chat_mode_row = tk.Frame(chat_header, bg="#081120")
        chat_mode_row.pack(fill="x", padx=8, pady=(0, 4))
        ttk.Checkbutton(
            chat_mode_row,
            text="Shanway aktiv",
            variable=self.shanway_enabled_var,
            command=self._on_shanway_toggle,
        ).pack(side="left", padx=(0, 8))
        ttk.Checkbutton(
            chat_mode_row,
            text="Browser-Liveanalyse aus",
            variable=self.shanway_browser_mode_var,
            command=self._on_shanway_browser_toggle,
            state="disabled",
        ).pack(side="left", padx=(0, 8))
        tk.Label(
            chat_mode_row,
            textvariable=self.shanway_sensitive_var,
            bg="#081120",
            fg="#F2C14E",
            font=("Segoe UI", 9),
        ).pack(side="left")
        chat_sync_row = tk.Frame(chat_header, bg="#081120")
        chat_sync_row.pack(fill="x", padx=8, pady=(0, 4))
        ttk.Entry(chat_sync_row, textvariable=self.chat_sync_url_var, width=26).pack(side="left", padx=(0, 4))
        ttk.Entry(chat_sync_row, textvariable=self.chat_sync_secret_var, width=14, show="*").pack(side="left", padx=(0, 4))
        ttk.Entry(chat_sync_row, textvariable=self.chat_sync_port_var, width=6).pack(side="left", padx=(0, 4))
        ttk.Button(chat_sync_row, text="Host", command=self._chat_sync_toggle_host).pack(side="left", padx=(0, 4))
        ttk.Button(chat_sync_row, text="Connect", command=self._chat_sync_connect).pack(side="left", padx=(0, 4))
        ttk.Button(chat_sync_row, text="Sync", command=self._chat_sync_poll_now).pack(side="left")
        tk.Label(
            chat_header,
            textvariable=self.chat_channel_note_var,
            bg="#081120",
            fg="#7AB6FF",
            wraplength=340,
            justify="left",
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=8, pady=(0, 4))
        tk.Label(
            chat_header,
            textvariable=self.chat_sync_status_var,
            bg="#081120",
            fg="#8FD3FF",
            wraplength=340,
            justify="left",
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=8, pady=(0, 4))
        tk.Label(
            chat_header,
            textvariable=self.chat_status_var,
            bg="#081120",
            fg="#2DE2E6",
            wraplength=340,
            justify="left",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=8, pady=(8, 2))
        tk.Label(
            chat_header,
            textvariable=self.chat_reply_var,
            bg="#081120",
            fg="#F6E7A7",
            wraplength=340,
            justify="left",
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=8, pady=(0, 2))
        tk.Label(
            chat_header,
            textvariable=self.chat_semantic_var,
            bg="#081120",
            fg="#9CB0CC",
            wraplength=340,
            justify="left",
            font=("Consolas", 9),
        ).pack(anchor="w", padx=8, pady=(0, 8))
        self.chat_text = tk.Text(
            chat_tab,
            bg="#07111F",
            fg="#D7E8FF",
            relief="flat",
            wrap="word",
            font=("Segoe UI", 10),
            padx=10,
            pady=10,
        )
        self.chat_text.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self.chat_text.configure(state="disabled")
        chat_input_card = tk.Frame(chat_tab, bg="#10223F", bd=0, relief="flat", highlightthickness=1, highlightbackground="#233A5A")
        chat_input_card.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(
            chat_input_card,
            text="Hier in den gewaelten Kanal schreiben. Ctrl+Enter sendet.",
            bg="#10223F",
            fg="#CFE8FF",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=10, pady=(10, 6))
        self.chat_compose_text = tk.Text(
            chat_input_card,
            bg="#0B1628",
            fg="#E7F4FF",
            insertbackground="#E7F4FF",
            relief="flat",
            wrap="word",
            font=("Segoe UI", 10),
            height=5,
            padx=10,
            pady=8,
        )
        self.chat_compose_text.pack(fill="x", padx=10, pady=(0, 8))
        self.chat_compose_text.bind("<Control-Return>", lambda _event: (self._send_chat_message("chat"), "break")[1])
        chat_input_row = tk.Frame(chat_input_card, bg="#10223F")
        chat_input_row.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(chat_input_row, text="Senden", command=lambda: self._send_chat_message("chat")).pack(side="left", padx=(0, 4))
        ttk.Button(chat_input_row, text="Aktualisieren", command=self._refresh_chat_view).pack(side="left", padx=(0, 4))
        ttk.Button(chat_input_row, text="Leeren", command=lambda: self._clear_message_input("chat")).pack(side="left")

        self.browser_tab_controls = self._create_browser_controls(browser_tab, outer_bg="#0D1930")
        self.browser_tab_status = self._create_browser_status_bar(browser_tab, bg="#081120")

        self.browser_panel = tk.Frame(browser_tab, bg="#07111F", bd=1, relief="groove")
        self.browser_panel.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        tk.Label(
            self.browser_panel,
            text="Browser | getrennt vom Aether-Oekosystem",
            bg="#07111F",
            fg="#CFE8FF",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", padx=10, pady=(10, 4))
        tk.Label(
            self.browser_panel,
            textvariable=self.browser_title_var,
            bg="#07111F",
            fg="#F6E7A7",
            wraplength=340,
            justify="left",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=10, pady=(0, 6))
        tk.Label(
            self.browser_panel,
            textvariable=self.browser_status_var,
            bg="#07111F",
            fg="#9CB0CC",
            wraplength=340,
            justify="left",
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=10, pady=(0, 8))
        ttk.Checkbutton(
            self.browser_panel,
            text="Browserfenster sichtbar halten",
            variable=self.browser_dock_var,
            command=self._toggle_browser_main_dock,
        ).pack(anchor="w", padx=10, pady=(0, 8))
        ttk.Checkbutton(
            self.browser_panel,
            text="Browser-Liveanalyse aus",
            variable=self.shanway_browser_mode_var,
            command=self._on_shanway_browser_toggle,
            state="disabled",
        ).pack(anchor="w", padx=10, pady=(0, 6))
        tk.Label(
            self.browser_panel,
            textvariable=self.shanway_sensitive_var,
            bg="#07111F",
            fg="#F2C14E",
            wraplength=340,
            justify="left",
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=10, pady=(0, 8))
        tk.Label(
            self.browser_panel,
            text="Der Browser bleibt verfuegbar, ist aber von Shanway, Raster, Vault, Chain und Audio getrennt. Er liefert nur visuelles Feedback und oeffnet Seiten ohne Liveanalyse.",
            bg="#07111F",
            fg="#7AB6FF",
            wraplength=340,
            justify="left",
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=10, pady=(0, 10))

        chain_actions = tk.Frame(chain_tab, bg="#0D1930")
        chain_actions.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(chain_actions, text="Original exportieren", command=self._export_original_from_chain).pack(side="left", fill="x", expand=True, padx=(0, 4))
        ttk.Button(chain_actions, text="Original oeffnen", command=self._open_original_from_chain).pack(side="left", fill="x", expand=True, padx=(4, 0))
        collective_actions = tk.Frame(chain_tab, bg="#0D1930")
        collective_actions.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(collective_actions, text="Snapshot export", command=self._export_collective_snapshot_dialog).pack(side="left", fill="x", expand=True, padx=(0, 4))
        ttk.Button(collective_actions, text="Snapshot import", command=self._import_collective_snapshot_dialog).pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(collective_actions, text="Snapshot merge", command=self._merge_collective_snapshots_dialog).pack(side="left", fill="x", expand=True, padx=(4, 0))
        dna_share_actions = tk.Frame(chain_tab, bg="#0D1930")
        dna_share_actions.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(dna_share_actions, text="DNA Share export", command=self._export_dna_share_dialog).pack(side="left", fill="x", expand=True, padx=(0, 4))
        ttk.Button(dna_share_actions, text="DNA Share import", command=self._import_dna_share_dialog).pack(side="left", fill="x", expand=True, padx=(4, 0))
        tk.Label(
            chain_tab,
            text="DNA-Share teilt nur CONFIRMED lossless DNA. Keine Rohdateien, keine lokalen Pfade, nur extrahierte Strukturmuster.",
            bg="#0D1930",
            fg="#7AB6FF",
            justify="left",
            wraplength=340,
            anchor="w",
            font=("Segoe UI", 9),
        ).pack(fill="x", padx=10, pady=(0, 8))
        tk.Label(
            chain_tab,
            textvariable=self.collective_status_var,
            bg="#0D1930",
            fg="#9CB0CC",
            justify="left",
            anchor="w",
            font=("Segoe UI", 9),
        ).pack(fill="x", padx=10, pady=(0, 8))

        action_row = tk.Frame(vault_tab, bg="#0D1930")
        action_row.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(action_row, text="Original exportieren", command=self._export_original_from_vault).pack(side="left", fill="x", expand=True, padx=(0, 4))
        ttk.Button(action_row, text="Original oeffnen", command=self._open_original_from_vault).pack(side="left", fill="x", expand=True, padx=(4, 4))
        ttk.Button(action_row, text="Export Vault", command=self._export_vault_json).pack(side="left", fill="x", expand=True, padx=(4, 4))
        ttk.Button(action_row, text="Export Delta", command=self._export_delta_json).pack(side="left", fill="x", expand=True, padx=(4, 0))

    def _build_voice_cards(self, parent: tk.Widget) -> None:
        """Baut die GP-Sprachkarten in den gewaehlten Container."""
        voice_panel = tk.Frame(parent, bg="#0D1930")
        voice_panel.pack(fill="x", padx=10, pady=(0, 10))
        voice_header = tk.Frame(voice_panel, bg="#0D1930", bd=1, relief="groove")
        voice_header.pack(fill="x")
        tk.Label(voice_header, textvariable=self.voice_status_var, bg="#0D1930", fg="#F2C14E", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12, pady=(8, 6))
        voice_cards = tk.Frame(voice_panel, bg="#0D1930")
        voice_cards.pack(fill="x", pady=(6, 0))
        self._voice_card_refs = []
        for index, variable in enumerate(self.voice_sentence_vars, start=1):
            card = tk.Frame(voice_cards, bg="#10223F", bd=0, relief="flat", highlightthickness=2, highlightbackground="#233A5A", highlightcolor="#233A5A")
            card.pack(side="left", fill="both", expand=True, padx=(0 if index == 1 else 4, 0))
            tk.Label(card, text=f"GP {index}", bg="#10223F", fg="#8FB5FF", font=("Consolas", 9, "bold")).pack(anchor="w", padx=10, pady=(8, 4))
            tk.Label(card, textvariable=variable, bg="#10223F", fg="#E7F4FF", wraplength=290, justify="left", anchor="w", font=("Segoe UI", 10)).pack(fill="both", expand=True, padx=10, pady=(0, 10))
            self._voice_card_refs.append(card)

    def _hide_augment_window(self) -> None:
        """Es gibt kein separates Zusatzfenster mehr; der rechte Bereich bleibt eingebettet."""
        self._apply_browser_surface()

    def _send_private_shanway_message(self) -> None:
        """Leitet eine Eingabe direkt in den privaten Shanway-Kanal."""
        self._refresh_chat_channels(selected_channel="private:shanway")
        try:
            for tab_index in range(self.right_notebook.index("end")):
                if str(self.right_notebook.tab(tab_index, "text")) == "SHANWAY":
                    self.right_notebook.select(tab_index)
                    break
        except Exception:
            pass
        self._send_chat_message("shanway")

    def _current_right_tab_label(self) -> str:
        """Liefert das Label des aktuell aktiven rechten Tabs."""
        try:
            return str(self.right_notebook.tab(self.right_notebook.select(), "text"))
        except Exception:
            return ""

    @staticmethod
    def _text_widget_value(widget: tk.Text | None) -> str:
        """Liest einen Text-Composer robust aus."""
        if widget is None:
            return ""
        try:
            return str(widget.get("1.0", "end-1c")).strip()
        except Exception:
            return ""

    @staticmethod
    def _clear_text_widget(widget: tk.Text | None) -> None:
        """Leert einen Text-Composer robust."""
        if widget is None:
            return
        try:
            widget.delete("1.0", tk.END)
        except Exception:
            pass

    def _message_input_text(self, source: str = "auto") -> str:
        """Liefert den sichtbaren Nachrichtentext passend zur aktiven Eingabeflaeche."""
        if source == "shanway":
            candidates = [getattr(self, "shanway_input_text", None), getattr(self, "chat_compose_text", None)]
        elif source == "chat":
            candidates = [getattr(self, "chat_compose_text", None), getattr(self, "shanway_input_text", None)]
        elif self._current_right_tab_label() == "SHANWAY":
            candidates = [getattr(self, "shanway_input_text", None), getattr(self, "chat_compose_text", None)]
        else:
            candidates = [getattr(self, "chat_compose_text", None), getattr(self, "shanway_input_text", None)]
        for widget in candidates:
            text = self._text_widget_value(widget)
            if text:
                return text
        return str(self.chat_input_var.get()).strip()

    def _clear_message_input(self, source: str = "auto") -> None:
        """Leert die zugehoerige Eingabeflaeche nach dem Senden."""
        if source == "shanway":
            self._clear_text_widget(getattr(self, "shanway_input_text", None))
        elif source == "chat":
            self._clear_text_widget(getattr(self, "chat_compose_text", None))
        elif self._current_right_tab_label() == "SHANWAY":
            self._clear_text_widget(getattr(self, "shanway_input_text", None))
        else:
            self._clear_text_widget(getattr(self, "chat_compose_text", None))
        self.chat_input_var.set("")

    def _shanway_corpus_root(self) -> Path:
        """Liefert den lokalen Shanway-Korpusordner."""
        return Path("data") / "shanway_corpus"

    def _infer_text_language_hint(self, path: Path) -> str:
        """Leitet aus Dateiname und Ordnern einen groben Sprachhinweis fuer Textdateien ab."""
        parts = [segment.lower() for segment in path.parts]
        if any(segment in {"de", "deutsch", "german"} for segment in parts):
            return "de"
        if any(segment in {"en", "englisch", "english"} for segment in parts):
            return "en"
        stem = path.stem.lower()
        if stem.endswith("_de") or stem.endswith("-de"):
            return "de"
        if stem.endswith("_en") or stem.endswith("-en"):
            return "en"
        return ""

    def _refresh_shanway_corpus_status(self) -> None:
        """Aktualisiert die sichtbare Uebersicht zum lokal gelernten Textkorpus."""
        summary = self.shanway_engine.corpus_summary()
        self.shanway_corpus_var.set(f"Corpus: {int(summary.get('de', 0))} de | {int(summary.get('en', 0))} en")

    def _open_shanway_corpus_dir(self) -> None:
        """Oeffnet den lokalen Shanway-Korpusordner im Systembrowser."""
        root = self._shanway_corpus_root()
        root.mkdir(parents=True, exist_ok=True)
        (root / "de").mkdir(parents=True, exist_ok=True)
        (root / "en").mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(root))
        except Exception as exc:
            messagebox.showerror("Corpus", f"Der Corpus-Ordner konnte nicht geoeffnet werden:\n{exc}", parent=self.root)

    def _import_shanway_corpus(self) -> None:
        """Liest lokale DE/EN-Textdateien ein und spiegelt sie in Shanway und Registry."""
        if self.shanway_corpus_thread is not None and self.shanway_corpus_thread.is_alive():
            self.loading_var.set("Shanway-Corpus wird bereits eingelesen ...")
            return
        root = self._shanway_corpus_root()
        root.mkdir(parents=True, exist_ok=True)
        (root / "de").mkdir(parents=True, exist_ok=True)
        (root / "en").mkdir(parents=True, exist_ok=True)
        self.loading_var.set("Shanway-Corpus wird eingelesen ...")
        self.shanway_corpus_thread = threading.Thread(target=self._shanway_corpus_worker, args=(root,), daemon=True)
        self.shanway_corpus_thread.start()

    def _shanway_corpus_worker(self, root: Path) -> None:
        """Verarbeitet lokale Textdateien fuer Shanway-Lexikon und Analysehistorie."""
        imported = 0
        failed = 0
        learned_tokens = 0
        for language in ("de", "en"):
            lang_root = root / language
            if not lang_root.exists():
                continue
            for file_path in sorted(lang_root.rglob("*")):
                if not file_path.is_file() or file_path.suffix.lower() not in {".txt", ".md"}:
                    continue
                try:
                    text = file_path.read_text(encoding="utf-8", errors="replace")
                    if not text.strip():
                        continue
                    learned_tokens += int(self.shanway_engine.learn_from_corpus_text(text, language_hint=language))
                    fingerprint = self.analysis_engine.analyze_bytes(
                        text.encode("utf-8", errors="replace"),
                        source_label=str(file_path),
                        source_type="text_corpus",
                    )
                    self.registry.save(
                        fingerprint,
                        self.session_context,
                        payload_update={
                            "shanway_corpus": True,
                            "corpus_language": language,
                            "corpus_path": str(file_path.relative_to(root)),
                        },
                    )
                    imported += 1
                except Exception:
                    failed += 1
        self.root.after(
            0,
            lambda: self._finish_shanway_corpus_import(
                imported=int(imported),
                failed=int(failed),
                learned_tokens=int(learned_tokens),
            ),
        )

    def _finish_shanway_corpus_import(self, imported: int, failed: int, learned_tokens: int) -> None:
        """Schliesst den sichtbaren Shanway-Corpus-Import ab."""
        self._refresh_shanway_corpus_status()
        self._refresh_history_cache()
        self.loading_var.set(
            f"Shanway-Corpus eingelesen | Dateien {imported} | Token {learned_tokens} | Fehler {failed}"
        )
        self.chat_status_var.set(
            f"Shanway-Corpus aktiv | Dateien {imported} | gelernte Token {learned_tokens}"
        )

    def _browser_tab_active(self) -> bool:
        """Liefert, ob der Browser-Tab im eingebetteten Notebook aktuell sichtbar ist."""
        try:
            label = self.right_notebook.tab(self.right_notebook.select(), "text")
        except Exception:
            return False
        return str(label) == "BROWSER"

    def _on_augment_tab_changed(self, _event=None) -> None:
        """Zeigt den Browser nur als getrenntes visuelles Companion-Fenster an."""
        if self._browser_tab_active():
            self._ensure_browser_running()
        self._apply_browser_surface()

    def _toggle_browser_main_dock(self) -> None:
        """Schaltet nur die Sichtbarkeit des getrennten Browserfensters."""
        if self.browser_dock_var.get():
            if not self._ensure_browser_running():
                self.browser_dock_var.set(False)
                return
            self.browser_status_var.set("Browserfenster sichtbar. Keine Audio- oder Liveanalyse aktiv.")
        else:
            self.browser_status_var.set("Browserfenster ausgeblendet. Browser bleibt vom Aether-System getrennt.")
        self._apply_browser_surface()

    def _show_main_browser_dock(self) -> None:
        """Es gibt keinen eingedockten Browser mehr."""
        return

    def _hide_main_browser_dock(self) -> None:
        """Es gibt keinen eingedockten Browser mehr."""
        return

    def _schedule_browser_host_sync(self, _event=None) -> None:
        """Der Browser wird nicht mehr eingedockt."""
        return

    def _sync_browser_host(self) -> None:
        """Kein Browser-HWND-Sync mehr."""
        self.browser_host_sync_job = None
        return

    def _apply_browser_surface(self) -> None:
        """Schaltet den Companion-Browser nur visuell an oder aus."""
        if not self.browser_engine.is_running:
            return
        if self.browser_dock_var.get() or self._browser_tab_active():
            self.browser_engine.show()
            return
        self.browser_engine.hide()

    def _ensure_browser_running(self) -> bool:
        """Startet den getrennten pywebview-Browser ohne Aether-Analysepfad."""
        if not self.browser_engine.available:
            self.browser_status_var.set("Browser deaktiviert: pywebview ist nicht installiert.")
            return False
        if self.browser_engine.start():
            self.browser_status_var.set("Browser aktiv. Nur visuell, ohne Audio und ohne Aether-Liveanalyse.")
            if self.browser_poll_job is None:
                self._poll_browser_events()
            self._apply_browser_surface()
            return True
        self.browser_status_var.set("Browser konnte nicht gestartet werden.")
        return False

    def _browser_navigate(self) -> None:
        """Navigiert den getrennten Browser ohne Analysepfad."""
        if not self._ensure_browser_running():
            return
        self.browser_ct_var.set("C(t): --")
        self.browser_d_var.set("D: --")
        self.browser_recon_var.set("RECON: ✗")
        self.browser_status_var.set("Seite wird geladen. Browser bleibt rein visuell.")
        self.browser_engine.navigate(self.browser_url_var.get())

    def _browser_back(self) -> None:
        """Geht im getrennten Browser zurueck."""
        if not self._ensure_browser_running():
            return
        self.browser_engine.back()

    def _browser_forward(self) -> None:
        """Geht im getrennten Browser vor."""
        if not self._ensure_browser_running():
            return
        self.browser_engine.forward()

    def _browser_reload(self) -> None:
        """Laedt den getrennten Browser neu."""
        if not self._ensure_browser_running():
            return
        self.browser_engine.reload()

    def _browser_open_external(self) -> None:
        """Oeffnet die aktuelle Seite im normalen Systembrowser."""
        url = self.browser_url_var.get().strip()
        if not url:
            messagebox.showwarning("Hinweis", "Es ist keine URL gesetzt.")
            return
        if "://" not in url:
            url = f"https://{url}"
            self.browser_url_var.set(url)
        try:
            webbrowser.open(url)
            self.browser_status_var.set("Seite im klassischen Systembrowser geoeffnet. Shanway bleibt lokal isoliert.")
        except Exception as exc:
            messagebox.showerror("Browserfehler", f"Die Seite konnte extern nicht geoeffnet werden:\n{exc}")

    def _poll_browser_events(self) -> None:
        """Liest nur visuelle Browserereignisse ohne Aether-Analyse aus."""
        for event in self.browser_engine.poll_events(limit=10):
            kind = str(event.get("kind", ""))
            if kind == "ready":
                self.browser_url_var.set(str(event.get("url", self.browser_url_var.get())))
                self._set_browser_lock(bool(event.get("secure", False)))
                self.browser_status_var.set("Browser bereit. Keine Audio- oder Liveanalyse aktiv.")
                self._apply_browser_surface()
            elif kind == "loaded":
                snapshot = BrowserSnapshot(
                    url=str(event.get("url", "")),
                    title=str(event.get("title", "")),
                    html=str(event.get("html", "")),
                    timestamp=float(event.get("timestamp", time.time())),
                    secure=bool(event.get("secure", False)),
                )
                self._handle_browser_loaded(snapshot)
            elif kind == "error":
                self.browser_status_var.set(str(event.get("message", "Browserfehler.")))

        if self.browser_engine.is_running:
            self.browser_poll_job = self.root.after(350, self._poll_browser_events)
        else:
            self.browser_poll_job = None

    def _handle_browser_loaded(self, snapshot: BrowserSnapshot) -> None:
        """Aktualisiert nur den Browserstatus; der Browser bleibt aus dem Live-Aether-Pfad heraus."""
        self.browser_url_var.set(snapshot.url)
        self.browser_title_var.set(snapshot.title or "Ohne Seitentitel")
        self._set_browser_lock(snapshot.secure)
        self.browser_status_var.set("Seite geladen. Browser bleibt vom Shanway- und Raster-Livepfad getrennt.")

    def _on_browser_analysis_complete(
        self,
        job_id: int,
        snapshot: BrowserSnapshot,
        fingerprint: AetherFingerprint,
        record_id: int,
        log_path: str,
    ) -> None:
        """Uebernimmt Browseranalyseergebnisse in denselben Aether-Fluss wie Dateidrops."""
        if job_id != self._browser_job_id:
            return
        self._register_final_modules(fingerprint, record_id=int(record_id))
        self._set_scene_from_fingerprint(fingerprint)
        self._update_integrity_monitor(fingerprint)
        self._update_semantic_status(fingerprint, source_text=snapshot.html)
        self.state_var.set(self.renderer.get_state_description(fingerprint))
        anchors, _, _ = self._fingerprint_anchors_with_interference(fingerprint)
        beauty_d = float(self.observer_engine._fractal_dimension(anchors)) if anchors else 1.0
        self.browser_ct_var.set(f"C(t): {getattr(fingerprint, 'coherence_score', 0.0):.2f}")
        self.browser_d_var.set(f"D: {beauty_d:.3f}")
        self.browser_recon_var.set("RECON: ✗")
        self.browser_status_var.set(
            f"{snapshot.title or snapshot.url} analysiert | Datensatz-ID: {record_id} | Log: {Path(log_path).name}"
        )
        self.loading_var.set(f"Browseranalyse abgeschlossen: {Path(log_path).name}")
        self._refresh_recent_logs()
        self._refresh_history_cache(preserve_record_id=int(record_id))
        if not self._is_text_silent_source(fingerprint):
            self.audio_engine.play(fingerprint)
        self._apply_shanway_browser_assessment(snapshot, fingerprint, int(record_id))

        if beauty_d < 1.08 or beauty_d > 1.92:
            self._flash_browser_alarm(play_sound=False)

    def _apply_shanway_browser_assessment(
        self,
        snapshot: BrowserSnapshot,
        fingerprint: AetherFingerprint,
        record_id: int,
    ) -> None:
        """Bewertet Browsertext explizit nur im aktivierten Shanway-Browsermodus."""
        if not bool(self.shanway_browser_mode_var.get()):
            self._set_shanway_guard("Shanway Guard: Browser-Modus aus")
            return
        context = self._assistant_context_for(fingerprint)
        browser_text = self.shanway_engine.strip_browser_text(snapshot.html)
        assessment = self.shanway_engine.detect_asymmetry(
            browser_text,
            coherence_score=float(getattr(fingerprint, "coherence_score", 0.0) or 0.0),
            anchor_details=list(context.ae_anchor_details or []),
            browser_mode=True,
            active=True,
        )
        try:
            self.registry.update_fingerprint_payload(
                int(record_id),
                {"shanway_assessment": assessment.to_payload()},
            )
        except Exception:
            pass
        try:
            self.ae_vault.integrate_asymmetry_detector(assessment.detector_payload(), bucket="sub")
            self._sync_ae_vault_registry()
        except Exception:
            pass
        self._set_shanway_guard(assessment.message)
        if assessment.sensitive:
            self.browser_status_var.set(
                f"{snapshot.title or snapshot.url} geladen | Sensible Inhalte erkannt - Analyse gestoppt"
            )
            return
        self.browser_status_var.set(
            f"{snapshot.title or snapshot.url} analysiert | Shanway {assessment.classification} | "
            f"Noether {assessment.noether_symmetry * 100.0:.0f}% | tox {assessment.toxicity_score * 100.0:.0f}%"
        )
        if assessment.classification == "toxic":
            self._flash_browser_alarm(play_sound=False)

    def _set_browser_lock(self, secure: bool) -> None:
        """Aktualisiert Symbol und Farbe des Browser-Locks."""
        self.browser_lock_var.set("🔒" if secure else "🔓")
        color = "#0E6B2F" if secure else "#8A1E1E"
        for frame in list(self._browser_address_frames):
            try:
                frame.configure(bg=color)
                children = frame.winfo_children()
                if children:
                    children[0].configure(bg=color)
            except Exception:
                continue

    def _flash_browser_alarm(self, play_sound: bool = True) -> None:
        """Signalisiert strukturelle Browseranomalien visuell und akustisch."""
        for frame in list(self._browser_address_frames):
            try:
                frame.configure(bg="#A01212")
                children = frame.winfo_children()
                if children:
                    children[0].configure(bg="#A01212")
            except Exception:
                continue
        if play_sound:
            self.audio_engine.play_alarm_burst(duration_ms=200)
        if self.browser_flash_job is not None:
            try:
                self.root.after_cancel(self.browser_flash_job)
            except Exception:
                pass
        self.browser_flash_job = self.root.after(
            2000,
            lambda: self._set_browser_lock(self.browser_url_var.get().lower().startswith("https://")),
        )

    def _chat_note_for_descriptor(self, descriptor: dict[str, object] | None) -> str:
        """Formatiert die sichtbare Datenschutz- und Kanalbeschreibung."""
        if not descriptor:
            return "Kanal: nicht verfuegbar"
        kind = str(descriptor.get("kind", "public"))
        if kind == "public":
            return "Kanal: global | oeffentlich | Shanway antwortet direkt"
        if kind == "private_shanway":
            return "Kanal: privat | lokal verschluesselt | nur du und Shanway"
        if kind == "private":
            return (
                f"Kanal: direkt mit {descriptor.get('recipient_username', '')} | "
                "lokal verschluesselt | ohne Gruppen-Shanway"
            )
        if kind == "group":
            shanway_text = "an" if bool(descriptor.get("shanway_enabled", False)) else "aus"
            return (
                f"Gruppe: {descriptor.get('title', '')} | lokal verschluesselt | "
                f"Shanway {shanway_text} | Rolle {descriptor.get('current_role', '')}"
            )
        return "Kanal: lokal"

    def _chat_current_descriptor(self) -> dict[str, object] | None:
        """Liefert den aktuell ausgewaehlten Chat-Kanal."""
        return self.chat_channel_map.get(self.chat_channel_var.get())

    def _refresh_chat_channels(
        self,
        selected_channel: str | None = None,
        extra_descriptor: dict[str, object] | None = None,
    ) -> None:
        """Aktualisiert die sichtbaren oeffentlichen, privaten und Gruppen-Kanaele."""
        channels = self.registry.get_user_chat_channels(
            user_id=int(getattr(self.session_context, "user_id", 0) or 0),
            username=str(getattr(self.session_context, "username", "")),
        )
        if extra_descriptor is not None:
            extra_channel = str(extra_descriptor.get("channel", "")).strip()
            if extra_channel and not any(str(item.get("channel", "")) == extra_channel for item in channels):
                channels.append(dict(extra_descriptor))

        label_map: dict[str, dict[str, object]] = {}
        values: list[str] = []
        for descriptor in channels:
            item = dict(descriptor)
            base_label = str(
                item.get("label")
                or item.get("title")
                or item.get("channel")
                or "chat"
            )
            label = base_label
            suffix = 2
            while label in label_map:
                label = f"{base_label} [{suffix}]"
                suffix += 1
            item["label"] = label
            label_map[label] = item
            values.append(label)

        self.chat_channels_cache = list(label_map.values())
        self.chat_channel_map = label_map
        if hasattr(self, "chat_channel_combo"):
            self.chat_channel_combo.configure(values=values)

        target_label = self.chat_channel_var.get()
        if selected_channel:
            for label, descriptor in label_map.items():
                if str(descriptor.get("channel", "")) == str(selected_channel):
                    target_label = label
                    break
        if target_label not in label_map and values:
            target_label = values[0]

        if values:
            self.chat_channel_var.set(target_label)
            self.chat_channel_note_var.set(self._chat_note_for_descriptor(label_map.get(target_label)))
        else:
            self.chat_channel_var.set("")
            self.chat_channel_note_var.set("Kanal: nicht verfuegbar")

    def _on_chat_channel_changed(self, _event=None) -> None:
        """Reagiert auf sichtbare Kanalwechsel im Chat-Panel."""
        self.chat_channel_note_var.set(self._chat_note_for_descriptor(self._chat_current_descriptor()))
        self._refresh_chat_view()

    def _chat_open_private_dialog(self) -> None:
        """Oeffnet oder erstellt einen lokalen Direktkanal."""
        users = self.registry.list_users(
            exclude_user_id=int(getattr(self.session_context, "user_id", 0) or 0),
            include_disabled=False,
            limit=24,
        )
        suggestions = ", ".join(str(item.get("username", "")) for item in users[:8])
        target = simpledialog.askstring(
            "Direktnachricht",
            "Nutzername fuer Direktnachricht eingeben:"
            + (f"\nVerfuegbar: {suggestions}" if suggestions else ""),
            parent=self.root,
        )
        if target is None:
            return
        normalized = str(target).strip()
        if not normalized:
            return
        if normalized == str(getattr(self.session_context, "username", "")):
            messagebox.showwarning("Hinweis", "Eine Direktnachricht an dich selbst ist nicht sinnvoll.", parent=self.root)
            return
        if normalized == "shanway":
            self._refresh_chat_channels(selected_channel="private:shanway")
            self._refresh_chat_view()
            return
        record = self.registry.get_user_by_username(normalized)
        if record is None or bool(record.get("disabled", False)):
            messagebox.showerror("Direktnachricht", "Der angegebene Nutzer ist nicht verfuegbar.", parent=self.root)
            return
        self._refresh_chat_channels(
            selected_channel=f"private:{normalized}",
            extra_descriptor={
                "kind": "private",
                "channel": f"private:{normalized}",
                "label": f"@ {normalized}",
                "title": f"Direkt mit {normalized}",
                "encrypted": True,
                "shanway_enabled": False,
                "recipient_username": normalized,
            },
        )
        self._refresh_chat_view()

    def _chat_create_group_dialog(self) -> None:
        """Fragt eine neue Gruppe ab und legt sie lokal verschluesselt an."""
        group_name = simpledialog.askstring("Neue Gruppe", "Gruppenname:", parent=self.root)
        if group_name is None:
            return
        members_raw = simpledialog.askstring(
            "Neue Gruppe",
            "Mitglieder komma-separiert eintragen:",
            parent=self.root,
        )
        if members_raw is None:
            return
        members = [item.strip() for item in str(members_raw).split(",") if item.strip()]
        invite_shanway = messagebox.askyesno(
            "Shanway einladen",
            "Shanway fuer diese Gruppe aktivieren?",
            parent=self.root,
        )
        try:
            group = self.registry.create_chat_group(
                creator_user_id=int(getattr(self.session_context, "user_id", 0) or 0),
                creator_username=str(getattr(self.session_context, "username", "")),
                group_name=str(group_name),
                member_usernames=members,
                shanway_enabled=bool(invite_shanway),
            )
        except Exception as exc:
            messagebox.showerror("Gruppe", str(exc), parent=self.root)
            return
        self._chat_sync_publish_group_snapshot(str(group.get("group_id", "")))
        self._refresh_chat_channels(selected_channel=f"group:{group.get('group_id', '')}")
        self._refresh_chat_view()

    def _chat_add_group_member(self) -> None:
        """Fuegt dem aktuell gewaehlten Gruppenkanal ein Mitglied hinzu."""
        descriptor = self._chat_current_descriptor()
        if not descriptor or str(descriptor.get("kind", "")) != "group":
            messagebox.showinfo("Gruppe", "Waehle zuerst einen Gruppenkanal aus.", parent=self.root)
            return
        target = simpledialog.askstring("Mitglied hinzufuegen", "Nutzername:", parent=self.root)
        if target is None or not str(target).strip():
            return
        try:
            self.registry.add_group_member(
                str(descriptor.get("group_id", "")),
                str(getattr(self.session_context, "username", "")),
                str(target).strip(),
            )
        except Exception as exc:
            messagebox.showerror("Gruppe", str(exc), parent=self.root)
            return
        self._chat_sync_publish_group_snapshot(str(descriptor.get("group_id", "")))
        self._refresh_chat_channels(selected_channel=str(descriptor.get("channel", "")))
        self._refresh_chat_view()

    def _chat_remove_group_member(self) -> None:
        """Entfernt ein Mitglied aus dem aktuell gewaehlten Gruppenkanal."""
        descriptor = self._chat_current_descriptor()
        if not descriptor or str(descriptor.get("kind", "")) != "group":
            messagebox.showinfo("Gruppe", "Waehle zuerst einen Gruppenkanal aus.", parent=self.root)
            return
        target = simpledialog.askstring("Mitglied entfernen", "Nutzername:", parent=self.root)
        if target is None or not str(target).strip():
            return
        try:
            self.registry.remove_group_member(
                str(descriptor.get("group_id", "")),
                str(getattr(self.session_context, "username", "")),
                str(target).strip(),
            )
        except Exception as exc:
            messagebox.showerror("Gruppe", str(exc), parent=self.root)
            return
        if self.registry.get_chat_group(str(descriptor.get("group_id", ""))) is None:
            self._chat_sync_publish_group_delete(str(descriptor.get("group_id", "")))
        else:
            self._chat_sync_publish_group_snapshot(str(descriptor.get("group_id", "")))
        self._refresh_chat_channels(selected_channel=str(descriptor.get("channel", "")))
        self._refresh_chat_view()

    def _chat_toggle_group_shanway(self) -> None:
        """Schaltet Shanway fuer den aktuell gewaehlten Gruppenkanal um."""
        descriptor = self._chat_current_descriptor()
        if not descriptor or str(descriptor.get("kind", "")) != "group":
            messagebox.showinfo("Gruppe", "Waehle zuerst einen Gruppenkanal aus.", parent=self.root)
            return
        enabled = not bool(descriptor.get("shanway_enabled", False))
        try:
            self.registry.toggle_group_shanway(
                str(descriptor.get("group_id", "")),
                str(getattr(self.session_context, "username", "")),
                enabled=enabled,
            )
        except Exception as exc:
            messagebox.showerror("Gruppe", str(exc), parent=self.root)
            return
        self._chat_sync_publish_group_snapshot(str(descriptor.get("group_id", "")))
        self._refresh_chat_channels(selected_channel=str(descriptor.get("channel", "")))
        self._refresh_chat_view()

    def _chat_leave_group(self) -> None:
        """Verlaesst den aktuell gewaehlten Gruppenkanal."""
        descriptor = self._chat_current_descriptor()
        if not descriptor or str(descriptor.get("kind", "")) != "group":
            messagebox.showinfo("Gruppe", "Waehle zuerst einen Gruppenkanal aus.", parent=self.root)
            return
        confirmed = messagebox.askyesno(
            "Gruppe verlassen",
            f"Gruppe '{descriptor.get('title', '')}' wirklich verlassen?",
            parent=self.root,
        )
        if not confirmed:
            return
        try:
            self.registry.leave_group(
                str(descriptor.get("group_id", "")),
                str(getattr(self.session_context, "username", "")),
            )
        except Exception as exc:
            messagebox.showerror("Gruppe", str(exc), parent=self.root)
            return
        if self.registry.get_chat_group(str(descriptor.get("group_id", ""))) is None:
            self._chat_sync_publish_group_delete(str(descriptor.get("group_id", "")))
        else:
            self._chat_sync_publish_group_snapshot(str(descriptor.get("group_id", "")))
        self._refresh_chat_channels(selected_channel="global")
        self._refresh_chat_view()

    def _chat_sync_origin_node(self) -> str:
        """Leitet eine stabile lokale Node-Kennung fuer Sync-Ereignisse ab."""
        node_id = str(getattr(self.session_context, "node_id", "") or "").strip()
        if node_id:
            return node_id[:32]
        return hashlib.sha256(
            f"{self.session_context.username}|{self.session_context.session_id}".encode("utf-8")
        ).hexdigest()[:32]

    def _chat_sync_base_url(self) -> str:
        """Normalisiert die aktuell konfigurierte Relay-URL."""
        return str(self.chat_sync_url_var.get()).strip().rstrip("/")

    def _chat_sync_secret(self) -> str:
        """Liefert das eingegebene Relay-Secret."""
        return str(self.chat_sync_secret_var.get()).strip()

    def _persist_shanway_preferences(self) -> None:
        """Speichert die globalen Shanway-Schalter im Nutzerprofil."""
        user_id = int(getattr(self.session_context, "user_id", 0) or 0)
        if user_id <= 0:
            return
        try:
            settings = self.registry.update_user_settings(
                user_id,
                {
                    "shanway_enabled": bool(self.shanway_enabled_var.get()),
                    "shanway_browser_mode": bool(self.shanway_browser_mode_var.get()),
                },
            )
            self.session_context.user_settings = dict(settings)
        except Exception as exc:
            self.loading_var.set(f"Shanway-Einstellungen konnten nicht gespeichert werden: {exc}")

    def _on_shanway_toggle(self) -> None:
        """Aktiviert oder deaktiviert Shanway fuer offene Kanaele."""
        enabled = bool(self.shanway_enabled_var.get())
        self._persist_shanway_preferences()
        state_text = "aktiv" if enabled else "inaktiv"
        self._set_shanway_guard(f"Shanway Guard: {state_text}")
        self.chat_status_var.set(f"Shanway {state_text} | globale Kanaele")

    def _on_shanway_browser_toggle(self) -> None:
        """Browser-Liveanalyse bleibt bewusst deaktiviert."""
        enabled = False
        self.shanway_browser_mode_var.set(False)
        self._persist_shanway_preferences()
        self.browser_status_var.set("Browser-Liveanalyse ist deaktiviert. Shanway bleibt privat im Chat.")
        self._set_shanway_guard("Shanway Guard: Browser-Liveanalyse aus")

    def _set_shanway_guard(self, message: str) -> None:
        """Aktualisiert die sichtbare Shanway-Schutzmeldung."""
        self.shanway_sensitive_var.set(str(message or "Shanway Guard: bereit"))

    @staticmethod
    def _is_direct_shanway_invocation(text: str) -> bool:
        lowered = str(text or "").strip().lower()
        return "@shanway" in lowered or lowered.startswith("/shanway")

    def _handle_shanway_toggle_command(self, text: str) -> bool:
        """Schaltet Shanway per Chatkommando lokal um."""
        lowered = str(text or "").strip().lower()
        if lowered in {"/shanway on", "@shanway start", "shanway on"}:
            self.shanway_enabled_var.set(True)
            self._on_shanway_toggle()
            self.chat_reply_var.set("Shanway: Aktiviert. Ich antworte jetzt in offenen Kanaelen.")
            self.chat_status_var.set("Shanway aktiv | per Kommando zugeschaltet")
            self.chat_semantic_var.set("Semantik: -- | Shanway manuell aktiviert")
            return True
        if lowered in {"/shanway off", "@shanway stop", "shanway off"}:
            self.shanway_enabled_var.set(False)
            self._on_shanway_toggle()
            self.chat_reply_var.set("Shanway: Deaktiviert. Ich bleibe still, bis du mich wieder zuschaltest.")
            self.chat_status_var.set("Shanway inaktiv | per Kommando abgeschaltet")
            self.chat_semantic_var.set("Semantik: -- | Shanway manuell deaktiviert")
            return True
        return False

    def _chat_sync_store_preferences(self) -> None:
        """Persistiert Relay-URL und Host-Port im Nutzerprofil."""
        user_id = int(getattr(self.session_context, "user_id", 0) or 0)
        if user_id <= 0:
            return
        try:
            settings = self.registry.update_user_settings(
                user_id,
                {
                    "chat_sync_url": self._chat_sync_base_url(),
                    "chat_sync_port": self.chat_sync_port_var.get().strip(),
                },
            )
            self.session_context.user_settings = dict(settings)
        except Exception:
            return

    def _chat_sync_toggle_host(self) -> None:
        """Startet oder stoppt den lokalen Relay-Host fuer Mehrrechner-Chat."""
        if self.chat_relay_server.is_running:
            self.chat_relay_server.stop()
            self.chat_sync_status_var.set("Mehrrechner-Sync: Host gestoppt")
            if self.chat_sync_job is not None:
                try:
                    self.root.after_cancel(self.chat_sync_job)
                except Exception:
                    pass
                self.chat_sync_job = None
            self.chat_sync_connected = False
            return
        secret = self._chat_sync_secret()
        if not secret:
            messagebox.showwarning("Sync", "Bitte zuerst ein Sync-Secret eintragen.", parent=self.root)
            return
        try:
            port = int(self.chat_sync_port_var.get().strip() or "8765")
        except Exception:
            messagebox.showerror("Sync", "Der Sync-Port ist ungueltig.", parent=self.root)
            return
        self.chat_relay_server.port = max(1, min(65535, int(port)))
        try:
            base_url = self.chat_relay_server.start(secret)
        except Exception as exc:
            messagebox.showerror("Sync", f"Relay-Host konnte nicht gestartet werden:\n{exc}", parent=self.root)
            return
        self.chat_sync_url_var.set(base_url)
        self.chat_sync_status_var.set(f"Mehrrechner-Sync: Host aktiv auf {base_url}")
        self._chat_sync_store_preferences()
        self._chat_sync_connect()

    def _chat_sync_publish_event(self, event_type: str, payload: dict[str, object]) -> bool:
        """Publiziert ein Relay-Ereignis, wenn Sync verbunden ist."""
        if not self.chat_sync_connected:
            return False
        base_url = self.chat_sync_last_url or self._chat_sync_base_url()
        secret = self._chat_sync_secret()
        if not base_url or not secret:
            return False
        event = {
            "event_uid": uuid4().hex,
            "event_type": str(event_type),
            "origin_node": self._chat_sync_origin_node(),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "payload": dict(payload or {}),
        }
        try:
            self.chat_sync_client.publish(
                base_url=base_url,
                shared_secret=secret,
                payload=event,
                origin_node=self._chat_sync_origin_node(),
            )
            return True
        except Exception as exc:
            self.chat_sync_status_var.set(f"Mehrrechner-Sync: Publish fehlgeschlagen | {sync_error_text(exc)}")
            return False

    def _chat_sync_publish_local_users(self) -> int:
        """Spiegelt lokale Nutzerstammdaten einmalig an das Relay."""
        published = 0
        for record in self.registry.export_user_sync_records(limit=400):
            if self._chat_sync_publish_event("user_upsert", record):
                published += 1
        return published

    def _chat_sync_publish_group_snapshot(self, group_id: str) -> bool:
        """Publiziert den aktuellen Zustand einer Gruppe als Snapshot."""
        snapshot = self.registry.get_chat_group_sync_snapshot(group_id)
        if snapshot is None:
            return False
        return self._chat_sync_publish_event("group_snapshot", snapshot)

    def _chat_sync_publish_group_delete(self, group_id: str) -> bool:
        """Publiziert eine Gruppen-Loeschung an andere Installationen."""
        return self._chat_sync_publish_event("group_delete", {"group_id": str(group_id)})

    def _chat_sync_publish_message(self, message_id: int) -> bool:
        """Publiziert eine lokal gespeicherte Chatnachricht verschluesselt ans Relay."""
        payload = self.registry.get_chat_message_raw(int(message_id))
        if payload is None:
            return False
        return self._chat_sync_publish_event("chat_message", payload)

    def _chat_sync_connect(self) -> None:
        """Verbindet die Installation mit einem Relay und startet Hintergrund-Polling."""
        base_url = self._chat_sync_base_url()
        secret = self._chat_sync_secret()
        if not base_url or not secret:
            messagebox.showwarning("Sync", "Relay-URL und Sync-Secret werden benoetigt.", parent=self.root)
            return
        try:
            health = self.chat_sync_client.health(base_url)
        except Exception as exc:
            messagebox.showerror("Sync", f"Relay nicht erreichbar:\n{sync_error_text(exc)}", parent=self.root)
            return
        self.chat_sync_last_url = base_url
        self.chat_sync_connected = True
        self.chat_sync_status_var.set(
            f"Mehrrechner-Sync: verbunden mit {base_url} | {int(health.get('events', 0) or 0)} Relay-Events"
        )
        self._chat_sync_store_preferences()
        self._chat_sync_publish_local_users()
        for channel in self.registry.get_user_chat_channels(
            user_id=int(getattr(self.session_context, "user_id", 0) or 0),
            username=str(getattr(self.session_context, "username", "")),
        ):
            if str(channel.get("kind", "")) == "group":
                self._chat_sync_publish_group_snapshot(str(channel.get("group_id", "")))
        self._chat_sync_schedule_poll(immediate=True)

    def _chat_sync_schedule_poll(self, immediate: bool = False) -> None:
        """Plant den naechsten Relay-Poll ein."""
        if self.chat_sync_job is not None:
            try:
                self.root.after_cancel(self.chat_sync_job)
            except Exception:
                pass
            self.chat_sync_job = None
        if not self.chat_sync_connected:
            return
        delay = 120 if immediate else 2800
        self.chat_sync_job = self.root.after(delay, self._chat_sync_poll_now)

    def _chat_sync_apply_event(self, event: dict[str, object], source_url: str) -> bool:
        """Wendet ein entschluesseltes Relay-Ereignis lokal an."""
        event_uid = str(event.get("event_uid", "")).strip()
        if not event_uid or self.registry.has_chat_sync_event(event_uid):
            return False
        if str(event.get("origin_node", "")).strip() == self._chat_sync_origin_node():
            return False
        event_type = str(event.get("event_type", "")).strip()
        payload = dict(event.get("payload", {}) or {})
        if event_type == "user_upsert":
            self.registry.apply_synced_user_record(payload)
        elif event_type == "group_snapshot":
            self.registry.apply_synced_chat_group_snapshot(payload)
        elif event_type == "group_delete":
            self.registry.delete_synced_chat_group(str(payload.get("group_id", "")))
        elif event_type == "chat_message":
            self.registry.apply_synced_chat_message(payload)
        else:
            return False
        self.registry.record_chat_sync_event(
            event_uid=event_uid,
            event_type=event_type,
            source_url=source_url,
            remote_event_id=int(event.get("_remote_event_id", 0) or 0),
            payload=payload,
        )
        return True

    def _chat_sync_poll_now(self) -> None:
        """Laedt neue Relay-Ereignisse asynchron und spiegelt sie lokal."""
        self.chat_sync_job = None
        if not self.chat_sync_connected or self.chat_sync_polling:
            self._chat_sync_schedule_poll()
            return
        base_url = self.chat_sync_last_url or self._chat_sync_base_url()
        secret = self._chat_sync_secret()
        if not base_url or not secret:
            self.chat_sync_connected = False
            self.chat_sync_status_var.set("Mehrrechner-Sync: Konfiguration unvollstaendig")
            return
        self.chat_sync_polling = True
        after_id = self.registry.get_chat_sync_cursor(base_url)

        def worker() -> None:
            try:
                events = self.chat_sync_client.fetch(
                    base_url=base_url,
                    shared_secret=secret,
                    after_id=after_id,
                    limit=128,
                )
                error_text = ""
            except Exception as exc:
                events = []
                error_text = sync_error_text(exc)

            def finalize() -> None:
                self.chat_sync_polling = False
                if error_text:
                    self.chat_sync_status_var.set(f"Mehrrechner-Sync: Poll fehlgeschlagen | {error_text}")
                    self._chat_sync_schedule_poll()
                    return
                latest_remote_id = after_id
                changed = False
                for event in events:
                    latest_remote_id = max(latest_remote_id, int(event.get("_remote_event_id", 0) or 0))
                    try:
                        changed = self._chat_sync_apply_event(event, base_url) or changed
                    except Exception as exc:
                        self.chat_sync_status_var.set(f"Mehrrechner-Sync: Importfehler | {exc}")
                self.registry.update_chat_sync_cursor(base_url, latest_remote_id)
                self.chat_sync_status_var.set(
                    f"Mehrrechner-Sync: verbunden | {len(events)} neue Relay-Events | Cursor {latest_remote_id}"
                )
                if changed:
                    self._refresh_chat_channels(selected_channel=str(self._chat_current_descriptor().get("channel", "global")) if self._chat_current_descriptor() else None)
                    self._refresh_chat_view()
                self._chat_sync_schedule_poll()

            self.root.after(0, finalize)

        threading.Thread(target=worker, daemon=True).start()

    def _refresh_chat_view(self) -> None:
        """Aktualisiert den lokalen Mehrnutzer-Chat samt Shanway-Antworten."""
        if not hasattr(self, "chat_text"):
            return
        if not self.chat_channel_map:
            self._refresh_chat_channels()
        descriptor = self._chat_current_descriptor()
        if descriptor is None:
            self.chat_text.configure(state="normal")
            self.chat_text.delete("1.0", tk.END)
            self.chat_text.insert("1.0", "Keine Chat-Kanaele verfuegbar.\n")
            self.chat_text.configure(state="disabled")
            return
        self.chat_channel_note_var.set(self._chat_note_for_descriptor(descriptor))
        messages = list(
            reversed(
                self.registry.get_chat_messages(
                    limit=160,
                    channel=str(descriptor.get("channel", "global")),
                    current_user_id=int(getattr(self.session_context, "user_id", 0) or 0),
                    current_username=str(getattr(self.session_context, "username", "")),
                )
            )
        )
        self.chat_text.configure(state="normal")
        self.chat_text.delete("1.0", tk.END)
        if not messages:
            kind = str(descriptor.get("kind", "public"))
            if kind == "public":
                text = (
                    "Noch keine lokalen Chatnachrichten vorhanden.\n"
                    "Jede oeffentliche Nachricht wird sofort durch die AETHER-Pipeline analysiert und von Shanway beantwortet.\n"
                    "Beispiele: status, graph, browser, historie, muster, sicherheit, vergleich, hilfe.\n"
                )
            elif kind == "private_shanway":
                text = (
                    "Noch kein privater Verlauf mit Shanway vorhanden.\n"
                    "Dieser Kanal bleibt lokal verschluesselt und fliesst nicht in Vault, Chain oder Export.\n"
                )
            elif kind == "private":
                text = (
                    "Noch keine Direktnachrichten vorhanden.\n"
                    "Direktnachrichten bleiben lokal verschluesselt und werden nicht von Shanway gelernt.\n"
                )
            else:
                text = (
                    "Noch keine Gruppennachrichten vorhanden.\n"
                    "Gruppen bleiben lokal verschluesselt. Shanway reagiert hier nur auf @shanway.\n"
                )
            self.chat_text.insert("1.0", text)
        else:
            for item in messages:
                payload = dict(item.get("payload_json", {}))
                timestamp = str(item.get("timestamp", ""))
                stamp = timestamp[11:19] if len(timestamp) >= 19 else timestamp
                self.chat_text.insert(
                    tk.END,
                    f"[{stamp}] {item.get('username', 'user')}: {item.get('message_text', '')}\n",
                )
                if str(item.get("reply_text", "")).strip():
                    self.chat_text.insert(
                        tk.END,
                        f"Shanway: {item.get('reply_text', '')}\n",
                    )
                if payload:
                    self.chat_text.insert(
                        tk.END,
                        "  "
                        f"{payload.get('semantics_label', '--')} | "
                        f"Intent {payload.get('assistant_intent', '--')} | "
                        f"Schoenheit {float(payload.get('beauty_score', 0.0)):.1f} | "
                        f"D {float(payload.get('beauty_d', 0.0)):.3f} | "
                        f"Graph {payload.get('graph_phase_state', '--')} {payload.get('graph_region', '')} | "
                        f"Bayes {float(payload.get('bayes_pattern_posterior', 0.0)) * 100.0:.0f}% | "
                        f"H_lambda {float(payload.get('h_lambda', 0.0)):.2f} | "
                        f"Tiefe {payload.get('model_depth_label', '--')} | "
                        f"Lernen {payload.get('delta_learning_label', '--')} | "
                        f"{payload.get('integrity_text', '--')}\n",
                    )
                self.chat_text.insert(tk.END, "\n")
        self.chat_text.configure(state="disabled")
        self.chat_text.see(tk.END)
        self._refresh_shanway_view()

    def _send_chat_message(self, source: str = "auto") -> None:
        """Analysiert eine lokale Chatnachricht und laesst Shanway deterministisch antworten."""
        text = self._message_input_text(source)
        if not text:
            return
        if self._handle_shanway_toggle_command(text):
            self._clear_message_input(source)
            return
        if not self.chat_channel_map:
            self._refresh_chat_channels()
        if source == "shanway":
            self._refresh_chat_channels(selected_channel="private:shanway")
        descriptor = self._chat_current_descriptor()
        if descriptor is None:
            messagebox.showwarning("Chat", "Es ist kein gueltiger Kanal ausgewaehlt.", parent=self.root)
            return
        self._clear_message_input(source)
        kind = str(descriptor.get("kind", "public"))
        channel_name = str(descriptor.get("channel", "global"))
        current_username = str(getattr(self.session_context, "username", "local"))
        current_user_id = int(getattr(self.session_context, "user_id", 0) or 0)
        partner_name = str(descriptor.get("recipient_username", ""))
        partner_record = self.registry.get_user_by_username(partner_name) if partner_name else None
        partner_user_id = int(partner_record["id"]) if isinstance(partner_record, dict) else 0
        group_id = str(descriptor.get("group_id", ""))

        if kind in {"private", "private_shanway"} and text.casefold() == "vergiss das":
            other_name = "shanway" if kind == "private_shanway" else partner_name
            deleted = self.registry.delete_private_conversation(current_username, other_name)
            self.chat_reply_var.set("Shanway: --")
            self.chat_status_var.set(f"Privater Verlauf geloescht | {deleted} Nachrichten")
            self.chat_semantic_var.set("Semantik: -- | privater Verlauf geloescht")
            self.loading_var.set(f"Privater Verlauf geloescht: {deleted} Nachrichten")
            self._refresh_chat_view()
            return

        self.chat_status_var.set("Chat wird verarbeitet ...")
        try:
            should_reply = False
            blocked_sensitive = False
            mention_requested = self._is_direct_shanway_invocation(text)
            persist_public_analysis = False
            source_type = "chat"
            source_label = f"chat://global/{current_username}"
            if kind == "private_shanway":
                should_reply = True
                persist_public_analysis = False
                source_type = "chat_private"
                source_label = f"chat://private/{current_username}/shanway"
            elif kind == "private":
                should_reply = False
                persist_public_analysis = False
                source_type = "chat_private"
                source_label = f"chat://private/{current_username}/{partner_name}"
            elif kind == "group":
                should_reply = bool(descriptor.get("shanway_enabled", False)) and mention_requested
                persist_public_analysis = False
                source_type = "chat_group"
                source_label = f"chat://group/{group_id}/{current_username}"
            else:
                should_reply = bool(self.shanway_enabled_var.get()) or mention_requested

            if kind == "group":
                self.registry.register_group_consensus_vote(
                    group_id=group_id,
                    user_id=current_user_id,
                    username=current_username,
                    message_text=text,
                )

            reply = None
            beauty_d = 0.0
            anchors = []
            assistant_response = None
            assistant_context = None
            fingerprint = None
            record_id = 0
            full_reply = ""
            shanway_assessment: ShanwayAssessment | None = None
            detector_dna_path = ""

            if should_reply:
                assistant_context = self._assistant_context_for()
                shanway_assessment = self.shanway_engine.detect_asymmetry(
                    text,
                    coherence_score=float(getattr(self.current_fingerprint, "coherence_score", 0.0) or 0.0)
                    if self.current_fingerprint is not None else 0.0,
                    anchor_details=list(assistant_context.ae_anchor_details or []),
                    browser_mode=False,
                    active=True,
                )
                if shanway_assessment.sensitive:
                    blocked_sensitive = True
                    should_reply = False
                    full_reply = self.shanway_engine.render_response(shanway_assessment)
                    self._set_shanway_guard(full_reply)

            if should_reply:
                reply = StructuralReply(
                    semantics_label={
                        "harmonic": "HARMONIC_DIALOG",
                        "uncertain": "AMBIVALENT_DIALOG",
                        "toxic": "BLOCKED_DIALOG",
                        "sensitive": "BLOCKED_DIALOG",
                    }.get(str(shanway_assessment.classification), "DIRECT_DIALOG"),
                    beauty_score=float(max(0.0, min(100.0, shanway_assessment.noether_symmetry * 100.0))),
                    beauty_label=(
                        "harmonisch"
                        if shanway_assessment.classification == "harmonic"
                        else ("vorsichtig" if shanway_assessment.classification == "uncertain" else "blockiert")
                    ),
                    response_text=str(shanway_assessment.message),
                )
                assistant_response = self.dialog_engine.assist(
                    user_text=text,
                    structural_reply=reply,
                    context=assistant_context,
                )
                beauty_d = float(shanway_assessment.noether_symmetry)
                anchors = list(assistant_context.ae_anchor_details or [])

                full_reply = self.shanway_engine.render_response(
                    shanway_assessment,
                    assistant_text=assistant_response.text,
                )

                if kind == "private_shanway" and shanway_assessment.classification != "toxic":
                    full_reply = f"{full_reply} Dieses Gespraech bleibt zwischen uns."
                elif kind == "group" and shanway_assessment.classification != "toxic":
                    consensus_hits = self.registry.get_group_consensus_knowledge(
                        group_id=group_id,
                        query_text=text,
                        limit=2,
                    )
                    if consensus_hits:
                        consensus_prefix = " | ".join(
                            f"Konsens {int(item.get('support_count', 0))}: {item.get('text', '')}"
                            for item in consensus_hits
                        )
                        full_reply = f"{consensus_prefix}. {full_reply}"
                    full_reply = f"{full_reply} Gruppeninformation bleibt in dieser Gruppe."

            payload = {}
            if reply is not None and assistant_response is not None and assistant_context is not None:
                payload = {
                    "semantics_label": reply.semantics_label,
                    "beauty_score": reply.beauty_score,
                    "beauty_label": reply.beauty_label,
                    "beauty_d": beauty_d,
                    "anchor_count": len(anchors),
                    "assistant_intent": assistant_response.intent,
                    "assistant_knowledge_layer": int(getattr(assistant_response, "knowledge_layer", 0) or 0),
                    "assistant_knowledge_key": str(getattr(assistant_response, "knowledge_key", "")),
                    "integrity_text": str(shanway_assessment.message),
                    "ethics_score": float(max(0.0, min(100.0, shanway_assessment.noether_symmetry * 100.0))),
                    "graph_phase_state": "",
                    "graph_region": "",
                    "graph_attractor_score": 0.0,
                    "graph_interference_mean": 0.0,
                    "graph_destructive_ratio": 0.0,
                    "bayes_anchor_posterior": 0.0,
                    "bayes_graph_phase": "",
                    "bayes_graph_confidence": 0.0,
                    "bayes_pattern_posterior": 0.0,
                    "bayes_interference_posterior": 0.0,
                    "bayes_alarm_posterior": 0.0,
                    "observer_mutual_info": 0.0,
                    "observer_knowledge_ratio": 0.0,
                    "h_lambda": 0.0,
                    "observer_state": "",
                    "beauty_signature": {},
                    "model_depth_label": assistant_context.model_depth_label,
                    "model_depth_score": assistant_context.model_depth_score,
                    "delta_learning_label": assistant_context.delta_learning_label,
                    "delta_learning_ratio": assistant_context.delta_learning_ratio,
                    "anomaly_memory_top": assistant_context.anomaly_memory_top,
                    "ae_lab": {},
                    "ae_anchor_details": [dict(item) for item in list(assistant_context.ae_anchor_details or [])[:16]],
                }
                if shanway_assessment is not None:
                    payload["shanway_assessment"] = shanway_assessment.to_payload()
                    payload["shanway_detector_dna"] = ""
            elif blocked_sensitive and shanway_assessment is not None:
                payload = {
                    "shanway_assessment": shanway_assessment.to_payload(),
                    "shanway_blocked": True,
                }
            if kind == "group":
                payload["group_id"] = group_id
                payload["group_shanway_enabled"] = bool(descriptor.get("shanway_enabled", False))
            if kind.startswith("private"):
                payload["private_scope"] = True

            message_id = self.registry.save_chat_message(
                session_id=self.session_context.session_id,
                user_id=current_user_id,
                username=current_username,
                message_text=text,
                fingerprint_id=int(record_id),
                reply_text=full_reply,
                channel=channel_name,
                payload=payload,
                is_private=kind in {"private", "private_shanway"},
                recipient_user_id=partner_user_id if kind == "private" else 0,
                recipient_username=partner_name if kind == "private" else ("shanway" if kind == "private_shanway" else ""),
                group_id=group_id if kind == "group" else "",
                visible_to_shanway=bool(should_reply or blocked_sensitive or kind == "private_shanway"),
            )
            if kind != "private_shanway":
                self._chat_sync_publish_message(int(message_id))

            if blocked_sensitive and shanway_assessment is not None:
                self.chat_reply_var.set(f"Shanway: {full_reply}")
                self.chat_semantic_var.set("Semantik: BLOCKED | sensible Daten")
                self.chat_status_var.set("Sensible Inhalte erkannt | Analyse gestoppt")
                self.loading_var.set("Sensible Inhalte erkannt | Shanway hat nicht analysiert")
            elif should_reply and reply is not None and assistant_response is not None and shanway_assessment is not None:
                self.chat_reply_var.set(f"Shanway: {full_reply}")
                self.chat_semantic_var.set(
                    f"Semantik: {reply.semantics_label} | Schoenheit: {reply.beauty_score:.1f} ({reply.beauty_label}) | "
                    f"Intent: {assistant_response.intent} | Layer {int(getattr(assistant_response, 'knowledge_layer', 0) or 0)} | "
                    f"Noether {shanway_assessment.noether_symmetry * 100.0:.0f}% | tox {shanway_assessment.toxicity_score * 100.0:.0f}%"
                )
                if shanway_assessment.classification == "toxic":
                    self.chat_status_var.set(
                        f"Shanway aktiv | Kanal {channel_name} | asymmetrische Struktur blockiert"
                    )
                else:
                    self.chat_status_var.set(
                        f"Shanway aktiv | Kanal {channel_name} | Intent {assistant_response.intent} | direkter Privatdialog"
                    )
                self.loading_var.set("Chatnachricht lokal verarbeitet | kein Einfluss auf Raster oder Browser")
                self._set_shanway_guard(shanway_assessment.message)
            else:
                self.chat_reply_var.set("Shanway: --")
                if kind == "group":
                    if bool(descriptor.get("shanway_enabled", False)):
                        self.chat_status_var.set("Gruppennachricht gespeichert | Shanway reagiert nur auf @shanway")
                    else:
                        self.chat_status_var.set("Gruppennachricht gespeichert | Shanway in dieser Gruppe deaktiviert")
                elif kind == "private":
                    self.chat_status_var.set(f"Direktnachricht an {partner_name} lokal verschluesselt gespeichert")
                else:
                    self.chat_status_var.set("Chatnachricht gespeichert | Shanway aus")
                self.chat_semantic_var.set("Semantik: -- | keine Shanway-Antwort fuer diesen Kanal")
                self.loading_var.set("Verschluesselte Chatnachricht gespeichert")
                self._set_shanway_guard("Shanway Guard: bereit")

            self._refresh_chat_channels(selected_channel=channel_name)
            self._refresh_chat_view()
        except Exception as exc:
            self.chat_status_var.set("Shanway-Analyse fehlgeschlagen")
            messagebox.showerror("Chatfehler", f"Die Chatnachricht konnte nicht analysiert werden:\n{exc}")

    def _refresh_shanway_view(self) -> None:
        """Zeigt den privaten Verlauf mit Shanway als eigenen klaren Verlauf an."""
        if not hasattr(self, "shanway_text"):
            return
        messages = list(
            reversed(
                self.registry.get_chat_messages(
                    limit=160,
                    channel="private:shanway",
                    current_user_id=int(getattr(self.session_context, "user_id", 0) or 0),
                    current_username=str(getattr(self.session_context, "username", "")),
                )
            )
        )
        self.shanway_text.configure(state="normal")
        self.shanway_text.delete("1.0", tk.END)
        if not messages:
            self.shanway_text.insert(
                "1.0",
                "Noch kein privater Verlauf mit Shanway vorhanden.\n\n"
                "Hier bleibt das Gespraech lokal verschluesselt und getrennt von oeffentlichen Kanaelen.\n",
            )
        else:
            for item in messages:
                payload = dict(item.get("payload_json", {}))
                timestamp = str(item.get("timestamp", ""))
                stamp = timestamp[11:19] if len(timestamp) >= 19 else timestamp
                self.shanway_text.insert(tk.END, f"[{stamp}] Du: {item.get('message_text', '')}\n")
                if str(item.get("reply_text", "")).strip():
                    self.shanway_text.insert(tk.END, f"Shanway: {item.get('reply_text', '')}\n")
                if payload:
                    assessment = dict(payload.get("shanway_assessment", {}) or {})
                    language = str(assessment.get("language", payload.get("language", "--")))
                    self.shanway_text.insert(
                        tk.END,
                        "  "
                        f"Sprache {language} | "
                        f"Intent {payload.get('assistant_intent', '--')} | "
                        f"Schoenheit {float(payload.get('beauty_score', 0.0)):.1f} | "
                        f"H_lambda {float(payload.get('h_lambda', 0.0)):.2f} | "
                        f"Noether {float(assessment.get('noether_symmetry', 0.0)) * 100.0:.0f}%\n",
                    )
                self.shanway_text.insert(tk.END, "\n")
        self.shanway_text.configure(state="disabled")
        self.shanway_text.see(tk.END)

    def _base_loop_delay_ms(self, loop_name: str) -> int:
        """Liefert die Basistakte aus dem statischen Geraeteprofil."""
        mapping = {
            "camera": self.device_profile.camera_interval_ms,
            "conway": self.device_profile.conway_interval_ms,
            "animation": self.device_profile.animation_interval_ms,
        }
        return int(mapping.get(loop_name, 80))

    def _loop_delay_ms(self, loop_name: str) -> int:
        """Liefert adaptive Schleifenintervalle inklusive aktueller Laufzeitlast."""
        base = self._base_loop_delay_ms(loop_name)
        security_scale = float(getattr(self.session_context, "security_policy", {}).get("maze_delay_scale", 1.0) or 1.0)
        return int(max(30, round(float(base) * float(self._runtime_delay_scale) * security_scale)))

    def _prime_language_panel(self) -> None:
        """Initialisiert die GP-Sprachkarten aus persistentem Zustand."""
        self.voice_status_var.set(
            self._language_status_text(
                "ontology_complete" if self.symbol_grounding.ontology_complete() else "ontology_shift",
                self.symbol_grounding.ontology_complete(),
            )
        )
        self._render_language_panel(
            self.language_engine.top_sentences(),
            ontology_complete=self.symbol_grounding.ontology_complete(),
        )

    def _render_language_panel(self, sentences: list[EvolvedSentence], ontology_complete: bool) -> None:
        """Stellt eine oder drei evolvierte Beschreibungen sichtbar dar."""
        texts = [str(item.text).strip() for item in sentences if str(item.text).strip()]
        fallback = "Das System sammelt noch genug Geometrie fuer seine erste eigene Aussage."
        for index, variable in enumerate(self.voice_sentence_vars):
            if index == 0:
                text = texts[0] if texts else fallback
            elif ontology_complete and index < len(texts):
                text = texts[index]
            elif ontology_complete:
                text = ""
            else:
                text = "Weitere GP-Saetze erscheinen, sobald die Ontologie vollstaendig ist." if index == 1 else ""
            variable.set(text)

            if index >= len(self._voice_card_refs):
                continue
            active = bool(text) and (ontology_complete or index == 0)
            background = "#10223F" if active else "#0C172B"
            border = "#F2C14E" if active else "#233A5A"
            header_color = "#F2C14E" if active else "#60728E"
            text_color = "#F6E7A7" if active else "#9CB0CC"
            card = self._voice_card_refs[index]
            card.configure(bg=background, highlightbackground=border, highlightcolor=border)
            children = card.winfo_children()
            if len(children) >= 2:
                children[0].configure(bg=background, fg=header_color)
                children[1].configure(bg=background, fg=text_color)

    def _language_status_text(self, event_type: str, ontology_complete: bool) -> str:
        """Formatiert den Status der evolvierten GP-Sprache."""
        labels = {
            "pattern_reinforced": "Muster verstaerkt",
            "contrast_discovered": "Gegensatz entdeckt",
            "ontology_shift": "Ontologie verschoben",
            "ontology_complete": "Ontologie spricht in drei Saetzen",
            "agent_resolved": "Agent-Aufloesung erkannt",
        }
        if ontology_complete:
            event_label = labels["ontology_complete"]
        else:
            event_label = labels.get(event_type, "Selbstbeschreibung aktiv")
        suffix = " | Low-End Mode" if self.device_profile.low_end else ""
        return f"GP-Systemsprache | {event_label} | 100 Generationen | 100 Baeume | kein LLM{suffix}"

    def _ontology_label(self) -> str:
        """Leitet eine knappe deutschsprachige Ontologie-Beschreibung ab."""
        named, total = self.symbol_grounding.named_counts()
        token_state = self.symbol_grounding.export_state().get("tokens", {})
        names = []
        for token, record in token_state.items():
            human_name = str(record.get("human_name", "")).strip()
            names.append(human_name or str(token))
            if len(names) >= 3:
                break
        if names:
            return f"{named}/{total} Token: {', '.join(names)}"
        return f"{named}/{total} Token im Feld"

    def _queue_language_event(self, context: dict[str, object]) -> None:
        """Startet eine GP-Evolution fuer ein systeminternes Ereignis im Hintergrund."""
        payload = dict(context)
        event_type = str(payload.get("event_type", "ontology_shift"))
        payload.setdefault("ontology_label", self._ontology_label())
        payload["ontology_complete"] = bool(self.symbol_grounding.ontology_complete())
        self.voice_status_var.set(self._language_status_text(event_type, bool(payload["ontology_complete"])) + " ...")
        self._language_job_id += 1
        job_id = self._language_job_id

        def worker() -> None:
            try:
                sentences = self.language_engine.describe(payload, bool(payload["ontology_complete"]))
            except Exception:
                return
            try:
                self.root.after(0, lambda: self._apply_language_result(job_id, payload, sentences))
            except Exception:
                return

        threading.Thread(target=worker, daemon=True).start()

    def _apply_language_result(
        self,
        job_id: int,
        context: dict[str, object],
        sentences: list[EvolvedSentence],
    ) -> None:
        """Uebernimmt das Ergebnis einer Hintergrund-Evolution in die GUI."""
        if job_id != self._language_job_id:
            return
        ontology_complete = bool(context.get("ontology_complete", False))
        self.voice_status_var.set(
            self._language_status_text(str(context.get("event_type", "ontology_shift")), ontology_complete)
        )
        self._render_language_panel(sentences, ontology_complete=ontology_complete)

    def _sync_vault_grounding_payload(self, vault_entries: list[dict[str, object]]) -> None:
        """Schreibt Token-, Bedeutungs- und Beziehungsdaten in persistente Vault-Payloads zurueck."""
        for entry in vault_entries:
            token_info = self.symbol_grounding.token_for_entry(entry["id"])
            if token_info is None:
                continue
            payload = dict(entry.get("payload_json", {}))
            token = str(token_info.get("token", ""))
            human_name = str(token_info.get("human_name", "")).strip()
            meaning = dict(token_info.get("meaning", {}))
            related = self.symbol_grounding.related_names(token)
            updated = False
            if payload.get("token") != token:
                payload["token"] = token
                updated = True
            if payload.get("token_name") != human_name:
                payload["token_name"] = human_name
                updated = True
            if payload.get("token_meaning") != meaning:
                payload["token_meaning"] = meaning
                updated = True
            if payload.get("semantic_related") != related:
                payload["semantic_related"] = related
                updated = True
            if updated:
                signature = self.augmentor.sign_payload(payload)
                self.registry.update_vault_payload(int(entry["id"]), payload, signature=signature)
                entry["payload_json"] = payload
                entry["signature"] = signature

    def _emit_language_events(self, pattern, token_info: dict[str, object] | None = None) -> None:
        """Leitet neue Strukturereignisse in die GP-Sprachschicht weiter."""
        if not self.session_context.security_allows("allow_gp_evolution", True):
            self.voice_status_var.set(
                f"GP pausiert | {self.session_context.trust_state} | Maze {self.session_context.maze_state}"
            )
            return
        token_name = ""
        if token_info is not None:
            token_name = str(token_info.get("human_name", "") or token_info.get("token", ""))
        named_total = self.symbol_grounding.named_counts()
        ontology_complete = self.symbol_grounding.ontology_complete()
        opposite_pairs = {tuple(sorted(pair)) for pair in self.symbol_grounding.opposite_pairs()}
        new_pairs = sorted(opposite_pairs - self._known_opposite_pairs)

        selected_context: dict[str, object] | None = None
        if pattern is not None:
            selected_context = {
                "event_type": "pattern_reinforced",
                "pattern_label": str(getattr(pattern, "label", "PATTERN FOUND")),
                "token_name": token_name,
            }
        if named_total != self._last_named_total:
            selected_context = {
                "event_type": "ontology_shift",
                "token_name": token_name,
            }
        if new_pairs:
            left, right = new_pairs[-1]
            selected_context = {
                "event_type": "contrast_discovered",
                "contrast_label": f"{left} vs {right}",
                "token_name": token_name,
            }
        if ontology_complete and not self._last_ontology_complete:
            selected_context = {
                "event_type": "ontology_complete",
                "token_name": token_name,
                "ontology_label": self._ontology_label(),
            }
        if selected_context is not None:
            self._queue_language_event(selected_context)

        self._known_opposite_pairs = opposite_pairs
        self._last_named_total = named_total
        self._last_ontology_complete = ontology_complete

    def _build_left_panel(self) -> None:
        """Baut den linken Bereich mit Analysekontrollen und Loganzeige."""
        tk.Label(self.left_frame, text="Analyse-Steuerung", bg="#111A4A", fg="#E7F4FF", font=("Segoe UI", 13, "bold")).pack(anchor="w", padx=12, pady=(12, 8))

        ttk.Button(self.left_frame, text="Datei analysieren", command=self._open_file_dialog).pack(fill="x", padx=12, pady=(0, 6))
        ttk.Button(self.left_frame, text="Lichtspektrum analysieren", command=self._open_spectrum_dialog).pack(fill="x", padx=12, pady=(0, 6))
        ttk.Button(self.left_frame, text="CSV 4D importieren", command=self._open_csv_dialog).pack(fill="x", padx=12, pady=(0, 6))
        ttk.Button(self.left_frame, text="AELAB DNA importieren", command=self._open_aelab_dna_dialog).pack(fill="x", padx=12, pady=(0, 6))
        ttk.Button(self.left_frame, text="AELAB Vault importieren", command=self._open_aelab_vault_dialog).pack(fill="x", padx=12, pady=(0, 6))

        ae_row = tk.Frame(self.left_frame, bg="#111A4A")
        ae_row.pack(fill="x", padx=12, pady=(0, 8))
        self.ae_stop_button = tk.Button(
            ae_row,
            textvariable=self.ae_stop_button_var,
            command=self._stop_ae_evolution,
            bg="#AA2E25",
            fg="#FFFFFF",
            activebackground="#7B241C",
            activeforeground="#FFFFFF",
            relief="flat",
            padx=10,
            pady=6,
            cursor="hand2",
        )
        self.ae_stop_button.pack(fill="x", expand=True)
        tk.Label(
            self.left_frame,
            textvariable=self.ae_iteration_var,
            bg="#111A4A",
            fg="#F2C14E",
            wraplength=345,
            justify="left",
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=12, pady=(0, 8))

        row = tk.Frame(self.left_frame, bg="#111A4A")
        row.pack(fill="x", padx=12, pady=(0, 8))
        ttk.Button(row, text="Theremin aktivieren", command=self._start_theremin).pack(side="left", fill="x", expand=True, padx=(0, 4))
        ttk.Button(row, text="Theremin stoppen", command=self._stop_theremin).pack(side="left", fill="x", expand=True, padx=(4, 0))

        export_row = tk.Frame(self.left_frame, bg="#111A4A")
        export_row.pack(fill="x", padx=12, pady=(0, 8))
        ttk.Button(export_row, text="Voxel-CSV exportieren", command=self._export_voxel_csv).pack(fill="x", expand=True)

        restore_row = tk.Frame(self.left_frame, bg="#111A4A")
        restore_row.pack(fill="x", padx=12, pady=(0, 8))
        ttk.Button(restore_row, text="Original oeffnen", command=self._open_reconstructed_original).pack(fill="x", expand=True)
        tk.Label(
            self.left_frame,
            textvariable=self.restore_status_var,
            bg="#111A4A",
            fg="#7AB6FF",
            wraplength=345,
            justify="left",
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=12, pady=(0, 8))
        ttk.Checkbutton(
            self.left_frame,
            text="Rohdaten speichern (lokal, verschluesselt)",
            variable=self.raw_storage_enabled_var,
            command=self._on_raw_storage_toggle,
        ).pack(anchor="w", padx=12, pady=(0, 4))
        tk.Label(
            self.left_frame,
            textvariable=self.raw_storage_status_var,
            bg="#111A4A",
            fg="#F2C14E",
            wraplength=345,
            justify="left",
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=12, pady=(0, 8))

        history_row = tk.Frame(self.left_frame, bg="#111A4A")
        history_row.pack(fill="x", padx=12, pady=(0, 8))
        ttk.Button(history_row, text="◀ Verlauf", command=self._history_prev).pack(side="left", fill="x", expand=True, padx=(0, 4))
        ttk.Button(history_row, text="Verlauf laden", command=self._history_reload_current).pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(history_row, text="Verlauf ▶", command=self._history_next).pack(side="left", fill="x", expand=True, padx=(4, 0))
        tk.Label(
            self.left_frame,
            textvariable=self.history_status_var,
            bg="#111A4A",
            fg="#F2C14E",
            wraplength=345,
            justify="left",
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=12, pady=(0, 8))

        browser_row = tk.Frame(self.left_frame, bg="#111A4A")
        browser_row.pack(fill="x", padx=12, pady=(0, 8))
        ttk.Checkbutton(
            browser_row,
            text="Browserfenster offen halten",
            variable=self.browser_dock_var,
            command=self._toggle_browser_main_dock,
        ).pack(side="left")

        tk.Label(self.left_frame, text="Storage-Layer", bg="#111A4A", fg="#C7D7FF", font=("Segoe UI", 9)).pack(anchor="w", padx=12)
        layer_box = ttk.Combobox(
            self.left_frame,
            textvariable=self.storage_layer_var,
            values=["Raw Deltas", "Heatmap"],
            state="readonly",
        )
        layer_box.pack(fill="x", padx=12, pady=(4, 8))
        layer_box.bind("<<ComboboxSelected>>", self._on_storage_layer_changed)

        tk.Label(self.left_frame, text="Datei oder CSV per Drag & Drop ins Fenster ziehen startet sofort die passende Analyse bzw. den 4D-Voxel-Import.", bg="#111A4A", fg="#8FB5FF", font=("Segoe UI", 9, "italic"), wraplength=345, justify="left").pack(anchor="w", padx=12, pady=(0, 8))

        tk.Label(self.left_frame, text="Theremin-Regler", bg="#111A4A", fg="#E7F4FF", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12, pady=(0, 4))
        tk.Label(self.left_frame, text="Entropie-Sensitivitaet", bg="#111A4A", fg="#C7D7FF", font=("Segoe UI", 9)).pack(anchor="w", padx=12)
        ttk.Scale(self.left_frame, from_=0.4, to=2.8, variable=self.sensitivity_var, orient="horizontal").pack(fill="x", padx=12, pady=(2, 6))
        tk.Label(self.left_frame, text="Harmonie / Dissonanz-Verhaeltnis", bg="#111A4A", fg="#C7D7FF", font=("Segoe UI", 9)).pack(anchor="w", padx=12)
        ttk.Scale(self.left_frame, from_=0.0, to=1.0, variable=self.harmony_var, orient="horizontal").pack(fill="x", padx=12, pady=(2, 8))

        tk.Label(self.left_frame, textvariable=self.wavelength_var, bg="#111A4A", fg="#E7F4FF", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12, pady=(0, 4))
        self.wavelength_canvas = tk.Canvas(self.left_frame, width=320, height=22, bg="#111A4A", highlightthickness=0, bd=0)
        self.wavelength_canvas.pack(anchor="w", padx=12, pady=(0, 10))
        self.wavelength_rect = self.wavelength_canvas.create_rectangle(0, 0, 320, 22, fill="#304060", outline="")

        tk.Label(self.left_frame, text="Dateipfad manuell eingeben (Enter startet Analyse):", bg="#111A4A", fg="#C7D7FF", font=("Segoe UI", 9)).pack(anchor="w", padx=12)
        self.path_entry = ttk.Entry(self.left_frame, textvariable=self.path_var)
        self.path_entry.pack(fill="x", padx=12, pady=(4, 8))
        self.path_entry.bind("<Return>", lambda _event: self._start_analysis_from_entry())

        self.speech_button = ttk.Button(self.left_frame, text="Spracheingabe starten", command=self._start_speech_input)
        self.speech_button.pack(fill="x", padx=12, pady=(0, 8))
        if sr is None:
            self.speech_button.configure(text="Spracheingabe starten (nicht verfuegbar)")

        self.progress = ttk.Progressbar(self.left_frame, orient="horizontal", mode="indeterminate")
        tk.Label(self.left_frame, textvariable=self.loading_var, bg="#111A4A", fg="#A8B9E8", justify="left", anchor="w", wraplength=350, font=("Segoe UI", 9)).pack(fill="x", padx=12, pady=(4, 10))

        tk.Label(self.left_frame, text="Letzte Log-Eintraege", bg="#111A4A", fg="#E7F4FF", font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=12, pady=(0, 6))
        log_container = tk.Frame(self.left_frame, bg="#111A4A")
        log_container.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.log_text = tk.Text(log_container, bg="#0C1238", fg="#D4E6FF", insertbackground="#D4E6FF", relief="flat", wrap="word", font=("Consolas", 9))
        scrollbar = ttk.Scrollbar(log_container, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.log_text.configure(state="disabled")

    def _build_right_panel(self) -> None:
        """Der rechte Bereich wird spaeter komplett als eingebettetes Modul-Notebook aufgebaut."""
        return

    def _create_integrity_row(
        self,
        parent: tk.Widget,
        label: str,
        variable: tk.DoubleVar,
        style_name: str,
    ) -> None:
        """Erzeugt eine einzelne Zeile des Integritaets-Monitors."""
        row = tk.Frame(parent, bg="#111A4A")
        row.pack(fill="x", pady=(0, 6))
        tk.Label(row, text=label, bg="#111A4A", fg="#C7D7FF", font=("Segoe UI", 9)).pack(anchor="w")
        ttk.Progressbar(
            row,
            orient="horizontal",
            mode="determinate",
            maximum=100,
            variable=variable,
            style=style_name,
        ).pack(fill="x", pady=(2, 0))

    def _toggle_camera_feed(self) -> None:
        """Aktiviert oder deaktiviert die additive Kamerabeobachtung."""
        if self.camera_toggle_var.get():
            if self.camera_capture is None:
                self.camera_capture = cv2.VideoCapture(0, cv2.CAP_DSHOW)
                if not self.camera_capture.isOpened():
                    self.camera_capture = cv2.VideoCapture(0)
                if self.camera_capture is None or not self.camera_capture.isOpened():
                    self.camera_capture = None
                    self.camera_toggle_var.set(False)
                    self.loading_var.set("Kamera konnte nicht gestartet werden.")
                    return
            self.observer_engine.reset()
            self._camera_loop()
            if self.conway_job is None:
                self._conway_loop()
        else:
            if self.camera_job is not None:
                try:
                    self.root.after_cancel(self.camera_job)
                except Exception:
                    pass
                self.camera_job = None
            if self.camera_capture is not None:
                try:
                    self.camera_capture.release()
                except Exception:
                    pass
                self.camera_capture = None
            if self.conway_job is not None:
                try:
                    self.root.after_cancel(self.conway_job)
                except Exception:
                    pass
                self.conway_job = None
            if self.camera_theremin_var.get():
                self.audio_engine.stop_aether_oscillator()

    def _toggle_camera_theremin(self) -> None:
        """Schaltet den additiven Aether-Oszillator fuer Kamerametriken."""
        if self.camera_theremin_var.get():
            if not self.audio_engine.start_aether_oscillator():
                self.camera_theremin_var.set(False)
                self.loading_var.set("Aether-Oszillator konnte nicht gestartet werden.")
        else:
            self.audio_engine.stop_aether_oscillator()

    def _on_agent_toggle(self) -> None:
        """Setzt den Agentzustand beim Umschalten sauber."""
        if not self.agent_toggle_var.get():
            self.agent_loop.reset()
            self._last_agent_resolved_count = 0
        self._refresh_augment_views()

    def _bootstrap_public_anchor_cycle(self) -> None:
        """Stoesst wartende Public-Anchor-Jobs nach dem GUI-Start einmal an."""
        try:
            summary = self.public_anchor.get_summary()
        except Exception:
            return
        pending = int(summary.get("pending", 0) or 0)
        if pending <= 0:
            return
        if bool(summary.get("online", False)):
            self.loading_var.set(f"Public Anchor: {pending} wartende Jobs werden erneut versucht ...")
            self._flush_public_anchor_queue()
        else:
            self.loading_var.set(f"Public Anchor: {pending} Jobs warten lokal auf Zugangsdaten.")

    def _flush_public_anchor_queue(self) -> None:
        """Versucht wartende Public-Anchor-Jobs manuell erneut."""
        summary = self.public_anchor.get_summary()
        pending = int(summary.get("pending", 0) or 0)
        if pending <= 0:
            self.loading_var.set("Public Anchor: keine wartenden Jobs.")
            self._refresh_augment_views()
            return

        def on_finish(result: dict[str, object]) -> None:
            processed = int(result.get("processed", 0) or 0)
            remaining = int(result.get("remaining", 0) or 0)
            mode = str(result.get("mode", "")).strip() or "offline"
            self.root.after(
                0,
                lambda: (
                    self.loading_var.set(
                        f"Public Anchor: {processed} verarbeitet, {remaining} wartend ({mode})."
                    ),
                    self._refresh_augment_views(),
                ),
            )

        self.loading_var.set(f"Public Anchor: {pending} Jobs werden geprueft ...")
        self.public_anchor.flush_pending_async(callback=on_finish)

    def _open_public_anchor_settings(self) -> None:
        """Oeffnet einen kleinen Drawer fuer API-Zugangsdaten."""
        drawer = tk.Toplevel(self.augment_window)
        drawer.title("Public Anchoring Settings")
        drawer.geometry("420x220")
        drawer.configure(bg="#0D1930")
        settings = self.public_anchor.load_settings()
        summary = self.public_anchor.get_summary()
        vars_map = {
            "blockcypher_token": tk.StringVar(value=settings.get("blockcypher_token", "")),
            "pinata_jwt": tk.StringVar(value=settings.get("pinata_jwt", "")),
            "pinata_api_key": tk.StringVar(value=settings.get("pinata_api_key", "")),
            "pinata_api_secret": tk.StringVar(value=settings.get("pinata_api_secret", "")),
        }
        for key, variable in vars_map.items():
            row = tk.Frame(drawer, bg="#0D1930")
            row.pack(fill="x", padx=12, pady=6)
            tk.Label(row, text=key, bg="#0D1930", fg="#CFE8FF", width=18, anchor="w").pack(side="left")
            ttk.Entry(row, textvariable=variable, show="*" if "secret" in key or "token" in key or "jwt" in key else "").pack(side="left", fill="x", expand=True)
        status_text = (
            f"Online: {'ja' if summary.get('online') else 'nein'} | "
            f"Queue: {int(summary.get('pending', 0) or 0)} | "
            f"Letzter Status: {str(summary.get('latest_status', '') or '--')}"
        )
        tk.Label(drawer, text=status_text, bg="#0D1930", fg="#F6E7A7", anchor="w").pack(fill="x", padx=12, pady=(6, 0))

        def save() -> None:
            self.public_anchor.save_settings({key: variable.get().strip() for key, variable in vars_map.items()})
            self.public_anchor.flush_pending_async(
                callback=lambda _summary: self.root.after(0, self._refresh_augment_views)
            )
            drawer.destroy()
            self._refresh_augment_views()

        ttk.Button(drawer, text="Speichern", command=save).pack(pady=12)

    def _camera_loop(self) -> None:
        """Liest Kamera-Frames, extrahiert Anker und aktualisiert Zusatzmodule."""
        if not self.camera_toggle_var.get() or self.camera_capture is None:
            return
        loop_start = time.perf_counter()

        ok, frame_bgr = self.camera_capture.read()
        if ok and frame_bgr is not None:
            frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
            if self.camera_mirror_var.get():
                frame_rgb = np.ascontiguousarray(frame_rgb[:, ::-1, :])
            prior_cells = self.registry.get_anchor_priors(limit=14)
            snapshot = self.observer_engine.process_frame(
                frame_rgb=frame_rgb,
                prior_cells=prior_cells,
                phi=self.current_phi,
                h_obs=self.current_h_obs,
            )
            self.registry.update_anchor_prior(self.observer_engine.prior_cells_from_anchors(snapshot.anchors))
            self.last_observer_metrics = snapshot.metrics
            self._update_observer_metrics(snapshot.metrics)
            profile = dict(snapshot.interference_profile or {})
            self._set_event_benford_metric(dict(profile.get("benford_profile", {}) or {}))
            live_prior_post = self.bayes_engine.anchor_prior_posterior(prior_cells, snapshot.anchors)
            self.bayes_anchor_var.set(f"Prior-Posterior {live_prior_post * 100.0:.0f}% | live")
            live_resonance = max(
                0.0,
                min(
                    1.0,
                    (0.55 * float(snapshot.metrics.constructive_ratio))
                    + (0.45 * (1.0 - float(snapshot.metrics.destructive_ratio))),
                ),
            )
            live_delta_ratio = max(
                0.0,
                min(1.0, float(len(snapshot.delta_ops)) / max(1.0, float(max(1, len(snapshot.anchors)) * 2.0))),
            )
            self._set_live_observer_gap(
                entropy_now=float(snapshot.metrics.ht),
                coherence=float(snapshot.metrics.coherence),
                resonance=live_resonance,
                prior_hint=max(float(live_prior_post), float(snapshot.metrics.prior_accuracy)),
                delta_ratio=live_delta_ratio,
            )
            self._update_camera_canvas(snapshot)
            self.conway_engine.seed_from_anchors(snapshot.anchors, snapshot.ghost_anchors)

            current_embedding = self.embedding_engine.embedding_from_anchors(snapshot.anchors)
            directive = self.agent_loop.update(self.vault_entries_cache, current_embedding, self.agent_toggle_var.get())
            if directive.resolved_count > self._last_agent_resolved_count:
                self._last_agent_resolved_count = directive.resolved_count
                related = self.symbol_grounding.related_names(self._latest_agent_token) if self._latest_agent_token else []
                self._mint_chain_block(
                    tag="AGENT ACQUISITION",
                    reconstruction_verified=False,
                    confirmed_lossless=False,
                    merkle_root="",
                    payload_extra={"agent_related": related},
                )
                if related:
                    self.pattern_found_var.set(f"VERBUNDEN MIT: {', '.join(related[:3])}")
                self._queue_language_event(
                    {
                        "event_type": "agent_resolved",
                        "agent_label": directive.instruction or "die offene Region",
                        "token_name": related[0] if related else self._latest_agent_token,
                    }
                )
            if self.camera_theremin_var.get():
                self.audio_engine.start_aether_oscillator()
                frequency = 110.0 + (snapshot.metrics.center_lum / 255.0) * 880.0
                detune = (snapshot.metrics.center_mass_x - 0.5) * 1200.0
                self.audio_engine.update_aether_state(frequency=frequency, detune=detune, volume=0.16)
            self._overlay_agent_text(directive)
            self._check_alarm_conditions(snapshot.metrics)

        self._refresh_runtime_adaptation("camera", time.perf_counter() - loop_start)
        # Use queue for thread-safe communication from background threads
        self.camera_queue = queue.Queue()
        def camera_worker():
            while self.camera_toggle_var.get() and self.camera_capture is not None:
                ok, frame_bgr = self.camera_capture.read()
                if ok and frame_bgr is not None:
                    self.camera_queue.put(frame_bgr)
                time.sleep(self._loop_delay_ms("camera") / 1000.0)
        self.camera_thread = threading.Thread(target=camera_worker, daemon=True)
        self.camera_thread.start()
        self._poll_camera_queue()

    def _poll_camera_queue(self):
        try:
            while True:
                frame_bgr = self.camera_queue.get_nowait()
                # Process frame in main thread
                frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
                if self.camera_mirror_var.get():
                    frame_rgb = np.ascontiguousarray(frame_rgb[:, ::-1, :])
                prior_cells = self.registry.get_anchor_priors(limit=14)
                snapshot = self.observer_engine.process_frame(
                    frame_rgb=frame_rgb,
                    prior_cells=prior_cells,
                    phi=self.current_phi,
                    h_obs=self.current_h_obs,
                )
                self.registry.update_anchor_prior(self.observer_engine.prior_cells_from_anchors(snapshot.anchors))
                self.last_observer_metrics = snapshot.metrics
                self._update_observer_metrics(snapshot.metrics)
                profile = dict(snapshot.interference_profile or {})
                self._set_event_benford_metric(dict(profile.get("benford_profile", {}) or {}))
                live_prior_post = self.bayes_engine.anchor_prior_posterior(prior_cells, snapshot.anchors)
                self.bayes_anchor_var.set(f"Prior-Posterior {live_prior_post * 100.0:.0f}% | live")
                live_resonance = max(
                    0.0,
                    min(
                        1.0,
                        (0.55 * float(snapshot.metrics.constructive_ratio))
                        + (0.45 * (1.0 - float(snapshot.metrics.destructive_ratio))),
                    ),
                )
                live_delta_ratio = max(
                    0.0,
                    min(1.0, float(len(snapshot.delta_ops)) / max(1.0, float(max(1, len(snapshot.anchors)) * 2.0))),
                )
                self._set_live_observer_gap(
                    entropy_now=float(snapshot.metrics.ht),
                    coherence=float(snapshot.metrics.coherence),
                    resonance=live_resonance,
                    prior_hint=max(float(live_prior_post), float(snapshot.metrics.prior_accuracy)),
                    delta_ratio=live_delta_ratio,
                )
                self._update_camera_canvas(snapshot)
                self.conway_engine.seed_from_anchors(snapshot.anchors, snapshot.ghost_anchors)
                current_embedding = self.embedding_engine.embedding_from_anchors(snapshot.anchors)
                directive = self.agent_loop.update(self.vault_entries_cache, current_embedding, self.agent_toggle_var.get())
                if directive.resolved_count > self._last_agent_resolved_count:
                    self._last_agent_resolved_count = directive.resolved_count
                    related = self.symbol_grounding.related_names(self._latest_agent_token) if self._latest_agent_token else []
                    self._mint_chain_block(
                        tag="AGENT ACQUISITION",
                        reconstruction_verified=False,
                        confirmed_lossless=False,
                        merkle_root="",
                        payload_extra={"agent_related": related},
                    )
                    if related:
                        self.pattern_found_var.set(f"VERBUNDEN MIT: {', '.join(related[:3])}")
                    self._queue_language_event(
                        {
                            "event_type": "agent_resolved",
                            "agent_label": directive.instruction or "die offene Region",
                            "token_name": related[0] if related else self._latest_agent_token,
                        }
                    )
                if self.camera_theremin_var.get():
                    self.audio_engine.start_aether_oscillator()
                    frequency = 110.0 + (snapshot.metrics.center_lum / 255.0) * 880.0
                    detune = (snapshot.metrics.center_mass_x - 0.5) * 1200.0
                    self.audio_engine.update_aether_state(frequency=frequency, detune=detune, volume=0.16)
                self._overlay_agent_text(directive)
                self._check_alarm_conditions(snapshot.metrics)
        except queue.Empty:
            pass
        self.root.after(self._loop_delay_ms("camera"), self._poll_camera_queue)

    def _conway_loop(self) -> None:
        """Aktualisiert das Conway-Feld alle 100 ms."""
        loop_start = time.perf_counter()
        snapshot = self.conway_engine.step()
        self.current_h_obs = float(snapshot.h_obs)
        self.current_phi = float(snapshot.phi)
        self.h_obs_live_var.set(max(0.0, min(100.0, (self.current_h_obs / 5.0) * 100.0)))
        self.metric_phi_var.set(f"{self.current_phi:.2f}")
        image = self.conway_engine.render_rgb(snapshot)
        pil = Image.fromarray(image).resize((540, 540), resample=Image.Resampling.NEAREST)
        self.conway_image_ref = ImageTk.PhotoImage(pil)
        self.conway_canvas.delete("all")
        self.conway_canvas.create_image(0, 0, image=self.conway_image_ref, anchor="nw")
        self._refresh_runtime_adaptation("conway", time.perf_counter() - loop_start)
        self.conway_queue = queue.Queue()
        def conway_worker():
            while True:
                snapshot = self.conway_engine.step()
                self.conway_queue.put(snapshot)
                time.sleep(self._loop_delay_ms("conway") / 1000.0)
        self.conway_thread = threading.Thread(target=conway_worker, daemon=True)
        self.conway_thread.start()
        self._poll_conway_queue()

    def _poll_conway_queue(self):
        try:
            while True:
                snapshot = self.conway_queue.get_nowait()
                self.current_h_obs = float(snapshot.h_obs)
                self.current_phi = float(snapshot.phi)
                self.h_obs_live_var.set(max(0.0, min(100.0, (self.current_h_obs / 5.0) * 100.0)))
                self.metric_phi_var.set(f"{self.current_phi:.2f}")
                image = self.conway_engine.render_rgb(snapshot)
                pil = Image.fromarray(image).resize((540, 540), resample=Image.Resampling.NEAREST)
                self.conway_image_ref = ImageTk.PhotoImage(pil)
                self.conway_canvas.delete("all")
                self.conway_canvas.create_image(0, 0, image=self.conway_image_ref, anchor="nw")
                self._refresh_runtime_adaptation("conway", time.perf_counter() - time.perf_counter())
        except queue.Empty:
            pass
        self.root.after(self._loop_delay_ms("conway"), self._poll_conway_queue)

    def _update_camera_canvas(self, snapshot) -> None:
        """Rendert das Kamerabild mit Anchor-Overlays."""
        pil = Image.fromarray(snapshot.frame_rgb).resize((280, 210), resample=Image.Resampling.BILINEAR)
        self.camera_image_ref = ImageTk.PhotoImage(pil)
        self.camera_canvas.delete("all")
        self.camera_canvas.create_image(0, 0, image=self.camera_image_ref, anchor="nw")
        width = 280
        height = 210
        for anchor in snapshot.ghost_anchors:
            x_pos = anchor.x * width
            y_pos = anchor.y * height
            radius = 4 + int(anchor.strength * 5.0)
            self.camera_canvas.create_oval(x_pos - radius, y_pos - radius, x_pos + radius, y_pos + radius, outline="#7AB6FF", width=1)
        for anchor in snapshot.anchors[:14]:
            x_pos = anchor.x * width
            y_pos = anchor.y * height
            radius = 4 + int(anchor.strength * 6.0)
            self.camera_canvas.create_oval(x_pos - radius, y_pos - radius, x_pos + radius, y_pos + radius, outline="#2DE2E6", width=2)

    def _overlay_agent_text(self, directive) -> None:
        """Zeichnet Agent-Hinweistext direkt auf das Kameracanvas."""
        if not directive.instruction:
            return
        text = directive.instruction
        if directive.resolved_flash and self.pattern_found_var.get().startswith("VERBUNDEN MIT:"):
            text = f"{text}\n{self.pattern_found_var.get()}"
        self.camera_canvas.create_text(
            140,
            190,
            text=text,
            fill="#2DE2E6",
            font=("Segoe UI", 11, "bold"),
        )
        self.metric_resolved_var.set(str(directive.resolved_count))

    def _update_observer_metrics(self, metrics) -> None:
        """Aktualisiert die Live-Metriken des Zusatzfensters."""
        self.metric_h0_var.set(f"{metrics.h0:.2f}")
        self.metric_ht_var.set(f"{metrics.ht:.2f}")
        self.metric_ct_var.set(f"{metrics.coherence:.2f}")
        self.metric_d_var.set(f"{metrics.beauty_d:.3f}")
        self.metric_phi_var.set(f"{metrics.phi:.2f}")
        self.metric_freq_var.set(f"{metrics.freq:.1f}")
        self.metric_detune_var.set(f"{metrics.detune:.0f}")
        bayes_suffix = ""
        if self._last_bayes_snapshot is not None:
            bayes_suffix = f" | B {self._last_bayes_snapshot.anchor_posterior * 100.0:.0f}%"
        self.metric_prior_var.set(f"{metrics.prior_accuracy * 100.0:.0f}%{bayes_suffix}")
        self.metric_anchor_count_var.set(str(metrics.anchors))
        self.coherence_live_var.set(max(0.0, min(100.0, metrics.coherence * 100.0)))

    def _set_event_benford_metric(self, profile: dict[str, object]) -> None:
        """Formatiert die Live-Anzeige fuer Event-Benford."""
        sample_count = int(profile.get("sample_count", 0) or 0)
        if sample_count <= 0:
            self.metric_benford_var.set("--")
            return
        score = float(profile.get("conformity_score", 0.0) or 0.0)
        informative = bool(profile.get("informative", False))
        suffix = "" if informative else "*"
        self.metric_benford_var.set(f"{score:.0f}{suffix} ({sample_count})")

    def _refresh_runtime_adaptation(self, loop_name: str, elapsed_seconds: float, ideal_delay_ms: int | None = None) -> None:
        """Misst Laufzeitdruck und passt Verzogerungen/FPS adaptiv an."""
        base_delay = int(ideal_delay_ms if ideal_delay_ms is not None else self._base_loop_delay_ms(loop_name))
        overrun = float(elapsed_seconds) / max(0.001, float(base_delay) / 1000.0)
        now = time.time()
        should_sample = (
            self._runtime_pressure is None
            or overrun >= 1.10
            or (now - self._last_runtime_sample_at) >= 1.25
            or loop_name != self._last_runtime_loop
        )
        if should_sample:
            self._runtime_pressure = self.device_profile_engine.sample_runtime(self.device_profile, loop_overrun=overrun)
            self._runtime_delay_scale = float(self._runtime_pressure.delay_scale)
            self._runtime_fps_scale = float(self._runtime_pressure.fps_scale)
            self._last_runtime_sample_at = now
            self._last_runtime_loop = loop_name
        if self._runtime_pressure is None:
            return
        runtime = self._runtime_pressure
        self.metric_runtime_var.set(f"{runtime.label} {runtime.loop_overrun:.2f}x")
        self.header_device_var.set(f"{self.device_profile.label} | {self.device_profile.detail} | {runtime.label}")
        target_fps = int(max(4, min(22, round((10 if self.device_profile.low_end else 14) * self._runtime_fps_scale))))
        self.theremin_engine.target_fps = target_fps

    def _check_alarm_conditions(self, metrics) -> None:
        """Loest D/H-Verletzungsalarme aus."""
        violation = bool(metrics.beauty_d < 1.08 or metrics.ht > 7.35 or self.current_h_obs > 4.4)
        if not violation:
            return
        alarm_posterior = float(self._last_bayes_snapshot.alarm_posterior if self._last_bayes_snapshot is not None else 0.0)
        self.augmentor.record_alarm(
            reason="D/H violation",
            severity="high" if alarm_posterior >= 0.68 else "medium",
            payload={
                "D": metrics.beauty_d,
                "H_t": metrics.ht,
                "H_obs": self.current_h_obs,
                "bayes_alarm_posterior": alarm_posterior,
            },
        )
        self.audio_engine.play_alarm_burst(duration_ms=200)
        self.augment_header.configure(bg="#61121A")
        if self._alarm_reset_job is not None:
            try:
                self.root.after_cancel(self._alarm_reset_job)
            except Exception:
                pass
        self._alarm_reset_job = self.root.after(2000, lambda: self.augment_header.configure(bg="#0B1B33"))
        self._refresh_augment_views()

    def _mint_chain_block(
        self,
        tag: str,
        reconstruction_verified: bool,
        confirmed_lossless: bool,
        merkle_root: str,
        payload_extra: dict[str, object] | None = None,
    ) -> None:
        """Mintet einen lokalen Block fuer Datei- oder Agent-Ereignisse."""
        security_policy = dict(getattr(self.session_context, "security_policy", {}) or {})
        if bool(security_policy.get("suppress_lossless_confirmation", False)):
            confirmed_lossless = False
        if not self.session_context.security_allows("allow_chain_append", True):
            self.loading_var.set(
                f"Chain-Append blockiert: {self.session_context.trust_state} | Maze {self.session_context.maze_state}"
            )
            self.registry.save_security_event(
                user_id=int(getattr(self.session_context, "user_id", 0) or 0),
                username=str(getattr(self.session_context, "username", "")),
                event_type="CHAIN_APPEND_BLOCKED",
                severity="warning",
                payload={
                    "tag": str(tag),
                    "trust_state": str(getattr(self.session_context, "trust_state", "UNTRUSTED")),
                    "maze_state": str(getattr(self.session_context, "maze_state", "NONE")),
                },
            )
            return
        payload = {
            "session_id": self.session_context.session_id,
            "user_id": int(getattr(self.session_context, "user_id", 0) or 0),
            "username": str(getattr(self.session_context, "username", "")),
            "live_session": str(getattr(self.session_context, "live_session_fingerprint", "")),
            "timestamp": time.time(),
            "tag": tag,
            "reconstruction_verified": reconstruction_verified,
            "confirmed_lossless": confirmed_lossless,
            "merkle_root": merkle_root,
            "lossless_label": "✓ LOSSLESS VERIFIED" if reconstruction_verified else "",
            "anchor_status": (
                "ANCHOR PENDING"
                if confirmed_lossless and self.session_context.security_allows("allow_public_anchor", True) and self.public_anchor.is_online_mode()
                else ("QUEUED OFFLINE" if confirmed_lossless else "LOCAL ONLY")
            ),
            "eth_tx": "",
            "ipfs_cid": "",
            "security_mode": str(getattr(self.session_context, "security_mode", "PROD")),
            "trust_state": str(getattr(self.session_context, "trust_state", "TRUSTED")),
            "maze_state": str(getattr(self.session_context, "maze_state", "NONE")),
        }
        if payload_extra:
            payload.update(payload_extra)
        payload["prev_hash"] = self.registry.next_prev_hash()
        payload["prevHash"] = str(payload["prev_hash"])
        block_hash = compute_chain_block_hash(payload)
        payload["block_hash"] = block_hash
        signature = self.augmentor.sign_payload({"block_hash": block_hash, "payload": payload})
        block_id = self.registry.save_chain_block(
            session_id=self.session_context.session_id,
            milestone=0,
            coherence=float(self.last_observer_metrics.coherence if self.last_observer_metrics is not None else 0.0),
            key_fingerprint=self.augmentor.key_fingerprint,
            block_hash=block_hash,
            payload=payload,
            signature=signature,
        )
        self._selected_chain_block_id = int(block_id)
        if confirmed_lossless and self.session_context.security_allows("allow_public_anchor", True):
            self.public_anchor.anchor_async(
                block_payload=payload,
                callback=lambda result, bid=block_id, base_payload=dict(payload): self.root.after(
                    0, lambda: self._apply_public_anchor_result(bid, base_payload, result)
                ),
            )
        self._refresh_augment_views()

    def _apply_public_anchor_result(self, block_id: int, payload: dict[str, object], result: dict[str, object]) -> None:
        """Ergaenzt Blockkarten um Public-Anchor-Rueckmeldungen."""
        payload["anchor_status"] = str(result.get("anchor_status", "")).strip() or "ANCHOR PENDING"
        eth_tx = str(result.get("eth_tx", "")).strip()
        ipfs_cid = str(result.get("ipfs_cid", "")).strip()
        anchor_job_id = str(result.get("anchor_job_id", "")).strip()
        anchor_receipt_id = str(result.get("anchor_receipt_id", "")).strip()
        anchor_error = str(result.get("error", "")).strip()
        if eth_tx:
            payload["eth_tx"] = eth_tx
        if ipfs_cid:
            payload["ipfs_cid"] = ipfs_cid
        if anchor_job_id:
            payload["anchor_job_id"] = anchor_job_id
        if anchor_receipt_id:
            payload["anchor_receipt_id"] = anchor_receipt_id
        if anchor_error:
            payload["public_anchor_error"] = anchor_error
        queue_size = result.get("queue_size", None)
        if queue_size is not None:
            try:
                payload["public_anchor_queue"] = int(queue_size)
            except Exception:
                pass
        payload["public_anchor_result"] = {
            "mode": str(result.get("mode", "")),
            "status": payload["anchor_status"],
            "eth_tx": eth_tx,
            "ipfs_cid": ipfs_cid,
            "anchor_job_id": anchor_job_id,
            "anchor_receipt_id": anchor_receipt_id,
            "error": anchor_error,
        }
        self.registry.update_chain_block_payload(block_id, payload, signature=self.augmentor.sign_payload(payload))
        self._refresh_augment_views()

    def _append_export_audit(self, export_kind: str, target_path: str, payload: dict[str, object] | None = None) -> None:
        """Haengt einen lokalen Export-Audit-Eintrag append-only an."""
        audit_payload = {
            "export_kind": str(export_kind),
            "target_path": str(target_path),
            "security_mode": str(getattr(self.session_context, "security_mode", "PROD")),
            "trust_state": str(getattr(self.session_context, "trust_state", "TRUSTED")),
            "maze_state": str(getattr(self.session_context, "maze_state", "NONE")),
        }
        if payload:
            audit_payload.update(dict(payload))
        self.registry.save_export_log(
            session_id=self.session_context.session_id,
            export_kind=str(export_kind),
            target_path=str(target_path),
            payload=audit_payload,
            signature=self.security_monitor.sign_payload(
                audit_payload,
                str(getattr(self.session_context, "baseline_node_id", "") or getattr(self.session_context, "node_id", "")),
            ),
        )

    def _collective_trust_weight(self) -> float:
        """Leitet ein konservatives Trust-Gewicht fuer Snapshot-Austausch ab."""
        trust_state = str(getattr(self.session_context, "trust_state", "TRUSTED") or "TRUSTED").upper()
        if trust_state == "UNTRUSTED":
            return 0.45
        if trust_state == "SUSPECT":
            return 0.72
        return 1.0

    def _apply_collective_feedback(self) -> dict[str, object]:
        """Aktiviert aggregierte Snapshot-Priors fuer Resonanz, Graph und Bayes."""
        feedback = self.registry.get_collective_feedback(limit=32)
        self.graph_engine.set_collective_feedback(feedback)
        self.bayes_engine.set_collective_feedback(feedback)
        snapshot_count = int(feedback.get("snapshot_count", 0) or 0)
        trust_mean = float(feedback.get("trust_mean", 0.0) or 0.0)
        cluster_count = int(feedback.get("cluster_count", 0) or 0)
        ref_count = int(len(list(feedback.get("resonance_references", []) or [])))
        if snapshot_count <= 0:
            self.collective_status_var.set("Collective: 0 Snapshots | keine Priors aktiv")
        else:
            self.collective_status_var.set(
                f"Collective: {snapshot_count} Snapshots | Trust {trust_mean:.2f} | Cluster {cluster_count} | Refs {ref_count}"
            )
        if self.current_fingerprint is not None:
            try:
                if hasattr(self.current_fingerprint, "_graph_snapshot"):
                    delattr(self.current_fingerprint, "_graph_snapshot")
            except Exception:
                pass
            try:
                self._update_graph_field(self.current_fingerprint)
                self._update_bayes_layer(self.current_fingerprint)
            except Exception:
                pass
        return feedback

    def _export_collective_snapshot_dialog(self) -> None:
        """Exportiert den aktuellen lokalen Wissensstand als Shared-Snapshot."""
        file_path = filedialog.asksaveasfilename(
            title="Collective Snapshot exportieren",
            defaultextension=".json",
            filetypes=[("JSON-Dateien", "*.json"), ("Alle Dateien", "*.*")],
        )
        if not file_path:
            return
        source_label = str(getattr(self.current_fingerprint, "source_label", "") or "manual_snapshot")
        payload = self.registry.build_collective_pattern_snapshot(
            source_label=source_label,
            origin_node_id=str(getattr(self.session_context, "node_id", "")),
            user_id=int(getattr(self.session_context, "user_id", 0) or 0),
        )
        signature = self.security_monitor.sign_payload(
            payload,
            str(getattr(self.session_context, "baseline_node_id", "") or getattr(self.session_context, "node_id", "")),
        )
        exported = self.registry.export_collective_snapshot(
            file_path=file_path,
            payload=payload,
            signature=signature,
            session_id=str(self.session_context.session_id),
            trust_weight=self._collective_trust_weight(),
            merged_count=1,
            persist_snapshot=True,
        )
        self._apply_collective_feedback()
        self._append_export_audit(
            "collective_snapshot",
            file_path,
            {
                "snapshot_hash": str(exported.get("snapshot_hash", "")),
                "trust_weight": float(exported.get("trust_weight", 0.0) or 0.0),
            },
        )
        self.loading_var.set(f"Collective Snapshot exportiert: {Path(file_path).name}")

    def _import_collective_snapshot_dialog(self) -> None:
        """Importiert ein externes Snapshot-Paket und aktiviert dessen Priors lokal."""
        file_path = filedialog.askopenfilename(
            title="Collective Snapshot importieren",
            filetypes=[("JSON-Dateien", "*.json"), ("Alle Dateien", "*.*")],
        )
        if not file_path:
            return
        try:
            imported = self.registry.import_collective_snapshot(
                file_path=file_path,
                session_id=str(self.session_context.session_id),
                trust_weight=self._collective_trust_weight(),
            )
        except Exception as exc:
            messagebox.showerror("Snapshot-Import fehlgeschlagen", str(exc))
            return
        self._apply_collective_feedback()
        self._refresh_augment_views()
        self.loading_var.set(f"Collective Snapshot importiert: {str(imported.get('snapshot_hash', ''))[:12]}")

    def _export_dna_share_dialog(self) -> None:
        """Exportiert den minimalen DNA-Share-Layer fuer bestaetigte lokale Ergebnisse."""
        file_path = filedialog.asksaveasfilename(
            title="DNA-Share exportieren",
            defaultextension=".json",
            filetypes=[("JSON-Dateien", "*.json"), ("Alle Dateien", "*.*")],
        )
        if not file_path:
            return
        try:
            payload = self.registry.build_dna_share_snapshot(
                source_label="dna_share_bundle",
                origin_node_id=str(getattr(self.session_context, "node_id", "")),
                user_id=int(getattr(self.session_context, "user_id", 0) or 0),
            )
        except Exception as exc:
            messagebox.showerror("DNA-Share fehlgeschlagen", str(exc))
            return
        signature = self.security_monitor.sign_payload(
            payload,
            str(getattr(self.session_context, "baseline_node_id", "") or getattr(self.session_context, "node_id", "")),
        )
        exported = self.registry.export_collective_snapshot(
            file_path=file_path,
            payload=payload,
            signature=signature,
            session_id=str(self.session_context.session_id),
            trust_weight=self._collective_trust_weight(),
            merged_count=1,
            persist_snapshot=True,
        )
        self._apply_collective_feedback()
        self._append_export_audit(
            "dna_share",
            file_path,
            {
                "snapshot_hash": str(exported.get("snapshot_hash", "")),
                "trust_weight": float(exported.get("trust_weight", 0.0) or 0.0),
                "record_count": int(
                    len(list(dict(payload.get("dna_share", {}) or {}).get("records", []) or []))
                ),
            },
        )
        self.loading_var.set(f"DNA-Share exportiert: {Path(file_path).name}")

    def _import_dna_share_dialog(self) -> None:
        """Importiert einen DNA-Share-Bund und aktiviert dessen Priors lokal."""
        file_path = filedialog.askopenfilename(
            title="DNA-Share importieren",
            filetypes=[("JSON-Dateien", "*.json"), ("Alle Dateien", "*.*")],
        )
        if not file_path:
            return
        try:
            imported = self.registry.import_collective_snapshot(
                file_path=file_path,
                session_id=str(self.session_context.session_id),
                trust_weight=self._collective_trust_weight(),
            )
        except Exception as exc:
            messagebox.showerror("DNA-Share-Import fehlgeschlagen", str(exc))
            return
        self._apply_collective_feedback()
        self._refresh_augment_views()
        self.loading_var.set(f"DNA-Share importiert: {str(imported.get('snapshot_hash', ''))[:12]}")

    def _merge_collective_snapshots_dialog(self) -> None:
        """Erzeugt einen lokalen Merge-Snapshot aus allen bekannten Paketen."""
        signature = self.security_monitor.sign_payload(
            {
                "source_label": "manual_merge",
                "origin_node_id": str(getattr(self.session_context, "node_id", "")),
                "session_id": str(self.session_context.session_id),
            },
            str(getattr(self.session_context, "baseline_node_id", "") or getattr(self.session_context, "node_id", "")),
        )
        merged = self.registry.merge_collective_snapshots(
            session_id=str(self.session_context.session_id),
            source_label="manual_merge",
            origin_node_id=str(getattr(self.session_context, "node_id", "")),
            trust_weight=self._collective_trust_weight(),
            limit=32,
            signature=signature,
        )
        self._apply_collective_feedback()
        self._refresh_augment_views()
        self.loading_var.set(
            f"Collective Snapshot gemerged: {str(merged.get('snapshot_hash', ''))[:12]} | {merged.get('merged_count', 0)}"
        )

    def _export_vault_json(self) -> None:
        """Exportiert Vault plus Symbolnetz als JSON."""
        file_path = filedialog.asksaveasfilename(
            title="Vault exportieren",
            defaultextension=".json",
            filetypes=[("JSON-Dateien", "*.json"), ("Alle Dateien", "*.*")],
        )
        if not file_path:
            return
        payload = {
            "vault": self.vault_entries_cache,
            "chain": self.registry.get_chain_blocks(
                limit=1000,
                user_id=int(getattr(self.session_context, "user_id", 0) or 0),
                include_genesis=False,
            ),
            "chat": self.registry.get_chat_messages(limit=1000),
            "semantic_network": self.symbol_grounding.export_state(),
        }
        signature = self.augmentor.sign_payload(payload)
        Path(file_path).write_text(
            json.dumps({"payload": payload, "signature": signature}, ensure_ascii=True, indent=2),
            encoding="utf-8",
        )
        self._append_export_audit("vault_json", file_path, {"records": int(len(payload.get("vault", [])))})

    def _export_delta_json(self) -> None:
        """Exportiert signierte Delta-Logs."""
        file_path = filedialog.asksaveasfilename(
            title="Delta-Logs exportieren",
            defaultextension=".json",
            filetypes=[("JSON-Dateien", "*.json"), ("Alle Dateien", "*.*")],
        )
        if not file_path:
            return
        exported = self.augmentor.export_signed_json("delta", file_path)
        self._append_export_audit("delta_json", file_path, {"records": int(exported)})

    def _highlight_text_line(self, widget: tk.Text, tag_name: str, line_number: int | None) -> None:
        """Markiert genau eine Zeile in einer Textansicht."""
        widget.tag_remove(tag_name, "1.0", tk.END)
        if line_number is None:
            return
        widget.tag_config(tag_name, background="#18304F", foreground="#F8F6D8")
        widget.tag_add(tag_name, f"{line_number}.0", f"{line_number}.end")

    def _select_vault_entry(self, event) -> str:
        """Waehlt einen Vault-Eintrag ueber seine Textzeile aus."""
        try:
            index = self.vault_text.index(f"@{event.x},{event.y}")
            line_number = int(index.split(".")[0])
        except Exception:
            return "break"
        entry = self._vault_line_map.get(line_number)
        if entry is None:
            return "break"
        self._selected_vault_entry_id = int(entry["id"])
        self._highlight_text_line(self.vault_text, "vault_selected", line_number)
        self.loading_var.set(f"Vault-Auswahl: {entry.get('source_label', '')}")
        return "break"

    def _select_chain_entry(self, event) -> str:
        """Waehlt einen Chain-Block ueber seine Textzeile aus."""
        try:
            index = self.chain_text.index(f"@{event.x},{event.y}")
            line_number = int(index.split(".")[0])
        except Exception:
            return "break"
        block = self._chain_line_map.get(line_number)
        if block is None:
            return "break"
        self._selected_chain_block_id = int(block["id"])
        self._highlight_text_line(self.chain_text, "chain_selected", line_number)
        payload = block.get("payload_json", {})
        self.loading_var.set(f"Chain-Auswahl: {payload.get('tag', 'BLOCK')} | {payload.get('source_label', '')}")
        return "break"

    def _resolve_record_from_vault_entry(self, entry: dict[str, object]) -> dict[str, object] | None:
        """Loest einen Vault-Eintrag auf einen rekonstruierbaren Datei-Datensatz auf."""
        if str(entry.get("source_type", "")) != "file":
            return None
        return self.registry.find_file_record(
            file_hash=str(entry.get("file_hash", "")),
            source_label=str(entry.get("source_label", "")),
            user_id=int(getattr(self.session_context, "user_id", 0) or 0),
        )

    def _resolve_record_from_chain_block(self, block: dict[str, object]) -> dict[str, object] | None:
        """Loest einen Chain-Block auf einen Datei-Datensatz auf, falls moeglich."""
        payload = dict(block.get("payload_json", {}))
        if str(payload.get("source_type", "file")) != "file":
            return None
        return self.registry.find_file_record(
            file_hash=str(payload.get("file_hash", "")),
            source_label=str(payload.get("source_label", "")),
            user_id=int(getattr(self.session_context, "user_id", 0) or 0),
        )

    def _write_reconstructed_record(self, record: dict[str, object], target_path: Path) -> Path:
        """Schreibt einen rekonstruierbaren Dateidatensatz an einen Zielpfad."""
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(
            self.registry.reconstruct_original(
                int(record["id"]),
                session_context=self.session_context,
            )
        )
        return target_path

    def _open_resolved_record(self, record: dict[str, object]) -> None:
        """Rekonstruiert einen Datensatz und oeffnet ihn nativ."""
        try:
            output_path = self._write_reconstructed_record(record, self._reconstructed_output_path(record))
        except Exception as exc:
            messagebox.showerror("Rekonstruktion fehlgeschlagen", str(exc))
            return
        self.restore_status_var.set(f"Original geoeffnet: {output_path.name}")
        self.loading_var.set(f"Original rekonstruiert: {output_path}")
        try:
            os.startfile(str(output_path))
        except AttributeError:
            messagebox.showinfo("Rekonstruiert", f"Datei wurde erstellt:\n{output_path}")
        except OSError as exc:
            messagebox.showerror("Datei konnte nicht geoeffnet werden", f"{output_path}\n\n{exc}")

    def _export_resolved_record(self, record: dict[str, object]) -> None:
        """Exportiert einen rekonstruierbaren Datensatz an einen frei waehbaren Pfad."""
        source_name = Path(str(record.get("source_label", ""))).name or f"record_{record.get('id', 0)}.bin"
        suffix = Path(source_name).suffix or ".bin"
        file_path = filedialog.asksaveasfilename(
            title="Original exportieren",
            initialfile=source_name,
            defaultextension=suffix,
            filetypes=[("Alle Dateien", "*.*")],
        )
        if not file_path:
            return
        try:
            output_path = self._write_reconstructed_record(record, Path(file_path))
        except Exception as exc:
            messagebox.showerror("Rekonstruktion fehlgeschlagen", str(exc))
            return
        self.restore_status_var.set(f"Original exportiert: {output_path.name}")
        self.loading_var.set(f"Original exportiert: {output_path}")
        self._append_export_audit(
            "original_bytes",
            str(output_path),
            {
                "record_id": int(record.get("id", 0) or 0),
                "source_label": str(record.get("source_label", "")),
                "file_hash": str(record.get("file_hash", "")),
            },
        )

    def _export_original_from_vault(self) -> None:
        """Exportiert den aktuell gewaehlten Vault-Dateieintrag."""
        entry = next((item for item in self.vault_entries_cache if int(item["id"]) == int(self._selected_vault_entry_id or -1)), None)
        if entry is None:
            messagebox.showwarning("Hinweis", "Bitte zuerst einen Datei-Eintrag im Vault auswaehlen.")
            return
        record = self._resolve_record_from_vault_entry(entry)
        if record is None:
            messagebox.showwarning("Hinweis", "Dieser Vault-Eintrag referenziert keine lokal rekonstruierbare Datei.")
            return
        self._export_resolved_record(record)

    def _open_original_from_vault(self) -> None:
        """Oeffnet den aktuell gewaehlten Vault-Dateieintrag nativ."""
        entry = next((item for item in self.vault_entries_cache if int(item["id"]) == int(self._selected_vault_entry_id or -1)), None)
        if entry is None:
            messagebox.showwarning("Hinweis", "Bitte zuerst einen Datei-Eintrag im Vault auswaehlen.")
            return
        record = self._resolve_record_from_vault_entry(entry)
        if record is None:
            messagebox.showwarning("Hinweis", "Dieser Vault-Eintrag referenziert keine lokal rekonstruierbare Datei.")
            return
        self._open_resolved_record(record)

    def _export_original_from_chain(self) -> None:
        """Exportiert die Datei hinter dem aktuell gewaehlten Chain-Block."""
        blocks = self.registry.get_chain_blocks(
            limit=120,
            user_id=int(getattr(self.session_context, "user_id", 0) or 0),
            include_genesis=False,
        )
        block = next((item for item in blocks if int(item["id"]) == int(self._selected_chain_block_id or -1)), None)
        if block is None:
            messagebox.showwarning("Hinweis", "Bitte zuerst einen passenden Chain-Block auswaehlen.")
            return
        record = self._resolve_record_from_chain_block(block)
        if record is None:
            messagebox.showwarning("Hinweis", "Dieser Chain-Block verweist auf keine lokal rekonstruierbare Datei.")
            return
        self._export_resolved_record(record)

    def _open_original_from_chain(self) -> None:
        """Oeffnet die Datei hinter dem aktuell gewaehlten Chain-Block nativ."""
        blocks = self.registry.get_chain_blocks(
            limit=120,
            user_id=int(getattr(self.session_context, "user_id", 0) or 0),
            include_genesis=False,
        )
        block = next((item for item in blocks if int(item["id"]) == int(self._selected_chain_block_id or -1)), None)
        if block is None:
            messagebox.showwarning("Hinweis", "Bitte zuerst einen passenden Chain-Block auswaehlen.")
            return
        record = self._resolve_record_from_chain_block(block)
        if record is None:
            messagebox.showwarning("Hinweis", "Dieser Chain-Block verweist auf keine lokal rekonstruierbare Datei.")
            return
        self._open_resolved_record(record)

    def _apply_raw_storage_mode_label(self, enabled: bool, detail: str = "") -> None:
        """Formatiert den sichtbaren Dual-Mode-Status kompakt."""
        if enabled:
            key_fingerprint = str(getattr(self.session_context, "raw_storage_key_fingerprint", "") or "")
            suffix = f" | KEY {key_fingerprint}" if key_fingerprint else ""
            base = f"Dual-Mode aktiv: Delta + AES-256-Rohdaten lokal{suffix}"
        else:
            base = "Dual-Mode: Delta-only | Rohdaten werden nach Analyse verworfen"
        self.raw_storage_status_var.set(f"{base}{detail}")

    def _on_raw_storage_toggle(self) -> None:
        """Aktualisiert den lokalen Dual-Mode-Schalter samt Nutzerprofil."""
        enabled = bool(self.raw_storage_enabled_var.get())
        self.session_context.raw_storage_enabled = enabled
        user_id = int(getattr(self.session_context, "user_id", 0) or 0)
        if user_id > 0:
            try:
                settings = self.registry.update_user_settings(
                    user_id,
                    {"store_raw_encrypted": enabled},
                )
                self.session_context.user_settings = dict(settings)
            except Exception as exc:
                self.loading_var.set(f"Storage-Einstellung konnte nicht gespeichert werden: {exc}")
        self._apply_raw_storage_mode_label(enabled)

    def _apply_security_snapshot(self, snapshot: object | None = None) -> None:
        """Spiegelt den aktuellen Sicherheitszustand in Header, Sidebar und Session."""
        if snapshot is not None:
            if hasattr(snapshot, "to_dict"):
                self.session_context.apply_security_state(snapshot.to_dict())
            elif isinstance(snapshot, dict):
                self.session_context.apply_security_state(snapshot)
        mode = str(getattr(self.session_context, "security_mode", "PROD") or "PROD").upper()
        trust = str(getattr(self.session_context, "trust_state", "TRUSTED") or "TRUSTED").upper()
        maze = str(getattr(self.session_context, "maze_state", "NONE") or "NONE").upper()
        node_id = str(getattr(self.session_context, "node_id", "") or "")
        self.header_security_var.set(f"{mode} | {trust} | DIAG {maze}")
        self.security_node_var.set(f"NODE {node_id[:24] or '--'}")
        self.security_trust_var.set(f"TRUST {trust}")
        self.security_maze_var.set(f"DIAG {maze}")
        self.security_summary_var.set(str(getattr(self.session_context, "security_summary", "") or ""))
        current_choice = self.security_mode_choice_var.get().strip().upper()
        if current_choice != mode:
            self._updating_security_mode = True
            try:
                self.security_mode_choice_var.set(mode)
            finally:
                self._updating_security_mode = False

    def _on_security_mode_changed(self) -> None:
        """Schreibt DEV/PROD lokal zurueck und startet einen neuen Integritaetscheck."""
        if self._updating_security_mode:
            return
        selected = self.security_mode_choice_var.get().strip().upper() or "PROD"
        if selected == str(getattr(self.session_context, "security_mode", "PROD")).upper():
            return
        user_id = int(getattr(self.session_context, "user_id", 0) or 0)
        if user_id > 0:
            try:
                settings = self.registry.update_user_settings(user_id, {"security_mode": selected})
                self.session_context.user_settings = dict(settings)
            except Exception as exc:
                self.loading_var.set(f"Sicherheitsmodus konnte nicht gespeichert werden: {exc}")
                return
        self.session_context.security_mode = selected
        self._run_security_recheck()

    def _run_security_recheck(self) -> None:
        """Fuehrt einen manuellen lokalen Integritaetscheck aus und aktualisiert die Anzeige."""
        try:
            snapshot = self.security_monitor.manual_recheck(self.session_context)
        except Exception as exc:
            self.loading_var.set(f"Sicherheitscheck fehlgeschlagen: {exc}")
            messagebox.showerror("Sicherheitscheck", str(exc))
            return
        self._apply_security_snapshot(snapshot)
        self._refresh_augment_views()
        self.loading_var.set(str(snapshot.summary))

    def _open_security_audit(self) -> None:
        """Zeigt die juengsten lokalen Sicherheitsereignisse kompakt an."""
        events = self.registry.get_security_events(
            limit=18,
            user_id=int(getattr(self.session_context, "user_id", 0) or 0),
        )
        if not events:
            messagebox.showinfo("Security Audit", "Noch keine lokalen Sicherheitsereignisse gespeichert.")
            return
        lines = []
        for event in events:
            stamp = str(event.get("timestamp", ""))
            stamp = stamp[11:19] if len(stamp) >= 19 else stamp
            payload = dict(event.get("payload_json", {}))
            reason = str(payload.get("message", payload.get("reason", "")) or "")
            if len(reason) > 64:
                reason = reason[:61] + "..."
            line = (
                f"[{stamp}] {str(event.get('severity', '')).upper()} | "
                f"{str(event.get('event_type', 'EVENT'))}"
            )
            if reason:
                line += f" | {reason}"
            lines.append(line)
        messagebox.showinfo("Security Audit", "\n".join(lines))

    def _fingerprint_chain_summary(self) -> dict[str, object]:
        """Liefert den Status des lokalen Fingerprint-Ledgers."""
        chain = getattr(self.analysis_engine, "chain", None)
        if chain is None:
            return {"connected": False, "entry_count": 0, "valid": True, "latest_hash": "", "latest_entry": {}}
        try:
            if hasattr(chain, "get_summary"):
                return dict(chain.get_summary())
            if hasattr(chain, "sync_network"):
                return dict(chain.sync_network())
        except Exception:
            return {"connected": False, "entry_count": 0, "valid": False, "latest_hash": "", "latest_entry": {}}
        return {"connected": False, "entry_count": 0, "valid": True, "latest_hash": "", "latest_entry": {}}

    def _public_anchor_summary(self) -> dict[str, object]:
        """Liefert einen kompakten Status der Public-Anchor-Queue."""
        try:
            if hasattr(self.public_anchor, "get_summary"):
                return dict(self.public_anchor.get_summary())
        except Exception:
            pass
        return {"online": False, "pending": 0, "latest_status": "", "latest_receipt_id": "", "latest_error": ""}

    def _refresh_augment_views(self) -> None:
        """Aktualisiert Header, Chain, Vault und Verify des Zusatzfensters."""
        self._apply_security_snapshot()
        self.vault_entries_cache = self.registry.get_vault_entries(
            limit=1000,
            user_id=int(getattr(self.session_context, "user_id", 0) or 0),
        )
        for entry in self.vault_entries_cache:
            entry["embedding_vector"] = list(entry.get("feature_vector", []))
        self._sync_vault_grounding_payload(self.vault_entries_cache)
        self.header_vault_var.set(f"VAULT {len(self.vault_entries_cache)}")
        chain_summary = self._fingerprint_chain_summary()
        chain_entries = int(chain_summary.get("entry_count", 0) or 0)
        chain_valid = bool(chain_summary.get("valid", True))
        chain_marker = "OK" if chain_valid else f"BROKEN@{chain_summary.get('broken_index', '?')}"
        self.header_chain_var.set(f"F-CHAIN {chain_entries} {chain_marker}")
        anchor_summary = self._public_anchor_summary()
        anchor_pending = int(anchor_summary.get("pending", 0) or 0)
        anchor_mode = "ON" if bool(anchor_summary.get("online", False)) else "OFF"
        self.header_anchor_var.set(f"ANCHOR Q{anchor_pending} {anchor_mode}")
        collective_summary = self.registry.get_collective_snapshot_summary(limit=32)
        self._apply_collective_feedback()
        self.header_alarm_var.set(f"ALARMS {self.augmentor.alarm_count()}")
        named, total = self.symbol_grounding.named_counts()
        self.header_named_var.set(f"NAMED {named} / TOTAL {total}")
        self.header_ontology_var.set("ONTOLOGIE VOLLSTAENDIG" if self.symbol_grounding.ontology_complete() else "")
        runtime_label = f" | {self._runtime_pressure.label}" if self._runtime_pressure is not None else ""
        self.header_device_var.set(f"{self.device_profile.label} | {self.device_profile.detail}{runtime_label}")
        self._refresh_learning_memory_status()
        self._render_language_panel(
            self.language_engine.top_sentences(),
            ontology_complete=self.symbol_grounding.ontology_complete(),
        )

        self.chain_text.configure(state="normal")
        self.chain_text.delete("1.0", tk.END)
        self._chain_line_map = {}
        chain_line = 1
        latest_hash = str(chain_summary.get("latest_hash", "") or chain_summary.get("latest_file_hash", ""))
        ledger_line = (
            f"LOCAL FINGERPRINT LEDGER | {'VALIDE' if chain_valid else 'INKONSISTENT'} | "
            f"{chain_entries} Eintraege"
        )
        if latest_hash:
            ledger_line += f" | {latest_hash[:12]}"
        self.chain_text.insert(tk.END, ledger_line + "\n")
        anchor_line = (
            f"PUBLIC ANCHOR | {'ONLINE' if bool(anchor_summary.get('online', False)) else 'OFFLINE'} | "
            f"Queue {anchor_pending}"
        )
        latest_anchor_status = str(anchor_summary.get("latest_status", "")).strip()
        if latest_anchor_status:
            anchor_line += f" | {latest_anchor_status}"
        self.chain_text.insert(tk.END, anchor_line + "\n")
        collective_line = (
            f"COLLECTIVE SNAPSHOTS | {int(collective_summary.get('snapshot_count', 0) or 0)} | "
            f"Trust {float(collective_summary.get('trust_mean', 0.0) or 0.0):.2f} | "
            f"Refs {int(collective_summary.get('resonance_reference_count', 0) or 0)}"
        )
        latest_collective_hash = str(collective_summary.get("latest_hash", "") or "")
        if latest_collective_hash:
            collective_line += f" | {latest_collective_hash[:12]}"
        self.chain_text.insert(tk.END, collective_line + "\n\n")
        chain_line += 3
        for block in self.registry.get_chain_blocks(
            limit=120,
            user_id=int(getattr(self.session_context, "user_id", 0) or 0),
            include_genesis=False,
        ):
            if int(block.get("id", -1)) == 0:
                continue
            payload = block.get("payload_json", {})
            line = (
                f"{payload.get('tag', 'BLOCK')} | {str(block.get('block_hash', ''))[:10]} | "
                f"{payload.get('lossless_label', '')} | {payload.get('anchor_status', '')}"
            )
            if payload.get("ipfs_cid"):
                line += f" | 📌 IPFS {str(payload.get('ipfs_cid'))[:10]}"
            self.chain_text.insert(tk.END, line + "\n")
            self._chain_line_map[chain_line] = block
            chain_line += 1
        if self._selected_chain_block_id is not None:
            selected_line = next((line_no for line_no, item in self._chain_line_map.items() if int(item["id"]) == int(self._selected_chain_block_id)), None)
            self._highlight_text_line(self.chain_text, "chain_selected", selected_line)
        self.chain_text.configure(state="disabled")
        genesis = self.registry.get_genesis_block()
        if genesis is not None:
            payload = genesis.get("payload_json", {})
            compromised = str(genesis.get("block_hash", "")) != GENESIS_HASH
            border = "#C61A1A" if compromised else "#F2C14E"
            bg = "#3A1111" if compromised else "#30240A"
            self.genesis_card.configure(bg=bg, highlightbackground=border, highlightcolor=border)
            for child in self.genesis_card.winfo_children():
                child.configure(bg=bg)
            self.genesis_text_var.set(
                f"{payload.get('hash', genesis.get('block_hash', ''))[:24]} | prev {payload.get('prevHash', '')}\n"
                f"{payload.get('content', '')}"
            )
        else:
            self.genesis_text_var.set("Genesis-Block fehlt.")

        self.vault_text.configure(state="normal")
        self.vault_text.delete("1.0", tk.END)
        self._vault_line_map = {}
        vault_line = 1
        for entry in self.vault_entries_cache[:120]:
            payload_json = dict(entry.get("payload_json", {}) or {})
            noether_profile = dict(payload_json.get("vault_noether", {}) or {})
            bayes_profile = dict(payload_json.get("vault_bayes", {}) or {})
            benford_profile = dict(payload_json.get("vault_benford", {}) or {})
            orbit_id = str(noether_profile.get("orbit_id", "") or "")[:8]
            membership = float(bayes_profile.get("membership_posterior", 0.0) or 0.0)
            reconstruction = float(bayes_profile.get("reconstruction_posterior", 0.0) or 0.0)
            benford_informative = bool(benford_profile.get("informative", False))
            benford_score = float(benford_profile.get("score", 0.0) or 0.0)
            token_info = self.symbol_grounding.token_for_entry(entry["id"])
            token_label = ""
            if token_info is not None:
                human = str(token_info.get("human_name", "")).strip()
                token_label = f" | ⬡ {token_info.get('token', '')}"
                if human:
                    token_label += f" · {human}"
                meaning = token_info.get("meaning", {})
                if meaning:
                    token_label += (
                        f" | BEDEUTUNG: {meaning.get('shape', '-')}"
                        f" · {meaning.get('character', '-')}"
                        f" · {meaning.get('health', '-')}"
                    )
            self.vault_text.insert(
                tk.END,
                (
                    f"{entry['cluster_label']} | {entry['source_label']} | sim {entry['similarity_best']:.2f}"
                    f" | orbit {orbit_id or '--'}"
                    f" | vault {membership * 100.0:.0f}%"
                    f" | recon {reconstruction * 100.0:.0f}%"
                    f" | Bf {f'{benford_score:.2f}' if benford_informative else 'n.i.'}"
                    f"{token_label}\n"
                ),
            )
            self._vault_line_map[vault_line] = entry
            vault_line += 1
        semantic_lines = self.symbol_grounding.semantic_lines()
        if semantic_lines:
            self.vault_text.insert(tk.END, "\n")
            for line in semantic_lines:
                self.vault_text.insert(tk.END, line + "\n")
                vault_line += 1
        if self._selected_vault_entry_id is not None:
            selected_line = next((line_no for line_no, item in self._vault_line_map.items() if int(item["id"]) == int(self._selected_vault_entry_id)), None)
            self._highlight_text_line(self.vault_text, "vault_selected", selected_line)
        self.vault_text.configure(state="disabled")

        self.verify_text.configure(state="normal")
        self.verify_text.delete("1.0", tk.END)
        for record in self.augmentor.verify_chain():
            status_text = {
                "current": "GREEN",
                "foreign": "AMBER",
                "tampered": "RED",
                "compromised": "COMPROMISED",
                "shared_root": "GENESIS",
            }.get(record.status, record.status.upper())
            self.verify_text.insert(tk.END, f"{status_text} | {record.block_hash} | milestone {record.milestone}\n")
        self.verify_text.configure(state="disabled")
        self._refresh_chat_view()

    def _rename_token_from_vault(self, event) -> str:
        """Ermoeglicht Klick-zu-Rename ueber die Vault-Textansicht."""
        try:
            index = self.vault_text.index(f"@{event.x},{event.y}")
            line_start = f"{index.split('.')[0]}.0"
            line_end = f"{index.split('.')[0]}.end"
            line = self.vault_text.get(line_start, line_end)
            if "⬡ " not in line:
                return "break"
            token = line.split("⬡ ", 1)[1].split()[0]
            current = self.symbol_grounding.export_state().get("tokens", {}).get(token, {})
            new_name = simpledialog.askstring(
                "Token benennen",
                f"Menschlichen Namen fuer ⬡ {token} eingeben:",
                initialvalue=str(current.get("human_name", "")),
                parent=self.augment_window,
            )
            if new_name is None:
                return "break"
            self.symbol_grounding.rename_token(token, new_name.strip())
            self.symbol_grounding.rebuild_network(self.vault_entries_cache)
            self._queue_language_event(
                {
                    "event_type": "ontology_shift",
                    "token_name": new_name.strip() or token,
                    "ontology_label": self._ontology_label(),
                }
            )
            self._emit_language_events(
                pattern=None,
                token_info={
                    "token": token,
                    "human_name": new_name.strip(),
                },
            )
            self._refresh_augment_views()
        except Exception:
            return "break"
        return "break"

    def _register_final_modules(
        self,
        fingerprint: AetherFingerprint,
        record_id: int | None = None,
    ) -> None:
        """Fuehrt Rekonstruktion, Embedding, Vault, Grounding und Lossless-Blockerzeugung aus."""
        security_policy = dict(getattr(self.session_context, "security_policy", {}) or {})
        confidence_scale = float(security_policy.get("maze_confidence_scale", 1.0) or 1.0)
        anchors, interference_profile, anchor_delta_ops = self._fingerprint_anchors_with_interference(fingerprint)
        graph_snapshot = self._graph_snapshot_for(fingerprint)
        source_label = str(getattr(fingerprint, "source_label", "") or fingerprint.file_hash[:12])

        reconstruction_verified = False
        merkle_root = ""
        delta_benford: dict[str, object] = dict(interference_profile.get("benford_profile", {}) or {})
        if str(getattr(fingerprint, "source_type", "file")) == "file":
            noise = self.session_context.generate_aether_noise(len(fingerprint.delta))
            original_bytes = bytes(a ^ b for a, b in zip(fingerprint.delta, noise))
            delta_log = self.reconstruction_engine.build_delta_log(original_bytes)
            reconstruction = self.reconstruction_engine.verify(
                original_hash=fingerprint.file_hash,
                delta_log=delta_log,
            )
            reconstruction_verified = bool(reconstruction.reconstruction_verified)
            merkle_root = reconstruction.merkle_root
            self.metric_recon_var.set("✓" if reconstruction_verified else "✗")
            self.recon_status_var.set(f"RECON: {'✓' if reconstruction_verified else '✗'}")
            self.augmentor.record_delta_log(
                source_label,
                reconstruction.delta_log,
                metadata={
                    "event_benford": delta_benford,
                    "anchor_delta_ops": anchor_delta_ops,
                    "security": {
                        "mode": str(getattr(self.session_context, "security_mode", "PROD")),
                        "trust_state": str(getattr(self.session_context, "trust_state", "TRUSTED")),
                        "maze_state": str(getattr(self.session_context, "maze_state", "NONE")),
                    },
                },
            )
        else:
            self.metric_recon_var.set("✗")
            self.recon_status_var.set("RECON: ✗")

        if bool(security_policy.get("suppress_lossless_confirmation", False)):
            reconstruction_verified = False
            self.metric_recon_var.set("✗")
            self.recon_status_var.set(
                f"RECON: ✗ | {str(getattr(self.session_context, 'trust_state', 'UNTRUSTED'))}"
            )

        embedding = self.embedding_engine.embedding_from_anchors(anchors)
        existing_entries = self.registry.get_vault_entries(
            limit=1000,
            user_id=int(getattr(self.session_context, "user_id", 0) or 0),
        )
        similarity_best = 0.0
        for entry in existing_entries:
            vector = list(entry.get("feature_vector", []))
            similarity_best = max(similarity_best, self.embedding_engine.cosine_similarity(embedding, vector))
        similarity_best *= confidence_scale

        beauty_d = float(self.observer_engine._fractal_dimension(anchors)) if anchors else 1.0
        payload = {
            "session_id": self.session_context.session_id,
            "user_id": int(getattr(self.session_context, "user_id", 0) or 0),
            "username": str(getattr(self.session_context, "username", "")),
            "live_session": str(getattr(self.session_context, "live_session_fingerprint", "")),
            "source_type": str(getattr(fingerprint, "source_type", "file")),
            "source_label": source_label,
            "file_hash": fingerprint.file_hash,
            "embedding_vector": embedding,
            "entropy_curve": [float(value) for value in list(getattr(fingerprint, "entropy_blocks", []))[:64]],
            "beauty_d": beauty_d,
            "anchor_delta_ops": anchor_delta_ops,
            "anchor_vector": list(getattr(fingerprint, "anchor_vector", []) or []),
            "anchor_interference": interference_profile,
            "alarm": bool(fingerprint.verdict == "CRITICAL"),
            "reconstruction_verified": reconstruction_verified,
            "confirmed_lossless": bool(reconstruction_verified),
            "entropy_mean": float(getattr(fingerprint, "entropy_mean", 0.0) or 0.0),
            "symmetry_score": float(getattr(fingerprint, "symmetry_score", 0.0) or 0.0),
            "periodicity": int(getattr(fingerprint, "periodicity", 0) or 0),
            "delta_ratio": float(getattr(fingerprint, "delta_ratio", 0.0) or 0.0),
            "delta_benford": delta_benford,
            "fourier_peaks": [dict(item) for item in list(getattr(fingerprint, "fourier_peaks", []))[:5]],
            "observer_mutual_info": float(getattr(fingerprint, "observer_mutual_info", 0.0) or 0.0),
            "observer_knowledge_ratio": float(getattr(fingerprint, "observer_knowledge_ratio", 0.0) or 0.0),
            "h_lambda": float(getattr(fingerprint, "h_lambda", 0.0) or 0.0),
            "observer_state": str(getattr(fingerprint, "observer_state", "")),
            "beauty_signature": dict(getattr(fingerprint, "beauty_signature", {}) or {}),
            "graph_region": graph_snapshot.region_label,
            "graph_region_nodes": graph_snapshot.region_node_count,
            "graph_phase_state": graph_snapshot.phase_state,
            "graph_phase_transition": graph_snapshot.phase_transition_score,
            "graph_attractor_score": graph_snapshot.attractor_score,
            "graph_stable_subgraphs": graph_snapshot.stable_subgraphs,
            "graph_benford_aux": graph_snapshot.benford_aux_score,
            "graph_interference_mean": graph_snapshot.interference_mean,
            "graph_constructive_ratio": graph_snapshot.constructive_ratio,
            "graph_destructive_ratio": graph_snapshot.destructive_ratio,
            "graph_confidence_mean": graph_snapshot.confidence_mean,
            "security_mode": str(getattr(self.session_context, "security_mode", "PROD")),
            "trust_state": str(getattr(self.session_context, "trust_state", "TRUSTED")),
            "maze_state": str(getattr(self.session_context, "maze_state", "NONE")),
        }
        if payload["source_type"] == "file":
            payload["original_name"] = Path(source_label).name
            payload["original_suffix"] = Path(source_label).suffix or ".bin"
        if hasattr(fingerprint, "page_url"):
            payload["url"] = str(getattr(fingerprint, "page_url", ""))
        if hasattr(fingerprint, "page_title"):
            payload["title"] = str(getattr(fingerprint, "page_title", ""))
        if hasattr(fingerprint, "page_loaded_at"):
            payload["page_timestamp"] = float(getattr(fingerprint, "page_loaded_at", 0.0))
        if hasattr(fingerprint, "page_content_hash"):
            payload["content_hash"] = str(getattr(fingerprint, "page_content_hash", ""))
        persist_clusters = bool(security_policy.get("allow_cluster_persist", True))
        dummy_cluster_mode = bool(security_policy.get("dummy_cluster_mode", False))
        signature = self.augmentor.sign_payload(payload)
        vault_entry_id = 0
        if persist_clusters:
            vault_entry_id = self.registry.save_vault_entry(
                session_id=self.session_context.session_id,
                source_type=payload["source_type"],
                source_label=source_label,
                file_hash=fingerprint.file_hash,
                feature_vector=embedding,
                similarity_best=float(similarity_best),
                cluster_label="TRANSITIONAL",
                payload=payload,
                signature=signature,
            )
            self._selected_vault_entry_id = int(vault_entry_id)
            vault_entries = self.registry.get_vault_entries(
                limit=1000,
                user_id=int(getattr(self.session_context, "user_id", 0) or 0),
            )
        else:
            self._selected_vault_entry_id = None
            vault_entries = list(existing_entries)

        embeddings = [list(entry.get("feature_vector", [])) for entry in vault_entries]
        labels = self.embedding_engine.kmeans_labels(embeddings, k=3) if embeddings else []
        label_names = {0: "HARMONIC", 1: "TRANSITIONAL", 2: "CHAOTIC"}
        self.cluster_variances_cache = {"HARMONIC": 1.0, "TRANSITIONAL": 1.0, "CHAOTIC": 1.0}
        if persist_clusters:
            for entry, cluster_id in zip(vault_entries, labels):
                cluster_name = label_names.get(int(cluster_id), "TRANSITIONAL")
                self.registry.update_vault_cluster(int(entry["id"]), cluster_name)
            vault_entries = self.registry.get_vault_entries(
                limit=1000,
                user_id=int(getattr(self.session_context, "user_id", 0) or 0),
            )
        for entry in vault_entries:
            entry["embedding_vector"] = list(entry.get("feature_vector", []))
        for cluster_name in ["HARMONIC", "TRANSITIONAL", "CHAOTIC"]:
            cluster_vectors = [list(entry.get("feature_vector", [])) for entry in vault_entries if entry.get("cluster_label") == cluster_name]
            if cluster_vectors:
                variance = float(np.mean(np.var(np.array(cluster_vectors, dtype=np.float64), axis=0)))
                self.cluster_variances_cache[cluster_name] = variance

        pattern = None if dummy_cluster_mode else self.embedding_engine.pattern_found(
            labels=labels,
            embeddings=embeddings,
            members=[str(entry.get("source_label", "")) for entry in vault_entries],
        )
        self._last_similarity_best = float(similarity_best)
        self._last_pattern_cluster = pattern
        if dummy_cluster_mode:
            self.pattern_found_var.set(f"LABYRINTH {str(getattr(self.session_context, 'maze_state', 'HARD'))}")
        elif pattern is not None:
            self.pattern_found_var.set(f"{pattern.label}: {', '.join(pattern.members[:4])}")
        else:
            self.pattern_found_var.set("")
        bayes_snapshot = self._update_bayes_layer(
            fingerprint,
            anchors=anchors,
            similarity_best=similarity_best,
            pattern=pattern,
        )
        model_depth_report = self.registry.get_model_depth_report(
            user_id=int(getattr(self.session_context, "user_id", 0) or 0)
        )
        delta_learning_curve = self.registry.get_delta_learning_curve(
            user_id=int(getattr(self.session_context, "user_id", 0) or 0)
        )
        anomaly_memory = self.registry.get_anomaly_memory(
            user_id=int(getattr(self.session_context, "user_id", 0) or 0),
            limit=3,
        )
        payload.update(
            {
                "bayes_anchor_posterior": bayes_snapshot.anchor_posterior,
                "bayes_graph_phase": bayes_snapshot.graph_phase_label,
                "bayes_graph_confidence": bayes_snapshot.graph_phase_confidence,
                "bayes_pattern_posterior": bayes_snapshot.pattern_posterior,
                "bayes_interference_posterior": bayes_snapshot.interference_posterior,
                "bayes_alarm_posterior": bayes_snapshot.alarm_posterior,
                "bayes_overall_confidence": bayes_snapshot.overall_confidence,
                "observer_mutual_info": float(getattr(fingerprint, "observer_mutual_info", 0.0) or 0.0),
                "observer_knowledge_ratio": float(getattr(fingerprint, "observer_knowledge_ratio", 0.0) or 0.0),
                "h_lambda": float(getattr(fingerprint, "h_lambda", 0.0) or 0.0),
                "observer_state": str(getattr(fingerprint, "observer_state", "")),
                "beauty_signature": dict(getattr(fingerprint, "beauty_signature", {}) or {}),
                "model_depth_label": str(model_depth_report.get("depth_label", "")),
                "model_depth_score": float(model_depth_report.get("depth_score", 0.0) or 0.0),
                "delta_learning_label": str(delta_learning_curve.get("trend_label", "")),
                "delta_learning_ratio": float(delta_learning_curve.get("improvement_ratio", 0.0) or 0.0),
                "anomaly_memory_top": (
                    f"{anomaly_memory[0].get('reason', 'alarm')} x{int(anomaly_memory[0].get('count', 0) or 0)}"
                    if anomaly_memory else "sauber"
                ),
            }
        )
        if int(vault_entry_id) > 0:
            self.registry.update_vault_payload(
                int(vault_entry_id),
                payload=payload,
                signature=self.augmentor.sign_payload(payload),
            )
        if persist_clusters:
            self.symbol_grounding.sync_clusters(vault_entries, self.cluster_variances_cache)
            self._sync_vault_grounding_payload(vault_entries)
        latest_entry = vault_entries[0] if vault_entries else None
        token_info = self.symbol_grounding.token_for_entry(latest_entry["id"]) if latest_entry is not None else None
        self._latest_agent_token = str(token_info.get("token", "")) if token_info else ""
        if self.session_context.security_allows("allow_gp_evolution", True):
            self._emit_language_events(pattern=pattern, token_info=token_info)
        ae_lab_summary = self._run_ae_lab(
            fingerprint=fingerprint,
            anchors=anchors,
            graph_snapshot=graph_snapshot,
            bayes_snapshot=bayes_snapshot,
            similarity_best=similarity_best,
            pattern=pattern,
            token_info=token_info,
            model_depth_report=model_depth_report,
            delta_learning_curve=delta_learning_curve,
            anomaly_memory=anomaly_memory,
        )
        payload["token"] = self._latest_agent_token
        payload["token_name"] = str(token_info.get("human_name", "")) if token_info else ""
        payload["pattern_found"] = self.pattern_found_var.get().strip()
        payload["ae_lab"] = dict(ae_lab_summary)
        payload["ae_anchors"] = [dict(item) for item in list(ae_lab_summary.get("anchors", []))[:16]]
        noether_profile = self.analysis_engine.vault_noether_profile(
            fingerprint,
            anchor_details=list(ae_lab_summary.get("anchors", [])),
        )
        benford_profile = self.analysis_engine.vault_benford_profile(
            fingerprint,
            anchor_details=list(ae_lab_summary.get("anchors", [])),
        )
        membership_posterior = self.bayes_engine.vault_membership_posterior(
            similarity_best=float(similarity_best),
            pattern_posterior=float(bayes_snapshot.pattern_posterior),
            overall_confidence=float(bayes_snapshot.overall_confidence),
            observer_knowledge_ratio=float(getattr(fingerprint, "observer_knowledge_ratio", 0.0) or 0.0),
        )
        reconstruction_posterior = self.bayes_engine.vault_reconstruction_posterior(
            fingerprint=fingerprint,
            overall_confidence=float(bayes_snapshot.overall_confidence),
            reconstruction_verified=bool(reconstruction_verified),
        )
        payload["vault_noether"] = dict(noether_profile)
        payload["vault_bayes"] = {
            "membership_posterior": float(membership_posterior),
            "reconstruction_posterior": float(reconstruction_posterior),
        }
        payload["vault_benford"] = dict(benford_profile)
        self._attest_fingerprint_with_anchors(
            fingerprint,
            record_id=int(record_id) if record_id is not None and int(record_id) > 0 else None,
        )
        payload["local_chain_tx_hash"] = str(getattr(fingerprint, "local_chain_tx_hash", ""))
        payload["local_chain_prev_hash"] = str(getattr(fingerprint, "local_chain_prev_hash", ""))
        payload["local_chain_endpoint"] = str(getattr(fingerprint, "local_chain_endpoint", ""))
        payload["local_chain_attested_at"] = str(getattr(fingerprint, "local_chain_attested_at", ""))
        if int(vault_entry_id) > 0:
            self.registry.update_vault_payload(
                int(vault_entry_id),
                payload=payload,
                signature=self.augmentor.sign_payload(payload),
            )
        source_type = str(getattr(fingerprint, "source_type", "file"))
        block_tag = {
            "file": "FILE DROP",
            "webpage": "WEB VISIT",
            "chat": "CHAT TURN",
            "csv": "CSV FLOW",
            "voxel": "VOXEL FLOW",
            "spectrum": "SPECTRUM",
        }.get(source_type, f"{source_type.upper()} FLOW")
        self._mint_chain_block(
            tag=block_tag,
            reconstruction_verified=reconstruction_verified,
            confirmed_lossless=reconstruction_verified,
            merkle_root=merkle_root,
            payload_extra={
                "source_type": source_type,
                "source_label": source_label,
                "file_hash": fingerprint.file_hash,
                "vault_entry_id": int(vault_entry_id),
                "integrity_text": str(getattr(fingerprint, "integrity_text", "")),
                "pattern_found": self.pattern_found_var.get().strip(),
                "anchor_count": int(len(list(ae_lab_summary.get("anchors", [])))),
                "anchor_preview": str(ae_lab_summary.get("anchor_preview", "")),
                "ae_anchors": [dict(item) for item in list(ae_lab_summary.get("anchors", []))[:16]],
                "vault_noether": dict(noether_profile),
                "vault_bayes": {
                    "membership_posterior": float(membership_posterior),
                    "reconstruction_posterior": float(reconstruction_posterior),
                    "anchor_posterior": float(bayes_snapshot.anchor_posterior),
                },
                "vault_benford": dict(benford_profile),
                "token": self._latest_agent_token,
                "token_name": str(token_info.get("human_name", "")) if token_info else "",
            },
        )
        if record_id is not None and int(record_id) > 0:
            storage_gp = dict(getattr(fingerprint, "_storage_gp_decision", {}) or {})
            language_top = [
                {
                    "text": sentence.text,
                    "score": float(sentence.score),
                    "tree": dict(sentence.tree),
                }
                for sentence in self.language_engine.top_sentences()
            ]
            language_events = [
                dict(item)
                for item in list(self.language_engine.state.get("events", []))[-12:]
                if isinstance(item, dict)
            ]
            anchor_payload = [
                {
                    "x": float(anchor.x),
                    "y": float(anchor.y),
                    "z": float(anchor.z),
                    "tau": float(anchor.tau),
                    "strength": float(anchor.strength),
                    "confidence": float(anchor.confidence),
                    "interference": float(anchor.interference),
                    "predicted": bool(anchor.predicted),
                    "label": str(anchor.interference_label),
                }
                for anchor in anchors[:64]
            ]
            local_payload = {
                "anchor_points": anchor_payload,
                "anchor_count": int(len(anchors)),
                "anchor_delta_ops": anchor_delta_ops,
                "anchor_interference": interference_profile,
                "dual_storage_mode": (
                    "delta_plus_encrypted_raw"
                    if bool(getattr(fingerprint, "_raw_storage_available", False))
                    else "delta_only"
                ),
                "raw_storage_available": bool(getattr(fingerprint, "_raw_storage_available", False)),
                "raw_storage_requested": bool(getattr(fingerprint, "_raw_storage_requested", False)),
                "storage_gp": storage_gp,
                "gp_rules": list(storage_gp.get("gp_rules", [])) if storage_gp else [],
                "gp_evolution_path": list(storage_gp.get("evolution_path", [])) if storage_gp else [],
                "system_gp_rules": language_top,
                "system_gp_evolution_path": language_events,
                "ae_lab": dict(ae_lab_summary),
                "ae_anchor_details": [dict(item) for item in list(ae_lab_summary.get("anchors", []))[:16]],
                "local_chain_tx_hash": str(getattr(fingerprint, "local_chain_tx_hash", "")),
                "local_chain_prev_hash": str(getattr(fingerprint, "local_chain_prev_hash", "")),
                "local_chain_endpoint": str(getattr(fingerprint, "local_chain_endpoint", "")),
                "local_chain_attested_at": str(getattr(fingerprint, "local_chain_attested_at", "")),
                "security_mode": str(getattr(self.session_context, "security_mode", "PROD")),
                "trust_state": str(getattr(self.session_context, "trust_state", "TRUSTED")),
                "maze_state": str(getattr(self.session_context, "maze_state", "NONE")),
            }
            self.registry.update_fingerprint_payload(int(record_id), local_payload)
            if self.session_context.security_allows("allow_gp_snapshots", True):
                if storage_gp:
                    gp_payload = {
                        "rules": list(storage_gp.get("gp_rules", [])),
                        "evolution_path": list(storage_gp.get("evolution_path", [])),
                        "score": float(storage_gp.get("gp_score", 0.0) or 0.0),
                        "scope": "storage",
                    }
                    self.registry.save_gp_rule_snapshot(
                        session_id=self.session_context.session_id,
                        scope="storage",
                        rule_type="storage_gp",
                        payload=gp_payload,
                        signature=self.security_monitor.sign_payload(
                            gp_payload,
                            str(getattr(self.session_context, "baseline_node_id", "") or getattr(self.session_context, "node_id", "")),
                        ),
                    )
                if language_top:
                    language_payload = {
                        "rules": language_top,
                        "evolution_path": language_events,
                        "scope": "language",
                    }
                    self.registry.save_gp_rule_snapshot(
                        session_id=self.session_context.session_id,
                        scope="language",
                        rule_type="system_language",
                        payload=language_payload,
                        signature=self.security_monitor.sign_payload(
                            language_payload,
                            str(getattr(self.session_context, "baseline_node_id", "") or getattr(self.session_context, "node_id", "")),
                        ),
                    )
        self._refresh_augment_views()

    def _estimate_coherence_score(self, entropy_blocks: list[float]) -> float:
        """Schaetzt Kohaerenz aus Entropie-Spruengen fuer Quellen ohne Ethikfelder."""
        if not entropy_blocks:
            return 100.0
        if len(entropy_blocks) < 2:
            return 96.0
        jumps = [abs(entropy_blocks[idx] - entropy_blocks[idx - 1]) for idx in range(1, len(entropy_blocks))]
        mean_jump = sum(jumps) / max(1, len(jumps))
        score = 100.0 - (mean_jump / 2.0) * 100.0
        return float(max(0.0, min(100.0, score)))

    def _derive_integrity_text(self, ethics_score: float) -> str:
        """Leitet den beschreibenden Integritaetszustand aus dem Score ab."""
        if ethics_score < 40.0:
            return "Strukturelle Anomalie erkannt"
        if ethics_score < 70.0:
            return "Strukturelle Spannung erkannt"
        return "Strukturell gesund"

    def _fingerprint_anchors_with_interference(
        self,
        fingerprint: AetherFingerprint,
    ) -> tuple[list[AnchorPoint], dict[str, object], list[dict[str, float | str]]]:
        """Liefert fuer Fingerprints interferenzangereicherte Dateianker mit Cache."""
        cached_anchors = getattr(fingerprint, "_interference_anchors", None)
        cached_profile = getattr(fingerprint, "_interference_profile", None)
        cached_ops = getattr(fingerprint, "_anchor_delta_ops", None)
        if isinstance(cached_anchors, list) and isinstance(cached_profile, dict) and isinstance(cached_ops, list):
            return list(cached_anchors), dict(cached_profile), list(cached_ops)

        raw_anchors = self.observer_engine.fingerprint_anchors(fingerprint)
        anchor_delta_ops = self.observer_engine.encode_delta_ops([], raw_anchors, tau=float(len(raw_anchors)))
        anchors, interference_profile = self.observer_engine.enrich_fingerprint_anchors(
            fingerprint,
            raw_anchors,
            anchor_delta_ops,
        )
        setattr(fingerprint, "_interference_anchors", list(anchors))
        setattr(fingerprint, "_interference_profile", dict(interference_profile))
        setattr(fingerprint, "_anchor_delta_ops", list(anchor_delta_ops))
        setattr(
            fingerprint,
            "anchor_vector",
            [
                (
                    float(anchor.x),
                    float(anchor.y),
                    float(anchor.z),
                    float(anchor.tau),
                    float(anchor.confidence),
                    float(anchor.interference),
                )
                for anchor in anchors
            ],
        )
        setattr(fingerprint, "anchor_interference_profile", dict(interference_profile))
        return anchors, interference_profile, anchor_delta_ops

    def _structural_reply_for(
        self,
        fingerprint: AetherFingerprint,
        source_text: str = "",
    ):
        """Verdichtet den aktuellen Fingerprint zu einer nicht-LLM-Antwort."""
        anchors, _, _ = self._fingerprint_anchors_with_interference(fingerprint)
        beauty_d = float(self.observer_engine._fractal_dimension(anchors)) if anchors else 1.0
        reply = self.dialog_engine.evaluate(
            fingerprint=fingerprint,
            beauty_d=beauty_d,
            anchor_count=len(anchors),
            source_text=source_text,
        )
        return reply, beauty_d, anchors

    def _graph_snapshot_for(self, fingerprint: AetherFingerprint) -> GraphFieldSnapshot:
        """Berechnet oder liest den aktuellen Graph-Feldzustand fuer einen Fingerprint."""
        cached = getattr(fingerprint, "_graph_snapshot", None)
        if isinstance(cached, GraphFieldSnapshot):
            self._last_graph_snapshot = cached
            return cached

        anchors, _, _ = self._fingerprint_anchors_with_interference(fingerprint)
        snapshot = self.graph_engine.analyze(
            fingerprint=fingerprint,
            anchors=anchors,
            session_context=self.session_context,
        )
        setattr(fingerprint, "_graph_snapshot", snapshot)
        setattr(fingerprint, "graph_node_count", int(snapshot.node_count))
        setattr(fingerprint, "graph_edge_count", int(snapshot.edge_count))
        setattr(fingerprint, "graph_attractor_score", float(snapshot.attractor_score))
        setattr(fingerprint, "graph_geodesic_energy", float(snapshot.geodesic_energy))
        setattr(fingerprint, "graph_phase_transition_score", float(snapshot.phase_transition_score))
        setattr(fingerprint, "graph_phase_state", str(snapshot.phase_state))
        setattr(fingerprint, "graph_stable_subgraphs", int(snapshot.stable_subgraphs))
        setattr(fingerprint, "graph_largest_subgraph", int(snapshot.largest_subgraph))
        setattr(fingerprint, "graph_benford_aux_score", float(snapshot.benford_aux_score))
        setattr(fingerprint, "graph_region_label", str(snapshot.region_label))
        setattr(fingerprint, "graph_region_node_count", int(snapshot.region_node_count))
        setattr(fingerprint, "graph_confidence_mean", float(snapshot.confidence_mean))
        setattr(fingerprint, "graph_interference_mean", float(snapshot.interference_mean))
        setattr(fingerprint, "graph_constructive_ratio", float(snapshot.constructive_ratio))
        setattr(fingerprint, "graph_destructive_ratio", float(snapshot.destructive_ratio))
        self._last_graph_snapshot = snapshot
        return snapshot

    def _update_graph_field(self, fingerprint: AetherFingerprint) -> None:
        """Aktualisiert die sichtbare Graph-Feldanalyse fuer den aktuellen Datensatz."""
        snapshot = self._graph_snapshot_for(fingerprint)
        sizes = " / ".join(str(size) for size in snapshot.stable_component_sizes[:3]) or "-"
        self.graph_region_var.set(
            f"{snapshot.region_label} | Knoten {snapshot.region_node_count}/{snapshot.node_count} | Kanten {snapshot.edge_count}"
        )
        self.graph_phase_var.set(
            f"Phase {snapshot.phase_state} | Uebergang {snapshot.phase_transition_score:.1f} | "
            f"Geo {snapshot.geodesic_energy:.1f} | Int {snapshot.interference_mean:+.2f}"
        )
        self.graph_attractor_var.set(
            f"Attraktor {snapshot.attractor_score:.1f} | Subgraphen {snapshot.stable_subgraphs} | "
            f"Groessen {sizes} | C+ {snapshot.constructive_ratio * 100.0:.0f}% | "
            f"D- {snapshot.destructive_ratio * 100.0:.0f}% | Benford-Aux {snapshot.benford_aux_score:.1f}"
        )

    def _update_bayes_layer(
        self,
        fingerprint: AetherFingerprint,
        anchors: list[AnchorPoint] | None = None,
        similarity_best: float | None = None,
        pattern=None,
        prior_cells: list[dict[str, float | int]] | None = None,
    ) -> BayesianBeliefSnapshot:
        """Aktualisiert die sichtbare Bayes-Schicht ueber Prior-, Graph- und Alarmmetriken."""
        resolved_anchors = list(anchors) if anchors is not None else self._fingerprint_anchors_with_interference(fingerprint)[0]
        resolved_graph = self._graph_snapshot_for(fingerprint)
        resolved_similarity = float(self._last_similarity_best if similarity_best is None else similarity_best)
        resolved_pattern = self._last_pattern_cluster if pattern is None else pattern
        resolved_priors = list(prior_cells) if prior_cells is not None else self.registry.get_anchor_priors(limit=14)
        snapshot = self.bayes_engine.evaluate(
            prior_cells=resolved_priors,
            anchors=resolved_anchors,
            graph_snapshot=resolved_graph,
            fingerprint=fingerprint,
            similarity_best=resolved_similarity,
            pattern=resolved_pattern,
        )
        setattr(fingerprint, "bayes_anchor_posterior", float(snapshot.anchor_posterior))
        setattr(fingerprint, "bayes_graph_phase_label", str(snapshot.graph_phase_label))
        setattr(fingerprint, "bayes_graph_phase_confidence", float(snapshot.graph_phase_confidence))
        setattr(fingerprint, "bayes_pattern_posterior", float(snapshot.pattern_posterior))
        setattr(fingerprint, "bayes_interference_posterior", float(snapshot.interference_posterior))
        setattr(fingerprint, "bayes_alarm_posterior", float(snapshot.alarm_posterior))
        setattr(fingerprint, "bayes_overall_confidence", float(snapshot.overall_confidence))
        self._last_bayes_snapshot = snapshot
        self.bayes_anchor_var.set(f"Prior-Posterior {snapshot.anchor_posterior * 100.0:.0f}%")
        self.bayes_phase_var.set(
            f"Phase {snapshot.graph_phase_label} {snapshot.graph_phase_confidence * 100.0:.0f}% | Int {snapshot.interference_posterior * 100.0:.0f}%"
        )
        self.bayes_pattern_var.set(
            f"Muster-Posterior {snapshot.pattern_posterior * 100.0:.0f}% | Gesamt {snapshot.overall_confidence * 100.0:.0f}%"
        )
        self.bayes_alarm_var.set(f"Alarm-Posterior {snapshot.alarm_posterior * 100.0:.0f}%")
        return snapshot

    def _draw_learning_curve(self, series: list[float]) -> None:
        """Zeichnet eine kompakte Lernkurve der juengsten Delta-Ratios."""
        if self.learning_curve_canvas is None:
            return
        canvas = self.learning_curve_canvas
        canvas.delete("all")
        width = max(80, int(canvas.winfo_width() or 260))
        height = max(32, int(canvas.winfo_height() or 42))
        canvas.create_rectangle(0, 0, width, height, fill="#0C172B", outline="#233A5A")
        if len(series) < 2:
            canvas.create_text(
                width / 2,
                height / 2,
                text="Lernkurve wartet auf genug Delta-Samples",
                fill="#60728E",
                font=("Segoe UI", 8),
            )
            return
        min_value = min(series)
        max_value = max(series)
        span = max(1e-6, max_value - min_value)
        points: list[float] = []
        for index, value in enumerate(series):
            x = 6.0 + (float(index) / max(1, len(series) - 1)) * (width - 12.0)
            y = 6.0 + (1.0 - ((float(value) - min_value) / span)) * (height - 12.0)
            points.extend([x, y])
        color = "#2DE2E6" if series[-1] <= series[0] else "#FFB347"
        canvas.create_line(*points, fill=color, width=2.0, smooth=True)
        canvas.create_text(8, height - 7, anchor="w", text=f"{series[0]:.3f}", fill="#60728E", font=("Consolas", 8))
        canvas.create_text(width - 8, height - 7, anchor="e", text=f"{series[-1]:.3f}", fill="#CFE8FF", font=("Consolas", 8, "bold"))

    def _open_anomaly_memory(self, _event=None) -> None:
        """Zeigt die juengsten Alarmspuren des lokalen Immungedaechtnisses an."""
        user_id = int(getattr(self.session_context, "user_id", 0) or 0)
        recent = self.registry.get_recent_alarm_events(user_id=user_id, limit=10)
        if not recent:
            messagebox.showinfo("Immungedaechtnis", "Noch keine lokalen Alarmereignisse gespeichert.")
            return
        lines = []
        for item in recent:
            stamp = str(item.get("timestamp", ""))
            stamp = stamp[11:19] if len(stamp) >= 19 else stamp
            payload = dict(item.get("payload_json", {}))
            details = []
            if "D" in payload:
                details.append(f"D {float(payload.get('D', 0.0)):.3f}")
            if "H_t" in payload:
                details.append(f"H(t) {float(payload.get('H_t', 0.0)):.2f}")
            if "bayes_alarm_posterior" in payload:
                details.append(f"Bayes {float(payload.get('bayes_alarm_posterior', 0.0)) * 100.0:.0f}%")
            lines.append(
                f"[{stamp}] {str(item.get('severity', '')).upper()} | {item.get('reason', '')}"
                + (f" | {' | '.join(details)}" if details else "")
            )
        messagebox.showinfo(
            "Immungedaechtnis",
            "Juengste Alarmspuren:\n\n" + "\n".join(lines) + "\n\nVerlauf laesst sich links ueber die Historiennavigation weiter laden.",
        )

    def _refresh_learning_memory_status(self) -> None:
        """Aktualisiert Modelltiefe, Delta-Lernen und lokales Immungedaechtnis sichtbar im UI."""
        user_id = int(getattr(self.session_context, "user_id", 0) or 0)
        depth_report = dict(self.registry.get_model_depth_report(user_id=user_id))
        learning_curve = dict(self.registry.get_delta_learning_curve(user_id=user_id))
        anomaly_memory = [dict(item) for item in self.registry.get_anomaly_memory(user_id=user_id, limit=3)]
        delta_ratio_series = list(self.registry.get_delta_ratio_series(user_id=user_id, limit=48))

        self._model_depth_report = depth_report
        self._delta_learning_curve = learning_curve
        self._anomaly_memory_cache = anomaly_memory
        self._delta_ratio_series = delta_ratio_series

        depth_label = str(depth_report.get("depth_label", "NAIV"))
        depth_score = float(depth_report.get("depth_score", 0.0) or 0.0)
        depth_samples = int(depth_report.get("samples", 0) or 0)
        depth_delta = float(depth_report.get("average_delta_ratio", 0.0) or 0.0)
        self.model_depth_var.set(
            f"Modelltiefe {depth_label} {depth_score:.1f} | Samples {depth_samples} | Delta {depth_delta:.3f}"
        )

        learning_label = str(learning_curve.get("trend_label", "NO_DATA"))
        learning_ratio = float(learning_curve.get("improvement_ratio", 0.0) or 0.0)
        early_average = float(learning_curve.get("early_average", 0.0) or 0.0)
        recent_average = float(learning_curve.get("recent_average", 0.0) or 0.0)
        self.delta_learning_var.set(
            f"Delta-Lernen {learning_label} {learning_ratio * 100.0:.0f}% | {early_average:.3f} -> {recent_average:.3f}"
        )
        self._draw_learning_curve(delta_ratio_series)

        if anomaly_memory:
            top = anomaly_memory[0]
            reason = str(top.get("reason", "alarm"))
            severity = str(top.get("severity", "info")).upper()
            count = int(top.get("count", 0) or 0)
            avg_bayes = float(top.get("avg_bayes_alarm_posterior", 0.0) or 0.0)
            self.anomaly_memory_var.set(
                f"Immungedaechtnis {reason} x{count} {severity} | Bayes {avg_bayes * 100.0:.0f}% | Klick: Details"
            )
        else:
            self.anomaly_memory_var.set("Immungedaechtnis sauber | keine wiederkehrenden Alarmmuster")

    def _set_live_observer_gap(
        self,
        entropy_now: float,
        coherence: float,
        resonance: float,
        prior_hint: float,
        delta_ratio: float,
    ) -> tuple[float, float, float, str]:
        """Leitet H_lambda live aus Laufzeitmetriken plus lokaler Beobachterreife ab."""
        if not self._model_depth_report and not self._delta_learning_curve:
            try:
                self._refresh_learning_memory_status()
            except Exception:
                pass

        depth_report = dict(self._model_depth_report or {})
        learning_curve = dict(self._delta_learning_curve or {})
        depth_ratio = float(depth_report.get("depth_score", 0.0) or 0.0) / 100.0
        learning_ratio = float(learning_curve.get("improvement_ratio", 0.0) or 0.0)
        learning_score = max(0.0, min(1.0, 0.5 + (learning_ratio * 2.5)))
        coherence_affinity = max(0.0, min(1.0, float(coherence)))
        resonance_affinity = max(0.0, min(1.0, float(resonance)))
        prior_affinity = max(0.0, min(1.0, float(prior_hint)))
        compression_affinity = max(0.0, min(1.0, 1.0 - float(delta_ratio)))
        knowledge_ratio = (
            (0.28 * depth_ratio)
            + (0.18 * learning_score)
            + (0.18 * coherence_affinity)
            + (0.14 * resonance_affinity)
            + (0.12 * prior_affinity)
            + (0.10 * compression_affinity)
        )
        knowledge_ratio = max(0.0, min(1.0, float(knowledge_ratio)))
        observer_information = max(0.0, float(entropy_now) * knowledge_ratio)
        h_lambda = max(0.0, float(entropy_now) - observer_information)
        if h_lambda <= 1.0:
            label = "LOSSLESS_NAH"
        elif h_lambda <= 2.8:
            label = "VERTRAUT"
        elif h_lambda <= 4.8:
            label = "LERNBAR"
        else:
            label = "OFFEN"
        self.observer_gap_var.set(
            f"H_lambda {h_lambda:.2f} | I(O;X|t) {observer_information:.2f} | Wissen {knowledge_ratio * 100.0:.0f}% | {label}"
        )
        return float(observer_information), float(knowledge_ratio), float(h_lambda), label

    def _assistant_context_for(self, fingerprint: AetherFingerprint | None = None) -> AssistantContext:
        """Verdichtet GUI-, Historien- und Verify-Zustand fuer die lokale Assistenz."""
        active = fingerprint if fingerprint is not None else self.current_fingerprint
        graph_snapshot = self._graph_snapshot_for(active) if active is not None else self._last_graph_snapshot
        bayes_snapshot = self._update_bayes_layer(active) if active is not None else self._last_bayes_snapshot
        if not self._model_depth_report and not self._delta_learning_curve and not self._anomaly_memory_cache:
            try:
                self._refresh_learning_memory_status()
            except Exception:
                pass
        chain_summary = self._fingerprint_chain_summary()
        anchor_summary = self._public_anchor_summary()
        verify_counts = {"current": 0, "foreign": 0, "tampered": 0, "compromised": 0, "shared_root": 0}
        try:
            for record in self.augmentor.verify_chain():
                status = str(record.status)
                verify_counts[status] = int(verify_counts.get(status, 0)) + 1
        except Exception:
            pass

        previous_source_label = ""
        previous_integrity_text = ""
        previous_entropy = 0.0
        previous_ethics = 0.0
        previous_h_lambda = 0.0
        if len(self.history_entries_cache) > 1:
            previous_entry = self.history_entries_cache[min(max(self.history_index, 0) + 1, len(self.history_entries_cache) - 1)]
            previous_source_label = str(previous_entry.get("source_label", ""))
            try:
                previous_fp = self.registry.load_fingerprint(int(previous_entry.get("id", 0)))
            except Exception:
                previous_fp = None
            if previous_fp is not None:
                previous_integrity_text = str(getattr(previous_fp, "integrity_text", ""))
                previous_entropy = float(getattr(previous_fp, "entropy_mean", 0.0) or 0.0)
                previous_ethics = float(getattr(previous_fp, "ethics_score", 0.0) or 0.0)
                previous_h_lambda = float(getattr(previous_fp, "h_lambda", 0.0) or 0.0)

        named, total = self.symbol_grounding.named_counts()
        depth_report = dict(self._model_depth_report or {})
        learning_curve = dict(self._delta_learning_curve or {})
        anomaly_memory = list(self._anomaly_memory_cache or [])
        if anomaly_memory:
            top = anomaly_memory[0]
            anomaly_top = (
                f"{top.get('reason', 'alarm')} x{int(top.get('count', 0) or 0)} "
                f"{str(top.get('severity', 'info')).upper()}"
            )
        else:
            anomaly_top = "sauber"
        ae_lab_summary = dict(getattr(active, "ae_lab_summary", {}) or {}) if active is not None else {}
        ae_anchor_details = [dict(item) for item in list(ae_lab_summary.get("anchors", []) or []) if isinstance(item, dict)]
        latest_block_anchor_status = ""
        try:
            latest_blocks = self.registry.get_chain_blocks(
                limit=1,
                user_id=int(getattr(self.session_context, "user_id", 0) or 0),
                include_genesis=False,
            )
            if latest_blocks:
                latest_block_anchor_status = str(latest_blocks[0].get("payload_json", {}).get("anchor_status", ""))
        except Exception:
            latest_block_anchor_status = ""
        return AssistantContext(
            username=str(getattr(self.session_context, "username", "local")),
            role=str(getattr(self.session_context, "user_role", "operator")),
            security_mode=str(getattr(self.session_context, "security_mode", "PROD")),
            trust_state=str(getattr(self.session_context, "trust_state", "TRUSTED")),
            maze_state=str(getattr(self.session_context, "maze_state", "NONE")),
            node_id=str(getattr(self.session_context, "node_id", "")),
            security_summary=str(getattr(self.session_context, "security_summary", "")),
            current_source_label=str(getattr(active, "source_label", "")) if active is not None else "",
            current_source_type=str(getattr(active, "source_type", "")) if active is not None else "",
            current_url=self.browser_url_var.get().strip(),
            current_integrity_text=str(getattr(active, "integrity_text", "")) if active is not None else "",
            current_entropy=float(getattr(active, "entropy_mean", 0.0) or 0.0) if active is not None else 0.0,
            current_ethics=float(getattr(active, "ethics_score", 0.0) or 0.0) if active is not None else 0.0,
            current_h_lambda=float(getattr(active, "h_lambda", 0.0) or 0.0) if active is not None else 0.0,
            current_observer_state=str(getattr(active, "observer_state", "")) if active is not None else "",
            current_observer_ratio=float(getattr(active, "observer_knowledge_ratio", 0.0) or 0.0) if active is not None else 0.0,
            history_count=len(self.history_entries_cache),
            vault_count=len(self.vault_entries_cache),
            alarms_count=int(self.augmentor.alarm_count()),
            named_tokens=int(named),
            total_tokens=int(total),
            ontology_complete=bool(self.symbol_grounding.ontology_complete()),
            pattern_found=self.pattern_found_var.get().strip(),
            previous_source_label=previous_source_label,
            previous_integrity_text=previous_integrity_text,
            previous_entropy=previous_entropy,
            previous_ethics=previous_ethics,
            previous_h_lambda=previous_h_lambda,
            graph_phase_state=str((graph_snapshot.phase_state if graph_snapshot is not None else "")),
            graph_region_label=str((graph_snapshot.region_label if graph_snapshot is not None else "")),
            graph_stable_subgraphs=int((graph_snapshot.stable_subgraphs if graph_snapshot is not None else 0)),
            graph_attractor_score=float((graph_snapshot.attractor_score if graph_snapshot is not None else 0.0)),
            graph_interference_mean=float((graph_snapshot.interference_mean if graph_snapshot is not None else 0.0)),
            graph_destructive_ratio=float((graph_snapshot.destructive_ratio if graph_snapshot is not None else 0.0)),
            bayes_anchor_confidence=float((bayes_snapshot.anchor_posterior if bayes_snapshot is not None else 0.0)),
            bayes_phase_confidence=float((bayes_snapshot.graph_phase_confidence if bayes_snapshot is not None else 0.0)),
            bayes_pattern_confidence=float((bayes_snapshot.pattern_posterior if bayes_snapshot is not None else 0.0)),
            bayes_interference_confidence=float((bayes_snapshot.interference_posterior if bayes_snapshot is not None else 0.0)),
            bayes_alarm_confidence=float((bayes_snapshot.alarm_posterior if bayes_snapshot is not None else 0.0)),
            model_depth_label=str(depth_report.get("depth_label", "")),
            model_depth_score=float(depth_report.get("depth_score", 0.0) or 0.0),
            delta_learning_label=str(learning_curve.get("trend_label", "")),
            delta_learning_ratio=float(learning_curve.get("improvement_ratio", 0.0) or 0.0),
            anomaly_memory_top=anomaly_top,
            ae_anchor_count=int(ae_lab_summary.get("anchor_count", 0) or 0),
            ae_main_vault_size=int(ae_lab_summary.get("main_vault_size", 0) or 0),
            ae_top_anchor_type=str((ae_lab_summary.get("top_anchor_types", [""]) or [""])[0]),
            ae_summary=str(
                getattr(active, "ae_lab_summary_text", "")
                or ae_lab_summary.get("anchor_preview", "")
                or "intern aktiv"
            ),
            ae_anchor_details=ae_anchor_details,
            local_chain_entries=int(chain_summary.get("entry_count", 0) or 0),
            local_chain_valid=bool(chain_summary.get("valid", True)),
            local_chain_latest_hash=str(chain_summary.get("latest_hash", "") or chain_summary.get("latest_file_hash", "")),
            current_local_chain_tx=str(getattr(active, "local_chain_tx_hash", "")) if active is not None else "",
            public_anchor_pending=int(anchor_summary.get("pending", 0) or 0),
            public_anchor_online=bool(anchor_summary.get("online", False)),
            public_anchor_latest_status=str(anchor_summary.get("latest_status", "")),
            current_anchor_status=latest_block_anchor_status,
            verify_counts=verify_counts,
        )

    def _update_semantic_status(self, fingerprint: AetherFingerprint, source_text: str = "") -> None:
        """Aktualisiert die sichtbare strukturelle Semantik fuer den aktuellen Datensatz."""
        reply, beauty_d, anchors = self._structural_reply_for(fingerprint, source_text=source_text)
        security_prefix = ""
        if not self.session_context.security_allows("allow_semantic_promotion", True):
            security_prefix = (
                f"{str(getattr(self.session_context, 'trust_state', 'UNTRUSTED'))}"
                f"/{str(getattr(self.session_context, 'maze_state', 'NONE'))} | "
            )
        self.semantic_state_var.set(
            f"{security_prefix}{reply.semantics_label} | "
            f"{getattr(fingerprint, 'integrity_text', self._derive_integrity_text(float(getattr(fingerprint, 'ethics_score', 0.0) or 0.0)))}"
        )
        self.beauty_state_var.set(
            f"Schoenheit {reply.beauty_score:.1f} | {reply.beauty_label} | D {beauty_d:.3f} | Anker {len(anchors)}"
        )
        beauty_signature = dict(getattr(fingerprint, "beauty_signature", {}) or {})
        if beauty_signature:
            self.beauty_signature_var.set(
                "Score {score:.1f} | 1/f {alpha:.2f} | Ly {lyap:.2f} | D {mandel:.2f} | "
                "K {kol:.2f} | B {ben:.2f} | Z {zipf:.2f} | Sym {sym:.2f}".format(
                    score=float(beauty_signature.get("beauty_score", 0.0) or 0.0),
                    alpha=float(beauty_signature.get("alpha_1f", 0.0) or 0.0),
                    lyap=float(beauty_signature.get("lyapunov", 0.0) or 0.0),
                    mandel=float(beauty_signature.get("mandelbrot_d", 0.0) or 0.0),
                    kol=float(beauty_signature.get("kolmogorov_k", 0.0) or 0.0),
                    ben=float(beauty_signature.get("benford_b", 0.0) or 0.0),
                    zipf=float(beauty_signature.get("zipf_z", 0.0) or 0.0),
                    sym=float(beauty_signature.get("symmetry_phi", 0.0) or 0.0),
                )
            )
        else:
            self.beauty_signature_var.set("Beauty 7D: --")
        observer_state = str(getattr(fingerprint, "observer_state", "OFFEN") or "OFFEN")
        observer_ratio = float(getattr(fingerprint, "observer_knowledge_ratio", 0.0) or 0.0)
        h_lambda = float(getattr(fingerprint, "h_lambda", 0.0) or 0.0)
        mutual_info = float(getattr(fingerprint, "observer_mutual_info", 0.0) or 0.0)
        self.observer_gap_var.set(
            f"H_lambda {h_lambda:.2f} | I(O;X|t) {mutual_info:.2f} | Wissen {observer_ratio * 100.0:.0f}% | {observer_state}"
        )
        self._update_graph_field(fingerprint)
        self._update_bayes_layer(fingerprint, anchors=anchors)

    def _update_integrity_monitor(self, fingerprint: AetherFingerprint) -> None:
        """Aktualisiert den Integritaets-Monitor fuer aktuelle Analysewerte."""
        symmetry = float(getattr(fingerprint, "symmetry_component", 0.0) or 0.0)
        if symmetry <= 0.0:
            symmetry = float(getattr(fingerprint, "symmetry_score", 0.0) or 0.0)

        coherence = float(getattr(fingerprint, "coherence_score", 0.0) or 0.0)
        if coherence <= 0.0:
            coherence = self._estimate_coherence_score(list(getattr(fingerprint, "entropy_blocks", []) or []))

        resonance = float(getattr(fingerprint, "resonance_score", 0.0) or 0.0)
        if resonance <= 0.0:
            if str(getattr(fingerprint, "verdict", "CLEAN")) == "CRITICAL":
                resonance = 28.0
            elif str(getattr(fingerprint, "verdict", "CLEAN")) == "SUSPICIOUS":
                resonance = 52.0
            else:
                resonance = 72.0

        ethics_score = float(getattr(fingerprint, "ethics_score", 0.0) or 0.0)
        if ethics_score <= 0.0:
            ethics_score = (0.4 * symmetry) + (0.4 * coherence) + (0.2 * resonance)

        symmetry = max(0.0, min(100.0, symmetry))
        coherence = max(0.0, min(100.0, coherence))
        resonance = max(0.0, min(100.0, resonance))
        ethics_score = max(0.0, min(100.0, ethics_score))

        integrity_text = str(getattr(fingerprint, "integrity_text", "") or "").strip()
        if not integrity_text:
            integrity_text = self._derive_integrity_text(ethics_score)

        if ethics_score < 40.0:
            accent = "#FF355E"
        elif ethics_score < 70.0:
            accent = "#FF8C42"
        else:
            accent = "#2DE2E6"

        self.symmetry_monitor_var.set(symmetry)
        self.coherence_monitor_var.set(coherence)
        self.resonance_monitor_var.set(resonance)
        self.integrity_score_var.set(f"{ethics_score:.1f}")
        self.integrity_text_var.set(integrity_text)
        self.integrity_score_label.configure(fg=accent)
        self.integrity_text_label.configure(fg=accent)

    def _algorithm_color(self, name: str) -> str:
        """Mappt Algorithmusnamen deterministisch auf abstrakte Symbolfarben."""
        palette = ["#4CC9F0", "#F9C74F", "#F94144", "#90BE6D", "#B388EB", "#FF8C42"]
        return palette[sum(ord(ch) for ch in name) % len(palette)]

    def _render_placeholder(self) -> None:
        """Zeigt eine initiale leere Raumzeitdarstellung."""
        fig = plt.Figure(figsize=(8, 6), facecolor="#050816")
        ax = fig.add_subplot(111, projection="3d")
        ax.set_facecolor("#0A0F2E")
        grid = np.arange(16, dtype=np.float64)
        grid_x, grid_y = np.meshgrid(grid, grid)
        base_z = (np.sin(grid_x / 2.4) * 0.45) + (np.cos(grid_y / 3.1) * 0.35)
        ax.plot_wireframe(
            grid_x,
            grid_y,
            base_z,
            rstride=1,
            cstride=1,
            color="#2DE2E6",
            linewidth=0.8,
            alpha=0.55,
        )
        ax.contourf(
            grid_x,
            grid_y,
            base_z,
            zdir="z",
            offset=-2.2,
            levels=14,
            cmap="winter",
            alpha=0.32,
        )

        delta_paths = [
            np.array([[1.0, 2.0, -1.5], [4.0, 5.0, -0.2], [7.0, 7.0, 0.9], [10.0, 10.0, 1.4], [13.0, 13.0, 0.3]]),
            np.array([[13.0, 2.0, -1.4], [10.0, 4.0, -0.3], [8.0, 7.0, 0.8], [5.0, 10.0, 1.3], [2.0, 13.0, 0.4]]),
            np.array([[3.0, 12.0, -1.1], [5.5, 10.0, -0.1], [8.0, 8.0, 1.0], [10.5, 6.0, 1.6], [13.0, 4.0, 0.5]]),
        ]
        path_colors = ["#67D5FF", "#F2C14E", "#90BE6D"]
        for path, color in zip(delta_paths, path_colors):
            ax.plot(path[:, 0], path[:, 1], path[:, 2], color=color, linewidth=2.2, alpha=0.95)
            ax.scatter(path[:, 0], path[:, 1], path[:, 2], color=color, s=18, alpha=0.9, depthshade=False)

        anchor_points = np.array(
            [
                [4.0, 4.0, 1.7],
                [8.0, 8.0, 2.1],
                [12.0, 11.0, 1.9],
            ],
            dtype=np.float64,
        )
        ax.scatter(
            anchor_points[:, 0],
            anchor_points[:, 1],
            anchor_points[:, 2],
            s=[180, 220, 180],
            color="#FFFFFF",
            edgecolors="#F6E7A7",
            linewidths=1.4,
            alpha=0.98,
            depthshade=False,
        )

        ax.set_xlim(0, 15)
        ax.set_ylim(0, 15)
        ax.set_zlim(-2.2, 2.4)
        ax.view_init(elev=26.0, azim=46.0)
        ax.set_title("Aether Raster | 4D Raumzeit-Deltafeld", color="#DDF9FF", pad=14)
        ax.set_xlabel("X", color="#C5D4FF")
        ax.set_ylabel("Y", color="#C5D4FF")
        ax.set_zlabel("Z / Zeit", color="#C5D4FF")
        ax.tick_params(colors="#A7B7E2")
        try:
            ax.xaxis.pane.set_facecolor((0.04, 0.08, 0.18, 0.95))
            ax.yaxis.pane.set_facecolor((0.04, 0.08, 0.18, 0.95))
            ax.zaxis.pane.set_facecolor((0.02, 0.04, 0.09, 0.95))
        except Exception:
            pass
        ax.text2D(
            0.03,
            0.96,
            "Mitte bleibt fuer Drag-and-Drop, Kamera und Theremin.\nBrowser und Shanway-Chat greifen dieses Raster nicht live an.",
            transform=ax.transAxes,
            color="#CFE8FF",
            fontsize=9,
            bbox={"facecolor": "#091426", "edgecolor": "#1F3558", "boxstyle": "round,pad=0.35", "alpha": 0.88},
        )
        self._set_figure(fig)

    def _set_figure(self, figure) -> None:
        """Ersetzt die eingebettete Matplotlib-Figur im Zentrum."""
        self._stop_scene_animation()
        if self.current_canvas is not None:
            self.current_canvas.get_tk_widget().destroy()
        if self.current_figure is not None and self.current_figure is not figure:
            plt.close(self.current_figure)
        self.current_figure = figure
        self.current_canvas = FigureCanvasTkAgg(figure, master=self.scene_frame)
        self.current_canvas.get_tk_widget().pack(fill="both", expand=True)
        self.current_canvas.draw()

    def _set_scene_from_fingerprint(self, fingerprint: AetherFingerprint) -> None:
        """Initialisiert eine dynamische Szene aus einem Fingerprint."""
        self.current_fingerprint = fingerprint
        self._refresh_ae_anchor_panel(self._resolve_ae_anchor_entries(fingerprint))
        scene = self.renderer.create_dynamic_scene(fingerprint)
        self._set_figure(scene.figure)
        self.animation_scene = scene
        self.audio_engine.update_audiovisual_frame(scene.audiovisual_frame)
        self._start_scene_animation()

    def _update_scene_fingerprint(self, fingerprint: AetherFingerprint) -> None:
        """Aktualisiert die laufende Szene mit neuen Fingerprint-Daten."""
        self.current_fingerprint = fingerprint
        self._refresh_ae_anchor_panel(self._resolve_ae_anchor_entries(fingerprint))
        if self.animation_scene is None or self.current_canvas is None:
            self._set_scene_from_fingerprint(fingerprint)
            return
        self.renderer.apply_fingerprint_to_scene(self.animation_scene, fingerprint)
        self.renderer.update_dynamic_scene(self.animation_scene)
        self.audio_engine.update_audiovisual_frame(self.animation_scene.audiovisual_frame)
        self.current_canvas.draw_idle()

    def _start_scene_animation(self) -> None:
        """Startet den periodischen Animations-Refresh."""
        if self.animation_scene is None:
            return
        self._animate_scene()

    def _animate_scene(self) -> None:
        """Fuehrt einen einzelnen Animationsschritt aus und plant den naechsten."""
        if self.animation_scene is None or self.current_canvas is None:
            return
        loop_start = time.perf_counter()
        try:
            self.renderer.update_dynamic_scene(self.animation_scene)
            self.audio_engine.update_audiovisual_frame(self.animation_scene.audiovisual_frame)
            self.current_canvas.draw_idle()
            self._refresh_runtime_adaptation("animation", time.perf_counter() - loop_start)
            self.animation_job = self.root.after(self._loop_delay_ms("animation"), self._animate_scene)
        except Exception:
            self.animation_job = None

    def _stop_scene_animation(self) -> None:
        """Beendet laufende Animations-Timer sauber."""
        if self.animation_job is not None:
            try:
                self.root.after_cancel(self.animation_job)
            except Exception:
                self.animation_job = None
            self.animation_job = None
        self.audio_engine.stop_audiovisual_stream()
        self.animation_scene = None

    def _set_loading(self, active: bool) -> None:
        """Aktiviert oder deaktiviert den Ladeindikator."""
        if active:
            self.progress.pack(fill="x", padx=12, pady=(0, 6))
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()

    def _update_wavelength_indicator(self, wavelength_nm: float, color_rgb: tuple[int, int, int] | None = None) -> None:
        """Aktualisiert die farbige Wellenlaengenanzeige."""
        if color_rgb is None:
            color_rgb = SpectrumEngine.wavelength_to_rgb(wavelength_nm)
        color_hex = "#{:02X}{:02X}{:02X}".format(
            int(max(0, min(255, color_rgb[0]))),
            int(max(0, min(255, color_rgb[1]))),
            int(max(0, min(255, color_rgb[2]))),
        )
        self.wavelength_canvas.itemconfig(self.wavelength_rect, fill=color_hex)
        self.wavelength_var.set(f"Dominante Wellenlaenge: {wavelength_nm:.1f} nm")

    def _decorate_fingerprint_with_voxels(self, fingerprint: AetherFingerprint) -> AetherFingerprint:
        """Reichert einen Fingerprint mit dem aktuellen 4D-Voxel-Zustand an."""
        if len(self.voxel_grid) <= 0:
            fingerprint.voxel_points = None
            return fingerprint

        fingerprint.voxel_points = self.voxel_grid.render_points(limit=900)
        heatmap_blocks = self.voxel_grid.build_entropy_blocks(size=16)
        if heatmap_blocks:
            fingerprint.entropy_blocks = heatmap_blocks
            fingerprint.entropy_mean = float(sum(heatmap_blocks) / len(heatmap_blocks))
            merged = list(fingerprint.anomaly_coordinates)
            for coordinate in self.voxel_grid.anomaly_coordinates(size=16):
                if coordinate not in merged:
                    merged.append(coordinate)
            fingerprint.anomaly_coordinates = merged
        return fingerprint

    def _open_file_dialog(self) -> None:
        """Oeffnet einen Dateiauswahldialog fuer generische Datei-Analyse."""
        file_path = filedialog.askopenfilename(title="Datei fuer Raumzeit-Analyse auswaehlen")
        if file_path:
            self.path_var.set(file_path)
            self._start_analysis(file_path)

    def _open_spectrum_dialog(self) -> None:
        """Oeffnet einen Dateidialog fuer Bild-Spektrumanalyse."""
        file_path = filedialog.askopenfilename(
            title="Bild fuer Lichtspektrum-Analyse auswaehlen",
            filetypes=[("Bilddateien", "*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tif;*.tiff"), ("Alle Dateien", "*.*")],
        )
        if file_path:
            self.path_var.set(file_path)
            self._start_spectrum_analysis(file_path)

    def _open_csv_dialog(self) -> None:
        """Oeffnet einen Dateidialog fuer 4D-Voxel-CSV-Import."""
        file_path = filedialog.askopenfilename(
            title="CSV fuer 4D-Voxel-Import auswaehlen",
            filetypes=[("CSV-Dateien", "*.csv"), ("Alle Dateien", "*.*")],
        )
        if file_path:
            self.path_var.set(file_path)
            self._start_csv_import(file_path)

    def _open_aelab_dna_dialog(self) -> None:
        """Oeffnet einen Dateidialog fuer den Import alter AELAB-DNA-Dateien."""
        file_path = filedialog.askopenfilename(
            title="AELAB-DNA importieren",
            filetypes=[("AELAB DNA", "*.dna"), ("Alle Dateien", "*.*")],
        )
        if file_path:
            self.path_var.set(file_path)
            self._start_dna_import(file_path)

    def _open_aelab_vault_dialog(self) -> None:
        """Oeffnet einen Ordnerdialog fuer rekursiven Import alter Vault-/Subvault-DNA."""
        directory_path = filedialog.askdirectory(title="AELAB Vault-Ordner importieren")
        if directory_path:
            self.path_var.set(directory_path)
            self._start_dna_directory_import(directory_path)

    def _setup_drag_and_drop(self) -> None:
        """Aktiviert Drag & Drop robust ueber tkinterdnd2."""
        if not TKDND_AVAILABLE:
            self.loading_var.set("Bereit. Drag & Drop ist nicht installiert.")
            return
        try:
            for widget in [self.root, self.left_frame, self.center_frame, self.path_entry]:
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind("<<Drop>>", self._on_drop_event)
            self.loading_var.set("Bereit. Drag & Drop ist aktiv.")
        except Exception:
            self.loading_var.set("Bereit. Drag & Drop konnte nicht initialisiert werden.")

    def _on_storage_layer_changed(self, _event=None) -> None:
        """Aktualisiert die Darstellungs-Schicht fuer die aktuelle Szene."""
        layer = self.renderer.set_storage_layer(self.storage_layer_var.get())
        if self.current_fingerprint is not None:
            self._set_scene_from_fingerprint(self.current_fingerprint)
        self.loading_var.set(f"Storage-Layer aktiv: {layer}")

    def _extract_dropped_paths(self, raw_data: str) -> list[str]:
        """Parst die vom Drop-Event gelieferten Dateipfade robust."""
        if not raw_data:
            return []
        try:
            parts = list(self.root.tk.splitlist(raw_data))
        except Exception:
            parts = [raw_data]
        result: list[str] = []
        for item in parts:
            candidate = item.strip().strip('"')
            if candidate.startswith("{") and candidate.endswith("}"):
                candidate = candidate[1:-1]
            if candidate:
                result.append(candidate)
        return result

    def _on_drop_event(self, event) -> str:
        """Nimmt ein Drop-Event entgegen und startet sofort die Dateianalyse."""
        try:
            dropped_paths = self._extract_dropped_paths(str(getattr(event, "data", "")))
            if dropped_paths:
                self._handle_dropped_file(dropped_paths[0])
            else:
                self.loading_var.set("Drop erkannt, aber kein gueltiger Dateipfad enthalten.")
        except Exception:
            self.loading_var.set("Drop erkannt, konnte aber nicht verarbeitet werden.")
        return "break"

    def _handle_dropped_file(self, file_path: str) -> None:
        """Uebernimmt eine per Drag & Drop uebergebene Datei und startet sofort die Analyse."""
        normalized = file_path.strip().strip('"')
        self.path_var.set(normalized)
        path = Path(normalized)
        if path.is_dir():
            self.loading_var.set("Legacy-Vault-Ordner erkannt. Rekursiver AELAB-Import startet ...")
            self._start_dna_directory_import(normalized)
            return
        if not path.is_file():
            self.loading_var.set("Drop erkannt, aber kein gueltiger Dateipfad.")
            return

        suffix = path.suffix.lower()
        if suffix == ".dna":
            self.loading_var.set("AELAB-DNA per Drag & Drop erkannt. Legacy-Import startet ...")
            self._start_dna_import(normalized)
        elif suffix == ".csv":
            self.loading_var.set("CSV per Drag & Drop erkannt. 4D-Voxel-Import startet ...")
            self._start_csv_import(normalized)
        elif suffix in {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff"}:
            self.loading_var.set("Bild per Drag & Drop erkannt. Spektrumanalyse startet ...")
            self._start_spectrum_analysis(normalized)
        else:
            self.loading_var.set("Datei per Drag & Drop erkannt. Analyse startet ...")
            self._start_analysis(normalized)

    def _start_analysis_from_entry(self) -> None:
        """Startet eine Analyse fuer den manuell eingegebenen Pfad."""
        candidate = self.path_var.get().strip()
        if candidate and Path(candidate).is_dir():
            self._start_dna_directory_import(candidate)
            return
        suffix = Path(candidate).suffix.lower() if candidate else ""
        if suffix == ".dna":
            self._start_dna_import(candidate)
        elif suffix == ".csv":
            self._start_csv_import(candidate)
        elif suffix in {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff"}:
            self._start_spectrum_analysis(candidate)
        else:
            self._start_analysis(candidate)

    def _start_dna_import(self, file_path: str) -> None:
        """Importiert alte AELAB-DNA-Dateien direkt in den neuen AE-Vault."""
        if not file_path or not Path(file_path).is_file():
            messagebox.showwarning("Hinweis", "Bitte einen gueltigen DNA-Pfad angeben.")
            return
        try:
            imported = self._import_legacy_dna_file(file_path, sync_registry=True)
            legacy = imported["legacy"]
            payload = dict(imported["payload"])
            self.loading_var.set(
                f"AELAB-DNA importiert: {Path(file_path).name} | Bucket {legacy.bucket} | Konstanten {int(payload.get('constant_count', 0) or 0)}"
            )
            if self.current_fingerprint is not None:
                probe = self._ae_probe_payload_from_fingerprint(self.current_fingerprint)
                snapshot = dict(self.ae_vault.snapshot(probe, limit=12))
                self._apply_ae_snapshot_to_current_fingerprint(snapshot)
        except Exception as exc:
            messagebox.showerror("AELAB-DNA-Import fehlgeschlagen", str(exc))

    def _start_dna_directory_import(self, directory_path: str) -> None:
        """Importiert einen alten AELAB-Vault rekursiv inklusive Vault-/Subvault-Buckets."""
        root = Path(directory_path)
        if not root.is_dir():
            messagebox.showwarning("Hinweis", "Bitte einen gueltigen Vault-Ordner angeben.")
            return
        dna_files = iter_legacy_dna_files(str(root))
        if not dna_files:
            messagebox.showinfo("AELAB Vault", "Im gewaelten Ordner wurden keine .dna-Dateien gefunden.")
            return
        imported = 0
        failed = 0
        bucket_counts = {"main": 0, "sub": 0}
        pi_like_total = 0
        first_error = ""
        for file_path in dna_files:
            try:
                result = self._import_legacy_dna_file(file_path, sync_registry=False)
                payload = dict(result.get("payload", {}) or {})
                legacy = result.get("legacy")
                bucket = str(getattr(legacy, "bucket", payload.get("bucket", "sub")) or "sub")
                bucket_counts[bucket] = int(bucket_counts.get(bucket, 0)) + 1
                pi_like_total += int(len(list(payload.get("pi_like_constants", [])) or []))
                imported += 1
            except Exception as exc:
                failed += 1
                if not first_error:
                    first_error = str(exc)
        self._sync_ae_vault_registry()
        if self.current_fingerprint is not None:
            probe = self._ae_probe_payload_from_fingerprint(self.current_fingerprint)
            snapshot = dict(self.ae_vault.snapshot(probe, limit=12))
            self._apply_ae_snapshot_to_current_fingerprint(snapshot)
        summary = (
            f"AELAB-Vault importiert | Dateien {imported}/{len(dna_files)} | "
            f"Main {int(bucket_counts.get('main', 0))} | Sub {int(bucket_counts.get('sub', 0))} | "
            f"pi-like {pi_like_total}"
        )
        if failed:
            summary = f"{summary} | Fehler {failed}"
        self.loading_var.set(summary)
        self.ae_iteration_var.set(
            f"Legacy-Vault importiert | Dateien {imported}/{len(dna_files)} | Fehler {failed}"
        )
        if failed and first_error:
            messagebox.showwarning("AELAB Vault-Import", f"{summary}\n\nErster Fehler:\n{first_error}")

    def _export_voxel_csv(self) -> None:
        """Exportiert die aktuelle 4D-Voxel-Historie als CSV."""
        file_path = filedialog.asksaveasfilename(
            title="Voxel-CSV exportieren",
            defaultextension=".csv",
            filetypes=[("CSV-Dateien", "*.csv"), ("Alle Dateien", "*.*")],
        )
        if not file_path:
            return

        exported = 0
        if len(self.voxel_grid) > 0:
            exported = self.voxel_grid.export_csv(file_path)
        else:
            exported = self.registry.export_voxel_events(file_path, session_id=self.session_context.session_id)

        if exported <= 0:
            messagebox.showwarning("Hinweis", "Es sind keine Voxel-Daten zum Export vorhanden.")
            return
        self._append_export_audit("voxel_csv", file_path, {"records": int(exported)})
        self.loading_var.set(f"Voxel-CSV exportiert: {Path(file_path).name} ({exported} Eintraege)")

    def _start_analysis(self, file_path: str) -> None:
        """Startet die klassische Dateianalyse in einem separaten Thread."""
        if not self.session_context.security_allows("allow_analysis", True):
            messagebox.showwarning(
                "Sicherheitsmodus",
                "Die lokale Sicherheitsdiagnose blockiert Analyse derzeit. Im DEV-Modus sollte das nicht mehr auftreten.",
            )
            return
        if self.analysis_thread is not None and self.analysis_thread.is_alive():
            self.loading_var.set("Analyse laeuft bereits.")
            return
        if not file_path or not Path(file_path).is_file():
            messagebox.showwarning("Hinweis", "Bitte einen gueltigen Dateipfad angeben.")
            return
        self.voxel_grid.clear()
        self.loading_var.set("Dateianalyse laeuft ...")
        self._set_loading(True)
        save_raw = bool(self.raw_storage_enabled_var.get())
        self.analysis_thread = threading.Thread(
            target=self._analysis_worker,
            args=(file_path, save_raw),
            daemon=True,
        )
        self.analysis_thread.start()

    def _start_csv_import(self, file_path: str) -> None:
        """Startet den 4D-Voxel-Import aus CSV in einem separaten Thread."""
        if not self.session_context.security_allows("allow_analysis", True):
            messagebox.showwarning(
                "Sicherheitsmodus",
                "Die lokale Sicherheitsdiagnose blockiert CSV-Import derzeit. Im DEV-Modus sollte das nicht mehr auftreten.",
            )
            return
        if self.csv_thread is not None and self.csv_thread.is_alive():
            self.loading_var.set("CSV-Import laeuft bereits.")
            return
        if not file_path or not Path(file_path).is_file():
            messagebox.showwarning("Hinweis", "Bitte einen gueltigen CSV-Pfad angeben.")
            return
        if self.theremin_engine.is_running:
            self._stop_theremin()
        self.loading_var.set("CSV-Import laeuft ...")
        self._set_loading(True)
        self.csv_thread = threading.Thread(target=self._csv_worker, args=(file_path,), daemon=True)
        self.csv_thread.start()

    def _start_spectrum_analysis(self, file_path: str) -> None:
        """Startet die Bild-Spektrumanalyse in einem separaten Thread."""
        if not self.session_context.security_allows("allow_analysis", True):
            messagebox.showwarning(
                "Sicherheitsmodus",
                "Die lokale Sicherheitsdiagnose blockiert Spektrumanalyse derzeit. Im DEV-Modus sollte das nicht mehr auftreten.",
            )
            return
        if self.spectrum_thread is not None and self.spectrum_thread.is_alive():
            self.loading_var.set("Spektrumanalyse laeuft bereits.")
            return
        if not file_path or not Path(file_path).is_file():
            messagebox.showwarning("Hinweis", "Bitte einen gueltigen Bildpfad angeben.")
            return
        self.voxel_grid.clear()
        self.loading_var.set("Lichtspektrum-Analyse laeuft ...")
        self._set_loading(True)
        self.spectrum_thread = threading.Thread(target=self._spectrum_worker, args=(file_path,), daemon=True)
        self.spectrum_thread.start()

    def _analysis_worker(self, file_path: str, save_raw: bool) -> None:
        """Fuehrt Datei-Analyse, Speicherung, Rendering und Logging im Hintergrund aus."""
        try:
            source_path = Path(file_path)
            raw_bytes = source_path.read_bytes()
            text_learning_info: dict[str, object] = {}
            is_text_source = source_path.suffix.lower() in {".txt", ".md"}
            if is_text_source:
                try:
                    text_content = raw_bytes.decode("utf-8", errors="ignore")
                    learned_tokens = self.shanway_engine.learn_from_corpus_text(
                        text_content,
                        language_hint=self._infer_text_language_hint(source_path),
                    )
                    text_learning_info = {
                        "shanway_text_corpus": True,
                        "learned_tokens": int(learned_tokens),
                    }
                except Exception:
                    text_learning_info = {
                        "shanway_text_corpus": False,
                        "learned_tokens": 0,
                    }
            fingerprint = self.analysis_engine.analyze_bytes(
                raw_bytes,
                source_label=str(source_path),
                source_type="text_file" if is_text_source else "file",
            )
            storage_decision = self.storage_gp_engine.evaluate(fingerprint)
            raw_saved = False
            local_payload = {
                "dual_storage_mode": "delta_only",
                "raw_storage_available": False,
                "storage_gp": storage_decision.to_dict(),
            }
            local_payload.update(text_learning_info)
            record_id = self.registry.save(
                fingerprint,
                self.session_context,
                payload_update=local_payload,
            )
            if save_raw:
                try:
                    self.registry.save_encrypted_raw_bytes(
                        fingerprint_id=int(record_id),
                        session_context=self.session_context,
                        raw_bytes=raw_bytes,
                        file_hash=fingerprint.file_hash,
                        source_label=str(source_path),
                        payload={
                            "gp_score": float(storage_decision.gp_score),
                            "rationale": str(storage_decision.rationale),
                            "recommended": bool(storage_decision.recommend_store_raw),
                            "validation_recommended": bool(storage_decision.recommend_validation),
                        },
                    )
                    raw_saved = True
                    self.registry.update_fingerprint_payload(
                        int(record_id),
                        {
                            "dual_storage_mode": "delta_plus_encrypted_raw",
                            "raw_storage_available": True,
                        },
                    )
                except Exception:
                    raw_saved = False
            setattr(fingerprint, "_storage_gp_decision", storage_decision.to_dict())
            setattr(fingerprint, "_raw_storage_available", bool(raw_saved))
            setattr(fingerprint, "_raw_storage_requested", bool(save_raw))
            log_path = self.log_system.write_analysis_log(fingerprint)
            screenshot_figure = self.renderer.render(fingerprint)
            self.log_system.save_screenshot(screenshot_figure)
            plt.close(screenshot_figure)

            honeypot_hit = False
            for coordinate in fingerprint.anomaly_coordinates:
                if self.session_context.is_honeypot(coordinate):
                    honeypot_hit = True
                    self.session_context.trigger_honeypot_alert(coordinate)
                    self.security_monitor.register_honeypot_trigger(
                        self.session_context,
                        coordinate=coordinate,
                        reason="Anomalie traf lokalen Honeypot-Koeder.",
                    )
                    break

            self.root.after(
                0,
                lambda: self._on_analysis_complete(
                    fingerprint=fingerprint,
                    record_id=record_id,
                    honeypot_hit=honeypot_hit,
                    log_path=str(log_path),
                ),
            )
            if bool(text_learning_info.get("shanway_text_corpus", False)):
                self.root.after(0, self._refresh_shanway_corpus_status)
        except Exception as exc:
            self.root.after(0, lambda: self._on_analysis_error(str(exc)))

    def _csv_worker(self, file_path: str) -> None:
        """Importiert eine Voxel-CSV, bewertet sie ethisch und rendert die Weltlinien."""
        try:
            imported = self.voxel_grid.load_csv(file_path)
            source_name = Path(file_path).name
            self.registry.save_voxel_events(
                session_id=self.session_context.session_id,
                source_type="csv",
                source_label=source_name,
                voxels=list(self.voxel_grid.changed_voxels),
            )
            fingerprint = self.analysis_engine.analyze_voxel_grid(self.voxel_grid, source_label=source_name)
            record_id = self.registry.save(fingerprint, self.session_context)
            log_path = self.log_system.write_analysis_log(fingerprint)
            screenshot_figure = self.renderer.render(fingerprint)
            self.log_system.save_screenshot(screenshot_figure)
            plt.close(screenshot_figure)
            self.root.after(
                0,
                lambda: self._on_csv_import_complete(
                    fingerprint=fingerprint,
                    record_id=record_id,
                    imported=imported,
                    log_path=str(log_path),
                ),
            )
        except Exception as exc:
            self.root.after(0, lambda: self._on_analysis_error(str(exc)))

    def _spectrum_worker(self, file_path: str) -> None:
        """Fuehrt Spektrum-Analyse fuer Bilddateien im Hintergrund aus."""
        try:
            spectrum = self.spectrum_engine.analyze_image(file_path)
            record_id = self.registry.save_spectrum_fingerprint(spectrum)
            fingerprint = spectrum.to_aether_fingerprint()
            log_path = self.log_system.write_analysis_log(fingerprint)
            screenshot_figure = self.renderer.render(fingerprint)
            self.log_system.save_screenshot(screenshot_figure)
            plt.close(screenshot_figure)
            self.root.after(
                0,
                lambda: self._on_spectrum_complete(
                    spectrum=spectrum,
                    fingerprint=fingerprint,
                    record_id=record_id,
                    log_path=str(log_path),
                ),
            )
        except Exception as exc:
            self.root.after(0, lambda: self._on_analysis_error(str(exc)))

    def _on_analysis_complete(self, fingerprint: AetherFingerprint, record_id: int, honeypot_hit: bool, log_path: str) -> None:
        """Aktualisiert GUI-Zustand nach erfolgreicher Dateianalyse."""
        self._set_loading(False)
        self._apply_security_snapshot()
        fingerprint = self._decorate_fingerprint_with_voxels(fingerprint)
        self._register_final_modules(fingerprint, record_id=int(record_id))
        self._latest_file_record_id = int(record_id)
        self._refresh_restore_status()
        self._refresh_history_cache(preserve_record_id=int(record_id))
        self._set_scene_from_fingerprint(fingerprint)
        self._update_integrity_monitor(fingerprint)
        self._update_semantic_status(fingerprint, source_text=str(getattr(fingerprint, "source_label", "")))
        self.state_var.set(self.renderer.get_state_description(fingerprint))
        if honeypot_hit:
            self.honeypot_var.set("Diagnostik: Aktivitaet erkannt")
            self.honeypot_label.configure(fg="#FFB347")
        else:
            self.honeypot_var.set("Diagnostik: keine Aktivitaet")
            self.honeypot_label.configure(fg="#7DE8A7")
        storage_decision = dict(getattr(fingerprint, "_storage_gp_decision", {}) or {})
        raw_saved = bool(getattr(fingerprint, "_raw_storage_available", False))
        decision_suffix = ""
        if storage_decision:
            decision_suffix = (
                f" | GP {float(storage_decision.get('gp_score', 0.0) or 0.0):.2f}"
                f" | Empfehlung {'RAW' if bool(storage_decision.get('recommend_store_raw', False)) else 'DELTA'}"
            )
        self._apply_raw_storage_mode_label(
            bool(raw_saved),
            detail=decision_suffix,
        )
        self.loading_var.set(f"Analyse abgeschlossen. Datensatz-ID: {record_id} | Log: {Path(log_path).name}")
        self._refresh_recent_logs()
        if not self._is_text_silent_source(fingerprint):
            self.audio_engine.play(fingerprint)

    def _on_csv_import_complete(self, fingerprint: AetherFingerprint, record_id: int, imported: int, log_path: str) -> None:
        """Aktualisiert GUI-Zustand nach erfolgreichem 4D-Voxel-Import."""
        self._set_loading(False)
        self._apply_security_snapshot()
        fingerprint = self._decorate_fingerprint_with_voxels(fingerprint)
        self._register_final_modules(fingerprint, record_id=int(record_id))
        self._refresh_history_cache(preserve_record_id=int(record_id))
        self._set_scene_from_fingerprint(fingerprint)
        self._update_integrity_monitor(fingerprint)
        self._update_semantic_status(fingerprint, source_text=str(getattr(fingerprint, "source_label", "")))
        self.state_var.set(
            f"4D-Voxel-Feld aktiv | Punkte: {len(self.voxel_grid)} | {self.renderer.get_state_description(fingerprint)}"
        )
        self.loading_var.set(
            f"CSV-Import abgeschlossen. Voxels: {imported} | Datensatz-ID: {record_id} | Log: {Path(log_path).name}"
        )
        self._refresh_recent_logs()
        if not self._is_text_silent_source(fingerprint):
            self.audio_engine.play(fingerprint)

    def _on_spectrum_complete(self, spectrum, fingerprint: AetherFingerprint, record_id: int, log_path: str) -> None:
        """Aktualisiert GUI-Zustand nach erfolgreicher Bild-Spektrumanalyse."""
        self._set_loading(False)
        self._apply_security_snapshot()
        fingerprint = self._decorate_fingerprint_with_voxels(fingerprint)
        self._register_final_modules(fingerprint, record_id=int(record_id))
        self._refresh_history_cache()
        self._set_scene_from_fingerprint(fingerprint)
        self._update_integrity_monitor(fingerprint)
        self._update_semantic_status(fingerprint, source_text=str(getattr(fingerprint, "source_label", "")))
        self._update_wavelength_indicator(float(spectrum.dominant_wavelength_nm), tuple(spectrum.dominant_color_rgb))
        self.state_var.set(self.renderer.get_state_description(fingerprint))
        self.loading_var.set(f"Spektrum gespeichert. Datensatz-ID: {record_id} | Log: {Path(log_path).name}")
        self._refresh_recent_logs()
        if not self._is_text_silent_source(fingerprint):
            self.audio_engine.play(fingerprint)

    def _on_analysis_error(self, error_message: str) -> None:
        """Zeigt eine benutzerfreundliche Fehlermeldung ohne Traceback."""
        self._set_loading(False)
        self.loading_var.set("Analyse fehlgeschlagen.")
        messagebox.showerror("Analysefehler", f"Die Analyse konnte nicht abgeschlossen werden:\n{error_message}")

    def _start_theremin(self) -> None:
        """Aktiviert die Echtzeit-Webcam-Analyse und den Theremin-Modus."""
        if not self.session_context.security_allows("allow_analysis", True):
            messagebox.showwarning(
                "Sicherheitsmodus",
                "Die lokale Sicherheitsdiagnose blockiert Theremin derzeit. Im DEV-Modus sollte das nicht mehr auftreten.",
            )
            return
        if self.theremin_engine.is_running:
            self.loading_var.set("Theremin laeuft bereits.")
            return
        self._previous_theremin_anchors = []
        started = self.theremin_engine.start(
            frame_callback=self._enqueue_theremin_frame,
            status_callback=self._enqueue_theremin_status,
            sensitivity_getter=lambda: float(self.sensitivity_var.get()),
            blend_getter=lambda: float(self.harmony_var.get()),
        )
        if started:
            self.theremin_state_var.set("Theremin: aktiv")
            self.theremin_label.configure(fg="#7DE8A7")
        else:
            self.theremin_state_var.set("Theremin: Start fehlgeschlagen")
            self.theremin_label.configure(fg="#FFB347")

    def _stop_theremin(self) -> None:
        """Stoppt den Theremin-Modus inklusive Audio-Stream."""
        if not self.theremin_engine.is_running:
            self.loading_var.set("Theremin ist bereits gestoppt.")
            return
        self.theremin_engine.stop()
        self._previous_theremin_anchors = []
        self.theremin_state_var.set("Theremin: inaktiv")
        self.theremin_label.configure(fg="#8FD6FF")

    def _enqueue_theremin_status(self, message: str) -> None:
        """Leitet Statusmeldungen thread-sicher an die GUI weiter."""
        self.root.after(0, lambda msg=message: self.loading_var.set(msg))

    def _enqueue_theremin_frame(self, frame_state: ThereminFrameState, fingerprint: AetherFingerprint) -> None:
        """Leitet Frame-Updates thread-sicher an die GUI weiter."""
        self.root.after(0, lambda fs=frame_state, fp=fingerprint: self._on_theremin_frame(fs, fp))

    def _on_theremin_frame(self, frame_state: ThereminFrameState, fingerprint: AetherFingerprint) -> None:
        """Aktualisiert GUI, Gitter und Anzeigen fuer einen Theremin-Frame."""
        current_anchors: list[AnchorPoint] = []
        if frame_state.hand_detected:
            current_anchors = [
                AnchorPoint(
                    x=max(0.0, min(1.0, float(frame_state.voxel_x) / 15.0)),
                    y=max(0.0, min(1.0, float(frame_state.voxel_y) / 15.0)),
                    strength=max(0.0, min(1.0, abs(float(frame_state.voxel_delta)) / 12.0)),
                    z=max(0.0, min(1.0, float(frame_state.voxel_z) / 15.0)),
                    tau=float(frame_state.voxel_t),
                    confidence=max(0.0, min(1.0, abs(float(frame_state.voxel_delta)) / 12.0)),
                )
            ]
        theremin_delta_ops = self.observer_engine.encode_delta_ops(
            self._previous_theremin_anchors,
            current_anchors,
            tau=float(frame_state.frame_index),
        )
        theremin_entropy_scores = [max(0.0, min(1.0, float(frame_state.entropy_total) / 8.0)) for _ in current_anchors]
        theremin_benford = self.observer_engine.event_benford_profile(theremin_delta_ops)
        current_anchors, interference_profile = self.observer_engine.apply_interference_to_anchors(
            current_anchors,
            theremin_entropy_scores,
            theremin_benford,
            tau=float(frame_state.frame_index),
        )
        self._previous_theremin_anchors = list(current_anchors)
        self._set_event_benford_metric(dict(interference_profile.get("benford_profile", {}) or {}))
        if frame_state.hand_detected:
            interference_value = float(current_anchors[0].interference) if current_anchors else 0.0
            self.voxel_grid.set_voxel(
                frame_state.voxel_x,
                frame_state.voxel_y,
                frame_state.voxel_z,
                frame_state.voxel_t,
                frame_state.voxel_delta,
                frame_state.voxel_freq,
                frame_state.voxel_amp,
                interference=interference_value,
            )
            if interference_value < -0.05:
                anomaly = (
                    max(0, min(15, int(round(float(frame_state.voxel_x))))),
                    max(0, min(15, int(round(float(frame_state.voxel_y))))),
                )
                if anomaly not in fingerprint.anomaly_coordinates:
                    fingerprint.anomaly_coordinates.append(anomaly)

        prior_cells = self.registry.get_anchor_priors(limit=14)
        live_prior_post = self.bayes_engine.anchor_prior_posterior(prior_cells, current_anchors)
        self.bayes_anchor_var.set(f"Prior-Posterior {live_prior_post * 100.0:.0f}% | theremin")
        confidence_hint = float(current_anchors[0].confidence) if current_anchors else 0.0
        self._set_live_observer_gap(
            entropy_now=float(frame_state.entropy_total),
            coherence=max(0.0, min(1.0, float(frame_state.coherence_score) / 100.0)),
            resonance=max(0.0, min(1.0, float(frame_state.resonance_score) / 100.0)),
            prior_hint=max(float(live_prior_post), confidence_hint),
            delta_ratio=max(0.0, min(1.0, float(frame_state.delta_ratio))),
        )
        fingerprint = self._decorate_fingerprint_with_voxels(fingerprint)
        self._update_scene_fingerprint(fingerprint)
        self._update_integrity_monitor(fingerprint)
        self._update_wavelength_indicator(float(frame_state.dominant_wavelength_nm), tuple(frame_state.dominant_color_rgb))
        if frame_state.recursive_state:
            self.theremin_state_var.set("Theremin: Rekursive Selbstbeobachtung (Goldresonanz)")
            self.theremin_label.configure(fg="#F2C14E")
        elif frame_state.recursion_collapsed:
            self.theremin_state_var.set("Theremin: Rekursion kollabiert durch Beobachter")
            self.theremin_label.configure(fg="#FFB347")
        else:
            self.theremin_state_var.set(f"Theremin aktiv | Bass {frame_state.bass_freq:.1f} Hz | Mitte {frame_state.mid_freq:.0f} Hz | Hoehen {frame_state.high_freq:.0f} Hz")
            self.theremin_label.configure(fg="#7DE8A7")

        profile = self.registry.get_session_entropy_profile(self.session_context.session_id)
        self.state_var.set(
            f"{self.renderer.get_state_description(fingerprint)}\n"
            f"Voxel-Weltlinien: {len(self.voxel_grid)} | Mic {frame_state.mic_peak_freq:.1f} Hz | "
            f"Ethik {frame_state.ethics_score:.1f}\n"
            f"Session-Entropie Mittelwert: {profile['entropy_mean']:.2f} "
            f"(Samples: {profile['samples']}, Anomalierate: {profile['anomaly_rate']:.2%})"
        )

    def _start_speech_input(self) -> None:
        """Startet die Spracherkennung asynchron."""
        if sr is None:
            self.loading_var.set("Spracherkennung nicht verfuegbar. Manuellen Pfad verwenden.")
            return
        if self.speech_thread is not None and self.speech_thread.is_alive():
            self.loading_var.set("Spracherkennung laeuft bereits.")
            return
        self.loading_var.set("Spracherkennung aktiv ...")
        self.speech_thread = threading.Thread(target=self._speech_worker, daemon=True)
        self.speech_thread.start()

    def _speech_worker(self) -> None:
        """Nimmt Sprache auf und wandelt sie in einen Dateipfad um."""
        try:
            recognizer = sr.Recognizer()
            with sr.Microphone() as source:
                recognizer.adjust_for_ambient_noise(source, duration=0.4)
                audio = recognizer.listen(source, timeout=5, phrase_time_limit=7)
            text = recognizer.recognize_google(audio, language="de-DE").strip()
            self.root.after(0, lambda: self._apply_speech_text(text))
        except Exception:
            self.root.after(0, lambda: self.loading_var.set("Spracherkennung momentan nicht verfuegbar."))

    def _apply_speech_text(self, text: str) -> None:
        """Uebernimmt erkannten Text in das Pfadfeld und startet ggf. die Analyse."""
        self.path_var.set(text)
        if Path(text).is_file():
            self._start_analysis(text)
        else:
            self.loading_var.set("Spracheingabe uebernommen. Bitte Dateipfad pruefen.")

    def _refresh_recent_logs(self) -> None:
        """Aktualisiert die Anzeige der letzten zehn Logeintraege."""
        logs = self.log_system.get_recent_logs()
        lines = []
        for item in logs:
            timestamp = str(item.get("timestamp", "-"))
            verdict = str(item.get("verdict", "-"))
            file_hash = str(item.get("file_hash", "-"))[:12]
            symmetry = float(item.get("symmetry_score", 0.0))
            lines.append(f"{timestamp}\nUrteil: {verdict} | Symmetrie: {symmetry:.2f} | Hash: {file_hash}\n")
        if not lines:
            lines = ["Noch keine Log-Eintraege vorhanden.\n"]
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert("1.0", "\n".join(lines))
        self.log_text.configure(state="disabled")

    def _refresh_restore_status(self) -> dict[str, object] | None:
        """Aktualisiert die Anzeige fuer den zuletzt rekonstruierbaren Dateidatensatz."""
        record = self.registry.get_latest_file_record(
            user_id=int(getattr(self.session_context, "user_id", 0) or 0)
        )
        if record is None:
            self._latest_file_record_id = None
            self.restore_status_var.set("Original-Open: kein Dateidatensatz")
            self._apply_raw_storage_mode_label(bool(self.raw_storage_enabled_var.get()))
            return None
        self._latest_file_record_id = int(record["id"])
        source_name = Path(str(record.get("source_label", ""))).name or f"record_{record['id']}.bin"
        storage_status = self.registry.get_raw_storage_status(int(record["id"]))
        mode_label = "RAW+DELTA" if bool(storage_status.get("has_raw_bytes", False)) else "DELTA"
        self.restore_status_var.set(f"Original-Open bereit: {source_name} | ID {record['id']} | {mode_label}")
        return record

    def _refresh_history_cache(self, preserve_record_id: int | None = None) -> None:
        """Aktualisiert die per-User-Historie ueber alle Logins hinweg."""
        if int(getattr(self.session_context, "user_id", 0) or 0) <= 0:
            self.history_entries_cache = []
            self.history_index = -1
            self.history_status_var.set("Historie: kein lokaler Nutzerkontext")
            return
        self.history_entries_cache = self.registry.get_user_fingerprint_history(
            user_id=int(self.session_context.user_id),
            limit=400,
        )
        if not self.history_entries_cache:
            self.history_index = -1
            self.history_status_var.set("Historie: noch keine gespeicherten Analysen")
            return
        target_id = int(preserve_record_id or 0)
        if target_id > 0:
            index = next(
                (
                    idx
                    for idx, item in enumerate(self.history_entries_cache)
                    if int(item.get("id", -1)) == target_id
                ),
                0,
            )
            self.history_index = index
        elif self.history_index < 0 or self.history_index >= len(self.history_entries_cache):
            self.history_index = 0
        self._update_history_status()

    def _update_history_status(self) -> None:
        """Formatiert den sichtbaren Historienstatus."""
        if not self.history_entries_cache or self.history_index < 0:
            self.history_status_var.set("Historie: noch keine gespeicherten Analysen")
            return
        entry = self.history_entries_cache[self.history_index]
        self.history_status_var.set(
            f"Historie {self.history_index + 1}/{len(self.history_entries_cache)} | "
            f"{entry.get('source_type', '')} | {Path(str(entry.get('source_label', ''))).name or entry.get('source_label', '')}"
        )

    def _history_reload_current(self) -> None:
        """Laedt den aktuell ausgewaehlten Historieneintrag erneut in Szene und Monitor."""
        if not self.history_entries_cache or self.history_index < 0:
            messagebox.showwarning("Hinweis", "Es ist noch keine Historie fuer diesen Nutzer vorhanden.")
            return
        entry = self.history_entries_cache[self.history_index]
        fingerprint = self.registry.load_fingerprint(int(entry["id"]))
        if fingerprint is None:
            messagebox.showwarning("Hinweis", "Der Historieneintrag konnte nicht geladen werden.")
            return
        self._set_scene_from_fingerprint(fingerprint)
        self._update_integrity_monitor(fingerprint)
        self._update_semantic_status(fingerprint, source_text=str(entry.get("source_label", "")))
        self.state_var.set(
            f"Historie geladen | {entry.get('source_type', '')} | {self.renderer.get_state_description(fingerprint)}"
        )
        self.loading_var.set(
            f"Historie geladen: ID {entry['id']} | {Path(str(entry.get('source_label', ''))).name or entry.get('source_label', '')}"
        )
        self._update_history_status()

    def _history_prev(self) -> None:
        """Navigiert zu einem aelteren Historieneintrag."""
        if not self.history_entries_cache:
            self._refresh_history_cache()
        if not self.history_entries_cache:
            return
        self.history_index = min(len(self.history_entries_cache) - 1, self.history_index + 1)
        self._history_reload_current()

    def _history_next(self) -> None:
        """Navigiert zu einem neueren Historieneintrag."""
        if not self.history_entries_cache:
            self._refresh_history_cache()
        if not self.history_entries_cache:
            return
        self.history_index = max(0, self.history_index - 1)
        self._history_reload_current()

    def _reconstructed_output_path(self, record: dict[str, object]) -> Path:
        """Leitet einen stabilen Cache-Pfad fuer rekonstruierte Originaldateien ab."""
        source_label = str(record.get("source_label", ""))
        source_name = Path(source_label).name or f"record_{record.get('id', 0)}"
        suffix = Path(source_name).suffix or ".bin"
        stem = Path(source_name).stem or "reconstructed"
        safe_stem = "".join(ch if ch.isalnum() or ch in (" ", "-", "_", ".") else "_" for ch in stem).strip()
        safe_stem = safe_stem or "reconstructed"
        base_dir = Path(os.environ.get("LOCALAPPDATA", str((Path("data") / "open_cache").resolve())))
        target_dir = base_dir / "VeraAetherCore" / "open_cache"
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir / f"{int(record.get('id', 0)):06d}_{str(record.get('file_hash', ''))[:12]}_{safe_stem}{suffix}"

    def _open_reconstructed_original(self) -> None:
        """Rekonstruiert die letzte Datei verlustfrei und oeffnet sie nativ ueber Windows."""
        record = self._refresh_restore_status()
        if record is None:
            messagebox.showwarning("Hinweis", "Es ist noch keine rekonstruierbare Dateianalyse vorhanden.")
            return
        try:
            self._open_resolved_record(record)
        except Exception as exc:
            messagebox.showerror("Rekonstruktion fehlgeschlagen", str(exc))
            return

    def _on_close(self) -> None:
        """Schliesst Ressourcen und beendet die Anwendung."""
        self._language_job_id += 1
        self._stop_scene_animation()
        self.camera_toggle_var.set(False)
        self._toggle_camera_feed()
        if self.conway_job is not None:
            try:
                self.root.after_cancel(self.conway_job)
            except Exception:
                pass
            self.conway_job = None
        if self.browser_poll_job is not None:
            try:
                self.root.after_cancel(self.browser_poll_job)
            except Exception:
                pass
            self.browser_poll_job = None
        if self.browser_flash_job is not None:
            try:
                self.root.after_cancel(self.browser_flash_job)
            except Exception:
                pass
            self.browser_flash_job = None
        if self.browser_host_sync_job is not None:
            try:
                self.root.after_cancel(self.browser_host_sync_job)
            except Exception:
                pass
            self.browser_host_sync_job = None
        if self.chat_sync_job is not None:
            try:
                self.root.after_cancel(self.chat_sync_job)
            except Exception:
                pass
            self.chat_sync_job = None
        try:
            self.registry.close_user_session(self.session_context.session_id)
            self.registry.save_security_event(
                user_id=int(getattr(self.session_context, "user_id", 0) or 0),
                username=str(getattr(self.session_context, "username", "")),
                event_type="logout",
                severity="info",
                payload={"session_id": self.session_context.session_id},
            )
        except Exception:
            pass
        self.browser_engine.stop()
        self.chat_relay_server.stop()
        self.audio_engine.stop_audiovisual_stream()
        self.audio_engine.stop_aether_oscillator()
        if self.theremin_engine.is_running:
            self.theremin_engine.stop()
        try:
            self.registry.close()
        finally:
            if self.current_figure is not None:
                plt.close(self.current_figure)
            if getattr(self, "augment_window", None) is not self.root:
                try:
                    self.augment_window.destroy()
                except Exception:
                    pass
            self.root.destroy()

    def run(self) -> None:
        """Startet die Tkinter-Hauptschleife."""
        self.root.mainloop()
