"""
AetherPipeline: Zentrale, deterministische, auditierbare Analyse-Kaskade
- Modular: Jede Schicht als Methode
- Auditierbar: Canonical JSON, UTC, append-only Log
- Lokal: Deltas verschlüsselt, Anker öffentlich
- Mathematische Invarianten als Anker
"""
try:
    from modules import aelab_engine as _aelab
    _aelab.initialize("data/aelab_vault")
except Exception:
    _aelab = None
import hashlib
import json
import os
import time
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.analysis_capsule import AnalysisCapsuleEngine
from modules.structure_map_engine import StructureMapEngine

try:
    from modules.ethics_engine import EthicsEngine as _EthicsEngine
    _ethics_engine = _EthicsEngine()
except Exception:
    _ethics_engine = None

try:
    from modules.reconstruction_engine import reconstruction_engine as _reconstruction_engine
except Exception:
    _reconstruction_engine = None

# ---------------------------------------------------------------------------
# Pipeline-Transport Singleton — lazy init, nur für push_algo_token
# ---------------------------------------------------------------------------
_pipeline_transport_singleton = None
_pipeline_transport_lock = None

def _get_pipeline_transport():
    """Lazy-init AethernetTransport für AlgoToken-Push aus der Pipeline."""
    global _pipeline_transport_singleton, _pipeline_transport_lock
    import threading
    if _pipeline_transport_lock is None:
        _pipeline_transport_lock = threading.Lock()
    with _pipeline_transport_lock:
        if _pipeline_transport_singleton is None:
            try:
                import json as _json
                from pathlib import Path as _P
                settings_path = _P("data/settings.json")
                node_id = ""
                if settings_path.exists():
                    _s = _json.loads(settings_path.read_text(encoding="utf-8"))
                    node_id = str(_s.get("node_id", "") or "").strip()
                if not node_id:
                    node_path = _P("data/rust_shell/users.json")
                    if node_path.exists():
                        _u = _json.loads(node_path.read_text(encoding="utf-8"))
                        users = _u if isinstance(_u, list) else [_u]
                        for u in users:
                            if u.get("node_id"):
                                node_id = str(u["node_id"])
                                break
                if node_id:
                    from modules.aethernet_transport import AethernetTransport
                    _pipeline_transport_singleton = AethernetTransport(node_id=node_id)
            except Exception:
                pass
        return _pipeline_transport_singleton


def _assert_rust_shell_trigger() -> None:
    """
    Erzwingt den einheitlichen Triggerpfad: produktive Pipeline-Aufrufe kommen
    ausschliesslich aus der Rust-Shell (AETHER_PIPELINE_TRIGGER=rust_shell).
    """
    trigger = str(os.getenv("AETHER_PIPELINE_TRIGGER", "") or "").strip().lower()
    allow_direct = str(os.getenv("AETHER_ALLOW_DIRECT_PIPELINE", "") or "").strip() == "1"
    if trigger == "rust_shell" or allow_direct or os.getenv("PYTEST_CURRENT_TEST"):
        return
    raise PermissionError(
        "AetherPipeline trigger denied: expected AETHER_PIPELINE_TRIGGER=rust_shell"
    )

class AetherPipeline:
    def learn_structural_patterns(self) -> dict:
        """
        Leitet statistische Baselines aus dem Audit-Log ab und markiert Messungen,
        die ausserhalb typischer Bereiche natuerlicher Signale liegen.
        Keine Inhaltsinterpretation — ausschliesslich Messwertvergleich gegen
        empirische Referenzbereiche (Shannon-Entropie, Noether-Symmetrie, Invariantenstaerke).
        Gibt Statistiken und reine Messbeschreibungen zurueck (keine Labels/Urteile).
        """
        if not self.audit_log:
            return {}
        # Sammle Werte
        entropies = [entry.get("entropy", 0.0) for entry in self.audit_log]
        symmetries = [entry.get("symmetry", 0.0) for entry in self.audit_log]
        periodicities = [entry.get("periodicity", 0.0) for entry in self.audit_log]
        invariant_strengths = [entry.get("invariants", {}).get("invariant_strength", 0.0) for entry in self.audit_log]
        # Statistische Auswertung
        import numpy as np
        def stats(arr):
            arr = np.array(arr)
            return {
                "mean": float(np.mean(arr)),
                "std": float(np.std(arr)),
                "min": float(np.min(arr)),
                "max": float(np.max(arr)),
            } if len(arr) else {}
        patterns = {
            "entropy": stats(entropies),
            "symmetry": stats(symmetries),
            "periodicity": stats(periodicities),
            "invariant_strength": stats(invariant_strengths),
        }
        # Heuristik: Auffällige Bereiche — reine Messbeschreibung, keine inhaltliche Interpretation
        hints = []
        e_mean = patterns["entropy"].get("mean", 0)
        s_mean = patterns["symmetry"].get("mean", 1)
        iv_mean = patterns["invariant_strength"].get("mean", 0)

        if e_mean > 7.5:
            hints.append({
                "metric": "entropy",
                "value": round(e_mean, 4),
                "observation": f"entropy_mean={e_mean:.4f} — exceeds natural-language baseline (typical: 3.5–5.5 bits/byte). "
                               "Near-random byte distribution. Common in compressed, encrypted, or densely packed binary payloads.",
            })
        if s_mean < 0.5:
            hints.append({
                "metric": "symmetry",
                "value": round(s_mean, 4),
                "observation": f"symmetry_mean={s_mean:.4f} — below structural baseline (typical: > 0.75). "
                               "Irregular distributional symmetry. Observed in strongly non-uniform byte sequences "
                               "and in text deviating from natural power-law distributions.",
            })
        if iv_mean > 0.7:
            hints.append({
                "metric": "invariant_strength",
                "value": round(iv_mean, 4),
                "observation": f"invariant_strength_mean={iv_mean:.4f} — above high-structure threshold (typical: < 0.5). "
                               "Strong mathematical invariants detected. Observed in highly regular, "
                               "algorithmically generated, or densely structured data streams.",
            })
        patterns["hints"] = hints
        return patterns

    def compute_invariants(self, data: bytes) -> dict:
        """
        Führt mathematische Invariantenerkennung (Fourier, Benford, Zipf, Mandelbrot) auf den Daten durch.
        Nutzt die Algorithmen aus modules/invariant_detector.py.
        """
        try:
            from modules import invariant_detector
        except ImportError:
            import invariant_detector
        # Beispiel: change_sequence = Byte-Differenzen
        arr = list(data)
        change_sequence = [abs(arr[i] - arr[i-1]) for i in range(1, len(arr))] if len(arr) > 1 else []
        # Anchor-Frequenzen: Hashes als Strings
        anchor_frequencies = {}
        for i in range(0, len(data), 256):
            block = data[i:i+256]
            h = hashlib.sha256(block).hexdigest()
            anchor_frequencies[h] = anchor_frequencies.get(h, 0) + 1
        # File sizes: nur aktuelle Datei
        file_sizes = [len(data)]
        # Mandelbrot: simuliert als Blocktiefe
        tree_depths = [1 for _ in range(len(data) // 256)]
        return invariant_detector.compute_invariant_score(
            change_sequence=change_sequence,
            anchor_frequencies=anchor_frequencies,
            file_sizes=file_sizes,
            tree_depths=tree_depths
        )

    def optimize_pipeline(self):
        """
        Analysiert die Audit-Logs und erkennt, welche Schichten/Pfade redundant oder ineffizient sind.
        Gibt Optimierungsvorschläge zurück (z.B. Schichten überspringen, Pfade verkürzen).
        """
        if not self.audit_log:
            print("[OPTIMIZE] Keine Audit-Daten vorhanden.")
            return []
        stats = {k: 0 for k in [
            "entropy", "h_lambda", "anchors", "symmetry", "xor_delta", "periodicity", "sce", "bayes", "trust"
        ]}
        for entry in self.audit_log:
            for k in stats:
                v = entry.get(k)
                if isinstance(v, (float, int)) and abs(v) > 1e-6:
                    stats[k] += 1
                elif isinstance(v, list) and v:
                    stats[k] += 1
                elif isinstance(v, str) and v.strip():
                    stats[k] += 1
        total = len(self.audit_log)
        redundant = [k for k, v in stats.items() if v < max(2, total // 10)]
        if redundant:
            print(f"[OPTIMIZE] Folgende Schichten sind meist redundant: {redundant}")
        else:
            print("[OPTIMIZE] Keine eindeutig redundanten Schichten gefunden.")
        return redundant
    def __init__(self):
        self.audit_log: List[Dict[str, Any]] = []
        self.capsule_engine = AnalysisCapsuleEngine()
        self.structure_map_engine = StructureMapEngine()

    def _build_performance_route_candidate(self, result: Dict[str, Any], capsule: Any) -> Dict[str, Any]:
        public_metrics = {
            "trust_score": round(float(capsule.metrics.trust_score), 12),
            "noether_consistency": round(float(capsule.metrics.noether_consistency), 12),
            "delta_ratio": round(float(capsule.metrics.delta_ratio), 12),
            "entropy": round(float(capsule.metrics.entropy), 12),
            "symmetry": round(float(capsule.metrics.symmetry), 12),
            "periodicity": round(float(capsule.metrics.periodicity), 12),
            "segment_count": int(capsule.envelope.segment_count),
        }
        route_seed = {
            "sha256": str(result.get("sha256", "") or ""),
            "source_hash": str(capsule.envelope.source_hash),
            "source_scope": str(capsule.envelope.source_scope),
            "public_metrics": public_metrics,
        }
        route_hash = hashlib.sha256(
            json.dumps(route_seed, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return {
            "artifact_class": "performance_route",
            "route_hash": route_hash,
            "source_scope": str(capsule.envelope.source_scope),
            "privacy_class": "public_metric_only",
            "share_channel": "auto_push",
            "user_confirmation_required": False,
            "genesis_override_allowed": True,
            "quorum_required": True,
            "public_metrics": public_metrics,
        }

    def _build_result(self, source_label: str, raw: bytes, capsule: Any) -> Dict[str, Any]:
        structure_map = self.structure_map_engine.build_from_capsule(capsule).to_dict()
        result = {
            "file": str(source_label),
            "size_bytes": int(len(raw)),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "capsule": capsule.to_dict(),
            "structure_map": structure_map,
            "entropy": float(capsule.metrics.entropy),
            "h_lambda": float(capsule.metrics.h_lambda),
            "anchors": [item.get("anchor_hash", "") for item in capsule.shared_anchor_pack.get("anchors", [])],
            "symmetry": float(capsule.metrics.symmetry),
            "xor_delta": str(capsule.local_delta.get("delta_hash", "")),
            "periodicity": float(capsule.metrics.periodicity),
            "sce": dict(capsule.sce),
            "sce_score": float(capsule.metrics.sce_score),
            "invariants": dict(capsule.invariants),
            "bayes": float(capsule.metrics.bayes_confidence),
            "trust": float(capsule.metrics.trust_score),
            "katz_dimension": float(capsule.metrics.katz_dimension),
            "zipf_alpha": float(capsule.metrics.zipf_alpha),
            "benford_score": float(capsule.metrics.benford_score),
            "delta_ratio": float(capsule.metrics.delta_ratio),
            "noether_consistency": float(capsule.metrics.noether_consistency),
            "godel_loop": dict(capsule.godel_loop),
            "anomaly_flags": list(capsule.anomaly_flags),
            "signal_policy": {
                "source_scope": str(capsule.envelope.source_scope),
                "privacy_class": str(capsule.envelope.privacy_class),
                "artifact_class": str(capsule.envelope.artifact_class),
                "segment_scheduler": str(capsule.envelope.segment_scheduler),
                "segment_count": int(capsule.envelope.segment_count),
                "segment_size_bytes": int(capsule.envelope.segment_size_bytes),
                "segment_manifest_hash": str(capsule.envelope.segment_manifest_hash),
            },
        }
        result["performance_route_candidate"] = self._build_performance_route_candidate(result, capsule)
        return result

    def _augment_result(self, result: Dict[str, Any], raw: bytes) -> None:
        result["reconstruction"] = self._build_reconstruction_summary(result)
        # ── Malware / Obfuskationserkennung ─────────────────────────────────
        # Wird deterministisch auf jede Nutzlast angewendet — kein optionaler Pfad.
        obfuscation_hints = self.learn_structural_patterns()
        result["obfuscation_scan"] = {
            "hints": obfuscation_hints.get("hints", []),
            "entropy_stats": obfuscation_hints.get("entropy", {}),
            "symmetry_stats": obfuscation_hints.get("symmetry", {}),
            "invariant_strength_stats": obfuscation_hints.get("invariant_strength", {}),
        }

        # ── Ethics-Engine (strukturelle Integritätsprüfung) ───────────────────
        if _ethics_engine is not None:
            ethics_result = _ethics_engine.assess(
                text=str(result.get("sha256", "")),
                entropy_mean=result.get("entropy"),
            )
            result["ethics"] = {
                "integrity_score": float(ethics_result.score),
                "zipf": float(ethics_result.zipf),
                "benford": float(ethics_result.benford),
                "noether": float(ethics_result.noether),
                "interferenz": float(ethics_result.interferenz),
                "heisenberg": float(ethics_result.heisenberg),
            }
        else:
            result["ethics"] = {"integrity_score": None, "error": "ethics_engine_unavailable"}

        # ── AELab (muss vor Compression laufen — Commit-Gate) ─────────────────
        if _aelab is not None:
            aelab_result = _aelab.analyze(raw)
            result["aelab"] = aelab_result
            # ── Commit-Gate (architektonisch) ───────────────────────────────
            # Vault-Commit nur erlaubt wenn lossless >= 0.95 UND Anker vorhanden.
            # Kein Code-Pfad kann dieses Gate umgehen — es ist kein Feature,
            # es ist die Grundbedingung.
            result["vault_commit_allowed"] = aelab_result.get("commit_allowed", False)
            # ── Cross-Domain Structural Hint ────────────────────────────────
            hints = self._find_cross_domain_hints(result)
            if hints:
                result["cross_domain_hints"] = hints
            # ── AlgoToken (nur wenn Gate bestanden) ─────────────────────────
            if result["vault_commit_allowed"]:
                from modules.algo_share import build_algo_token
                from pathlib import Path as _Path
                domain = str(_Path(result.get("file", "")).suffix.lstrip(".") or "generic")
                token = build_algo_token(aelab_result, domain_hint=domain)
                if token:
                    result["algo_token"] = token.to_dict()
                    # AlgoToken sofort peer-to-peer senden — kein Quorum nötig
                    try:
                        from modules.aethernet_transport import AethernetTransport as _AT
                        _transport = _get_pipeline_transport()
                        if _transport is not None:
                            _transport.push_algo_token(aelab_result, domain_hint=domain)
                    except Exception:
                        pass
        else:
            result["vault_commit_allowed"] = False

        # ── Compression (nach aelab — braucht commit_gate Ergebnis) ──────────
        result["compression"] = self._build_compression_summary(raw, result.get("aelab", {}))

        # ── Pipeline-Metriken ins Gossip-Netz einspeisen ──────────────────────
        # Nur bereits berechnete Werte — keine Vorhersagen, keine Imputationen.
        # ── Pipeline-Metriken ins Gossip-Netz einspeisen + AE-Evolution prüfen ──
        try:
            # capsule.to_dict() → result["capsule"]["metrics"] (nicht result["metrics"])
            cap_metrics = result.get("capsule", {}).get("metrics", {})
            delta_ratio = float(result.get("delta_ratio", cap_metrics.get("delta_ratio", 0.0)) or 0.0)
            h_lambda = float(cap_metrics.get("h_lambda", 0.0) or 0.0)
            shannon_limit = float(cap_metrics.get("shannon_limit_estimate", 8.0) or 8.0)
            # Shannon-Lücke: wie weit h_lambda noch von der theoretischen Grenze entfernt ist
            shannon_gap_pct = round((h_lambda / max(0.001, shannon_limit)) * 100.0, 4)
            anchor_cov = float(result.get("compression", {}).get("coverage_ratio", 0.0) or 0.0)
            trust_score = float(result.get("trust", 0.0) or 0.0)

            from modules.swarm_p2p import set_pipeline_metrics
            set_pipeline_metrics({
                "delta_ratio":     round(delta_ratio, 6),
                "h_lambda":        round(h_lambda, 6),
                "shannon_gap_pct": round(shannon_gap_pct, 4),
                "anchor_coverage": round(anchor_cov, 6),
                "trust_score":     round(trust_score, 6),
            })

            # ── AE-Evolution-Trigger (deterministisch) ────────────────────────
            # bpj_reference = 0.0 für Datei-Analyse (nur live-render hat echte BPJ-Werte)
            # → BPJ-Zweig feuert nicht (bpj_ref > 0.0 Guard greift)
            from modules.ae_evolution_core import should_trigger_ae_evolution
            from modules.swarm_p2p import get_last_network_metrics
            net = get_last_network_metrics()
            net_delta_median = net.get("delta_ratio") if net.get("peer_count", 0) >= 2 else None
            _trig, _reason = should_trigger_ae_evolution(
                delta_ratio=delta_ratio,
                bits_per_joule=0.0,    # file-analysis: kein cpu_joules Tracking
                bpj_reference=0.0,
                network_delta_median=net_delta_median,
            )
            result["ae_evolution_trigger"] = {"trigger": _trig, "reason": _reason}
        except Exception:
            pass

    def _build_compression_summary(self, raw: bytes, aelab_result: dict) -> Dict[str, Any]:
        """
        Echter Anchor-Delta-Split statt zlib.
        Commit nur wenn lossless >= 0.95 UND Anker vorhanden (Gate aus aelab_engine).
        Unter dem Gate: raw bleibt raw, kein falscher Commit.
        """
        from modules.anchor_delta_pack import build_anchor_delta_pack
        from modules.aelab_motor import _DeltaSession
        from modules.unified_cascade import CASCADE_VERSION

        commit_allowed = bool(aelab_result.get("commit_allowed", False))
        lossless = float(aelab_result.get("lossless", 0.0))
        tree_sig = str(aelab_result.get("signature", ""))

        if not commit_allowed:
            # Gate nicht bestanden: Rohdaten bleiben lokal, kein falscher Commit
            return {
                "format": "raw",
                "reason": f"commit_gate_failed (lossless={lossless:.3f}, has_anchor={aelab_result.get('has_anchor', False)})",
                "original_bytes": len(raw),
                "coverage_ratio": 0.0,
                "commit_allowed": False,
            }

        # Gate bestanden: echter Split
        try:
            from modules.reconstruction_engine import LosslessReconstructionEngine
            engine = LosslessReconstructionEngine()
            delta_log = engine.build_delta_log(raw)
            meta = next((e for e in delta_log if e.get("op") == "meta"), {})
            coverage_ratio = float(meta.get("coverage_ratio", 0.0))
        except Exception:
            delta_log = []
            coverage_ratio = 0.0

        # Invarianten-Hash aus Kapsel
        try:
            from modules.analysis_capsule import CapsuleSpec
            invariants_json = json.dumps(
                self.capsule_engine.from_bytes(
                    raw,
                    spec=CapsuleSpec(trigger="compression", source_type="bytes", source_label="compress"),
                ).invariants,
                sort_keys=True, ensure_ascii=True,
            )
            invariant_hash = hashlib.sha256(invariants_json.encode()).hexdigest()
        except Exception:
            invariant_hash = hashlib.sha256(b"unavailable").hexdigest()

        # Session-Key (RAM only) — wrapper: _DeltaSession.encrypt takes list
        session = _DeltaSession()
        anchor_pack, delta_pack = build_anchor_delta_pack(
            raw=raw,
            delta_log=delta_log,
            tree_sig=tree_sig,
            invariant_hash=invariant_hash,
            session_encrypt_fn=lambda b: session.encrypt(list(b)),
            session_id=session.session_id,
            cascade_version=CASCADE_VERSION,
        )

        return {
            "format": "anchor_delta",
            "commit_allowed": True,
            "lossless": round(lossless, 4),
            "original_bytes": len(raw),
            "anchor_count": anchor_pack.anchor_count,
            "coverage_ratio": round(coverage_ratio, 4),
            # Öffentlich: nur Hashes, nie Inhalte
            "public_id": anchor_pack.public_id(),
            "invariant_hash": invariant_hash,
            "tree_signature": tree_sig,
            # Lokal: delta_pack wird nie serialisiert oder geloggt
            "_delta_pack_session_id": session.session_id,
            "delta_hash": delta_pack.delta_hash,
        }

    def _build_reconstruction_summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        anchors = list(result.get("anchors", []) or [])
        reconstruction_input = {
            "entropy": float(result.get("entropy", 0.0)),
            "symmetry": float(result.get("symmetry", 0.0)),
            "sce_score": float(result.get("sce_score", 0.0)),
            "anchor_coverage": min(1.0, len(anchors) / 8.0),
            "trust_score": float(result.get("trust", 0.0)),
            "bayes_posterior": float(result.get("bayes", 0.0)),
            "delta_score": float(1.0 - min(max(result.get("delta_ratio", 0.0), 0.0), 1.0)),
            "periodicity_score": float(result.get("periodicity", 0.0)),
        }
        if _reconstruction_engine is None:
            return {
                "quality_score": 0.0,
                "verified": False,
                "error_count": 1,
                "error_fields": ["reconstruction_engine_unavailable"],
                "path": [
                    "capsule.metrics",
                    "capsule.local_delta",
                    "structure_map.snapshot",
                ],
                "compressibility": round(1.0 - reconstruction_input["entropy"] / 8.0, 4),
                "anchor_coverage": round(reconstruction_input["anchor_coverage"], 4),
            }

        reconstruction = _reconstruction_engine(reconstruction_input)
        error_map = dict(reconstruction.get("error_map", {}) or {})
        return {
            "quality_score": float(reconstruction.get("quality_score", 0.0)),
            "verified": not error_map,
            "error_count": len(error_map),
            "error_fields": sorted(error_map.keys()),
            "path": [
                "capsule.metrics",
                "capsule.local_delta",
                "structure_map.snapshot",
                "aelab.vault_seed" if "aelab" in result else "aelab.unavailable",
            ],
            "compressibility": round(1.0 - reconstruction_input["entropy"] / 8.0, 4),
            "anchor_coverage": round(reconstruction_input["anchor_coverage"], 4),
        }

    def process(self, file_path: Path, session_key: Optional[bytes] = None) -> Dict[str, Any]:
        _assert_rust_shell_trigger()
        raw = file_path.read_bytes()
        capsule = self.capsule_engine.from_file(file_path)
        result = self._build_result(str(file_path), raw, capsule)
        self._augment_result(result, raw)
        # ── Temporal-Metadata-Consent: source_date isoliert extrahieren ──────
        # Läuft NACH _augment_result; kein Einfluss auf Fingerprint/Gossip/Anker.
        # Ergebnis landet NUR im "source_date"-Feld des Pipeline-Outputs —
        # ausschließlich für den Zeitgraph-Tab auswertbar.
        try:
            from modules.analysis_engine import has_temporal_metadata_consent, extract_source_date
            if has_temporal_metadata_consent():
                result["source_date"] = extract_source_date(file_path)
            else:
                result["source_date"] = None
        except Exception:
            result["source_date"] = None
        # Audit-Log
        self.append_audit(result)
        return result

    def process_live_signal(
        self,
        raw: bytes,
        source_label: str = "live_render",
        previous_signal: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        _assert_rust_shell_trigger()
        capsule = self.capsule_engine.from_live_signal(
            raw,
            source_label=source_label,
            previous_signal=previous_signal,
        )
        result = self._build_result(str(source_label), raw, capsule)
        self._augment_result(result, raw)
        self.append_audit(result)
        return result

    def compute_entropy(self, data: bytes) -> float:
        from math import log2
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        total = len(data)
        return -sum((c/total)*log2(c/total) for c in freq if c)

    def compute_h_lambda(self, data: bytes) -> float:
        return float(self._capsule_for(data, "h_lambda").metrics.h_lambda)

    def _capsule_for(self, data: bytes, label: str):
        from modules.analysis_capsule import AnalysisCapsuleEngine, CapsuleSpec
        spec = CapsuleSpec(trigger="direct", source_type="bytes", source_label=label)
        return AnalysisCapsuleEngine().from_bytes(data, spec=spec)

    def compute_symmetry(self, data: bytes) -> float:
        return float(self._capsule_for(data, "symmetry").metrics.symmetry)

    def compute_periodicity(self, data: bytes) -> float:
        return float(self._capsule_for(data, "periodicity").metrics.periodicity)

    def compute_sce(self, data: bytes) -> str:
        import json
        return json.dumps(self._capsule_for(data, "sce").sce, ensure_ascii=False)

    def compute_bayes(self, data: bytes) -> float:
        return float(self._capsule_for(data, "bayes").metrics.bayes_confidence)

    def compute_trust(self, data: bytes) -> float:
        return float(self._capsule_for(data, "trust").metrics.trust_score)

    def _find_cross_domain_hints(self, current: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Sucht in bereits analysierten Einträgen nach strukturellen Parallelen
        zum aktuellen Ergebnis. Rein metrisch — kein semantisches Label, kein Urteil.

        Vergleicht: Entropie-Profil, Fourier/Periodizität, Symmetrie, Benford-Score.
        Gibt nur Hinweise zurück wenn similarity > 0.80 und Domain verschieden.
        """
        if len(self.audit_log) < 2:
            return []

        cur_domain = current.get("file", "unknown")
        cur_entropy = float(current.get("entropy", 0.0))
        cur_symmetry = float(current.get("symmetry", 0.0))
        cur_periodicity = float(current.get("periodicity", 0.0))
        cur_benford = float(current.get("benford_score", 0.0))
        cur_katz = float(current.get("katz_dimension", 0.0))
        cur_zipf = float(current.get("zipf_alpha", 0.0))
        cur_anchor_sig = current.get("aelab", {}).get("signature", "")

        hints = []
        for past in self.audit_log[:-1]:  # nicht mit sich selbst vergleichen
            past_domain = past.get("file", "unknown")
            if past_domain == cur_domain:
                continue

            past_entropy = float(past.get("entropy", 0.0))
            past_symmetry = float(past.get("symmetry", 0.0))
            past_periodicity = float(past.get("periodicity", 0.0))
            past_benford = float(past.get("benford_score", 0.0))
            past_katz = float(past.get("katz_dimension", 0.0))
            past_zipf = float(past.get("zipf_alpha", 0.0))
            past_anchor_sig = past.get("aelab", {}).get("signature", "")

            # Metrischer Vergleich: L1-Distanz normiert auf [0, 1]
            # Alle 6 Metriken aus dem README (Shannon, Zipf, Fourier, Benford, Katz, Symmetrie)
            # Keine proprietären Algorithmen — jede Komponente mathematisch definiert.
            matching_metrics = []
            diffs = []

            e_diff = abs(cur_entropy - past_entropy) / 8.0
            diffs.append(e_diff)
            if e_diff < 0.10:
                matching_metrics.append("entropy")

            s_diff = abs(cur_symmetry - past_symmetry)
            diffs.append(s_diff)
            if s_diff < 0.10:
                matching_metrics.append("symmetry")

            p_diff = abs(cur_periodicity - past_periodicity)
            diffs.append(p_diff)
            if p_diff < 0.10:
                matching_metrics.append("periodicity")

            b_diff = abs(cur_benford - past_benford)
            diffs.append(b_diff)
            if b_diff < 0.10:
                matching_metrics.append("benford")

            # Katz-Dimension: normalisierte fraktale Kurvenlänge — Selbstähnlichkeit
            k_diff = abs(cur_katz - past_katz)
            diffs.append(k_diff)
            if k_diff < 0.10:
                matching_metrics.append("katz_dimension")

            # Zipf-Konformität: Potenzgesetz-Fit f ∝ r^-α — Natürlichkeit
            z_diff = abs(cur_zipf - past_zipf)
            diffs.append(z_diff)
            if z_diff < 0.10:
                matching_metrics.append("zipf")

            similarity = 1.0 - (sum(diffs) / len(diffs))

            if similarity >= 0.80 and matching_metrics:
                hints.append({
                    # Nur Signaturen (SHA-256-Prefix), niemals Rohdaten
                    "anchor_a": hashlib.sha256(cur_anchor_sig.encode()).hexdigest()[:16],
                    "anchor_b": hashlib.sha256(past_anchor_sig.encode()).hexdigest()[:16],
                    "domain_a": cur_domain,
                    "domain_b": past_domain,
                    "structural_similarity": round(similarity, 4),
                    "matching_metrics": matching_metrics,
                    # Konfidenz = Anteil übereinstimmender Metriken (max 6)
                    "confidence": round(len(matching_metrics) / 6.0, 4),
                })

        # Maximal 3 Hints pro Analyse — Signal, kein Rauschen
        return hints[:3]

    def close(self) -> None:
        """
        Ordentlicher Shutdown: Motor-Session zeroizen, RAM-only Keys löschen.
        Muss beim Beenden von Aether aufgerufen werden.
        """
        if _aelab is not None:
            try:
                from modules.aelab_motor import close_motor_session
                close_motor_session()
            except Exception:
                pass

    def append_audit(self, result: Dict[str, Any]):
        self.audit_log.append(result)
        with open("aether_audit_log.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")

# Beispielnutzung
if __name__ == "__main__":
    from modules.session_guard import require_session
    require_session()
    os.environ.setdefault("AETHER_ALLOW_DIRECT_PIPELINE", "1")
    pipeline = AetherPipeline()
    res = pipeline.process(Path("test.bin"))
    print(json.dumps(res, indent=2, ensure_ascii=False))
    pipeline.optimize_pipeline()
    pipeline.close()  # Zeroize RAM-only Keys
