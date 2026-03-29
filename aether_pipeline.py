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
import time
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.analysis_capsule import AnalysisCapsuleEngine
from modules.structure_map_engine import StructureMapEngine

try:
    from reconstruction_engine import reconstruction_engine as _reconstruction_engine
except Exception:
    _reconstruction_engine = None

class AetherPipeline:
    def learn_structural_patterns(self) -> dict:
        """
        Lernt typische mathematische Strukturen (z.B. Symmetrie, Entropie, Invarianten) aus dem Audit-Log.
        Erkennt Muster von Malware, Obfuskation, KI-generierten Texten, verschleiertem Code usw.
        Keine Inhaltsanalyse, nur mathematische Regeln/Verteilungen.
        Gibt typische Wertebereiche und Auffälligkeiten zurück.
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
        # Heuristik: Auffällige Bereiche
        hints = []
        if patterns["entropy"].get("mean", 0) > 7.5:
            hints.append("Hohe Entropie: Mögliche Verschlüsselung/Obfuskation/Malware")
        if patterns["symmetry"].get("mean", 1) < 0.5:
            hints.append("Niedrige Symmetrie: Starke Obfuskation oder KI-generierter Text")
        if patterns["invariant_strength"].get("mean", 0) > 0.7:
            hints.append("Starke mathematische Invarianten: KI-generierte oder stark strukturierte Daten")
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

    def _build_result(self, source_label: str, raw: bytes, capsule: Any) -> Dict[str, Any]:
        structure_map = self.structure_map_engine.build_from_capsule(capsule).to_dict()
        return {
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
        }

    def _augment_result(self, result: Dict[str, Any], raw: bytes) -> None:
        result["compression"] = self._build_compression_summary(raw)
        result["reconstruction"] = self._build_reconstruction_summary(result)
        if _aelab is not None:
            result["aelab"] = _aelab.analyze(raw)

    def _build_compression_summary(self, raw: bytes) -> Dict[str, Any]:
        compressed = zlib.compress(raw, level=9)
        original_bytes = int(len(raw))
        compressed_bytes = int(len(compressed))
        ratio = (compressed_bytes / float(original_bytes)) if original_bytes else 1.0
        gain_percent = (1.0 - ratio) * 100.0 if original_bytes else 0.0
        return {
            "format": "zlib_interim",  # TODO: replace with anchor-xor-delta once implemented
            "note": "Aether-Anchor-Delta not yet implemented — zlib used as interim compression",
            "original_bytes": original_bytes,
            "compressed_bytes": compressed_bytes,
            "ratio": round(ratio, 6),
            "gain_percent": round(gain_percent, 4),
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

    def process(self, file_path: Path, session_key: bytes = b"default_session_key") -> Dict[str, Any]:
        raw = file_path.read_bytes()
        capsule = self.capsule_engine.from_file(file_path)
        result = self._build_result(str(file_path), raw, capsule)
        self._augment_result(result, raw)
        # Audit-Log
        self.append_audit(result)
        return result

    def process_live_signal(
        self,
        raw: bytes,
        source_label: str = "live_render",
        previous_signal: Optional[bytes] = None,
    ) -> Dict[str, Any]:
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
        # Platzhalter für Restunsicherheitsberechnung
        return 0.0

    def detect_anchors(self, data: bytes, session_key: bytes = b"default_session_key") -> List[str]:
        """
        Detektiert quasi-Invarianten (z.B. Blöcke mit stabilen Eigenschaften), verschlüsselt sie mit SHA256,
        und gibt die Anker als Puzzle-Teile zurück. Die Anker können mit dem Session-Key entschlüsselt werden.
        """
        block_size = 256
        anchors = []
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            if not block:
                continue
            # Quasi-Invariante: Mittelwert als Beispiel
            invariant = sum(block) / len(block)
            # SHA256-Hash (verschlüsselt)
            anchor_hash = hashlib.sha256(block + session_key).hexdigest()
            anchors.append(anchor_hash)
        return anchors

    def compute_symmetry(self, data: bytes) -> float:
        # Platzhalter für Symmetrie
        return 0.0

    def compute_xor_delta(self, data: bytes, session_key: bytes = b"default_session_key") -> str:
        """
        Berechnet das individuelle Delta (XOR gegen Session-Key, z.B. als individuelles Bild),
        verschlüsselt das Ergebnis mit SHA256 (individuell pro Datei).
        """
        # Erzeuge einen deterministischen Seed aus dem Session-Key
        key = hashlib.sha256(session_key).digest()
        delta = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
        # Verschlüssele das Delta selbst noch einmal mit SHA256
        delta_hash = hashlib.sha256(delta).hexdigest()
        return delta_hash

    def compute_periodicity(self, data: bytes) -> float:
        # Platzhalter für Periodizität
        return 0.0

    def compute_sce(self, data: bytes) -> str:
        # Platzhalter für SCE
        return ""

    def compute_bayes(self, data: bytes) -> float:
        # Platzhalter für Bayes-Posterior
        return 0.0

    def compute_trust(self, result: Dict[str, Any]) -> float:
        # Platzhalter für Trust-Berechnung
        return 0.0

    def append_audit(self, result: Dict[str, Any]):
        self.audit_log.append(result)
        with open("aether_audit_log.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")

# Beispielnutzung
if __name__ == "__main__":
    pipeline = AetherPipeline()
    res = pipeline.process(Path("test.bin"))
    print(json.dumps(res, indent=2, ensure_ascii=False))
    # Pipeline-Optimierungsvorschlag anzeigen
    pipeline.optimize_pipeline()
