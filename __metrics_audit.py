"""Quick metrics audit for analysis pipeline."""
import sys, os
sys.path.insert(0, ".")

from unittest.mock import MagicMock
from modules.analysis_engine import AnalysisEngine

sc = MagicMock()
sc.session_id = "test-session-001"
sc.user_id = 0

ae = AnalysisEngine(session_context=sc)
data = bytes(range(256)) * 16  # deterministic, uniform distribution

fp = ae.analyze_bytes(data, source_label="test", source_type="memory")

print("=== FINGERPRINT CORE METRICS ===")
print(f"  entropy_mean:             {fp.entropy_mean:.6f}")
print(f"  fourier_peaks_count:      {len(fp.fourier_peaks)}")
print(f"  symmetry_score:           {fp.symmetry_score:.6f}")
print(f"  delta_ratio:              {fp.delta_ratio:.6f}")
print(f"  coherence_score:          {fp.coherence_score:.6f}")
print(f"  resonance_score:          {fp.resonance_score:.6f}")
print(f"  ethics_score:             {fp.ethics_score:.6f}")
print(f"  observer_knowledge_ratio: {fp.observer_knowledge_ratio:.6f}")
print(f"  h_lambda:                 {fp.h_lambda:.6f}")
print(f"  e_lambda:                 {fp.e_lambda:.6f}  ({fp.e_lambda_label})")
print(f"  observer_state:           {fp.observer_state}")
print(f"  integrity_state:          {fp.integrity_state}")
print(f"  verdict:                  {fp.verdict}")

print("\n=== SCE SIGNATURE (7D Schoenheitssignatur) ===")
sce = fp.sce_signature or {}
for k, v in sce.items():
    print(f"  {k}: {v}")

print("\n=== NOETHER STABILITY ===")
sp = fp.scan_payload or {}
for k in ("noether_k","delta_k","stability_state","spectral_similarity","entropy_delta_norm","delta_variance_norm","symmetry_preserved"):
    print(f"  {k}: {sp.get(k)}")

print("\n=== RECONSTRUCTION VERIFICATION ===")
pfp = fp.file_profile or {}
for k in ("reconstruction_verified","reconstruction_method","snapshot_divergence","reconstruction_note"):
    print(f"  {k}: {pfp.get(k)}")

print("\nDONE")
