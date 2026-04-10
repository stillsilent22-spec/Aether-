"""Quick smoke test for blindspot_engine and swarm_p2p hook."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

errors = []

# 1. Import blindspot_engine
try:
    from modules.blindspot_engine import (
        BlindspotEngine, BlindspotSignal, BlindspotHint,
        GAP_MISSING_MODULE, GAP_COMPUTE_LIMIT, GAP_KNOWLEDGE_GAP,
        GAP_BOOTSTRAP_GAP, GAP_PROGRESSION_STEP, GAP_UNSOLVABLE,
    )
    print("[OK] blindspot_engine import")
except Exception as e:
    errors.append(f"[FAIL] blindspot_engine import: {e}")
    print(errors[-1])

# 2. BlindspotEngine singleton
try:
    e = BlindspotEngine.instance()
    print("[OK] BlindspotEngine.instance()")
except Exception as exc:
    errors.append(f"[FAIL] BlindspotEngine.instance(): {exc}")
    print(errors[-1])

# 3. register_gap
try:
    sig = BlindspotEngine.instance().register_gap(
        domain="numpy",
        gap_type=GAP_MISSING_MODULE,
        description="Test: numpy nicht verfügbar",
        priority=8,
    )
    assert sig.domain == "numpy"
    assert sig.gap_type == GAP_MISSING_MODULE
    print(f"[OK] register_gap → {sig.signal_id[:20]}...")
except Exception as exc:
    errors.append(f"[FAIL] register_gap: {exc}")
    print(errors[-1])

# 4. get_signals_for_broadcast
try:
    # Force last_broadcast_ts to 0 so it gets picked up
    e = BlindspotEngine.instance()
    for sig in e._active_gaps.values():
        sig.last_broadcast_ts = 0.0
    signals = e.get_signals_for_broadcast()
    assert isinstance(signals, list)
    print(f"[OK] get_signals_for_broadcast → {len(signals)} signal(s)")
except Exception as exc:
    errors.append(f"[FAIL] get_signals_for_broadcast: {exc}")
    print(errors[-1])

# 5. BlindspotSignal round-trip
try:
    sig = BlindspotSignal(
        signal_id="test-sig-001",
        domain="yggdrasil",
        gap_type=GAP_MISSING_MODULE,
        description="Yggdrasil nicht installiert",
        priority=9,
        created_ts=1000.0,
    )
    d = sig.to_dict()
    sig2 = BlindspotSignal.from_dict(d)
    assert sig2.domain == "yggdrasil"
    assert sig2.priority == 9
    print("[OK] BlindspotSignal round-trip")
except Exception as exc:
    errors.append(f"[FAIL] BlindspotSignal round-trip: {exc}")
    print(errors[-1])

# 6. BlindspotHint round-trip
try:
    hint = BlindspotHint(
        hint_id="hint-001",
        signal_id="test-sig-001",
        from_peer="peer123",
        domain="yggdrasil",
        hint_type="instruction",
        payload_hash="abc",
        instructions="sudo apt install yggdrasil",
        fingerprints=["fp1", "fp2"],
        priority_boost=0.8,
        ts=2000.0,
    )
    d = hint.to_dict()
    hint2 = BlindspotHint.from_dict(d)
    assert hint2.instructions == "sudo apt install yggdrasil"
    assert hint2.priority_boost == 0.8
    print("[OK] BlindspotHint round-trip")
except Exception as exc:
    errors.append(f"[FAIL] BlindspotHint round-trip: {exc}")
    print(errors[-1])

# 7. absorb_peer_gaps
try:
    n = BlindspotEngine.instance().absorb_peer_gaps(
        "peer-x",
        [{"signal_id": "x", "domain": "numpy", "gap_type": GAP_MISSING_MODULE,
          "description": "no numpy", "priority": 7}],
    )
    assert n >= 1
    print(f"[OK] absorb_peer_gaps → {n}")
except Exception as exc:
    errors.append(f"[FAIL] absorb_peer_gaps: {exc}")
    print(errors[-1])

# 8. get_evolutionary_status
try:
    status = BlindspotEngine.instance().get_evolutionary_status()
    assert "evolutionary_maturity" in status
    assert "godel_label" in status
    print(f"[OK] get_evolutionary_status → maturity={status['evolutionary_maturity']}, label={status['godel_label']!r}")
except Exception as exc:
    errors.append(f"[FAIL] get_evolutionary_status: {exc}")
    print(errors[-1])

# 9. swarm_p2p still importable (checks for no syntax errors in hook)
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "swarm_p2p",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules", "swarm_p2p.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    print("[OK] swarm_p2p.py still importable (no syntax errors)")
except Exception as exc:
    errors.append(f"[FAIL] swarm_p2p import: {exc}")
    print(errors[-1])

# Summary
print()
if errors:
    print(f"FAIL: {len(errors)} error(s)")
    sys.exit(1)
else:
    print("ALL TESTS PASSED")
