from modules.aetherguard import AetherGuard, evaluate_aetherguard


def test_aetherguard_is_deterministic() -> None:
    guard = AetherGuard()
    evidence = {
        "metrics": {
            "trust_score": 0.62,
            "entropy": 6.9,
            "periodicity": 0.22,
            "asymmetry": 0.18,
            "reconstruction_ok": True,
        },
        "flags": {
            "eicar_hit": False,
            "policy_hit": False,
            "sensitive_hit": False,
        },
    }
    first = guard.evaluate(evidence).to_payload()
    second = guard.evaluate(evidence).to_payload()
    assert first == second


def test_aetherguard_blocks_eicar() -> None:
    result = evaluate_aetherguard(
        {
            "metrics": {
                "trust_score": 0.95,
                "entropy": 5.0,
                "periodicity": 0.05,
                "asymmetry": 0.02,
                "reconstruction_ok": True,
            },
            "flags": {
                "eicar_hit": True,
            },
        }
    )
    assert result["verdict"] == "block"
    assert result["risk_score"] == 1.0


def test_aetherguard_quarantine_on_high_risk() -> None:
    guard = AetherGuard()
    result = guard.evaluate(
        {
            "metrics": {
                "trust_score": 0.08,
                "entropy": 7.95,
                "periodicity": 0.91,
                "asymmetry": 0.88,
                "reconstruction_ok": False,
            },
            "flags": {
                "policy_hit": True,
                "sensitive_hit": True,
            },
        }
    )
    assert result.verdict in {"quarantine", "block"}
    assert result.risk_score >= 0.75
