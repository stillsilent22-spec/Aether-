from modules.preload_optimizer import PreloadOptimizer


def test_compute_anchor_weights_are_purely_logarithmic() -> None:
    optimizer = PreloadOptimizer(vault_analysis_path="missing.json")
    weights = optimizer.compute_anchor_weights({"10.000000000000": 10, "1.618030000000": 5, "0.0": 0})
    assert weights["10.000000000000"] == 1.0
    assert weights["1.618030000000"] > 0.0
    assert weights["0.0"] == 0.0


def test_log_scale_coverage_gain_bounds() -> None:
    optimizer = PreloadOptimizer(vault_analysis_path="missing.json")
    assert optimizer.log_scale_coverage_gain(1.0, 10) == 0.0
    assert optimizer.log_scale_coverage_gain(0.0, 0) == 0.0


def test_adaptive_k_factor_grows_monotonically() -> None:
    optimizer = PreloadOptimizer(vault_analysis_path="missing.json")
    low = optimizer.adaptive_k_factor([{"outcome": {"coverage_improved": False}}])
    high = optimizer.adaptive_k_factor(
        [
            {"outcome": {"coverage_improved": True}},
            {"outcome": {"coverage_improved": True}},
            {"outcome": {"coverage_improved": False}},
        ]
    )
    assert high >= low >= 0.15
