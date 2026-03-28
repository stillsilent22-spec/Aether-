from modules.godel_loop_renderer import GoedelLoopRenderer
from modules.assistant import AssistantEngine


def test_godel_loop_is_deterministic_for_same_input() -> None:
    renderer = GoedelLoopRenderer()
    sample = ".#.\n..#\n###"
    first = renderer.render_with_self_reference(sample, max_depth=3)
    second = renderer.render_with_self_reference(sample, max_depth=3)
    assert first == second
    assert first.get("deterministic") is True


def test_godel_loop_stops_with_message() -> None:
    renderer = GoedelLoopRenderer()
    result = renderer.render_with_self_reference("abcabcabcabc", max_depth=2)
    assert result.get("stop_reached") is True
    assert isinstance(result.get("stop_reason"), str)
    assert "Goedel-Stop erreicht" in str(result.get("stop_message", ""))
    assert len(list(result.get("levels", []))) >= 1


def test_assistant_engine_godel_integration() -> None:
    engine = AssistantEngine(enable_godel_loop=True)
    assessment = engine.detect_asymmetry(
        "Conway glider pattern sample",
        enable_godel_loop=True,
        max_godel_depth=2,
    )
    assert isinstance(assessment.recursive_reflections, list)
    assert len(assessment.recursive_reflections) >= 1
    assert "Goedel" in str(assessment.learned_insight)
