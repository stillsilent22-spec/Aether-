from modules.godel_loop_renderer import GoedelLoopRenderer


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
