from modules.preload_optimizer import PreloadOptimizer
from modules.assistant import AssistantEngine
from modules.assistant_interface import AssistantInterface


def test_analyze_and_route_without_browser_engine_runs() -> None:
    interface = AssistantInterface(
        assistant_engine=AssistantEngine(),
        preload_optimizer=PreloadOptimizer(),
        auto_push_ttd=False,
    )
    result = interface.analyze_and_route("strukturtest")
    assert result.assessment is not None
    assert result.ttd_push_status == "disabled"


def test_analyze_and_route_disables_external_context() -> None:
    interface = AssistantInterface(
        assistant_engine=AssistantEngine(),
        preload_optimizer=PreloadOptimizer(),
        auto_push_ttd=False,
    )
    result = interface.analyze_and_route("strukturtest")
    assert result.web_context["ok"] is False
    assert result.web_context["reason"] == "disabled_non_core"


def test_auto_push_default_is_disabled() -> None:
    interface = AssistantInterface(
        assistant_engine=AssistantEngine(),
        preload_optimizer=PreloadOptimizer(),
        auto_push_ttd=False,
    )
    result = interface.analyze_and_route("keine ttd freigabe")
    assert result.ttd_push_status == "disabled"
