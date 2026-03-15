from types import SimpleNamespace

from modules.shanway_response_builder import ShanwayResponseBuilder


def _assessment(symmetry: float = 0.9, classification: str = "harmonic"):
    return SimpleNamespace(
        noether_symmetry=symmetry,
        classification=classification,
        message="struktur stabil",
    )


def _interface_result(web_context: dict):
    return SimpleNamespace(
        web_context=web_context,
        library_context={"vault_abgleich": "unbekannt", "detail": "Kein Abgleich"},
    )


def test_empty_web_data_sets_keine_datenlage() -> None:
    builder = ShanwayResponseBuilder()
    response = builder.build(_assessment(), _interface_result({"ok": False, "reason": "empty"}), raw_answer="")
    assert response.keine_datenlage is True


def test_low_symmetry_marks_widerspruch() -> None:
    builder = ShanwayResponseBuilder()
    response = builder.build(
        _assessment(),
        _interface_result({"ok": True, "consistency": "low", "source_symmetry": 0.1}),
        raw_answer="roh",
    )
    assert response.quellen_widerspruechlich is True


def test_render_contains_all_fields() -> None:
    builder = ShanwayResponseBuilder()
    response = builder.build(
        _assessment(),
        _interface_result({"ok": True, "consistency": "high", "source_symmetry": 0.8}),
        raw_answer="roh",
    )
    rendered = response.render()
    assert "[1] ERGEBNIS" in rendered
    assert "[6] ENDBEWERTUNG" in rendered
