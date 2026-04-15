import json
from pathlib import Path
from typing import Any

import pytest

from modules.prediction_engine import DecisionSignal, PredictionEngine


def reset_engine(tmp_path: Path, monkeypatch: Any) -> PredictionEngine:
    monkeypatch.setattr("modules.prediction_engine.TRANSITIONS_PATH", tmp_path / "chunk_transitions.json")
    monkeypatch.setattr("modules.prediction_engine.PREFETCH_QUEUE_PATH", tmp_path / "prefetch_queue.json")
    PredictionEngine._instance = None
    return PredictionEngine.instance()


def test_predict_next_chunks_basic(monkeypatch: Any, tmp_path: Path) -> None:
    pe = reset_engine(tmp_path, monkeypatch)
    state_fp = "state1" * 8
    decision = DecisionSignal("render_delta", 0, 0, 0, state_fp)
    pe.record_transition(state_fp, decision, "next1" * 8)
    pe.record_transition(state_fp, decision, "next1" * 8)
    pe.record_transition(state_fp, decision, "next2" * 8)

    hints = pe.predict_next_chunks(state_fp, decision, top_n=2)
    assert len(hints) == 2
    assert hints[0][0].startswith("next1")
    assert hints[0][1] > hints[1][1]


def test_context_bias_boosts_local_game_predictions(monkeypatch: Any, tmp_path: Path) -> None:
    pe = reset_engine(tmp_path, monkeypatch)
    state_fp = "state2" * 8
    decision = DecisionSignal("render_delta", 0, 0, 0, state_fp)
    pe.record_transition(state_fp, decision, "nextA" * 8)
    pe.record_transition(state_fp, decision, "nextA" * 8)
    pe.record_transition(state_fp, decision, "nextA" * 8)
    pe.record_transition(state_fp, decision, "nextA" * 8)
    pe.record_transition(state_fp, decision, "nextB" * 8)
    pe.record_transition(state_fp, decision, "nextC" * 8, context_key="game:alpha")
    pe.record_transition(state_fp, decision, "nextC" * 8, context_key="game:alpha")
    pe.record_transition(state_fp, decision, "nextC" * 8, context_key="game:alpha")

    baseline = [fp for fp, _ in pe.predict_next_chunks(state_fp, decision, top_n=3)]
    context_hits = [fp for fp, _ in pe.predict_next_chunks(state_fp, decision, top_n=3, context_key="game:alpha")]
    expected_c = ("nextC" * 8)[:32]
    expected_a = ("nextA" * 8)[:32]

    assert expected_c in context_hits
    assert context_hits[0] == expected_c
    assert baseline[0] == expected_a


def test_predict_next_sequences_returns_probable_paths(monkeypatch: Any, tmp_path: Path) -> None:
    pe = reset_engine(tmp_path, monkeypatch)
    state_fp = "state3" * 8
    decision = DecisionSignal("render_delta", 0, 0, 0, state_fp)
    pe.record_transition(state_fp, decision, "n1" * 16)
    pe.record_transition(state_fp, decision, "n1" * 16)
    pe.record_transition(state_fp, decision, "n2" * 16)
    sequences = pe.predict_next_sequences(state_fp, decision, depth=2, beam=2, top_n=2)

    assert sequences
    assert all(isinstance(item, dict) for item in sequences)
    assert all("sequence" in item and "probability" in item for item in sequences)


def test_schedule_prefetch_writes_queue(monkeypatch: Any, tmp_path: Path) -> None:
    pe = reset_engine(tmp_path, monkeypatch)
    state_fp = "state4" * 8
    decision = DecisionSignal("render_delta", 0, 0, 0, state_fp)
    pe.record_transition(state_fp, decision, "pref" * 16)
    pe.record_transition(state_fp, decision, "pref" * 16)
    pe.record_transition(state_fp, decision, "next" * 16)

    written = pe.schedule_prefetch("game:beta", state_fp, decision, depth=1, beam=2, top_n=2)
    assert written > 0
    queue_path = tmp_path / "prefetch_queue.json"
    assert queue_path.exists()
    with queue_path.open("r", encoding="utf-8") as handle:
        content = json.load(handle)
    assert isinstance(content, list)
    assert content
