"""
tests/test_bootstrap_logic.py -- Unit tests for bootstrap.py boot logic.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Make sure the repo root is importable
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# ── helpers ──────────────────────────────────────────────────────────────── #

def _write_status(tmp_path: Path, mode: str, capability: int) -> Path:
    p = tmp_path / "bootstrap_status.json"
    p.write_text(json.dumps({"mode": mode, "capability": capability}), encoding="utf-8")
    return p


# ── _read_bootstrap_status ────────────────────────────────────────────────── #

def test_read_bootstrap_status_happy(tmp_path):
    import bootstrap as bs
    status_file = _write_status(tmp_path, "full", 1)
    with patch.object(bs, "BOOTSTRAP_STATUS_PATH", status_file):
        result = bs._read_bootstrap_status()
    assert result["mode"] == "full"
    assert result["capability"] == 1


def test_read_bootstrap_status_missing(tmp_path):
    import bootstrap as bs
    missing = tmp_path / "does_not_exist.json"
    with patch.object(bs, "BOOTSTRAP_STATUS_PATH", missing):
        result = bs._read_bootstrap_status()
    assert result["mode"] == "learn"
    assert result["capability"] == 0


def test_read_bootstrap_status_corrupt(tmp_path):
    import bootstrap as bs
    corrupt = tmp_path / "status.json"
    corrupt.write_bytes(b"\x00\xff\xfe")
    with patch.object(bs, "BOOTSTRAP_STATUS_PATH", corrupt):
        result = bs._read_bootstrap_status()
    assert result["mode"] == "learn"


# ── _find_iced_binary ─────────────────────────────────────────────────────── #

def test_find_iced_binary_in_bin(tmp_path):
    import bootstrap as bs
    fake_bin = tmp_path / "bin" / "aether_iced"
    fake_bin.parent.mkdir(parents=True)
    fake_bin.touch()
    with patch.object(bs, "ROOT", tmp_path):
        found = bs._find_iced_binary()
    assert found == str(fake_bin)


def test_find_iced_binary_not_found(tmp_path):
    import bootstrap as bs
    with patch.object(bs, "ROOT", tmp_path):
        with patch.object(bs, "_which", return_value=None):
            found = bs._find_iced_binary()
    assert found is None


# ── _guard_genesis ────────────────────────────────────────────────────────── #

def test_guard_genesis_passes_normal_id():
    import bootstrap as bs
    bs._guard_genesis({"node_id": "abcdef0123456789"})  # must not raise


def test_guard_genesis_halts_on_genesis_id():
    import bootstrap as bs
    with pytest.raises(SystemExit):
        bs._guard_genesis({"node_id": bs.GENESIS_NODE_ID})


# ── main() integration ────────────────────────────────────────────────────── #

def test_main_learn_mode_no_iced(tmp_path, monkeypatch):
    import bootstrap as bs
    status_file = _write_status(tmp_path, "learn", 0)
    monkeypatch.setattr(bs, "BOOTSTRAP_STATUS_PATH", status_file)
    monkeypatch.setattr(bs, "_ensure_node_identity", lambda: {"node_id": "deadbeef12345678"})
    monkeypatch.setattr(bs, "_launch_learn_mode", MagicMock())
    bs.main()
    bs._launch_learn_mode.assert_called_once()


def test_main_full_mode_with_iced(tmp_path, monkeypatch):
    import bootstrap as bs
    status_file = _write_status(tmp_path, "full", 1)
    fake_bin = tmp_path / "aether_iced"
    monkeypatch.setattr(bs, "BOOTSTRAP_STATUS_PATH", status_file)
    monkeypatch.setattr(bs, "_ensure_node_identity", lambda: {"node_id": "deadbeef12345678"})
    monkeypatch.setattr(bs, "_find_iced_binary", lambda: str(fake_bin))
    launched = []
    monkeypatch.setattr(bs, "_launch_full_mode", lambda p: launched.append(p))
    bs.main()
    assert launched == [str(fake_bin)]


def test_main_full_mode_no_iced_falls_back(tmp_path, monkeypatch):
    import bootstrap as bs
    status_file = _write_status(tmp_path, "full", 1)
    monkeypatch.setattr(bs, "BOOTSTRAP_STATUS_PATH", status_file)
    monkeypatch.setattr(bs, "_ensure_node_identity", lambda: {"node_id": "deadbeef12345678"})
    monkeypatch.setattr(bs, "_find_iced_binary", lambda: None)
    monkeypatch.setattr(bs, "_launch_learn_mode", MagicMock())
    bs.main()
    bs._launch_learn_mode.assert_called_once()


def test_main_linux_fallback_mode(tmp_path, monkeypatch):
    import bootstrap as bs
    status_file = _write_status(tmp_path, "linux_fallback", 0)
    monkeypatch.setattr(bs, "BOOTSTRAP_STATUS_PATH", status_file)
    monkeypatch.setattr(bs, "_ensure_node_identity", lambda: {"node_id": "deadbeef12345678"})
    monkeypatch.setattr(bs, "_launch_linux_fallback_mode", MagicMock())
    bs.main()
    bs._launch_linux_fallback_mode.assert_called_once()
