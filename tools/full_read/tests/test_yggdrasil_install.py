from __future__ import annotations

from pathlib import Path

import pytest

from modules import yggdrasil_install as yi


def test_sha256_verification_fails_on_wrong_hash(tmp_path: Path) -> None:
    source = tmp_path / "dummy.bin"
    source.write_bytes(b"aether-yggdrasil-test")
    dest = tmp_path / "copy.bin"
    with pytest.raises(RuntimeError):
        yi.download_and_verify(source.as_uri(), "0" * 64, dest)


def test_platform_detection() -> None:
    detected = yi.detect_platform()
    assert isinstance(detected, str)
    assert "-" in detected


def test_binary_path_platform_specific(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(yi.platform, "system", lambda: "Windows")
    assert yi.yggdrasil_binary_path().name == "yggdrasil.exe"

    monkeypatch.setattr(yi.platform, "system", lambda: "Linux")
    assert yi.yggdrasil_binary_path().name == "yggdrasil"


def test_managed_process_guard_cleans_invalid_pid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pid_path = tmp_path / "yggdrasil.pid"
    pid_path.write_text("999999", encoding="utf-8")
    monkeypatch.setattr(yi, "YGGDRASIL_PID_PATH", pid_path)
    monkeypatch.setattr(yi.os, "name", "nt")

    class Result:
        stdout = "INFO: No tasks are running which match the specified criteria."

    monkeypatch.setattr(yi.subprocess, "run", lambda *args, **kwargs: Result())

    assert yi.is_yggdrasil_managed_running() is False
    assert not pid_path.exists()