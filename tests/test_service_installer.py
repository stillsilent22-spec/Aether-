"""
tests/test_service_installer.py -- Unit tests for modules/service_installer.py.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import service_installer as si


# ── dry-run installs ──────────────────────────────────────────────────────── #

def test_install_dry_run_linux(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(si, "_is_linux",    lambda: True)
    monkeypatch.setattr(si, "_is_windows",  lambda: False)
    monkeypatch.setattr(si, "_have_systemd", lambda: True)
    monkeypatch.setattr(si, "_bootstrap_path", lambda: tmp_path / "bootstrap.py")
    (tmp_path / "bootstrap.py").write_text("# stub", encoding="utf-8")

    result = si.install(dry_run=True)

    assert result is True
    out = capsys.readouterr().out
    assert "dry-run" in out.lower() or "would" in out.lower()


def test_install_dry_run_windows(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(si, "_is_linux",   lambda: False)
    monkeypatch.setattr(si, "_is_windows", lambda: True)
    monkeypatch.setattr(si, "_bootstrap_path", lambda: tmp_path / "bootstrap.py")
    (tmp_path / "bootstrap.py").write_text("# stub", encoding="utf-8")

    result = si.install(dry_run=True)

    assert result is True
    out = capsys.readouterr().out
    assert "dry-run" in out.lower() or "would" in out.lower()


def test_uninstall_dry_run_linux(capsys, monkeypatch):
    monkeypatch.setattr(si, "_is_linux",     lambda: True)
    monkeypatch.setattr(si, "_is_windows",   lambda: False)
    monkeypatch.setattr(si, "_have_systemd", lambda: True)

    result = si.uninstall(dry_run=True)

    assert result is True
    out = capsys.readouterr().out
    assert "dry-run" in out.lower() or "would" in out.lower()


def test_uninstall_dry_run_windows(capsys, monkeypatch):
    monkeypatch.setattr(si, "_is_linux",   lambda: False)
    monkeypatch.setattr(si, "_is_windows", lambda: True)

    result = si.uninstall(dry_run=True)

    assert result is True
    out = capsys.readouterr().out
    assert "dry-run" in out.lower() or "would" in out.lower()


# ── status returns expected structure ─────────────────────────────────────── #

def test_status_linux_structure(monkeypatch):
    monkeypatch.setattr(si, "_is_linux",     lambda: True)
    monkeypatch.setattr(si, "_is_windows",   lambda: False)
    monkeypatch.setattr(si, "_have_systemd", lambda: True)
    monkeypatch.setattr(si, "_run", lambda cmd: (1, "inactive"))

    s = si.status()
    assert "backend" in s
    assert "active" in s
    assert "enabled" in s
    assert s["backend"] == "systemd"


def test_status_windows_structure(monkeypatch):
    monkeypatch.setattr(si, "_is_linux",   lambda: False)
    monkeypatch.setattr(si, "_is_windows", lambda: True)
    monkeypatch.setattr(si, "_run", lambda cmd: (0, "STATE : 4 RUNNING"))

    s = si.status()
    assert s["backend"] == "sc.exe"
    assert s["active"] is True


def test_status_unsupported_os(monkeypatch):
    monkeypatch.setattr(si, "_is_linux",   lambda: False)
    monkeypatch.setattr(si, "_is_windows", lambda: False)

    s = si.status()
    assert s["backend"] == "none"
    assert s["active"] is False


# ── missing bootstrap.py aborts install ──────────────────────────────────── #

def test_install_fails_without_bootstrap(tmp_path, monkeypatch):
    monkeypatch.setattr(si, "_bootstrap_path", lambda: tmp_path / "nonexistent.py")
    result = si.install(dry_run=False)
    assert result is False


# ── _run helper ──────────────────────────────────────────────────────────── #

def test_run_returns_tuple():
    rc, out = si._run(["echo", "hello"])
    assert isinstance(rc, int)
    assert isinstance(out, str)


def test_run_missing_command():
    rc, out = si._run(["__nonexistent_command_xyz__"])
    assert rc != 0
