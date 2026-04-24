"""
service_installer.py -- Install / uninstall Aether as a system service.

Supported targets:
  Linux   -> systemd  (requires root, writes /etc/systemd/system/aether.service)
  Windows -> SC.EXE   (requires Administrator, registers as Windows Service)

The service's executable chain:
  aether_node_bootstrap[.exe]  ->  bootstrap.py  ->  aether_iced

All service operations require explicit user confirmation; this module never
runs destructive actions automatically.

Public API:
  install(dry_run=False)   -> bool
  uninstall(dry_run=False) -> bool
  status()                 -> dict
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]

_SERVICE_NAME = "aether"
_SERVICE_DISPLAY = "Aether Node"
_SERVICE_DESCRIPTION = "Aether decentralised node daemon"

# Systemd unit template ----------------------------------------------------- #
_SYSTEMD_UNIT = """\
[Unit]
Description={description}
After=network.target

[Service]
Type=simple
WorkingDirectory={workdir}
ExecStart={python} {bootstrap}
Restart=on-failure
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
"""

_SYSTEMD_PATH = Path("/etc/systemd/system/aether.service")


# ── helpers ──────────────────────────────────────────────────────────────── #

def _is_windows() -> bool:
    return platform.system() == "Windows"


def _is_linux() -> bool:
    return platform.system() == "Linux"


def _python_exe() -> str:
    return sys.executable or "python3"


def _bootstrap_path() -> Path:
    return ROOT / "bootstrap.py"


def _run(cmd: list[str], capture: bool = True) -> tuple[int, str]:
    """Run a subprocess and return (returncode, combined output)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=30,
        )
        out = (result.stdout or "") + (result.stderr or "")
        return result.returncode, out.strip()
    except FileNotFoundError:
        return -1, f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except Exception as exc:
        return -1, str(exc)


def _have_systemd() -> bool:
    rc, _ = _run(["systemctl", "--version"])
    return rc == 0


# ── Linux / systemd ──────────────────────────────────────────────────────── #

def _systemd_install(dry_run: bool) -> bool:
    unit = _SYSTEMD_UNIT.format(
        description=_SERVICE_DESCRIPTION,
        workdir=str(ROOT),
        python=_python_exe(),
        bootstrap=str(_bootstrap_path()),
    )
    if dry_run:
        print(f"[dry-run] would write {_SYSTEMD_PATH}:\n{unit}")
        return True
    try:
        _SYSTEMD_PATH.write_text(unit, encoding="utf-8")
    except PermissionError:
        print(
            "service_installer: cannot write systemd unit — run as root",
            file=sys.stderr,
        )
        return False
    for cmd in [
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", _SERVICE_NAME],
        ["systemctl", "start",  _SERVICE_NAME],
    ]:
        rc, out = _run(cmd)
        if rc != 0:
            print(f"service_installer: {cmd} failed: {out}", file=sys.stderr)
            return False
    print(f"service_installer: systemd service '{_SERVICE_NAME}' installed and started")
    return True


def _systemd_uninstall(dry_run: bool) -> bool:
    if dry_run:
        print(f"[dry-run] would remove {_SYSTEMD_PATH} and disable the unit")
        return True
    _run(["systemctl", "stop",    _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    try:
        if _SYSTEMD_PATH.exists():
            _SYSTEMD_PATH.unlink()
    except PermissionError:
        print(
            "service_installer: cannot remove systemd unit — run as root",
            file=sys.stderr,
        )
        return False
    _run(["systemctl", "daemon-reload"])
    print(f"service_installer: systemd service '{_SERVICE_NAME}' removed")
    return True


def _systemd_status() -> dict:
    rc, out = _run(["systemctl", "is-active", _SERVICE_NAME])
    active = rc == 0
    _, enabled_out = _run(["systemctl", "is-enabled", _SERVICE_NAME])
    return {
        "backend": "systemd",
        "active": active,
        "enabled": enabled_out.strip() == "enabled",
        "raw": out,
    }


# ── Windows / SC ─────────────────────────────────────────────────────────── #

def _sc_install(dry_run: bool) -> bool:
    python = _python_exe()
    bootstrap = str(_bootstrap_path())
    bin_path = f'"{python}" "{bootstrap}"'
    cmd = [
        "sc", "create", _SERVICE_NAME,
        "binPath=", bin_path,
        "DisplayName=", _SERVICE_DISPLAY,
        "start=", "auto",
    ]
    if dry_run:
        print(f"[dry-run] would run: {' '.join(cmd)}")
        return True
    rc, out = _run(cmd)
    if rc != 0:
        print(f"service_installer: sc create failed: {out}", file=sys.stderr)
        return False
    desc_cmd = ["sc", "description", _SERVICE_NAME, _SERVICE_DESCRIPTION]
    _run(desc_cmd)
    rc2, out2 = _run(["sc", "start", _SERVICE_NAME])
    if rc2 != 0:
        print(f"service_installer: sc start failed: {out2}", file=sys.stderr)
    print(f"service_installer: Windows service '{_SERVICE_NAME}' installed")
    return True


def _sc_uninstall(dry_run: bool) -> bool:
    if dry_run:
        print(f"[dry-run] would run: sc delete {_SERVICE_NAME}")
        return True
    _run(["sc", "stop", _SERVICE_NAME])
    rc, out = _run(["sc", "delete", _SERVICE_NAME])
    if rc != 0:
        print(f"service_installer: sc delete failed: {out}", file=sys.stderr)
        return False
    print(f"service_installer: Windows service '{_SERVICE_NAME}' removed")
    return True


def _sc_status() -> dict:
    rc, out = _run(["sc", "query", _SERVICE_NAME])
    active = "RUNNING" in out
    return {
        "backend": "sc.exe",
        "active": active,
        "enabled": rc == 0,
        "raw": out,
    }


# ── Public API ───────────────────────────────────────────────────────────── #

def install(dry_run: bool = False) -> bool:
    """Install the Aether service. Returns True on success."""
    if not _bootstrap_path().exists():
        print(
            "service_installer: bootstrap.py not found — run from repo root",
            file=sys.stderr,
        )
        return False
    if _is_linux() and _have_systemd():
        return _systemd_install(dry_run)
    if _is_windows():
        return _sc_install(dry_run)
    print(
        "service_installer: unsupported OS or no systemd — manual setup required",
        file=sys.stderr,
    )
    return False


def uninstall(dry_run: bool = False) -> bool:
    """Uninstall the Aether service. Returns True on success."""
    if _is_linux() and _have_systemd():
        return _systemd_uninstall(dry_run)
    if _is_windows():
        return _sc_uninstall(dry_run)
    print("service_installer: unsupported OS", file=sys.stderr)
    return False


def status() -> dict:
    """Return a dict describing the current service state."""
    if _is_linux() and _have_systemd():
        return _systemd_status()
    if _is_windows():
        return _sc_status()
    return {"backend": "none", "active": False, "enabled": False, "raw": ""}


# ── CLI ──────────────────────────────────────────────────────────────────── #

def _cli() -> None:
    import argparse
    p = argparse.ArgumentParser(description="Aether service installer")
    p.add_argument("action", choices=["install", "uninstall", "status"])
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    if args.action == "install":
        ok = install(dry_run=args.dry_run)
        sys.exit(0 if ok else 1)
    elif args.action == "uninstall":
        ok = uninstall(dry_run=args.dry_run)
        sys.exit(0 if ok else 1)
    else:
        import json
        print(json.dumps(status(), indent=2))


if __name__ == "__main__":
    _cli()
