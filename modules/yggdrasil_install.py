"""Yggdrasil Auto-Download und Setup.

Download nur von offiziellem GitHub Release, SHA256-verifiziert.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict


ROOT = Path(__file__).resolve().parent.parent
BIN_DIR = ROOT / "bin"
DATA_DIR = ROOT / "data"
YGGDRASIL_PID_PATH = DATA_DIR / "yggdrasil.pid"

YGGDRASIL_VERSION = "0.5.8"

YGGDRASIL_RELEASES: Dict[str, Dict[str, str]] = {
    "linux-amd64": {
        "url": "https://github.com/yggdrasil-network/yggdrasil-go/releases/download/v0.5.8/yggdrasil-0.5.8-amd64.deb",
        "sha256": "98c6fbe0f7b69c62c081b37be5c55057654604d5ede5916de74798800f7535a2",
        "binary": "yggdrasil",
    },
    "linux-arm64": {
        "url": "https://github.com/yggdrasil-network/yggdrasil-go/releases/download/v0.5.8/yggdrasil-0.5.8-arm64.deb",
        "sha256": "f1567e9adc585d700b90ed5a9c7cef4b367e3527d9526ead4ca2d323b75e4605",
        "binary": "yggdrasil",
    },
    "windows-amd64": {
        "url": "https://github.com/yggdrasil-network/yggdrasil-go/releases/download/v0.5.8/yggdrasil-0.5.8-x64.msi",
        "sha256": "e91b2e3b0ec0cf2410feeddcb29290a65f5442129f057f34a7df73c6477fc4f1",
        "binary": "yggdrasil.exe",
    },
    "darwin-amd64": {
        "url": "https://github.com/yggdrasil-network/yggdrasil-go/releases/download/v0.5.8/yggdrasil-0.5.8-macos-amd64.pkg",
        "sha256": "1119b983bcf07c1125d6b2947ba36911d4b53944ef8724dfb79543524bafe8aa",
        "binary": "yggdrasil",
    },
    "darwin-arm64": {
        "url": "https://github.com/yggdrasil-network/yggdrasil-go/releases/download/v0.5.8/yggdrasil-0.5.8-macos-arm64.pkg",
        "sha256": "7f5cf3d17280c4a219a102f045b8a87cba1e0f97d6cbc1045304fc37dce56eee",
        "binary": "yggdrasil",
    },
}


def detect_platform() -> str:
    """Gibt den Platform-String zurueck, z.B. windows-amd64."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system.startswith("msys") or system.startswith("cygwin"):
        system = "windows"
    if machine in {"x86_64", "amd64"}:
        arch = "amd64"
    elif machine in {"arm64", "aarch64"}:
        arch = "arm64"
    else:
        arch = machine
    return f"{system}-{arch}"


def yggdrasil_binary_path() -> Path:
    """Gibt den erwarteten Pfad zum lokalen Yggdrasil-Binary zurueck."""
    suffix = ".exe" if platform.system().lower().startswith("win") else ""
    return BIN_DIR / f"yggdrasil{suffix}"


def is_yggdrasil_available() -> bool:

    """True, wenn Yggdrasil lokal oder im PATH verfuegbar ist."""
    local_binary = yggdrasil_binary_path()
    if local_binary.is_file() and os.access(local_binary, os.X_OK):
        return True
    binary_name = "yggdrasil.exe" if platform.system().lower().startswith("win") else "yggdrasil"
    return shutil.which(binary_name) is not None


def is_yggdrasil_managed_running() -> bool:
    """True, wenn ein lokal verwalteter Yggdrasil-Prozess bereits laeuft."""
    if not YGGDRASIL_PID_PATH.is_file():
        return False
    try:
        pid = int(YGGDRASIL_PID_PATH.read_text(encoding="utf-8").strip())
    except Exception:
        YGGDRASIL_PID_PATH.unlink(missing_ok=True)
        return False

    if pid <= 0:
        YGGDRASIL_PID_PATH.unlink(missing_ok=True)
        return False

    try:
        if os.name == "nt":
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                check=False,
            )
            output = result.stdout.strip()
            if not output or "No tasks are running" in output:
                YGGDRASIL_PID_PATH.unlink(missing_ok=True)
                return False
            return True

        os.kill(pid, 0)
        return True
    except OSError:
        YGGDRASIL_PID_PATH.unlink(missing_ok=True)
        return False


def download_and_verify(url: str, expected_sha256: str, dest: Path) -> None:
    """Laedt ein Artefakt herunter und prueft seinen SHA256-Hash."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp_path = dest.with_suffix(dest.suffix + ".tmp")
    if temp_path.exists():
        temp_path.unlink()

    hasher = hashlib.sha256()
    with urllib.request.urlopen(url) as response, temp_path.open("wb") as handle:
        total = int(response.headers.get("Content-Length", "0") or 0)
        downloaded = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            handle.write(chunk)
            hasher.update(chunk)
            downloaded += len(chunk)
            if total > 0:
                print(f"[YGGDRASIL] Download {downloaded}/{total} bytes")
            else:
                print(f"[YGGDRASIL] Download {downloaded} bytes")

    digest = hasher.hexdigest().lower()
    if digest != str(expected_sha256 or "").lower():
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise RuntimeError(f"SHA256 mismatch for {url}: expected {expected_sha256}, got {digest}")

    temp_path.replace(dest)
    if os.name != "nt":
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def install_yggdrasil(dest_dir: str = "bin") -> Path:
    """Erkennt die Plattform, laedt Yggdrasil herunter und versucht es lokal bereitzustellen."""
    platform_key = detect_platform()
    if platform_key not in YGGDRASIL_RELEASES:
        raise RuntimeError(
            f"Platform '{platform_key}' nicht unterstuetzt.\n"
            "Bitte Yggdrasil manuell installieren: https://yggdrasil-network.github.io"
        )

    target_binary = ROOT / dest_dir / YGGDRASIL_RELEASES[platform_key]["binary"]
    if target_binary.is_file():
        return target_binary

    release = YGGDRASIL_RELEASES[platform_key]
    downloads_dir = ROOT / dest_dir / "downloads"
    artifact_name = release["url"].rstrip("/").rsplit("/", 1)[-1]
    artifact_path = downloads_dir / artifact_name
    download_and_verify(release["url"], release["sha256"], artifact_path)

    extracted_binary = _prepare_local_binary(platform_key, artifact_path, target_binary)
    if extracted_binary is None or not extracted_binary.is_file():
        raise RuntimeError(
            "Yggdrasil wurde heruntergeladen, aber das Binary konnte nicht lokal bereitgestellt werden.\n"
            f"Artefakt: {artifact_path}\n"
            "Bitte Yggdrasil manuell installieren und erneut bootstrappen."
        )
    return extracted_binary


def _inject_public_peers(config_path: Path) -> None:
    """Injiziert public Yggdrasil peers in eine frisch generierte Config.

    Peers werden nur gesetzt wenn das Peers-Array noch leer ist.
    Die Liste kann in data/settings.json unter 'yggdrasil_peers' ueberschrieben werden.
    Quelle community-Peers: https://publicpeers.neilalexander.dev/
    Alle Verbindungen sind Yggdrasil-seitig end-to-end verschluesselt.
    """
    import json as _json

    # Benutzerdefinierte Peers aus settings.json lesen
    settings_path = DATA_DIR / "settings.json"
    custom_peers: list[str] = []
    try:
        if settings_path.is_file():
            raw = _json.loads(settings_path.read_text(encoding="utf-8"))
            custom_peers = [str(p) for p in (raw.get("yggdrasil_peers") or []) if p]
    except Exception:
        pass

    # Stabile community peers als Fallback (Stand 2025 â€” bei Bedarf in settings.json ueberschreiben)
    default_peers = [
        "tls://ygg.maru.hk:18395",
        "tls://vpn1.ht4.ca:5122",
        "tls://s1.geo.trnsz.com:655",
    ]
    peers_to_inject = custom_peers if custom_peers else default_peers

    try:
        raw_conf = config_path.read_text(encoding="utf-8")
        conf = _json.loads(raw_conf)
    except Exception:
        return  # Format unbekannt, nicht anfassen

    if not isinstance(conf.get("Peers"), list) or conf["Peers"]:
        return  # Peers schon gesetzt, nicht ueberschreiben

    conf["Peers"] = peers_to_inject
    try:
        config_path.write_text(
            _json.dumps(conf, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"[YGGDRASIL] Public peers injiziert: {peers_to_inject}")
    except Exception as err:
        print(f"[YGGDRASIL] Peer-Injektion fehlgeschlagen: {err}")


def start_yggdrasil_subprocess(config_path: str = "data/yggdrasil.conf") -> None:
    """Startet Yggdrasil als Hintergrundprozess und speichert die PID."""
    if is_yggdrasil_managed_running():
        return
    binary = _resolve_binary_for_execution()
    config = ROOT / config_path
    config.parent.mkdir(parents=True, exist_ok=True)
    if not config.is_file():
        generated = subprocess.run(
            [str(binary), "-genconf"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        config.write_text(generated.stdout, encoding="utf-8")
        _inject_public_peers(config)

    kwargs = {
        "cwd": str(ROOT),
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    process = subprocess.Popen([str(binary), "-useconffile", str(config)], **kwargs)
    YGGDRASIL_PID_PATH.parent.mkdir(parents=True, exist_ok=True)
    YGGDRASIL_PID_PATH.write_text(str(process.pid), encoding="utf-8")


def stop_yggdrasil_subprocess() -> None:
    """Beendet den Yggdrasil-Prozess anhand der gespeicherten PID."""
    if not YGGDRASIL_PID_PATH.is_file():
        return
    try:
        pid = int(YGGDRASIL_PID_PATH.read_text(encoding="utf-8").strip())
    except Exception:
        YGGDRASIL_PID_PATH.unlink(missing_ok=True)
        return

    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False)
    else:
        try:
            os.kill(pid, 15)
        except OSError:
            pass
    YGGDRASIL_PID_PATH.unlink(missing_ok=True)


def _prepare_local_binary(platform_key: str, artifact_path: Path, target_binary: Path) -> Path | None:
    target_binary.parent.mkdir(parents=True, exist_ok=True)
    if platform_key.startswith("linux-"):
        return _extract_from_deb(artifact_path, target_binary)
    if platform_key.startswith("windows-"):
        return _extract_from_msi(artifact_path, target_binary)
    if platform_key.startswith("darwin-"):
        return _extract_from_pkg(artifact_path, target_binary)
    return None


def _extract_from_deb(artifact_path: Path, target_binary: Path) -> Path | None:
    ar_binary = shutil.which("ar")
    if ar_binary is None:
        return None
    with tempfile.TemporaryDirectory(prefix="aether-ygg-deb-") as temp_dir:
        temp_root = Path(temp_dir)
        subprocess.run([ar_binary, "x", str(artifact_path)], cwd=str(temp_root), check=True, capture_output=True)
        data_archive = next(iter(sorted(temp_root.glob("data.tar.*"))), None)
        if data_archive is None:
            return None
        with tarfile.open(data_archive, "r:*") as archive:
            archive.extractall(path=temp_root)
        candidates = sorted(temp_root.glob("**/usr/bin/yggdrasil"))
        if not candidates:
            candidates = sorted(temp_root.glob("**/yggdrasil"))
        if not candidates:
            return None
        shutil.copy2(candidates[0], target_binary)
        target_binary.chmod(target_binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return target_binary


def _extract_from_msi(artifact_path: Path, target_binary: Path) -> Path | None:
    msiexec = shutil.which("msiexec")
    if msiexec is None:
        return None
    with tempfile.TemporaryDirectory(prefix="aether-ygg-msi-") as temp_dir:
        subprocess.run(
            [msiexec, "/a", str(artifact_path), "/qn", f"TARGETDIR={temp_dir}"],
            capture_output=True,
            check=True,
        )
        candidates = sorted(Path(temp_dir).glob("**/yggdrasil.exe"))
        if not candidates:
            return None
        shutil.copy2(candidates[0], target_binary)
        return target_binary


def _extract_from_pkg(artifact_path: Path, target_binary: Path) -> Path | None:
    pkgutil = shutil.which("pkgutil")
    if pkgutil is None:
        return None
    with tempfile.TemporaryDirectory(prefix="aether-ygg-pkg-") as temp_dir:
        expanded = Path(temp_dir) / "expanded"
        subprocess.run([pkgutil, "--expand-full", str(artifact_path), str(expanded)], capture_output=True, check=True)
        candidates = sorted(expanded.glob("**/yggdrasil"))
        for candidate in candidates:
            if candidate.is_file() and not candidate.name.endswith(".plist"):
                shutil.copy2(candidate, target_binary)
                target_binary.chmod(target_binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                return target_binary
    return None


def _resolve_binary_for_execution() -> Path:
    local_binary = yggdrasil_binary_path()
    if local_binary.is_file():
        return local_binary
    path_binary = shutil.which("yggdrasil.exe" if os.name == "nt" else "yggdrasil")
    if path_binary:
        return Path(path_binary)
    raise RuntimeError("Yggdrasil binary not available")
