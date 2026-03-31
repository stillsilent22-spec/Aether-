from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


def _needs_bootstrap() -> bool:
	settings = Path("data/settings.json")
	if not settings.is_file():
		return True
	try:
		s = json.loads(settings.read_text(encoding="utf-8"))
		return not s.get("solo_genesis_mode", False)
	except Exception:
		return True


if _needs_bootstrap():
	import solo_bootstrap

	solo_bootstrap.run_bootstrap()


ROOT = Path(__file__).resolve().parent
REQUIREMENTS_FILE = ROOT / "requirements.txt"

CORE_IMPORTS = {
	"numpy": "numpy",
	"scipy": "scipy",
	"matplotlib": "matplotlib",
	"sounddevice": "sounddevice",
	"tkinterdnd2": "tkinterdnd2",
	"opencv-python": "cv2",
	"pillow": "PIL",
	"cryptography": "cryptography",
	"fonttools": "fontTools",
	"mss": "mss",
	"pydub": "pydub",
	"moviepy": "moviepy",
	"PyMuPDF": "fitz",
	"psutil": "psutil",
	"speechrecognition": "speech_recognition",
}

OPTIONAL_IMPORTS = {
	"pywebview": "webview",
	"python-magic": "magic",
	"llama-cpp-python": "llama_cpp",
	"winshell": "winshell",
	"pywin32": "win32api",
}


def _load_requirements(path: Path) -> list[str]:
	requirements: list[str] = []
	if not path.exists():
		return requirements
	for raw_line in path.read_text(encoding="utf-8").splitlines():
		line = raw_line.strip()
		if not line or line.startswith("#"):
			continue
		requirements.append(line)
	return requirements


def _is_installed(import_name: str) -> bool:
	return importlib.util.find_spec(import_name) is not None


def _missing_packages(packages: dict[str, str], available: list[str]) -> list[str]:
	missing: list[str] = []
	available_set = set(available)
	for package_name, import_name in packages.items():
		if package_name not in available_set:
			continue
		if not _is_installed(import_name):
			missing.append(package_name)
	return missing


def _run_pip_install(packages: list[str]) -> bool:
	if not packages:
		return True
	command = [sys.executable, "-m", "pip", "install", *packages]
	print("Installiere fehlende Pakete:", ", ".join(packages))
	return subprocess.call(command, cwd=str(ROOT)) == 0


def _optional_packages_for_runtime() -> list[str]:
	optional_packages = ["pywebview", "python-magic", "llama-cpp-python"]
	if sys.platform.startswith("win"):
		optional_packages.extend(["winshell", "pywin32"])
	if sys.platform.startswith("win") and sys.version_info >= (3, 14):
		optional_packages = [name for name in optional_packages if name != "pywebview"]
	return optional_packages


def ensure_dependencies() -> bool:
	available_requirements = _load_requirements(REQUIREMENTS_FILE)
	core_missing = _missing_packages(CORE_IMPORTS, available_requirements)
	if core_missing and not _run_pip_install(core_missing):
		print("\nAbbruch: Pflichtabhaengigkeiten konnten nicht installiert werden.")
		print("Pruefe Python-Version, Compiler-Toolchain und Netzwerkzugriff.")
		return False

	optional_candidates = _optional_packages_for_runtime()
	optional_missing = [
		package_name
		for package_name in optional_candidates
		if not _is_installed(OPTIONAL_IMPORTS[package_name])
	]
	if optional_missing:
		print("\nOptionale Pakete fehlen:", ", ".join(optional_missing))
		if (
			sys.platform.startswith("win")
			and sys.version_info >= (3, 14)
			and "pywebview" not in optional_candidates
		):
			print("pywebview wird auf Windows mit Python 3.14 nicht automatisch installiert.")
			print("Die Anwendung startet trotzdem; nur die Browser-Einbettung bleibt deaktiviert.")
		else:
			success = _run_pip_install(optional_missing)
			if not success:
				print("Optionale Pakete konnten nicht vollstaendig installiert werden.")
				print("Die Anwendung startet trotzdem mit reduzierten Zusatzfunktionen.")

	return True


def main() -> int:
	print("Aether-Start wird vorbereitet...")
	try:
		from modules.capability_score import probe_and_write as _cap_probe
		result = _cap_probe()
		print(f"[START] Aether OS Readiness: {result.get('percent_int', 0)}% — {result.get('stage', '?')}")
	except Exception as exc:
		print(f"[START] Capability-Score konnte nicht ermittelt werden: {exc}")
	try:
		from modules.lan_beacon import start as _beacon_start
		_beacon_start()
		print("[START] LAN-Beacon aktiv.")
	except Exception as exc:
		print(f"[START] LAN-Beacon nicht verfuegbar: {exc}")
	if not ensure_dependencies():
		return 1

	
	try:
		from modules.runtime_core import init_runtime
	except ModuleNotFoundError:
		import sys as _sys, os as _os
		_sys.path.insert(0, _os.path.dirname(__file__))
		from runtime_core import init_runtime
	try:
		from modules.unified_cascade import run_full_pipeline
		print("[START] Pipeline bereit.")
	except Exception as exc:
		print(f"[START] Pipeline konnte nicht geladen werden: {exc}")
		return 1

	print("[START] Aether laeuft. Druecke Ctrl+C zum Beenden.")
	try:
		import time
		while True:
			time.sleep(10)
	except KeyboardInterrupt:
		print("[START] Aether gestoppt.")
	return 0



if __name__ == "__main__":
	raise SystemExit(main())
