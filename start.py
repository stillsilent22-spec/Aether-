from __future__ import annotations

import importlib.util
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

import os

ROOT = Path(__file__).resolve().parent

_IS_ANDROID = (
    os.environ.get("AETHER_PLATFORM") == "android"
    or os.path.exists("/data/data/com.termux")
    or os.path.exists("/system/build.prop")
)

# Default: kein Git-Pull/Push fuer Swarm-Runtime, ausser explizit aktiviert.
os.environ.setdefault("AETHER_SWARM_GIT_SYNC", "0")


def _needs_bootstrap() -> bool:
	node_json = Path("data/swarm/node.json")
	private_key = Path("data/keys/node_private.key")
	return not (node_json.is_file() and private_key.is_file())


def _derive_local_yggdrasil_addr() -> str:
	node_private_key = ROOT / "data" / "keys" / "node_private.key"
	if not node_private_key.is_file():
		return ""
	try:
		from modules.key_derivation import AetherKeyTree, master_key_from_private_pem
		from modules.yggdrasil_addr import derive_yggdrasil_address

		node_pem = node_private_key.read_bytes()
		master = master_key_from_private_pem(node_pem)
		tree = AetherKeyTree(master)
		try:
			return derive_yggdrasil_address(tree.yggdrasil_key)
		finally:
			tree.zeroize()
	except Exception:
		return ""


def _sync_local_identity_materials() -> None:
	node_json_path = ROOT / "data" / "swarm" / "node.json"
	if not node_json_path.is_file():
		return
	try:
		payload = json.loads(node_json_path.read_text(encoding="utf-8"))
		if not isinstance(payload, dict):
			return
	except Exception:
		return

	node_id = str(payload.get("node_id", "") or "").strip()
	if not node_id:
		return

	device_fingerprint = ""
	try:
		from modules.device_lock import get_local_fingerprint, initialize_binding

		initialize_binding(node_id)
		device_fingerprint = str(get_local_fingerprint() or "")
	except Exception as exc:
		raise RuntimeError(f"Hardware-Bindung fuer Node '{node_id}' konnte nicht initialisiert werden: {exc}") from exc

	yggdrasil_addr = _derive_local_yggdrasil_addr()
	changed = False
	if device_fingerprint and str(payload.get("device_fingerprint", "") or "") != device_fingerprint:
		payload["device_fingerprint"] = device_fingerprint
		changed = True
	if yggdrasil_addr and str(payload.get("yggdrasil_addr", "") or "") != yggdrasil_addr:
		payload["yggdrasil_addr"] = yggdrasil_addr
		changed = True
	if not changed:
		return

	serialized = json.dumps(payload, indent=2, ensure_ascii=False)
	node_json_path.write_text(serialized, encoding="utf-8")
	local_node_copy = ROOT / "data" / "swarm" / "nodes" / f"{node_id}.json"
	local_node_copy.parent.mkdir(parents=True, exist_ok=True)
	local_node_copy.write_text(serialized, encoding="utf-8")


if _needs_bootstrap():
	import solo_bootstrap

	solo_bootstrap.run_bootstrap()

_sync_local_identity_materials()
STARTUP_ROUTE_PATH = ROOT / "data" / "interbus" / "startup_route.json"
FULL_REQUIREMENTS_FILE = ROOT / "requirements.txt"
LEGACY_REQUIREMENTS_FILE = ROOT / "requirements_legacy.txt"
ANDROID_REQUIREMENTS_FILE = ROOT / "requirements_android.txt"


def _read_json(path: Path, default: Optional[Dict] = None) -> Dict:
	if default is None:
		default = {}
	try:
		if not path.is_file():
			return dict(default)
		payload = json.loads(path.read_text(encoding="utf-8"))
		return payload if isinstance(payload, dict) else dict(default)
	except Exception:
		return dict(default)


def _write_json(path: Path, payload: Dict) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _startup_route() -> Dict:
	system = platform.system().strip().lower()
	release = platform.release().strip().lower()
	version = platform.version().strip().lower()
	architecture = platform.architecture()[0].strip().lower()
	python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
	forced_runtime = os.environ.get("AETHER_FORCE_RUNTIME", "").strip().lower()
	route = {
		"platform": system or "unknown",
		"release": release,
		"version": version,
		"architecture": architecture,
		"python": python_version,
		"mode": "full",
		"reason": "default_full_runtime",
		"requirements_profile": "full",
		"recommended_entrypoint": "start.py",
	}
	if _IS_ANDROID:
		route["mode"] = "android"
		route["reason"] = "android_managed_elsewhere"
		route["requirements_profile"] = "android"
		return route
	if forced_runtime in {"headless", "legacy"}:
		route["mode"] = "headless"
		route["reason"] = "forced_legacy_runtime"
		route["requirements_profile"] = "legacy"
		route["recommended_entrypoint"] = "daemon_headless.py"
		return route
	if forced_runtime in {"ultra-legacy", "ultra_legacy"}:
		route["mode"] = "ultra_legacy"
		route["reason"] = "forced_ultra_legacy_runtime"
		route["requirements_profile"] = "ultra_legacy"
		route["recommended_entrypoint"] = "legacy_bootstrap.py"
		return route
	if sys.version_info < (3, 6):
		route["mode"] = "ultra_legacy"
		route["reason"] = "python_too_old_for_headless"
		route["requirements_profile"] = "ultra_legacy"
		route["recommended_entrypoint"] = "legacy_bootstrap.py"
		return route
	if system.startswith("win"):
		if release in {"95", "98", "me"} or version.startswith("4."):
			route["mode"] = "ultra_legacy"
			route["reason"] = "win9x_ultra_legacy_bootstrap"
			route["requirements_profile"] = "ultra_legacy"
			route["recommended_entrypoint"] = "legacy_bootstrap.py"
		elif release == "2000":
			route["mode"] = "headless"
			route["reason"] = "win2000_forced_headless"
			route["requirements_profile"] = "legacy"
			route["recommended_entrypoint"] = "daemon_headless.py"
		elif release in {"xp", "2003", "2003server"}:
			route["mode"] = "headless"
			route["reason"] = "winxp_forced_headless"
			route["requirements_profile"] = "legacy"
			route["recommended_entrypoint"] = "daemon_headless.py"
		elif release in {"vista", "7"} and architecture == "32bit":
			route["mode"] = "headless"
			route["reason"] = "winvista7_32bit_headless"
			route["requirements_profile"] = "legacy"
			route["recommended_entrypoint"] = "daemon_headless.py"
	return route


def _write_startup_route(route: Dict) -> None:
	try:
		payload = dict(route)
		payload["timestamp"] = str(_read_json(STARTUP_ROUTE_PATH, {}).get("timestamp", "") or "")
		if not payload["timestamp"]:
			from time import gmtime, strftime
			payload["timestamp"] = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
		_write_json(STARTUP_ROUTE_PATH, payload)
	except Exception:
		pass


def _route_with_override(route: Dict, mode: str, reason: str, requirements_profile: str, entrypoint: str) -> Dict:
	updated = dict(route)
	updated["mode"] = mode
	updated["reason"] = reason
	updated["requirements_profile"] = requirements_profile
	updated["recommended_entrypoint"] = entrypoint
	return updated


def _run_headless_daemon(reason: str, route: Optional[Dict] = None) -> int:
	print(f"[START] Fair-Fallback aktiv: {reason}. Starte daemon_headless fuer lokalen/alten PC-Modus.")
	if route is not None:
		_write_startup_route(route)
		if str(route.get("requirements_profile", "") or "") == "legacy":
			ensure_dependencies(profile="legacy", strict=False, install_optional=False)
	try:
		import daemon_headless
		daemon_headless.main()
		return 0
	except KeyboardInterrupt:
		print("[START] Headless-Daemon gestoppt.")
		return 0
	except Exception as exc:
		print(f"[START] Headless-Daemon konnte nicht gestartet werden: {exc}")
		return 1


def _run_ultra_legacy_bootstrap(reason: str, route: Optional[Dict] = None) -> int:
	print(f"[START] Ultra-Legacy-Pfad aktiv: {reason}. Starte minimalen Bootstrap fuer sehr alte Systeme.")
	if route is not None:
		_write_startup_route(route)
	try:
		import legacy_bootstrap
		legacy_bootstrap.main()
		return 0
	except KeyboardInterrupt:
		print("[START] Ultra-Legacy-Bootstrap gestoppt.")
		return 0
	except Exception as exc:
		print(f"[START] Ultra-Legacy-Bootstrap konnte nicht gestartet werden: {exc}")
		return 1


def _load_bound_user_record() -> Optional[Dict]:
	from modules.identity_claim import load_sole_user_record

	return load_sole_user_record(ROOT)


def _sync_local_identity_metadata() -> None:
	from modules.identity_claim import (
		IDENTITY_LOCK_MODE,
		admin_publisher_id,
		compute_identity_lock,
		infer_native_ygg_capable,
		load_trusted_publishers,
		public_key_b64_from_pem,
	)

	node_path = ROOT / "data" / "swarm" / "node.json"
	if not node_path.is_file():
		return

	node_payload = _read_json(node_path, {})
	node_id = str(node_payload.get("node_id", "") or "").strip()
	public_key_pem = str(node_payload.get("public_key_pem", "") or "").strip()
	role = str(node_payload.get("role", "peer") or "peer").strip().lower() or "peer"
	if not node_id or not public_key_pem:
		return

	public_key_b64 = public_key_b64_from_pem(public_key_pem)
	bound_user = _load_bound_user_record() or {}
	bound_username = str(node_payload.get("account_username", "") or "").strip() or str(bound_user.get("username", "") or "").strip()
	yggdrasil_addr = str(node_payload.get("yggdrasil_addr", "") or "").strip()
	route = _read_json(STARTUP_ROUTE_PATH, _startup_route())
	hw_capability = _read_json(ROOT / "data" / "interbus" / "hw_capability.json", {})
	native_ygg_bound = infer_native_ygg_capable(route, hw_capability, role, yggdrasil_addr)

	settings_path = ROOT / "data" / "settings.json"
	settings = _read_json(settings_path, {})
	settings["node_id"] = node_id
	settings.setdefault("bootstrap_version", 1)
	settings.setdefault("created_at", str(node_payload.get("registered_at", "") or ""))
	settings["node_role"] = role
	if bound_username:
		settings["account_username"] = bound_username
	settings["native_ygg_bound"] = native_ygg_bound
	settings.pop("account_identity_lock", None)
	settings.pop("identity_lock_mode", None)
	if role == "genesis":
		settings["solo_genesis_mode"] = True
		settings["genesis_node_id"] = node_id
	else:
		settings.setdefault("solo_genesis_mode", False)

	trusted = load_trusted_publishers(ROOT)
	trusted_admin_publisher_id = admin_publisher_id(trusted)
	account_identity_lock = compute_identity_lock(
		bound_username,
		node_id,
		public_key_b64,
		str(node_payload.get("device_fingerprint", "") or "").strip(),
		yggdrasil_addr,
		native_ygg_bound,
	)
	if account_identity_lock:
		settings["account_identity_lock"] = account_identity_lock
		settings["identity_lock_mode"] = IDENTITY_LOCK_MODE
	if role == "genesis" and bound_username:
		settings["creator_locked_username"] = trusted_admin_publisher_id

	trusted_path = ROOT / "data" / "trusted_publishers.json"
	publishers = trusted.get("publishers", {})
	if not isinstance(publishers, dict):
		publishers = {}
	trusted["publishers"] = publishers

	if role == "genesis":
		admin_publisher_id = str(
			trusted.get("admin_publisher_id", "") or bound_username or "tryharder997"
		).strip() or "tryharder997"
		old_admin_key = ""
		if isinstance(publishers.get(admin_publisher_id), dict):
			old_admin_key = str(publishers[admin_publisher_id].get("public_key", "") or "").strip()
		trusted["schema"] = str(trusted.get("schema", "") or "aether.trusted_publishers.v1")
		trusted["admin_publisher_id"] = admin_publisher_id
		entry = publishers.get(admin_publisher_id, {})
		if not isinstance(entry, dict):
			entry = {}
		entry.update(
			{
				"enabled": True,
				"signature_scheme": "ed25519",
				"public_key": public_key_b64,
				"node_id": node_id,
				"role": "genesis",
			}
		)
		entry.setdefault("notes", "Admin / Genesis Node.")
		publishers[admin_publisher_id] = entry

		default_publisher_id = str(trusted.get("default_publisher_id", "") or "").strip()
		if default_publisher_id:
			default_entry = publishers.get(default_publisher_id, {})
			if not isinstance(default_entry, dict):
				default_entry = {}
			default_key = str(default_entry.get("public_key", "") or "").strip()
			if not default_key or (old_admin_key and default_key == old_admin_key):
				default_entry.setdefault("enabled", True)
				default_entry.setdefault("signature_scheme", "ed25519")
				default_entry["public_key"] = public_key_b64
				default_entry.setdefault("notes", "Offizieller GitHub-Mirror-Publisher.")
				publishers[default_publisher_id] = default_entry

		_write_json(trusted_path, trusted)

	try:
		from modules.device_lock import initialize_binding, peer_account_allowed

		device_fingerprint = initialize_binding(node_id)
		if device_fingerprint:
			node_payload["device_fingerprint"] = device_fingerprint
			account_identity_lock = compute_identity_lock(
				bound_username,
				node_id,
				public_key_b64,
				device_fingerprint,
				yggdrasil_addr,
				native_ygg_bound,
			)
			if bound_username:
				peer_account_allowed(
					node_id,
					device_fingerprint,
					account_username=bound_username,
					yggdrasil_addr=yggdrasil_addr,
					identity_lock=account_identity_lock,
				)
	except Exception as exc:
		print(f"[START] Device-Bindung konnte nicht initialisiert werden: {exc}")

	node_payload["node_id"] = node_id
	node_payload["public_key_pem"] = public_key_pem
	if bound_username:
		node_payload["account_username"] = bound_username
	node_payload["native_ygg_bound"] = native_ygg_bound
	settings["native_ygg_bound"] = native_ygg_bound
	if account_identity_lock:
		node_payload["account_identity_lock"] = account_identity_lock
		node_payload["identity_lock_mode"] = IDENTITY_LOCK_MODE
		settings["account_identity_lock"] = account_identity_lock
		settings["identity_lock_mode"] = IDENTITY_LOCK_MODE
	else:
		node_payload.pop("account_identity_lock", None)
		node_payload.pop("identity_lock_mode", None)
		settings.pop("account_identity_lock", None)
		settings.pop("identity_lock_mode", None)
	if role == "genesis" and bound_username:
		node_payload["creator_locked_username"] = trusted_admin_publisher_id
		settings["creator_locked_username"] = trusted_admin_publisher_id
	_write_json(settings_path, settings)
	_write_json(node_path, node_payload)
	_write_json(ROOT / "data" / "swarm" / "nodes" / f"{node_id}.json", node_payload)

	if bound_user and bound_username and str(bound_user.get("username", "") or "").strip().lower() == bound_username.lower():
		users_path = ROOT / "data" / "rust_shell" / "users.json"
		users_payload = _read_json(users_path, {"users": []})
		users = users_payload.get("users", [])
		if isinstance(users, list) and len(users) == 1 and isinstance(users[0], dict):
			user_entry = users[0]
			user_entry["node_id"] = node_id
			user_entry["public_key_b64"] = public_key_b64
			user_entry["yggdrasil_addr"] = yggdrasil_addr
			user_entry["device_fingerprint"] = str(node_payload.get("device_fingerprint", "") or "").strip()
			user_entry["native_ygg_bound"] = native_ygg_bound
			user_entry["genesis_bound"] = role == "genesis" and bound_username.lower() == trusted_admin_publisher_id.lower()
			if account_identity_lock:
				user_entry["identity_lock"] = account_identity_lock
			else:
				user_entry.pop("identity_lock", None)
			user_settings = user_entry.get("user_settings", {})
			if not isinstance(user_settings, dict):
				user_settings = {}
			user_settings["bound_node_id"] = node_id
			if str(node_payload.get("device_fingerprint", "") or "").strip():
				user_settings["bound_device_fingerprint"] = str(node_payload.get("device_fingerprint", "") or "").strip()
			if yggdrasil_addr:
				user_settings["bound_yggdrasil_addr"] = yggdrasil_addr
			if account_identity_lock:
				user_settings["bound_identity_lock"] = account_identity_lock
				user_settings["identity_lock_mode"] = IDENTITY_LOCK_MODE
			user_settings["native_ygg_bound"] = "true" if native_ygg_bound else "false"
			user_entry["user_settings"] = user_settings
			users_payload["users"] = users
			_write_json(users_path, users_payload)

ANDROID_CORE_IMPORTS = {
	"numpy": "numpy",
	"cryptography": "cryptography",
	"psutil": "psutil",
}

FULL_CORE_IMPORTS = {
	"numpy": "numpy",
	"scipy": "scipy",
	"matplotlib": "matplotlib",
	"sounddevice": "sounddevice",
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

LEGACY_CORE_IMPORTS = {
	"psutil": "psutil",
}

OPTIONAL_IMPORTS = {
	"pywebview": "webview",
	"python-magic": "magic",
	"llama-cpp-python": "llama_cpp",
	"winshell": "winshell",
	"pywin32": "win32api",
}


def _requirements_path(profile: str) -> Path:
	if profile == "android":
		return ANDROID_REQUIREMENTS_FILE
	if profile == "legacy":
		return LEGACY_REQUIREMENTS_FILE
	return FULL_REQUIREMENTS_FILE


def _core_imports(profile: str) -> Dict[str, str]:
	if profile == "android":
		return dict(ANDROID_CORE_IMPORTS)
	if profile == "legacy":
		return dict(LEGACY_CORE_IMPORTS)
	return dict(FULL_CORE_IMPORTS)


def _load_requirements(path: Path) -> List[str]:
	requirements: List[str] = []
	if not path.exists():
		return requirements
	for raw_line in path.read_text(encoding="utf-8").splitlines():
		line = raw_line.strip()
		if not line or line.startswith("#"):
			continue
		requirements.append(line)
	return requirements


def _canonical_requirement_name(requirement: str) -> str:
	name = requirement.split(";", 1)[0].strip()
	if "#" in name:
		name = name.split("#", 1)[0].strip()
	for separator in ("==", ">=", "<=", "~=", "!=", ">", "<"):
		if separator in name:
			name = name.split(separator, 1)[0].strip()
	if "[" in name:
		name = name.split("[", 1)[0].strip()
	return name.lower()


def _is_installed(import_name: str) -> bool:
	return importlib.util.find_spec(import_name) is not None


def _missing_packages(packages: Dict[str, str], available: List[str]) -> List[str]:
	missing: List[str] = []
	available_set = {_canonical_requirement_name(entry) for entry in available}
	for package_name, import_name in packages.items():
		if package_name.lower() not in available_set:
			continue
		if not _is_installed(import_name):
			missing.append(package_name)
	return missing


def _run_pip_install(packages: List[str]) -> bool:
	if not packages:
		return True
	command = [sys.executable, "-m", "pip", "install", *packages]
	print("Installiere fehlende Pakete:", ", ".join(packages))
	return subprocess.call(command, cwd=str(ROOT)) == 0


def _optional_packages_for_runtime() -> List[str]:
	if _IS_ANDROID:
		return []
	optional_packages = ["pywebview", "python-magic", "llama-cpp-python"]
	if sys.platform.startswith("win"):
		optional_packages.extend(["winshell", "pywin32"])
	if sys.platform.startswith("win") and sys.version_info >= (3, 14):
		optional_packages = [name for name in optional_packages if name != "pywebview"]
	return optional_packages


def ensure_dependencies(profile: str = "full", strict: bool = True, install_optional: bool = True) -> bool:
	available_requirements = _load_requirements(_requirements_path(profile))
	core_missing = _missing_packages(_core_imports(profile), available_requirements)
	if core_missing and not _run_pip_install(core_missing):
		if strict:
			print("\nAbbruch: Pflichtabhaengigkeiten konnten nicht installiert werden.")
			print("Pruefe Python-Version, Compiler-Toolchain und Netzwerkzugriff.")
			return False
		print("\nLegacy-Start laeuft weiter: leichte Zusatzpakete konnten nicht installiert werden.")
		return True

	if not install_optional or profile in {"legacy", "ultra_legacy"}:
		return True

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


def _ensure_yggdrasil() -> None:
	"""Installiert Yggdrasil automatisch wenn es nicht verfuegbar ist."""
	try:
		from modules.yggdrasil_install import is_yggdrasil_available, install_yggdrasil
		if not is_yggdrasil_available():
			print("[START] Yggdrasil nicht gefunden – starte Autoinstall ...")
			binary = install_yggdrasil()
			print(f"[START] Yggdrasil installiert: {binary}")
		else:
			print("[START] Yggdrasil verfuegbar.")
	except Exception as exc:
		print(f"[START] Yggdrasil-Autoinstall fehlgeschlagen: {exc}")
		print("[START] Aether startet ohne Yggdrasil-Overlay.")


def main() -> int:
	print("Aether-Start wird vorbereitet...")
	route = _startup_route()
	_write_startup_route(route)
	if route.get("mode") == "ultra_legacy":
		return _run_ultra_legacy_bootstrap(str(route.get("reason", "ultra_legacy")), route)
	if route.get("mode") == "headless":
		return _run_headless_daemon(str(route.get("reason", "legacy_headless")), route)
	if not ensure_dependencies(profile=str(route.get("requirements_profile", "full") or "full")):
		fallback_route = _route_with_override(route, "headless", "dependency_install_failed", "legacy", "daemon_headless.py")
		return _run_headless_daemon("dependency_install_failed", fallback_route)
	try:
		_sync_local_identity_metadata()
	except Exception as exc:
		print(f"[START] Lokale Identitaets-Synchronisierung fehlgeschlagen: {exc}")
	_ensure_yggdrasil()
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

	# AE-Evolutions-Orchestrator als permanenter Hintergrund-Thread
	try:
		from modules.evolution_orchestrator import start as _orch_start, is_enabled as _orch_enabled
		_orch_start()
		print(f"[START] AE-Evolutions-Orchestrator gestartet (aktiv={_orch_enabled()}).")
	except Exception as exc:
		print(f"[START] AE-Orchestrator nicht verfuegbar: {exc}")

	# Autostart bei Windows-Boot registrieren wenn in Einstellungen aktiviert
	try:
		settings_now = _read_json(ROOT / "data" / "settings.json", {})
		if bool(settings_now.get("ae_autostart", True)):
			from modules.autostart import register as _autostart_register, is_registered as _autostart_check
			if not _autostart_check():
				ok = _autostart_register()
				print(f"[START] Autostart registriert: {ok}")
			else:
				print("[START] Autostart bereits registriert.")
		else:
			from modules.autostart import unregister as _autostart_remove, is_registered as _autostart_check
			if _autostart_check():
				_autostart_remove()
				print("[START] Autostart entfernt (deaktiviert in Einstellungen).")
	except Exception as exc:
		print(f"[START] Autostart-Verwaltung nicht verfuegbar: {exc}")

	if _IS_ANDROID:
		print("[START] Android mode erkannt. Starte android_daemon (ohne Desktop-UI-Stack).")
		try:
			import android_daemon
			android_daemon.main()
			return 0
		except KeyboardInterrupt:
			print("[START] Android daemon gestoppt.")
			return 0
		except Exception as exc:
			print(f"[START] Android daemon konnte nicht gestartet werden: {exc}")
			return 1

	
	try:
		from modules.runtime_invariant.runtime_core import init_runtime
	except ModuleNotFoundError:
		import sys as _sys, os as _os
		_sys.path.insert(0, _os.path.dirname(__file__))
		from runtime_core import init_runtime
	try:
		from modules.unified_cascade import run_full_pipeline
		print("[START] Pipeline bereit.")
	except Exception as exc:
		print(f"[START] Pipeline konnte nicht geladen werden: {exc}")
		fallback_route = _route_with_override(route, "headless", "pipeline_unavailable", "legacy", "daemon_headless.py")
		return _run_headless_daemon("pipeline_unavailable", fallback_route)

	print("[START] Aether laeuft. Druecke Ctrl+C zum Beenden.")
	try:
		import time
		while True:
			time.sleep(30)
	except KeyboardInterrupt:
		print("[START] Aether gestoppt.")
		try:
			from modules.evolution_orchestrator import stop as _orch_stop
			_orch_stop()
		except Exception:
			pass
	return 0



if __name__ == "__main__":
	raise SystemExit(main())
