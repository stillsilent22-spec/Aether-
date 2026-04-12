from __future__ import print_function

import hashlib
import os
import subprocess
import sys
import time

try:
    import json
except ImportError:
    json = None

try:
    import platform as _platform
except ImportError:
    _platform = None


ROOT = os.path.dirname(os.path.abspath(__file__))
INTERBUS_DIR = os.path.join(ROOT, "data", "interbus")
STARTUP_ROUTE_PATH = os.path.join(INTERBUS_DIR, "startup_route.json")
BACKEND_STATE_PATH = os.path.join(INTERBUS_DIR, "backend_state.json")
HW_CAPABILITY_PATH = os.path.join(INTERBUS_DIR, "hw_capability.json")
VAULT_DIR = os.path.join(ROOT, "data", "vault")
NODE_JSON_PATH = os.path.join(ROOT, "data", "swarm", "node.json")
ACCOUNT_CLAIM_PATH = os.path.join(ROOT, "data", "swarm", "account_claim.json")
DEVICE_LOCK_PATH = os.path.join(ROOT, "data", "device_lock.json")
SETTINGS_PATH = os.path.join(ROOT, "data", "settings.json")
RELAY_POOL_PATH = os.path.join(ROOT, "data", "swarm", "relay_pool.json")
PEER_CACHE_PATH = os.path.join(ROOT, "data", "swarm", "peer_cache.json")
VAULT_PROBE_VERDICT_PATH = os.path.join(INTERBUS_DIR, "vault_probe_verdict.json")
VAULT_PROBE_CONVERSION_PATH = os.path.join(INTERBUS_DIR, "aether_conversion_request.json")
LEGACY_LEARNING_STATE_PATH = os.path.join(INTERBUS_DIR, "legacy_learning_state.json")
LEGACY_SELF_OBS_PATH = os.path.join(INTERBUS_DIR, "legacy_self_observation.json")
VAULT_PROBE_LAST_RUN_PATH = os.path.join(INTERBUS_DIR, "vault_probe_last_run.json")
VAULT_PROBE_BIN_PATHS = (
    os.path.join(ROOT, "tools", "vault_probe.exe"),
    os.path.join(ROOT, "vault_probe.exe"),
)


def _safe_makedirs(path):
    if not path:
        return
    if os.path.isdir(path):
        return
    try:
        os.makedirs(path)
    except OSError:
        if not os.path.isdir(path):
            raise


def _timestamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _write_json(path, payload):
    _safe_makedirs(os.path.dirname(path))
    if json is None:
        handle = open(path, "w")
        try:
            handle.write(repr(payload))
        finally:
            handle.close()
        return
    handle = open(path, "w")
    try:
        handle.write(json.dumps(payload, indent=2, ensure_ascii=True))
    finally:
        handle.close()


def _count_files(root_path):
    total = 0
    if not os.path.isdir(root_path):
        return 0
    for _, _, filenames in os.walk(root_path):
        total += len(filenames)
    return total


def _load_json_file(path):
    """Liest JSON robust (Python 2/3 kompatibel), sonst leeres Dict."""
    if json is None or not os.path.isfile(path):
        return {}
    try:
        raw = open(path).read()
        payload = json.loads(raw)
        if isinstance(payload, dict):
            return payload
        return {}
    except Exception:
        return {}


def _print_vault_probe_state():
    """Zeigt den letzten Stand des Python-freien C-Probes an, falls vorhanden."""
    verdict = _load_json_file(VAULT_PROBE_VERDICT_PATH)
    if not verdict:
        return

    action = str(verdict.get("action", "") or "").strip()
    if action:
        print("[LEGACY] vault_probe action: " + action)

    if action == "waiting_retry_window":
        try:
            sec = int(verdict.get("retry_after_sec", 0) or 0)
        except Exception:
            sec = 0
        if sec > 0:
            print("[LEGACY] vault_probe retry active: " + str(sec) + " sec")
        return

    if action == "inject_and_retry":
        print("[LEGACY] vault_probe requests seed injection and 24h retry window.")
        return

    if action == "linux_fallback":
        conversion = _load_json_file(VAULT_PROBE_CONVERSION_PATH)
        req = conversion.get("requested", None)
        if req is None:
            req = verdict.get("conversion_requested", -1)
        if req in (1, True, "1", "true", "True"):
            print("[LEGACY] conversion requested before linux fallback.")
        elif req in (0, False, "0", "false", "False"):
            print("[LEGACY] linux fallback allowed without conversion request.")
        else:
            print("[LEGACY] linux fallback ready; conversion preference not set.")
        distro = str(verdict.get("recommended_linux_distro", "") or "").strip()
        if distro:
            print("[LEGACY] recommended linux distro: " + distro)
        return

    print("[LEGACY] vault_probe verdict present; action not recognized.")


def _boolish(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value or "").strip().lower()
    return text in ("1", "true", "yes", "y", "on")


def _find_vault_probe_binary():
    for path in VAULT_PROBE_BIN_PATHS:
        if os.path.isfile(path):
            return path
    return ""


def _run_vault_probe_if_available(min_interval_sec):
    """Fuehrt die C-Probe aus, wenn vorhanden und Intervall erreicht ist."""
    probe_bin = _find_vault_probe_binary()
    now = int(time.time())
    min_interval = max(60, int(_safe_float(min_interval_sec, 600)))

    if not probe_bin:
        return {
            "ran": False,
            "status": "missing_binary",
            "timestamp": _timestamp(),
        }

    last = _load_json_file(VAULT_PROBE_LAST_RUN_PATH)
    last_epoch = int(_safe_float(last.get("last_epoch", 0), 0.0))
    elapsed = now - last_epoch if last_epoch > 0 else (min_interval + 1)
    if elapsed < min_interval:
        return {
            "ran": False,
            "status": "throttled",
            "retry_in_sec": int(min_interval - elapsed),
            "timestamp": _timestamp(),
        }

    exit_code = -1
    status = "ran"
    detail = ""
    try:
        devnull_in = open(os.devnull, "r")
        devnull_out = open(os.devnull, "w")
        try:
            # Non-interaktiv: C-Probe bekommt EOF auf stdin und blockiert nicht.
            exit_code = int(subprocess.call([probe_bin], stdin=devnull_in, stdout=devnull_out, stderr=devnull_out))
        finally:
            devnull_in.close()
            devnull_out.close()
    except Exception as exc:
        status = "exec_error"
        detail = str(exc)

    payload = {
        "schema": "aether.vault_probe.runner.v1",
        "probe_bin": probe_bin,
        "ran": status == "ran",
        "status": status,
        "exit_code": exit_code,
        "detail": detail,
        "last_epoch": now,
        "timestamp": _timestamp(),
    }
    _write_json(VAULT_PROBE_LAST_RUN_PATH, payload)
    return payload


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return float(default)


def _clamp01(value):
    v = _safe_float(value, 0.0)
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def _avg(values):
    items = list(values or [])
    if not items:
        return 0.0
    return sum([_safe_float(v, 0.0) for v in items]) / float(len(items))


def _derive_legacy_learning(vault_count):
    """Leitet AE-Lernstaerken bevorzugt aus C-Probe-Metriken ab."""
    verdict = _load_json_file(VAULT_PROBE_VERDICT_PATH)
    if not verdict:
        base = _clamp01(float(vault_count) / 64.0)
        recon = _clamp01(0.2 + base * 0.6)
        strengths = {
            "ae.vault_retention": round(base, 4),
            "ae.bootstrap": round(_clamp01(0.2 + base * 0.5), 4),
            "ae.reconstruction_path": round(recon, 4),
        }
        return {
            "source": "vault_count_fallback",
            "known_strengths": strengths,
            "learning_score": round(_avg(strengths.values()), 4),
            "probe_action": "",
            "probe_gate": "unknown",
            "metrics": {},
            "strong_patterns": 0,
            "compression_ratio_pct": 100,
            "reconstruction_score": recon,
            "invariant_usage_score": _clamp01(_avg([base, recon])),
            "vault_ready": False,
            "metric_ok": False,
            "ram_ok": False,
            "compress_ok": False,
        }

    metrics = verdict.get("metrics") or {}
    if not isinstance(metrics, dict):
        metrics = {}

    entropy_shannon = _safe_float(metrics.get("entropy_shannon", 0.0))
    symmetry = _clamp01(metrics.get("symmetry", 0.0))
    periodicity = _clamp01(metrics.get("periodicity", 0.0))
    zipf_alpha = _safe_float(metrics.get("zipf_alpha", 0.0))
    benford_score = _clamp01(metrics.get("benford_score", 0.0))
    bit_position_score = _clamp01(metrics.get("bit_position_score", 0.0))
    perm_entropy = _clamp01(metrics.get("perm_entropy", 1.0))
    noether_consistency = _clamp01(metrics.get("noether_consistency", 0.0))
    gradient_coherence = _clamp01(metrics.get("gradient_coherence", 0.0))

    sce_score = _clamp01(verdict.get("sce_score", 0.0))
    trust_score = _clamp01(verdict.get("trust_score", 0.0))
    invariant_strength = _clamp01(verdict.get("invariant_strength", 0.0))
    strong_patterns = int(_safe_float(verdict.get("strong_patterns", 0), 0.0))
    compression_ratio_pct = int(_safe_float(verdict.get("compress_ratio_pct", 100), 100.0))
    if compression_ratio_pct < 0:
        compression_ratio_pct = 0
    if compression_ratio_pct > 100:
        compression_ratio_pct = 100

    vault_ready = _boolish(verdict.get("vault_ready", False))
    metric_ok = _boolish(verdict.get("metric_ok", False))
    ram_ok = _boolish(verdict.get("ram_ok", False))
    compress_ok = _boolish(verdict.get("compress_ok", False))

    entropy_norm = _clamp01(entropy_shannon / 8.0)
    zipf_fit = _clamp01(1.0 - abs(zipf_alpha - 1.0))
    temporal_order = _clamp01(1.0 - perm_entropy)
    vault_density = _clamp01(float(vault_count) / 64.0)
    compression_efficiency = _clamp01(1.0 - (float(compression_ratio_pct) / 100.0))

    structural_strength = _clamp01(_avg([symmetry, gradient_coherence, noether_consistency, sce_score]))
    distribution_strength = _clamp01(_avg([benford_score, zipf_fit, entropy_norm, bit_position_score]))
    temporal_strength = _clamp01(_avg([periodicity, temporal_order, invariant_strength]))
    retention_strength = _clamp01(_avg([vault_density, trust_score, sce_score]))
    reconstruction_score = _clamp01(
        _avg([
            structural_strength,
            temporal_strength,
            retention_strength,
            compression_efficiency,
            invariant_strength,
        ])
    )
    invariant_usage_score = _clamp01(_avg([structural_strength, temporal_strength, distribution_strength]))

    strengths = {
        "ae.structural_coherence": round(structural_strength, 4),
        "ae.distribution_alignment": round(distribution_strength, 4),
        "ae.temporal_invariants": round(temporal_strength, 4),
        "ae.vault_retention": round(retention_strength, 4),
        "ae.reconstruction_path": round(reconstruction_score, 4),
        "ae.invariant_usage": round(invariant_usage_score, 4),
    }

    probe_gate = "open" if (vault_ready and metric_ok and compress_ok) else "constrained"

    return {
        "source": "vault_probe",
        "known_strengths": strengths,
        "learning_score": round(_avg(strengths.values()), 4),
        "probe_action": str(verdict.get("action", "") or ""),
        "probe_gate": probe_gate,
        "metrics": {
            "entropy_shannon": round(entropy_shannon, 6),
            "symmetry": round(symmetry, 6),
            "periodicity": round(periodicity, 6),
            "benford_score": round(benford_score, 6),
            "bit_position_score": round(bit_position_score, 6),
            "noether_consistency": round(noether_consistency, 6),
            "sce_score": round(sce_score, 6),
            "trust_score": round(trust_score, 6),
            "invariant_strength": round(invariant_strength, 6),
            "compression_ratio_pct": compression_ratio_pct,
            "reconstruction_score": round(reconstruction_score, 6),
        },
        "strong_patterns": strong_patterns,
        "compression_ratio_pct": compression_ratio_pct,
        "reconstruction_score": reconstruction_score,
        "invariant_usage_score": invariant_usage_score,
        "vault_ready": vault_ready,
        "metric_ok": metric_ok,
        "ram_ok": ram_ok,
        "compress_ok": compress_ok,
    }


def _update_self_observation(learning_payload):
    """Fuehrt eine leichte Selbstbeobachtung mit Trend ueber die letzten Lernzyklen."""
    prior = _load_json_file(LEGACY_SELF_OBS_PATH)
    history = list(prior.get("history") or [])

    entry = {
        "timestamp": _timestamp(),
        "learning_score": round(_clamp01(learning_payload.get("learning_score", 0.0)), 4),
        "reconstruction_score": round(_clamp01(learning_payload.get("reconstruction_score", 0.0)), 4),
        "invariant_usage_score": round(_clamp01(learning_payload.get("invariant_usage_score", 0.0)), 4),
        "compression_ratio_pct": int(_safe_float(learning_payload.get("compression_ratio_pct", 100), 100.0)),
        "probe_gate": str(learning_payload.get("probe_gate", "unknown") or "unknown"),
    }
    history.append(entry)
    history = history[-48:]

    learning_series = [_safe_float(item.get("learning_score", 0.0), 0.0) for item in history]
    short_avg = _avg(learning_series[-6:])
    prev_avg = _avg(learning_series[-12:-6]) if len(learning_series) >= 12 else short_avg
    trend_delta = round(short_avg - prev_avg, 4)

    if trend_delta > 0.03:
        mode = "amplify"
    elif trend_delta < -0.03:
        mode = "recover"
    else:
        mode = "stabilize"

    payload = {
        "schema": "aether.legacy_self_observation.v1",
        "mode": mode,
        "trend_delta": trend_delta,
        "window": {
            "short_avg": round(short_avg, 4),
            "prev_avg": round(prev_avg, 4),
            "samples": len(history),
        },
        "history": history,
        "updated_at": _timestamp(),
    }
    _write_json(LEGACY_SELF_OBS_PATH, payload)
    return payload


def _legacy_learning_tick(node_id, network_tier, vault_count):
    """Persistiert eine leichte AE-Lernsicht fuer Ultra-Legacy-Knoten."""
    learning = _derive_legacy_learning(vault_count)
    strengths = dict(learning.get("known_strengths") or {})
    if strengths:
        _save_strengths(strengths)

    payload = {
        "schema": "aether.legacy_learning_state.v1",
        "node_id": node_id,
        "network_tier": network_tier,
        "vault_entry_count": vault_count,
        "source": str(learning.get("source", "unknown") or "unknown"),
        "learning_score": round(_clamp01(learning.get("learning_score", 0.0)), 4),
        "known_strengths": strengths,
        "probe_action": str(learning.get("probe_action", "") or ""),
        "probe_gate": str(learning.get("probe_gate", "unknown") or "unknown"),
        "strong_patterns": int(_safe_float(learning.get("strong_patterns", 0), 0.0)),
        "compression_ratio_pct": int(_safe_float(learning.get("compression_ratio_pct", 100), 100.0)),
        "reconstruction_score": round(_clamp01(learning.get("reconstruction_score", 0.0)), 4),
        "invariant_usage_score": round(_clamp01(learning.get("invariant_usage_score", 0.0)), 4),
        "vault_ready": bool(learning.get("vault_ready", False)),
        "metric_ok": bool(learning.get("metric_ok", False)),
        "ram_ok": bool(learning.get("ram_ok", False)),
        "compress_ok": bool(learning.get("compress_ok", False)),
        "timestamp": _timestamp(),
    }

    metrics = learning.get("metrics") or {}
    if isinstance(metrics, dict) and metrics:
        payload["metrics"] = metrics

    obs = _update_self_observation(payload)
    if isinstance(obs, dict) and obs:
        payload["self_observation_mode"] = str(obs.get("mode", "stabilize") or "stabilize")
        payload["self_observation_delta"] = round(_safe_float(obs.get("trend_delta", 0.0), 0.0), 4)

    _write_json(LEGACY_LEARNING_STATE_PATH, payload)
    return payload


def _print_legacy_learning_state():
    state = _load_json_file(LEGACY_LEARNING_STATE_PATH)
    if not state:
        return
    score = _safe_float(state.get("learning_score", 0.0), 0.0)
    recon = _safe_float(state.get("reconstruction_score", 0.0), 0.0)
    source = str(state.get("source", "unknown") or "unknown")
    mode = str(state.get("self_observation_mode", "stabilize") or "stabilize")
    strengths = state.get("known_strengths") or {}
    domains = sorted([str(k) for k in strengths.keys()]) if isinstance(strengths, dict) else []
    if domains:
        print("[LEGACY] AE learning score=%.3f recon=%.3f mode=%s source=%s domains=%s" % (score, recon, mode, source, ",".join(domains[:3])))
    else:
        print("[LEGACY] AE learning score=%.3f recon=%.3f mode=%s source=%s" % (score, recon, mode, source))


# ── Identity (hardware fingerprint + stable node_id + alias username) ─────
# Python 2.x kompatibel: keine f-strings, keine Type-Hints, keine pathlib.
# Wird einmalig beim ersten Start erzeugt und ist danach unveränderlich.

def _windows_machine_guid():
    """Liest MachineGuid aus Windows-Registry (WinNT 4.0+ / Win9x via winreg)."""
    try:
        # Python 2: _winreg  |  Python 3: winreg
        try:
            import winreg as _reg
        except ImportError:
            import _winreg as _reg
        key = _reg.OpenKey(
            _reg.HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Cryptography",
        )
        guid = _reg.QueryValueEx(key, "MachineGuid")[0]
        _reg.CloseKey(key)
        return str(guid).strip()
    except Exception:
        return ""


def _compute_network_entry_id(node_id, device_fp):
    """Deterministischer DHT-Peer-Bezeichner fuer Legacy-Knoten.

    Identische Ableitung wie modules/symbiont_engine.py und auth.rs,
    damit jeder Legacy-PC eine stabile, Hardware-gebundene Peer-ID hat.
    """
    raw = "legacy-dht|" + device_fp + "|" + node_id
    if sys.version_info[0] >= 3:
        raw = raw.encode("utf-8")
    return "peer-" + hashlib.sha256(raw).hexdigest()[:32]


def _compute_identity_lock(alias_username, node_id, device_fp, network_entry_id):
    """SHA-256 identity lock — kompatibel mit auth.rs dht-hw-user-lock.v1 Schema."""
    raw = (
        "aether.dht-hw-user-lock.v1|"
        + alias_username + "|"
        + node_id + "||"
        + device_fp + "|"
        + network_entry_id
    )
    if sys.version_info[0] >= 3:
        raw = raw.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _compute_legacy_fingerprint(node_id):
    """SHA-256 Hardware-Fingerprint — stabil, nicht umkehrbar.

    Quellen: Windows MachineGuid, Hostname, Python-Pfad, node_id.
    Fällt auf reine node_id + Hostname zurück wenn Registry nicht verfügbar.
    """
    parts = []
    guid = _windows_machine_guid()
    if guid:
        parts.append("win-guid:" + guid)
    try:
        import socket
        parts.append("hostname:" + socket.gethostname())
    except Exception:
        pass
    try:
        parts.append("py:" + os.path.abspath(sys.executable))
    except Exception:
        pass
    parts.append("node:" + node_id)
    raw = "|".join(sorted(parts))
    if sys.version_info[0] >= 3:
        raw = raw.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _load_or_create_node_id():
    """Lädt stabile node_id aus node.json oder erzeugt eine neue.

    Ohne cryptography-Modul wird eine stabile UUID aus Fingerprint gebaut
    (nicht kryptografisch, aber Hardware-gebunden und stabil über Neustarts).
    """
    node_json = NODE_JSON_PATH
    _safe_makedirs(os.path.dirname(node_json))
    if os.path.isfile(node_json) and json is not None:
        try:
            payload = json.loads(open(node_json).read())
            nid = str(payload.get("node_id", "") or "").strip()
            if nid:
                return nid
        except Exception:
            pass
    # Deterministisch aus Hostname + py-Pfad (keine Crypto-Deps nötig)
    try:
        import socket
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"
    seed = "legacy|" + hostname + "|" + os.path.abspath(sys.executable)
    if sys.version_info[0] >= 3:
        seed = seed.encode("utf-8")
    node_id = hashlib.sha256(seed).hexdigest()[:16]
    return node_id


def _ensure_legacy_identity():
    """Erstellt node.json + account_claim.json + device_lock.json falls noch nicht vorhanden.

    Kein Ed25519, keine externen Deps — reine stdlib. Für Win95/98/2000/XP.
    Der Knoten hat danach:
      - eine stabile node_id (Hardware-gebunden via SHA-256)
      - einen deterministischen alias_username ("aether_<node_id[:8]>")
      - einen device_fingerprint (MachineGuid oder Fallback)
      - claim_mode="alias" → wird zu "registered" sobald Netz erreichbar
    """
    node_id = _load_or_create_node_id()
    device_fp = _compute_legacy_fingerprint(node_id)
    alias_username = "aether_" + node_id[:8]
    network_entry_id = _compute_network_entry_id(node_id, device_fp)
    identity_lock = _compute_identity_lock(alias_username, node_id, device_fp, network_entry_id)
    ts = _timestamp()

    node_record = {
        "schema": "aether.swarm.node.v2",
        "node_id": node_id,
        "public_key_pem": "",
        "registered_at": ts,
        "role": "peer",
        "relay": False,
        "yggdrasil_addr": None,
        "device_fingerprint": device_fp,
        "alias_username": alias_username,
        "runtime": "ultra-legacy-bootstrap",
    }
    _safe_makedirs(os.path.dirname(NODE_JSON_PATH))
    if not os.path.isfile(NODE_JSON_PATH):
        _write_json(NODE_JSON_PATH, node_record)
        nodes_dir = os.path.join(ROOT, "data", "swarm", "nodes")
        _safe_makedirs(nodes_dir)
        _write_json(os.path.join(nodes_dir, node_id + ".json"), node_record)

    # Keypair-Aequivalent fuer Legacy-Knoten ohne Ed25519
    # hw_id (device_fp) + net_id (network_entry_id) -> priv_equiv + pub_equiv
    _pub_equiv = ""
    try:
        _sym_dir_uid = os.path.join(ROOT, "modules")
        if _sym_dir_uid not in sys.path:
            sys.path.insert(0, _sym_dir_uid)
        from universal_identity import entry_keypair_seed as _eks
        from universal_identity import MEDIUM_UNKNOWN as _MU
        _pe, _pub_equiv = _eks(device_fp, network_entry_id, _MU)
    except Exception:
        pass

    if not os.path.isfile(ACCOUNT_CLAIM_PATH):
        _write_json(ACCOUNT_CLAIM_PATH, {
            "schema": "aether.account_claim.v1",
            "node_id": node_id,
            "alias_username": alias_username,
            "account_username": alias_username,
            "device_fingerprint": device_fp,
            "claim_mode": "alias",
            "relay_bridge_mode": True,
            "ygg_addr": "",
            "identity_lock": identity_lock,
            "network_entry_id": network_entry_id,
            "entry_pub_equiv": _pub_equiv,
            "entry_medium": "unknown",
            "native_ygg_bound": False,
            "created_at": ts,
        })
    elif json is not None:
        # Backfill identity_lock, network_entry_id, entry_pub_equiv if missing
        # from older bootstrap runs.
        try:
            claim = json.loads(open(ACCOUNT_CLAIM_PATH).read())
            updated = False
            if not str(claim.get("network_entry_id", "") or "").strip():
                claim["network_entry_id"] = network_entry_id
                updated = True
            if not str(claim.get("identity_lock", "") or "").strip():
                claim["identity_lock"] = identity_lock
                updated = True
            if not str(claim.get("entry_pub_equiv", "") or "").strip() and _pub_equiv:
                claim["entry_pub_equiv"] = _pub_equiv
                updated = True
            if "entry_medium" not in claim:
                claim["entry_medium"] = "unknown"
                updated = True
            if updated:
                _write_json(ACCOUNT_CLAIM_PATH, claim)
        except Exception:
            pass

    if not os.path.isfile(DEVICE_LOCK_PATH):
        _write_json(DEVICE_LOCK_PATH, {
            "schema": "aether.device_lock.v1",
            "node_id": node_id,
            "device_fingerprint": device_fp,
        })

    return {
        "node_id": node_id,
        "alias_username": alias_username,
        "device_fingerprint": device_fp,
        "network_entry_id": network_entry_id,
        "identity_lock": identity_lock,
    }


def _read_relay_url():
    """Liest relay_url aus data/settings.json — leer wenn nicht konfiguriert."""
    if json is None or not os.path.isfile(SETTINGS_PATH):
        return ""
    try:
        data = json.loads(open(SETTINGS_PATH).read())
        p2p = data.get("swarm_p2p") or data.get("p2p") or {}
        return str(p2p.get("relay_url", "") or "").strip()
    except Exception:
        return ""


def _read_relay_pool():
    """Gibt alle bekannten Relay-URLs zurück (Python 2.x kompatibel).

    Quellen:
      1. settings.json → swarm_p2p.relay_urls (Liste)
      2. settings.json → swarm_p2p.relay_url  (veraltetes Einzel-Feld)
      3. data/swarm/relay_pool.json            (selbst gelernte Relays)
    """
    pool = []
    if json is not None and os.path.isfile(SETTINGS_PATH):
        try:
            data = json.loads(open(SETTINGS_PATH).read())
            p2p = data.get("swarm_p2p") or data.get("p2p") or {}
            for url in list(p2p.get("relay_urls") or []):
                u = str(url).strip()
                if u:
                    pool.append(u)
            single = str(p2p.get("relay_url", "") or "").strip()
            if single:
                pool.append(single)
        except Exception:
            pass
    if json is not None and os.path.isfile(RELAY_POOL_PATH):
        try:
            data = json.loads(open(RELAY_POOL_PATH).read())
            for url in list(data.get("urls", [])):
                u = str(url).strip()
                if u:
                    pool.append(u)
        except Exception:
            pass
    # Deduplizieren ohne set() (Python 2.x sicher)
    seen = []
    result = []
    for u in pool:
        if u not in seen:
            seen.append(u)
            result.append(u)
    return result


def _learn_relay_urls_legacy(urls):
    """Persistiert neue Relay-URLs im lokalen Pool (idempotent, Python 2.x)."""
    if json is None or not urls:
        return
    pool = _read_relay_pool()
    changed = False
    for url in urls:
        u = str(url).strip()
        if u and u.startswith(("http://", "https://")) and u not in pool:
            pool.append(u)
            changed = True
    if not changed:
        return
    try:
        _safe_makedirs(os.path.dirname(RELAY_POOL_PATH))
        f = open(RELAY_POOL_PATH, "w")
        f.write(json.dumps({"schema": "aether.relay_pool.v1", "urls": pool[:64]},
                           ensure_ascii=True))
        f.close()
    except Exception:
        pass


def _pick_live_relay_legacy(pool, timeout=5):
    """Gibt erste erreichbare Relay-URL zurück, leer wenn keine antwortet.

    Probiert GET /gossip/latest — antwortet der HTTP-Server, ist der Relay online.
    Python 2.x: urllib2, Python 3.x: urllib.request.
    """
    for url in pool:
        check_url = url.rstrip("/") + "/gossip/latest"
        try:
            if sys.version_info[0] >= 3:
                import urllib.request as _ureq
                with _ureq.urlopen(check_url, timeout=timeout) as resp:
                    if 200 <= resp.status < 500:
                        return url
            else:
                import urllib2 as _u2
                resp = _u2.urlopen(check_url, timeout=timeout)
                if 200 <= resp.getcode() < 500:
                    return url
        except Exception:
            continue
    return ""


def _relay_gossip_push_legacy(relay_url, node_id, device_fp, alias_username, known_relays):
    """Sendet Gossip-Paket mit known_relay_urls an einen Relay-Knoten.

    Python 2.6+ urllib2 und Python 3.x urllib.request.
    Das Paket trägt known_relay_urls — so lernt jeder Relay das gesamte Netz.
    """
    if not relay_url or json is None:
        return False
    network_entry_id = _compute_network_entry_id(node_id, device_fp)
    identity_lock = _compute_identity_lock(alias_username, node_id, device_fp, network_entry_id)
    payload_data = {
        "schema": "aether.swarm.p2p.gossip.v1",
        "node_id": node_id,
        "device_fingerprint": device_fp,
        "account_username": alias_username,
        "peer_id": network_entry_id,
        "identity_lock": identity_lock,
        "fingerprints": [],
        "metrics_summary": {"network_tier": "LocalOnly", "relay_bridge_mode": True},
        "is_genesis_node": False,
        "relay_bridge_mode": True,
        "known_relay_urls": known_relays[:16],
    }
    body = json.dumps(payload_data, ensure_ascii=True)
    body_bytes = body.encode("utf-8") if sys.version_info[0] >= 3 else body
    target = relay_url.rstrip("/") + "/gossip"
    try:
        if sys.version_info[0] >= 3:
            import urllib.request as _ureq
            req = _ureq.Request(target, data=body_bytes,
                                headers={"Content-Type": "application/json"},
                                method="POST")
            with _ureq.urlopen(req, timeout=8) as resp:
                return 200 <= resp.status < 300
        else:
            import urllib2 as _u2
            req = _u2.Request(target, body_bytes,
                              {"Content-Type": "application/json"})
            resp = _u2.urlopen(req, timeout=8)
            return 200 <= resp.getcode() < 300
    except Exception:
        return False


def _relay_gossip_pull_legacy(relay_url):
    """Holt Gossip-Pakete vom Relay (GET /gossip/latest), lernt neue Relay-URLs."""
    if not relay_url or json is None:
        return []
    target = relay_url.rstrip("/") + "/gossip/latest"
    try:
        if sys.version_info[0] >= 3:
            import urllib.request as _ureq
            with _ureq.urlopen(target, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        else:
            import urllib2 as _u2
            resp = _u2.urlopen(target, timeout=8)
            data = json.loads(resp.read())
        msgs = [m for m in list(data.get("messages", []))
                if isinstance(m, dict)
                and str(m.get("schema", "")) == "aether.swarm.p2p.gossip.v1"]
        # Lerne neue Relays aus den empfangenen Paketen
        for m in msgs:
            _learn_relay_urls_legacy(list(m.get("known_relay_urls") or []))
        return msgs
    except Exception:
        return []


def _relay_announce(relay_url, node_id, device_fp, alias_username):
    """Meldet diesen Knoten beim Relay-Knoten an (HTTP POST /register).

    Liest die in der Antwort enthaltenen known_relay_urls und lernt sie —
    so erhält der Legacy-PC beim ersten Kontakt sofort alle bekannten Relays.
    """
    if not relay_url:
        return False
    known_relays = _read_relay_pool()
    if relay_url not in known_relays:
        known_relays.append(relay_url)
    payload_data = {
        "schema": "aether.relay_announce.v1",
        "node_id": node_id,
        "device_fingerprint": device_fp,
        "alias_username": alias_username,
        "runtime": "ultra-legacy",
        "relay_bridge_mode": True,
        "known_relay_urls": known_relays[:16],
    }
    if json is None:
        return False
    body = json.dumps(payload_data, ensure_ascii=True).encode("utf-8") if sys.version_info[0] >= 3 else json.dumps(payload_data, ensure_ascii=True)
    try:
        if sys.version_info[0] >= 3:
            import urllib.request as _req
            r = _req.Request(
                relay_url.rstrip("/") + "/register",
                data=body if isinstance(body, bytes) else body.encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with _req.urlopen(r, timeout=8) as resp:
                ok = 200 <= resp.status < 300
                if ok:
                    try:
                        resp_data = json.loads(resp.read().decode("utf-8"))
                        _learn_relay_urls_legacy(list(resp_data.get("known_relay_urls") or []))
                    except Exception:
                        pass
        else:
            import urllib2 as _req2
            r = _req2.Request(
                relay_url.rstrip("/") + "/register",
                data=body,
                headers={"Content-Type": "application/json"},
            )
            resp = _req2.urlopen(r, timeout=8)
            ok = 200 <= resp.getcode() < 300
            if ok:
                try:
                    resp_data = json.loads(resp.read())
                    _learn_relay_urls_legacy(list(resp_data.get("known_relay_urls") or []))
                except Exception:
                    pass
        if ok:
            print("[LEGACY] Relay-Registrierung erfolgreich: " + relay_url)
        return ok
    except Exception as exc:
        print("[LEGACY] Relay-Registrierung fehlgeschlagen: " + str(exc))
        return False


def _platform_release():
    if _platform is None:
        return "", ""
    try:
        release = (_platform.release() or "").strip().lower()
    except Exception:
        release = ""
    try:
        version = (_platform.version() or "").strip().lower()
    except Exception:
        version = ""
    return release, version


def _detect_profile():
    # Architektur: vault_probe.exe (C) ist auf Windows die Entscheidungsinstanz.
    # Wenn dieser Bootstrap auf Linux laeuft, ist die Hardware-Entscheidung bereits
    # gefallen — die C-Probe hat auf Windows "linux_fallback" geschrieben.
    # Auf Linux: kein RAM-/Kernel-Check, direkt Yggdrasil anstreben.
    # Kein Knoten zweiter Klasse: Linux ist die Leiter ins Netz, nicht eine Begrenzung.
    system = sys.platform.lower()
    release, version = _platform_release()
    if system.startswith("win"):
        if release in ("95", "98", "me") or version.startswith("4."):
            return "Win9x", "LocalOnly", 0, "win9x_ultra_legacy_bootstrap"
        if release == "2000":
            return "Win2000", "LanBeacon", 1, "python_too_old_for_headless"
        # WinLegacy = XP und neuer in legacy_bootstrap (Python zu alt oder kein Headless).
        # WinTun unterstuetzt XP SP3+ -> Yggdrasil ist installierbar.
        # Probe-Urteil lesen: wenn ram_ok oder yggdrasil_recommended -> LanP2P Rank 2.
        verdict = _load_json_file(VAULT_PROBE_VERDICT_PATH)
        probe_ygg = _boolish(verdict.get("yggdrasil_recommended", False))
        probe_ram = _boolish(verdict.get("ram_ok", False))
        probe_action = str(verdict.get("action", "") or "").strip()
        if probe_ygg or probe_ram or probe_action in ("local_only", "linux_fallback"):
            return "WinLegacy", "LanP2P", 2, "winlegacy_yggdrasil_path"
        return "WinLegacy", "LanBeacon", 1, "python_too_old_for_headless"
    if system in ("linux", "linux2"):
        # Letztes C-Probe-Urteil lesen, falls die Hardware zuvor auf Windows lief.
        verdict = _load_json_file(VAULT_PROBE_VERDICT_PATH)
        probe_action = str(verdict.get("action", "") or "").strip()
        if probe_action == "linux_fallback":
            # C-Probe hat explizit Fallback angeordnet — Ziel: volle Netzwerkteilnahme.
            return "LinuxFallback", "YggdrasilP2P", 3, "linux_fallback_from_probe"
        # Native Linux-Installation oder kein Probe-Urteil vorhanden.
        return "LinuxNative", "YggdrasilP2P", 3, "linux_native_bootstrap"
    return "Unknown", "LocalOnly", 0, "python_too_old_for_headless"


def _route_payload(os_platform, network_tier, reason):
    return {
        "platform": sys.platform,
        "release": os_platform,
        "version": "",
        "architecture": "unknown",
        "python": "%s.%s.%s" % (sys.version_info[0], sys.version_info[1], sys.version_info[2]),
        "mode": "ultra_legacy",
        "reason": reason,
        "requirements_profile": "ultra_legacy",
        "recommended_entrypoint": "legacy_bootstrap.py",
        "network_tier": network_tier,
        "timestamp": _timestamp(),
    }


def _hw_payload(os_platform, network_tier, tier_rank, vault_count):
    # ── Tier-Tabelle ──────────────────────────────────────────────────────────
    #
    #  Platform          Tier/Rank  yggdrasil  dht   Begruendung
    #  ──────────────────────────────────────────────────────────────────────────
    #  Win9x             0          nein       nein  kein TUN-Treiber moeglich
    #  Win2000           1          nein       nein  WinTun unterstuetzt NT 5.0 nicht
    #  WinLegacy (XP+)   2          JA         nein  WinTun ab XP SP3; Yggdrasil install.
    #  LinuxFallback     3          JA         nein  C-Probe: linux_fallback
    #  LinuxNative       3          JA         nein  native Linux, kein Probe-Urteil
    #
    #  KEIN Knoten zweiter Klasse:
    #    Win9x/2000: genuiner Treiber-Deckel. Relay-Bridge ist ihr Wachstumspfad.
    #    WinLegacy (XP/Vista/7/8/10/11 im legacy path): WinTun + Yggdrasil direkt.
    #    Linux: kommt aus linux_fallback oder ist native; direkt ins Mesh.
    # ──────────────────────────────────────────────────────────────────────────
    is_linux = os_platform.startswith("Linux")
    is_win_legacy = (os_platform == "WinLegacy")

    if os_platform == "Win9x":
        # Win9x: kein TUN-Treiber – echter Hardware-Deckel
        native_tier_rank = 2
        native_network_tier = "LanP2P"
        yggdrasil = False
        dht = False
    elif os_platform == "Win2000":
        # Win2000: WinTun unterstuetzt NT 5.0 nicht
        native_tier_rank = tier_rank
        native_network_tier = network_tier
        yggdrasil = False
        dht = False
    elif is_win_legacy:
        # WinLegacy = XP SP3 und neuer: WinTun laeuft, Yggdrasil installierbar.
        # Kein Knoten zweiter Klasse — Windows-Pfad kriegt Yggdrasil genauso.
        native_tier_rank = tier_rank
        native_network_tier = network_tier
        yggdrasil = True
        dht = False  # DHT erst ab Linux/ModernWindows sinnvoll
    elif is_linux:
        # Linux: kommt per linux_fallback oder native; volle Netzwerkteilnahme.
        native_tier_rank = tier_rank
        native_network_tier = network_tier
        yggdrasil = True
        dht = (tier_rank >= 4)
    else:
        native_tier_rank = tier_rank
        native_network_tier = network_tier
        yggdrasil = False
        dht = False

    lan_p2p = is_linux or is_win_legacy  # beide koennen LAN-P2P
    vault_bootstrap_only = (tier_rank <= 1) and not is_linux and not is_win_legacy
    capability_pct = max(0.1, round(tier_rank / 4.0, 2))
    _stages = {0: "Basis-Daemon", 1: "LAN-Beacon", 2: "LAN-P2P", 3: "Yggdrasil-P2P", 4: "Full-DHT"}
    cap_stage = _stages.get(tier_rank, "Basis-Daemon")

    return {
        "os_platform": os_platform,
        "network_tier": network_tier,
        "native_network_tier": native_network_tier,
        "tier_rank": tier_rank,
        "native_tier_rank": native_tier_rank,
        "vault_bootstrap_only": vault_bootstrap_only,
        "lan_beacon": True if os_platform == "Win9x" else (network_tier in ("LanBeacon", "LanP2P", "YggdrasilP2P", "FullDht")),
        "lan_p2p": lan_p2p,
        "yggdrasil": yggdrasil,
        "dht": dht,
        "runtime": "ultra-legacy-bootstrap",
        "shell_capable": False,
        "progressive_network_unlock": True,
        "capability_percent": capability_pct,
        "capability_stage": cap_stage,
        "capability_stage_index": tier_rank,
        "shell_ready": False,
        "overlay_ready": yggdrasil,
        "full_member_ready": dht,
        "swarm_learning_active": vault_count > 0,
        "startup_mode": "ultra_legacy",
        "startup_reason": "python_too_old_for_headless",
        "requirements_profile": "ultra_legacy",
        "recommended_entrypoint": "legacy_bootstrap.py",
        "progression_track": "ultra-legacy",
        "base_progression_mode": "vault-first",
        "progression_mode": "ultra-legacy-local",
        "next_goal": "Lokalen Vault pflegen; mit neuerer Python-Laufzeit spaeter Headless oder Relay-Bruecke ins Aethernet freischalten.",
        "fair_inclusion_path": True,
        "network_end_goal": "FullDht" if is_linux else ("YggdrasilP2P" if is_win_legacy else "RelayBridgeToAethernet"),
        "overlay_path": "ultra-legacy-bootstrap",
        "relay_bridge_required": not is_linux and not is_win_legacy,
        "symbiont_role": "local-symbiont",
        "emergent_network_role": "local-bootstrap",
        "aethernet_goal_message": "LAN ist nicht das Endziel; dieser Knoten bleibt symbiotisch kompatibel und kann spaeter ueber Headless/Relay ins P2P-Aethernet wachsen.",
        "note": "Ultra-Legacy fairness path active.",
        "vault_entry_count": vault_count,
        "updated_at": _timestamp(),
    }


def _backend_payload(network_tier, vault_count):
    payload = {
        "vault_main": vault_count,
        "vault_sub": 0,
        "entropy_mean": 0.0,
        "anchor_count": 0,
        "cpu_pct": 0.0,
        "mem_used_gb": 0.0,
        "swarm_node_count": 0,
        "swarm_reachable_node_count": 0,
        "swarm_pack_count": 0,
        "swarm_candidate_count": 0,
        "swarm_consensus_count": 0,
        "swarm_genesis_key_ok": False,
        "swarm_quorum_reachable": False,
        "swarm_estimated_saving_percent": 0.0,
        "swarm_summary": "Ultra-legacy bootstrap | %s | relay-growth path" % network_tier,
        "capability_score": 0.1,
        "capability_stage": "Basis-Daemon",
        "daemon_mode": "ultra-legacy",
        "startup_mode": "ultra_legacy",
        "startup_reason": "python_too_old_for_headless",
        "requirements_profile": "ultra_legacy",
        "progression_track": "ultra-legacy",
        "base_progression_mode": "vault-first",
        "progression_mode": "ultra-legacy-local",
        "next_goal": "Lokalen Vault pflegen; mit neuerer Python-Laufzeit spaeter Headless oder Relay-Bruecke ins Aethernet freischalten.",
        "network_tier": network_tier,
        "fair_inclusion_path": True,
        "network_end_goal": "RelayBridgeToAethernet",
        "overlay_path": "ultra-legacy-bootstrap",
        "relay_bridge_required": True,
        "symbiont_role": "local-symbiont",
        "emergent_network_role": "local-bootstrap",
        "aethernet_goal_message": "LAN ist nicht das Endziel; dieser Knoten bleibt symbiotisch kompatibel und kann spaeter ueber Headless/Relay ins P2P-Aethernet wachsen.",
        "updated_at": _timestamp(),
    }
    return payload


def _backend_payload_with_learning(network_tier, vault_count, learning_state):
    payload = _backend_payload(network_tier, vault_count)
    if not isinstance(learning_state, dict) or not learning_state:
        return payload

    score = _clamp01(learning_state.get("learning_score", 0.0))
    source = str(learning_state.get("source", "unknown") or "unknown")
    strengths = learning_state.get("known_strengths") or {}
    domains = sorted([str(k) for k in strengths.keys()]) if isinstance(strengths, dict) else []

    payload["ae_learning_score"] = round(score, 4)
    payload["ae_learning_source"] = source
    payload["ae_learning_domains"] = domains
    payload["ae_reconstruction_score"] = round(_clamp01(learning_state.get("reconstruction_score", 0.0)), 4)
    payload["ae_invariant_usage_score"] = round(_clamp01(learning_state.get("invariant_usage_score", 0.0)), 4)
    payload["probe_gate"] = str(learning_state.get("probe_gate", "unknown") or "unknown")
    payload["self_observation_mode"] = str(learning_state.get("self_observation_mode", "stabilize") or "stabilize")
    payload["self_observation_delta"] = round(_safe_float(learning_state.get("self_observation_delta", 0.0), 0.0), 4)
    payload["swarm_learning_active"] = bool(domains) or (vault_count > 0)
    payload["capability_score"] = round(max(0.1, score), 4)
    if domains:
        payload["capability_stage"] = "AE-Legacy-Learning"

    metrics = learning_state.get("metrics") or {}
    if isinstance(metrics, dict):
        payload["entropy_mean"] = round(_safe_float(metrics.get("entropy_shannon", payload.get("entropy_mean", 0.0))), 6)

    payload["anchor_count"] = int(_safe_float(learning_state.get("strong_patterns", payload.get("anchor_count", 0)), 0.0))
    return payload


def _write_snapshot():
    os_platform, network_tier, tier_rank, reason = _detect_profile()
    probe_interval_sec = 1200 if tier_rank <= 1 else 900
    _run_vault_probe_if_available(probe_interval_sec)
    vault_count = _count_files(VAULT_DIR)
    # Identität sicherstellen (idempotent — ändert nichts wenn schon vorhanden)
    identity = _ensure_legacy_identity()
    learning_state = _legacy_learning_tick(identity.get("node_id", ""), network_tier, vault_count)
    _write_json(STARTUP_ROUTE_PATH, _route_payload(os_platform, network_tier, reason))
    _write_json(HW_CAPABILITY_PATH, _hw_payload(os_platform, network_tier, tier_rank, vault_count))
    _write_json(BACKEND_STATE_PATH, _backend_payload_with_learning(network_tier, vault_count, learning_state))
    return identity


# ── Kybernetische Progression (3. Ordnung) ──────────────────────────────── #

def _load_local_strengths():
    """Laedt bekannte Staerken aus blindspot_state.json (graceful, kein Crash)."""
    if json is None:
        return {}
    path = os.path.join(ROOT, "data", "interbus", "blindspot_state.json")
    if not os.path.isfile(path):
        return {}
    try:
        data = json.loads(open(path).read())
        return dict(data.get("known_strengths") or {})
    except Exception:
        return {}


def _save_strengths(new_strengths):
    """Mergt neue Staerken in blindspot_state.json (idempotent, kein Verlust)."""
    if json is None or not new_strengths:
        return
    path = os.path.join(ROOT, "data", "interbus", "blindspot_state.json")
    _safe_makedirs(os.path.dirname(path))
    existing = {}
    if os.path.isfile(path):
        try:
            existing = json.loads(open(path).read())
        except Exception:
            existing = {}
    current = dict(existing.get("known_strengths") or {})
    changed = False
    for domain, val in new_strengths.items():
        try:
            v = float(val)
        except Exception:
            continue
        if v > float(current.get(domain, 0)):
            current[str(domain)] = round(min(1.0, v), 4)
            changed = True
    if not changed:
        return
    existing["known_strengths"] = current
    if "schema" not in existing:
        existing["schema"] = "aether.blindspot.state.v1"
    try:
        f = open(path, "w")
        f.write(json.dumps(existing, ensure_ascii=True, indent=2))
        f.close()
    except Exception:
        pass


def _absorb_gossip_strengths(msgs):
    """Extrahiert Staerken aus empfangenen Gossip-Paketen und speichert sie lokal.

    Das ist der Godel-Boost fuer Legacy-Knoten: jeder empfangene Peer kann
    unsere Faehigkeiten erweitern ohne dass wir selbst die Deps haben.
    """
    if not msgs:
        return
    merged = {}
    for m in msgs:
        if not isinstance(m, dict):
            continue
        # Volle Gossip-Pakete (von Relay uebersetzt)
        legacy_strengths = m.get("legacy_strengths") or {}
        if isinstance(legacy_strengths, dict):
            for dom, val in legacy_strengths.items():
                try:
                    v = float(val)
                    if v > float(merged.get(dom, 0)):
                        merged[str(dom)] = v
                except Exception:
                    pass
        # Direkte Blindspot-Hints → instructions als Staerken extrahieren
        for hint in list(m.get("blindspot_hints") or []):
            if not isinstance(hint, dict):
                continue
            dom = str(hint.get("domain", "") or "")
            boost = float(hint.get("priority_boost") or 0.4)
            if dom and boost > 0:
                if boost > float(merged.get(dom, 0)):
                    merged[dom] = boost
    if merged:
        _save_strengths(merged)
        print("[LEGACY] Staerken aus Gossip gelernt: " + str(sorted(merged.keys())))


def _dht_bootstrap_legacy(node_id, device_fp, tier_rank, relay_pool):
    """Startet DHT-Bootstrap und Legacy-Proto-Discovery fuer diesen Knoten.

    1. DHT-Bootstrap: liest bekannte Knoten, kontaktiert Relays
    2. DNS-Seeds abfragen und Relay-Pool erweitern
    3. Compact-Gossip via legacy_proto.py senden

    Graceful: kein Fehler wenn Module nicht verfuegbar (fehlende Deps).
    """
    _sym_dir = os.path.join(ROOT, "modules")
    if _sym_dir not in sys.path:
        sys.path.insert(0, _sym_dir)

    # DHT-Bootstrap starten (modern Python 3.x auf altem Hardware == kein Problem)
    try:
        from dht_bootstrap import DHTBootstrap as _DHT
        dht = _DHT.instance()
        if not dht._is_running:
            dht.start(node_id)
            print("[LEGACY] DHT-Bootstrap gestartet — node_id=%s" % node_id[:16])
        # Progression-Empfehlung ausgeben
        suggestion = dht.get_network_tier_suggestion()
        print("[LEGACY] Netz-Progression: " + suggestion.get("description", ""))
        print("[LEGACY] Naechster Schritt: " + suggestion.get("next_action", ""))
    except Exception as dht_err:
        print("[LEGACY] DHT-Bootstrap nicht verfuegbar: " + str(dht_err))

    # Legacy-Proto compact-Gossip senden
    if not relay_pool:
        return
    try:
        from legacy_proto import build_packet as _build_pkt
        from legacy_proto import send_packet as _send_pkt
        strengths = _load_local_strengths()
        pkt = _build_pkt(
            node_id=node_id,
            tier_rank=tier_rank,
            device_fp=device_fp[:16],
            relay_urls=relay_pool[:3],
            strengths=strengths or {},
        )
        # An alle bekannten Relays senden
        sent = 0
        for url in relay_pool[:4]:
            try:
                if _send_pkt(url, pkt, timeout=6):
                    sent += 1
            except Exception:
                pass
        if sent > 0:
            print("[LEGACY] Legacy-Proto Gossip gesendet an %d Relay(s)." % sent)
    except Exception as lp_err:
        print("[LEGACY] Legacy-Proto nicht verfuegbar: " + str(lp_err))


def _pull_and_absorb(relay_url, node_id, device_fp, alias_username, relay_pool):
    """Pull-Gossip + Legacy-Proto-Pull + Staerken absorbieren.

    Gibt Liste empfangener Nachrichten zurueck.
    """
    msgs = _relay_gossip_pull_legacy(relay_url)
    # Auch Legacy-Proto-Pull versuchen (fuer Hints und Staerken)
    try:
        _sym_dir = os.path.join(ROOT, "modules")
        if _sym_dir not in sys.path:
            sys.path.insert(0, _sym_dir)
        from legacy_proto import pull_gossip as _pull_legacy
        legacy_msgs = _pull_legacy(relay_url, timeout=6)
        msgs = msgs + legacy_msgs
    except Exception:
        pass
    _absorb_gossip_strengths(msgs)
    return msgs


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    interval = 30
    run_once = False
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--once":
            run_once = True
        elif arg == "--interval" and index + 1 < len(argv):
            index += 1
            try:
                interval = int(argv[index])
            except Exception:
                interval = 30
        index += 1

    print("[LEGACY] Ultra-legacy bootstrap active.")
    identity = _write_snapshot()
    _print_vault_probe_state()
    _print_legacy_learning_state()
    if not isinstance(identity, dict) or not identity:
        identity = _ensure_legacy_identity()
    node_id = identity["node_id"]
    device_fp = identity["device_fingerprint"]
    alias_username = identity["alias_username"]

    os_platform, network_tier, tier_rank, _reason = _detect_profile()

    # modules/ in sys.path fuer alle folgenden Importe
    _sym_dir = os.path.join(ROOT, "modules")
    if _sym_dir not in sys.path:
        sys.path.insert(0, _sym_dir)

    # Symbiont-Engine tick (3. Ordnung) — graceful fallback fuer Win95/98/2000
    try:
        from symbiont_engine import tick as _symbiont_tick
        _hw_cap = {"tier_rank": tier_rank, "native_tier_rank": tier_rank}
        _symbiont_tick(node_id, device_fp, alias_username, _hw_cap)
        print("[LEGACY] Symbiont-Engine Tick (Kybernetischer Schwarm 3. Ordnung) OK.")
    except Exception as _sym_err:
        print("[LEGACY] Symbiont-Engine nicht verfuegbar: " + str(_sym_err))

    # Beim Start: Relay-Pool laden, ersten lebenden Relay auswählen, registrieren.
    relay_pool = _read_relay_pool()
    active_relay = ""
    if relay_pool:
        active_relay = _pick_live_relay_legacy(relay_pool)
        if active_relay:
            _relay_announce(active_relay, node_id, device_fp, alias_username)
            # Pool kann durch die Antwort gewachsen sein — neu lesen
            relay_pool = _read_relay_pool()
        else:
            print("[LEGACY] Kein Relay erreichbar — arbeite offline bis zum nächsten Versuch.")

    # Kein Relay via Pool gefunden — alle Einsprung-Kanaele versuchen:
    # Clearnet (oeffentliche IP + DNS-Seeds), Bluetooth (pybluez), USB/Serial (pyserial)
    if not active_relay:
        try:
            _sym_dir_ec = os.path.join(ROOT, "modules")
            if _sym_dir_ec not in sys.path:
                sys.path.insert(0, _sym_dir_ec)
            from entry_channels import discover_entry as _discover_entry
            print("[LEGACY] Kein Relay im Pool — suche Einsprung via clearnet/bt/usb ...")
            _cid, _rurl, _medium = _discover_entry(relay_pool, timeout=12)
            print("[LEGACY] Einsprung: medium=%s  connection_id=%s" % (_medium, _cid))
            if _rurl:
                _learn_relay_urls_legacy([_rurl])
                relay_pool = _read_relay_pool()
                active_relay = _rurl
                _relay_announce(active_relay, node_id, device_fp, alias_username)
                relay_pool = _read_relay_pool()
                print("[LEGACY] Relay via %s gefunden und registriert: %s" % (_medium, active_relay))
            # entry_medium in account_claim persistieren
            if _cid and json is not None and os.path.isfile(ACCOUNT_CLAIM_PATH):
                try:
                    _claim = json.loads(open(ACCOUNT_CLAIM_PATH).read())
                    if str(_claim.get("entry_medium", "unknown") or "unknown") == "unknown":
                        _claim["entry_medium"] = _medium
                        _write_json(ACCOUNT_CLAIM_PATH, _claim)
                except Exception:
                    pass
        except Exception as _ec_err:
            print("[LEGACY] entry_channels nicht verfuegbar: " + str(_ec_err))

    # DHT-Bootstrap + Legacy-Proto-Gossip automatisch starten
    # Kybernetik: unabhaengig vom Relay-Status — DHT sucht selbst
    _dht_bootstrap_legacy(node_id, device_fp, tier_rank, relay_pool)

    if run_once:
        return 0

    try:
        while True:
            time.sleep(max(5, interval))
            _write_snapshot()
            # Relay-Pool kann sich geändert haben (z.B. neue relay_pool.json durch andere Session)
            relay_pool = _read_relay_pool()
            if relay_pool:
                # Letzten bekannten Relay zuerst — lieber nicht neu suchen wenn er noch lebt
                if active_relay and active_relay in relay_pool:
                    candidates = [active_relay] + [r for r in relay_pool if r != active_relay]
                else:
                    candidates = relay_pool
                live = _pick_live_relay_legacy(candidates)
                if live:
                    active_relay = live
                    _relay_gossip_push_legacy(live, node_id, device_fp, alias_username, relay_pool)
                    msgs = _pull_and_absorb(live, node_id, device_fp, alias_username, relay_pool)
                    if msgs:
                        print("[LEGACY] Gossip empfangen: " + str(len(msgs)) + " Pakete von " + live)
            # Periodisch DHT-Bootstrap wiederholen wenn zu wenig Peers bekannt
            try:
                from dht_bootstrap import DHTBootstrap as _DHT2
                if _DHT2.instance()._total_peers() < 3:
                    _dht_bootstrap_legacy(node_id, device_fp, tier_rank, relay_pool)
            except Exception:
                pass
    except KeyboardInterrupt:
        print("[LEGACY] Stopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())