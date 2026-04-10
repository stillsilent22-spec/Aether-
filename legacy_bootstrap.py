from __future__ import print_function

import hashlib
import os
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
            "native_ygg_bound": False,
            "created_at": ts,
        })
    elif json is not None:
        # Backfill identity_lock and network_entry_id if still empty from
        # an older bootstrap run that pre-dates this fix.
        try:
            claim = json.loads(open(ACCOUNT_CLAIM_PATH).read())
            updated = False
            if not str(claim.get("network_entry_id", "") or "").strip():
                claim["network_entry_id"] = network_entry_id
                updated = True
            if not str(claim.get("identity_lock", "") or "").strip():
                claim["identity_lock"] = identity_lock
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
    system = sys.platform.lower()
    release, version = _platform_release()
    if system.startswith("win"):
        if release in ("95", "98", "me") or version.startswith("4."):
            return "Win9x", "LocalOnly", 0, "win9x_ultra_legacy_bootstrap"
        if release == "2000":
            return "Win2000", "LanBeacon", 1, "python_too_old_for_headless"
        return "WinLegacy", "LocalOnly", 0, "python_too_old_for_headless"
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
    return {
        "os_platform": os_platform,
        "network_tier": network_tier,
        "native_network_tier": network_tier,
        "tier_rank": tier_rank,
        "native_tier_rank": tier_rank,
        "vault_bootstrap_only": True,
        "lan_beacon": network_tier == "LanBeacon",
        "lan_p2p": False,
        "yggdrasil": False,
        "dht": False,
        "runtime": "ultra-legacy-bootstrap",
        "shell_capable": False,
        "progressive_network_unlock": True,
        "capability_percent": 0.1,
        "capability_stage": "Basis-Daemon",
        "capability_stage_index": 0,
        "shell_ready": False,
        "overlay_ready": False,
        "full_member_ready": False,
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
        "network_end_goal": "RelayBridgeToAethernet",
        "overlay_path": "ultra-legacy-bootstrap",
        "relay_bridge_required": True,
        "symbiont_role": "local-symbiont",
        "emergent_network_role": "local-bootstrap",
        "aethernet_goal_message": "LAN ist nicht das Endziel; dieser Knoten bleibt symbiotisch kompatibel und kann spaeter ueber Headless/Relay ins P2P-Aethernet wachsen.",
        "note": "Ultra-Legacy fairness path active.",
        "vault_entry_count": vault_count,
        "updated_at": _timestamp(),
    }


def _backend_payload(network_tier, vault_count):
    return {
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


def _write_snapshot():
    os_platform, network_tier, tier_rank, reason = _detect_profile()
    vault_count = _count_files(VAULT_DIR)
    # Identität sicherstellen (idempotent — ändert nichts wenn schon vorhanden)
    identity = _ensure_legacy_identity()
    _write_json(STARTUP_ROUTE_PATH, _route_payload(os_platform, network_tier, reason))
    _write_json(HW_CAPABILITY_PATH, _hw_payload(os_platform, network_tier, tier_rank, vault_count))
    _write_json(BACKEND_STATE_PATH, _backend_payload(network_tier, vault_count))


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
    _write_snapshot()
    identity = _ensure_legacy_identity()
    node_id = identity["node_id"]
    device_fp = identity["device_fingerprint"]
    alias_username = identity["alias_username"]

    os_platform, network_tier, tier_rank, _reason = _detect_profile()

    # Symbiont-Engine tick (3. Ordnung) — graceful fallback fuer Win95/98/2000
    try:
        _sym_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules")
        if _sym_dir not in sys.path:
            sys.path.insert(0, _sym_dir)
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
                    msgs = _relay_gossip_pull_legacy(live)
                    if msgs:
                        print("[LEGACY] Gossip empfangen: " + str(len(msgs)) + " Pakete von " + live)
    except KeyboardInterrupt:
        print("[LEGACY] Stopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())