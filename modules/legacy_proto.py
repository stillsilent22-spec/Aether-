"""
legacy_proto.py — Ultra-Legacy Gossip-Protokoll fuer Aether
============================================================

ZWECK: Ermoeglicht Knoten auf Windows 95/98/2000/XP (Python 2.4+) eine
vollwertige Teilnahme am Aether-Schwarm ohne:
  - Yggdrasil
  - Ed25519 / cryptography-Modul
  - Mehr als 512 Bytes pro Gossip-Paket (Bandbreiten-Schutz)
  - Komplexe Abhaengigkeiten

PROTOKOLL:

  Paket-Format (JSON, max. ~512 Bytes):
  {
    "s":  "ap1",          # schema "aether.legacy.proto.v1" kuerzform
    "n":  "<node_id>",    # 16 hex chars
    "t":  <unix_ts>,      # float
    "tr": <tier_rank>,    # int 0-4
    "fp": "<dev_fp>",     # 16 chars device fingerprint
    "ru": ["url", ...],   # relay_urls list (max 3)
    "bs": [               # blindspot_signals (max 2, zusammengekuerzt)
      {"sid": "...", "dom": "...", "prio": 5}
    ],
    "bh": [               # blindspot_hints relay (max 2, kurzform)
      {"sid": "...", "dom": "...", "ins": "...", "hop": 1}
    ],
    "st": {               # strengths (max 3 Domaenen)
      "domain": 0.8
    }
  }

  Jedes Feld ist optional ausser "s" und "n".
  Gesamt-Budget: 512 Bytes.

INTEGRATION:
  - Wird von legacy_bootstrap.py genutzt um mit Relay-Bruecken zu kommunizieren
  - Relay-Bruecken (moderne Aether-Knoten) uebersetzt zwischen diesem Protokoll
    und dem vollen aether.swarm.p2p.gossip.v1 Schema
  - aethernet_transport.py nimmt Legacy-Pakete auf /gossip/legacy endpoint an

KYBERNETIK:
  - Strengths werden geteilt → Peers koennen Blindspot-Hints liefern
  - Blindspot-Signals werden geteilt → Schwarm erkennt was fehlt
  - Relay-Broadcast: Hints werden mit hop-counter weitergetragen
  - Progression: wenn Legacy-Knoten Hints empfaengt, wachsen seine Staerken
    → naechstes Mal kann er anderen helfen (Godel-Boost auf Win95)

Python 2.4 Kompatibilitaets-Notizen:
  - Keine f-strings (% statt)
  - Keine pathlib (os.path statt)
  - Kein 'with' statement in Py < 2.5 auf manchen Implementierungen
    → try/finally statt
  - json nicht in stdlib vor 2.6 → simplejson Fallback
  - socket.create_connection erst ab 2.6 → direkte socket.connect statt
"""
from __future__ import print_function

import hashlib
import os
import socket
import sys
import time

# JSON: stdlib (2.6+) oder simplejson (2.4+) oder repr-Fallback
try:
    import json as _json
    def _dumps(obj):
        return _json.dumps(obj, ensure_ascii=True, separators=(',', ':'))
    def _loads(s):
        return _json.loads(s)
except ImportError:
    try:
        import simplejson as _json
        def _dumps(obj):
            return _json.dumps(obj)
        def _loads(s):
            return _json.loads(s)
    except ImportError:
        _json = None
        def _dumps(obj):
            # Minimaler Fallback fuer Win95 ohne json/simplejson
            # Erzeugt gueltiges JSON fuer einfache dicts/lists/strings/numbers
            return repr(obj).replace("'", '"').replace("True", "true").replace("False", "false").replace("None", "null")
        def _loads(s):
            raise ImportError("json nicht verfuegbar")


# ── Protokoll-Konstanten ─────────────────────────────────────────────────── #

SCHEMA_SHORT    = "ap1"           # Kurzform fuer "aether.legacy.proto.v1"
MAX_PACKET_BYTES = 480            # Konservatives Budget unter 512 Bytes
MAX_RELAY_URLS   = 3
MAX_BS_SIGNALS   = 2
MAX_BS_HINTS     = 2
MAX_STRENGTHS    = 3
RELAY_MAX_HOPS   = 3              # Identisch mit modules/blindspot_engine.py


# ── Paket bauen ──────────────────────────────────────────────────────────── #

def build_packet(
    node_id,
    tier_rank=0,
    device_fp="",
    relay_urls=None,
    blindspot_signals=None,
    blindspot_hints=None,
    strengths=None,
):
    """Baut ein kompaktes Legacy-Gossip-Paket (<= MAX_PACKET_BYTES Bytes).

    Felder werden nach Budget-Prioritaet eingefuegt:
      1. Pflicht:   s, n, t
      2. Wichtig:   tr, fp, ru (Relay-URLs)
      3. Ergaenzend: st (Staerken), bh (Hint-Relay), bs (Gap-Signale)

    Gibt den JSON-String zurueck.
    """
    ts = time.time()
    pkt = {
        "s": SCHEMA_SHORT,
        "n": str(node_id)[:16],
        "t": round(ts, 1),
    }
    if tier_rank:
        pkt["tr"] = int(tier_rank)
    if device_fp:
        pkt["fp"] = str(device_fp)[:16]

    # Relay-URLs (wichtig fuer Peer-Discovery)
    if relay_urls:
        urls = [str(u)[:80] for u in list(relay_urls)[:MAX_RELAY_URLS] if str(u).startswith(("http://", "https://"))]
        if urls:
            pkt["ru"] = urls

    # Staerken (damit andere Peers unsere Gaps schliessen koennen)
    if strengths and isinstance(strengths, dict):
        top = sorted(strengths.items(), key=lambda kv: -float(kv[1]))[:MAX_STRENGTHS]
        pkt["st"] = {str(k)[:24]: round(float(v), 2) for k, v in top}

    # Blindspot-Hints weiterleiten (flood-relay)
    if blindspot_hints:
        short_hints = []
        for h in list(blindspot_hints)[:MAX_BS_HINTS]:
            hop = int(h.get("relay_hop") or h.get("hop") or 0)
            if hop >= RELAY_MAX_HOPS:
                continue
            short_hints.append({
                "sid": str(h.get("signal_id", ""))[:16],
                "dom": str(h.get("domain", ""))[:20],
                "ins": str(h.get("instructions", ""))[:60],
                "hop": hop + 1,
            })
        if short_hints:
            pkt["bh"] = short_hints

    # Blindspot-Signale (eigene Gaps melden)
    if blindspot_signals:
        short_sigs = []
        for s in list(blindspot_signals)[:MAX_BS_SIGNALS]:
            short_sigs.append({
                "sid": str(s.get("signal_id", ""))[:16],
                "dom": str(s.get("domain", ""))[:20],
                "prio": int(s.get("priority", 5)),
            })
        if short_sigs:
            pkt["bs"] = short_sigs

    # Budget pruefen — wenn ueber Limit, Felder entfernen
    raw = _dumps(pkt)
    if len(raw.encode("utf-8")) > MAX_PACKET_BYTES:
        # Erst Signals entfernen (weniger kritisch fuer Routing)
        pkt.pop("bs", None)
        raw = _dumps(pkt)
    if len(raw.encode("utf-8")) > MAX_PACKET_BYTES:
        # Dann Hints entfernen
        pkt.pop("bh", None)
        raw = _dumps(pkt)
    if len(raw.encode("utf-8")) > MAX_PACKET_BYTES:
        # Dann Staerken kuerzen
        pkt.pop("st", None)
        raw = _dumps(pkt)

    return raw


# ── Paket parsen ─────────────────────────────────────────────────────────── #

def parse_packet(raw):
    """Parst ein Legacy-Paket und gibt strukturierte Felder zurueck.

    Gibt None zurueck wenn das Paket ungueltiges Format hat.
    Alle Felder sind defensiv geparst — kein Fehler stoerzt ab.
    """
    if _json is None and str is type(raw):
        return None
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        data = _loads(raw)
    except Exception:
        return None

    if not isinstance(data, dict):
        return None
    schema = str(data.get("s", "") or "")
    if schema not in (SCHEMA_SHORT, "aether.legacy.proto.v1"):
        return None

    node_id = str(data.get("n", "") or "").strip()
    if not node_id:
        return None

    return {
        "node_id":          node_id,
        "ts":               float(data.get("t", time.time()) or time.time()),
        "tier_rank":        int(data.get("tr", 0) or 0),
        "device_fp":        str(data.get("fp", "") or ""),
        "relay_urls":       [str(u) for u in list(data.get("ru") or []) if str(u).startswith(("http://", "https://"))],
        "strengths":        {str(k): float(v) for k, v in (data.get("st") or {}).items()},
        "blindspot_hints":  _expand_hints(list(data.get("bh") or [])),
        "blindspot_signals": _expand_signals(list(data.get("bs") or [])),
    }


def _expand_hints(short_list):
    """Macht aus Legacy-Kurzformat vollstaendige Blindspot-Hint-Dicts."""
    result = []
    now = time.time()
    for h in short_list:
        if not isinstance(h, dict):
            continue
        sid = str(h.get("sid", "") or "")
        dom = str(h.get("dom", "") or "")
        ins = str(h.get("ins", "") or "")
        hop = int(h.get("hop", 1) or 1)
        if not sid or not dom:
            continue
        result.append({
            "schema":        "aether.blindspot.hint.v1",
            "hint_id":       "legacy-" + hashlib.sha256((sid + dom + ins).encode("utf-8") if sys.version_info[0] >= 3 else (sid + dom + ins)).hexdigest()[:16],
            "signal_id":     sid,
            "from_peer":     "legacy-relay",
            "domain":        dom,
            "hint_type":     "instruction",
            "payload_hash":  hashlib.sha256(ins.encode("utf-8") if sys.version_info[0] >= 3 else ins).hexdigest(),
            "instructions":  ins,
            "fingerprints":  [],
            "priority_boost": 0.4,
            "ts":            round(now, 3),
            "relay_hop":     hop,
        })
    return result


def _expand_signals(short_list):
    """Macht aus Legacy-Kurzformat vollstaendige Blindspot-Signal-Dicts."""
    result = []
    now = time.time()
    for s in short_list:
        if not isinstance(s, dict):
            continue
        sid = str(s.get("sid", "") or "")
        dom = str(s.get("dom", "") or "")
        prio = int(s.get("prio", 5) or 5)
        if not sid or not dom:
            continue
        result.append({
            "schema":      "aether.blindspot.signal.v1",
            "signal_id":   sid,
            "domain":      dom,
            "gap_type":    "knowledge_gap",
            "description": "Gap von Legacy-Knoten: " + dom,
            "priority":    prio,
            "created_ts":  round(now, 3),
            "last_broadcast_ts": round(now, 3),
            "hint_count":  0,
            "resolved":    False,
            "resolved_ts": 0.0,
            "resolved_by": "",
            "metadata":    {"legacy_source": True},
        })
    return result


# ── HTTP-Transport (Python 2.4+ kompatibel) ─────────────────────────────── #

def send_packet(relay_url, packet_str, timeout=8):
    """Sendet ein Legacy-Paket an einen Relay-Knoten.

    POST /gossip/legacy — Relay uebersetzt es ins volle Schema.
    Python 2.4 kompatibel: manuelle socket-basierte HTTP-Anfrage.
    """
    if not relay_url or not packet_str:
        return False

    # Versuche zuerst urllib (einfacher)
    try:
        if sys.version_info >= (2, 6):
            return _send_via_urllib(relay_url, packet_str, timeout)
    except Exception:
        pass

    # Fallback: manuelle Socket-Verbindung (Python 2.4)
    try:
        return _send_via_socket(relay_url, packet_str, timeout)
    except Exception:
        return False


def _send_via_urllib(relay_url, packet_str, timeout):
    body = packet_str.encode("utf-8") if sys.version_info[0] >= 3 else packet_str
    target = relay_url.rstrip("/") + "/gossip/legacy"
    if sys.version_info[0] >= 3:
        import urllib.request as _ureq
        req = _ureq.Request(
            target,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        handle = _ureq.urlopen(req, timeout=timeout)
        try:
            return 200 <= handle.status < 300
        finally:
            handle.close()
    else:
        import urllib2 as _u2
        req = _u2.Request(target, body, {"Content-Type": "application/json"})
        resp = _u2.urlopen(req, timeout=timeout)
        code = resp.getcode()
        resp.close()
        return 200 <= code < 300


def _send_via_socket(relay_url, packet_str, timeout):
    """Manuelle HTTP-POST-Anfrage via raw socket (Python 2.4 Fallback)."""
    if relay_url.startswith("https://"):
        return False  # kein TLS ohne stdlib-Support
    # URL parsen: http://host:port/path
    url = relay_url.rstrip("/") + "/gossip/legacy"
    host, path = _parse_http_url(url)
    if not host:
        return False

    port = 80
    if ":" in host:
        parts = host.rsplit(":", 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except Exception:
            port = 80

    body = packet_str.encode("utf-8") if sys.version_info[0] >= 3 else packet_str
    header = (
        "POST " + path + " HTTP/1.0\r\n"
        "Host: " + host + "\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + str(len(body)) + "\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    raw_header = header.encode("ascii") if sys.version_info[0] >= 3 else header

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(raw_header + body)
        response = b""
        while True:
            chunk = sock.recv(256)
            if not chunk:
                break
            response += chunk
            if len(response) > 512:
                break
    finally:
        sock.close()

    response_str = response.decode("utf-8", errors="replace") if sys.version_info[0] >= 3 else response
    first_line = response_str.split("\n")[0]
    try:
        code = int(first_line.split(" ")[1])
        return 200 <= code < 300
    except Exception:
        return False


def _parse_http_url(url):
    """Zerlegt http://host:port/path in (host_with_port, path)."""
    if not url.startswith("http://"):
        return "", "/"
    rest = url[7:]
    slash = rest.find("/")
    if slash == -1:
        return rest, "/"
    return rest[:slash], rest[slash:]


def pull_gossip(relay_url, timeout=8):
    """Holt Legacy-Gossip-Pakete vom Relay (GET /gossip/legacy/latest).

    Gibt Liste geparster Pakete zurueck.
    """
    target = relay_url.rstrip("/") + "/gossip/legacy/latest"
    raw_data = None
    try:
        if sys.version_info >= (2, 6):
            if sys.version_info[0] >= 3:
                import urllib.request as _ureq
                resp = _ureq.urlopen(target, timeout=timeout)
                try:
                    raw_data = resp.read().decode("utf-8")
                finally:
                    resp.close()
            else:
                import urllib2 as _u2
                resp = _u2.urlopen(target, timeout=timeout)
                raw_data = resp.read()
                resp.close()
    except Exception:
        return []

    if not raw_data:
        return []
    try:
        data = _loads(raw_data)
        msgs = list(data.get("packets") or data.get("messages") or [])
        result = []
        for m in msgs:
            if isinstance(m, dict):
                # Schon geparst (volle Gossip-Pakete vom Relay-Uebersetzer)
                result.append(m)
            elif isinstance(m, str):
                parsed = parse_packet(m)
                if parsed:
                    result.append(parsed)
        return result
    except Exception:
        return []


# ── Relay-Uebersetzer-Integration ────────────────────────────────────────── #
# Wird von aethernet_transport.py aufgerufen wenn POST /gossip/legacy eingeht.

def translate_to_full_gossip(legacy_packet_str, relay_node_id="relay"):
    """Uebersetzt ein Legacy-Paket in das volle aether.swarm.p2p.gossip.v1-Schema.

    Wird von Relay-Knoten (moderne Aether-Nodes) aufgerufen um Legacy-Knoten
    als vollwertige Swarm-Mitglieder zu integrieren.
    Gibt None zurueck bei ungueltigen Paketen.
    """
    parsed = parse_packet(legacy_packet_str)
    if not parsed:
        return None

    node_id   = parsed["node_id"]
    tier_rank = parsed["tier_rank"]

    full = {
        "schema":       "aether.swarm.p2p.gossip.v1",
        "node_id":      node_id,
        "fingerprints": [],
        "metrics_summary": {
            "network_tier":     _tier_name(tier_rank),
            "tier_rank":        tier_rank,
            "relay_bridge_mode": True,
        },
        "is_genesis_node":    False,
        "relay_bridge_mode":  True,
        "known_relay_urls":   parsed["relay_urls"],
        "legacy_proto":       True,
        "legacy_ts":          parsed["ts"],
        "legacy_device_fp":   parsed["device_fp"],
    }

    # Blindspot-Signale und Hints uebergeben
    if parsed["blindspot_hints"]:
        full["blindspot_hints"] = parsed["blindspot_hints"]
    if parsed["blindspot_signals"]:
        full["blindspot_signals"] = parsed["blindspot_signals"]

    # Staerken als Gossip-Metriken uebergeben
    if parsed["strengths"]:
        full["legacy_strengths"] = parsed["strengths"]

    return full


def _tier_name(tier_rank):
    names = {0: "LocalOnly", 1: "LanBeacon", 2: "RelayBridge", 3: "Swarm", 4: "AetherOS"}
    return names.get(int(tier_rank), "LocalOnly")


# ── Standalone-Test ──────────────────────────────────────────────────────── #

if __name__ == "__main__":
    test_pkt = build_packet(
        node_id="abc123def456abc1",
        tier_rank=0,
        device_fp="fp1234567890",
        relay_urls=["http://relay1.example.com:7385"],
        strengths={"numpy": 0.9, "rust_shell": 0.0},
        blindspot_signals=[{
            "signal_id": "cap-abcd1234",
            "domain": "numpy",
            "priority": 8,
        }],
    )
    print("[legacy_proto] Test-Paket (%d Bytes): %s" % (len(test_pkt.encode("utf-8")), test_pkt))
    parsed = parse_packet(test_pkt)
    print("[legacy_proto] Geparst:", parsed)
    assert parsed is not None
    assert parsed["node_id"] == "abc123def456abc1"
    assert len(test_pkt.encode("utf-8")) <= MAX_PACKET_BYTES
    print("[legacy_proto] Alle Tests bestanden.")
