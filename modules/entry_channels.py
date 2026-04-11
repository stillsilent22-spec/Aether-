"""
entry_channels.py — Universale Einsprung-Wege ins AetherNet
============================================================

KONZEPT:
  Egal ueber welchen Kanal ein Knoten ins Netz kommt — er landet immer
  im selben AetherNet und bekommt eine stabile, einmalig erzeugte Identitaet.

  Jeder Kanal produziert:
    connection_id — eindeutiger Bezeichner des Einstiegspunkts
    relay_url     — HTTP-URL eines erreichbaren Relay-Knotens (oder leer)
    medium        — Kanal-Tag ("lan", "clearnet", "bluetooth", "usb_serial", "relay")

  Die connection_id fliesst direkt in universal_identity.build_full_identity()
  und bestimmt so den hardware+netz-gebundenen Keypair des Knotens.

KANAELE (in Prioritaetsreihenfolge):
  1. LAN         — UDP Multicast 239.255.42.7:7742 (sofort, kein Config noetig)
  2. Relay-Pool  — direkt bekannte Relay-URLs (bereits konfiguriert)
  3. Clearnet    — oeffentliche IP + DNS-Seeds + Relay-HTTP-Discovery
  4. Bluetooth   — RFCOMM-Scan nach AETHER_BT_SERVICE_UUID (pybluez optional)
  5. USB/Serial  — Serieller Port mit AETHER_PING/PONG Protokoll (pyserial optional)

SICHERHEIT:
  - Nur "http://" und "https://" Relay-URLs werden akzeptiert
  - BT: nur Geraete die den AETHER_BT_SERVICE_UUID annoncieren
  - Alle Kanaele produzieren connection_id fuer Identity-Ableitung
  - Keine privaten Daten werden uebertragen

OFFLINE-FALLBACK:
  - Kein Kanal erreichbar -> ("local:offline", "", "unknown")
  - Der Knoten hat trotzdem eine Identitaet (rein HW-basiert)
  - Sobald Netz verfuegbar: discover_entry() erneut aufrufen

Python 2.6+ kompatibel: keine f-strings, keine Type-Hints, keine pathlib, keine walrus-ops.
"""
from __future__ import print_function

import hashlib
import os
import socket
import sys
import time

# JSON: stdlib (2.6+) oder simplejson (2.4+) Fallback
try:
    import json as _json_mod
    def _jloads(s):
        return _json_mod.loads(s)
    def _jdumps(o):
        return _json_mod.dumps(o, ensure_ascii=True, separators=(",", ":"))
except ImportError:
    try:
        import simplejson as _sjson
        def _jloads(s):
            return _sjson.loads(s)
        def _jdumps(o):
            return _sjson.dumps(o)
    except ImportError:
        _jloads = None
        _jdumps = None

# ── Konstanten ────────────────────────────────────────────────────────────── #

LAN_MULTICAST_GROUP  = "239.255.42.7"
LAN_MULTICAST_PORT   = 7742
AETHER_GOSSIP_PORT   = 7385

# Bluetooth: UUID der Aether-RFCOMM Service Discovery
AETHER_BT_SERVICE_UUID = "ae71e200-aet4-4ae1-b0b0-aether00net1"

# Oeffentliche IP-Reflection Dienste (nur IP, kein Cookie, kein Tracking)
_IP_REFLECT_URLS = [
    "http://api4.ipify.org",
    "http://ifconfig.me/ip",
    "http://icanhazip.com",
    "http://checkip.amazonaws.com",
]

# Standard DNS-Seeds (HTTP /seeds.json Fallback)
_DEFAULT_DNS_SEEDS = [
    "seed1.aethernet.io",
    "seed2.aethernet.io",
    "aether-seed.duckdns.org",
]


# ── HTTP-Hilfsfunktionen (Python 2.6+ kompatibel) ───────────────────────── #

def _safe_url(url):
    """Gibt URL zurueck wenn sie http(s) ist — sonst leer."""
    u = str(url or "").strip()
    if u.startswith("http://") or u.startswith("https://"):
        return u
    return ""


def _http_get(url, timeout=5):
    """Einfacher HTTP GET. Gibt Text-Antwort oder None zurueck."""
    try:
        if sys.version_info[0] >= 3:
            import urllib.request as _ureq
            req = _ureq.Request(
                url,
                headers={"User-Agent": "AetherNode/1.0"},
            )
            with _ureq.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", "ignore")
        else:
            import urllib2 as _u2
            req = _u2.Request(
                url,
                headers={"User-Agent": "AetherNode/1.0"},
            )
            resp = _u2.urlopen(req, timeout=timeout)
            return resp.read()
    except Exception:
        return None


def _relay_alive(relay_url, timeout=4):
    """Gibt True zurueck wenn der Relay-Server antwortet."""
    check = relay_url.rstrip("/") + "/gossip/latest"
    return _http_get(check, timeout=timeout) is not None


def _url_hash(url):
    """Kurzgehash einer URL fuer connection_id."""
    raw = str(url)
    if sys.version_info[0] >= 3:
        raw = raw.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


# ── Kanal 1: LAN (UDP Multicast) ────────────────────────────────────────── #

def try_lan_entry(timeout=2.0):
    """Schickt UDP-Multicast-Ping und wartet kurz auf Antworten.

    Gibt (connection_id, relay_url) oder ("", "") zurueck.
    connection_id = "lan:<subnet>" (erste 3 Oktette des Absender-IP)
    relay_url     = "http://<sender_ip>:<port>" falls Absender HTTP-Port meldet
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        ping_body = '{"type":"aether_ping"}'
        if sys.version_info[0] >= 3:
            ping_body = ping_body.encode("utf-8")
        sock.sendto(ping_body, (LAN_MULTICAST_GROUP, LAN_MULTICAST_PORT))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
                sender_ip = str(addr[0])
                subnet = ".".join(sender_ip.split(".")[:3])
                connection_id = "lan:" + subnet
                relay_url = ""
                if _jloads is not None:
                    try:
                        if sys.version_info[0] >= 3 and isinstance(data, bytes):
                            data = data.decode("utf-8", "ignore")
                        msg = _jloads(data)
                        p = int(msg.get("port", 0) or 0)
                        if 1024 <= p <= 65535:
                            relay_url = "http://" + sender_ip + ":" + str(p)
                    except Exception:
                        pass
                if not relay_url:
                    # Versuche Aether-Standard-Port
                    candidate = "http://" + sender_ip + ":" + str(AETHER_GOSSIP_PORT)
                    if _relay_alive(candidate, timeout=1):
                        relay_url = candidate
                sock.close()
                return connection_id, relay_url
            except socket.timeout:
                break
            except Exception:
                break
        sock.close()
    except Exception:
        pass
    return "", ""


# ── Kanal 2 und 3: Relay-Pool + Clearnet ─────────────────────────────────── #

def _reflect_public_ip(timeout=4):
    """Ermittelt oeffentliche IP ueber Reflection-Dienste. Gibt "" zurueck wenn offline."""
    for url in _IP_REFLECT_URLS:
        text = _http_get(url, timeout=timeout)
        if text:
            ip = str(text).strip().split("\n")[0].strip()
            # Einfache Plausibilitaets-Pruefung: 3 Punkte (IPv4) oder Doppelpunkte (IPv6)
            if 6 < len(ip) < 40 and " " not in ip:
                return ip
    return ""


def try_clearnet_entry(relay_pool=None, dns_seeds=None, timeout=10):
    """Versucht Clearnet-Einstieg:
      1. Oeffentliche IP via Reflection-Dienst ermitteln
      2. Bekannte Relay-Pool-URLs testen
      3. DNS-Seeds nach Relay-URLs befragen

    Gibt (connection_id, relay_url) oder ("", "") zurueck.
    connection_id = "clearnet:<public_ip>" oder "relay:<url_hash>"
    """
    if relay_pool is None:
        relay_pool = []
    if dns_seeds is None:
        dns_seeds = list(_DEFAULT_DNS_SEEDS)

    short_to = min(timeout, 4)

    # Schritt 1: oeffentliche IP
    public_ip = _reflect_public_ip(timeout=short_to)
    connection_id = "clearnet:" + public_ip if public_ip else ""

    # Schritt 2: bekannte Relay-Pool-URLs
    for rel in relay_pool:
        u = _safe_url(rel)
        if u and _relay_alive(u, timeout=short_to):
            if not connection_id:
                connection_id = "relay:" + _url_hash(u)
            return connection_id, u

    # Schritt 3: DNS-Seeds
    for host in dns_seeds:
        seed_url = "http://" + host + "/seeds.json"
        text = _http_get(seed_url, timeout=short_to)
        if text and _jloads is not None:
            try:
                data = _jloads(text)
                urls = list(data.get("relay_urls") or data.get("urls") or [])
                for url_raw in urls:
                    u = _safe_url(str(url_raw))
                    if u and _relay_alive(u, timeout=short_to):
                        if not connection_id:
                            connection_id = "relay:" + _url_hash(u)
                        return connection_id, u
            except Exception:
                pass

    return connection_id, ""


# ── Kanal 4: Bluetooth (pybluez, optional) ──────────────────────────────── #

def try_bluetooth_entry(timeout=8):
    """Scannt Bluetooth-Umgebung nach Aether-Nodes.

    Benoetigt pybluez (pip install pybluez). Graceful skip wenn nicht installiert.
    Gibt (connection_id, relay_url) oder ("", "") zurueck.
    connection_id = "bt:<local_bt_mac>"
    relay_url     = "" (BT hat kein HTTP — Relay-URL muss ueber Gossip
                        nachgeliefert werden sobald BT-Verbindung besteht)
    """
    try:
        import bluetooth as _bt  # pybluez
    except ImportError:
        return "", ""

    local_mac = ""
    try:
        local_mac = _bt.read_local_bdaddr()
    except Exception:
        pass

    connection_id = "bt:" + local_mac if local_mac else "bt:unknown"

    try:
        nearby = _bt.discover_devices(
            duration=min(timeout, 6),
            lookup_names=True,
            flush_cache=True,
        )
        for addr, _name in nearby:
            if not addr:
                continue
            try:
                services = _bt.find_service(uuid=AETHER_BT_SERVICE_UUID, address=addr)
            except Exception:
                services = []
            for svc in (services or []):
                port = svc.get("port", 0)
                host = svc.get("host", addr)
                if port:
                    # Gefunden: Aether-Node per BT entdeckt
                    # Verbindung aufbauen (RFCOMM) ist hier nicht noetig —
                    # die connection_id reicht fuer Identitaets-Ableitung.
                    # relay_url kommt spaeter ueber Gossip.
                    print("[entry_channels/bt] Aether-Node gefunden: %s Port %s" % (host, port))
                    return connection_id, ""
        return connection_id, ""
    except Exception:
        return connection_id, ""


# ── Kanal 5: USB/Serial (pyserial, optional) ─────────────────────────────── #

def try_usb_serial_entry(timeout=5):
    """Scannt serielle Ports nach einem Aether-Relay-Echo.

    Sendet "AETHER_PING\\n", erwartet "AETHER_PONG" in der Antwort.
    Benoetigt pyserial. Graceful skip wenn nicht installiert.
    Gibt (connection_id, relay_url) oder ("", "") zurueck.
    """
    try:
        import serial
        import serial.tools.list_ports as _lp
    except ImportError:
        return "", ""

    candidates = []
    try:
        candidates = [str(p.device) for p in _lp.comports()]
    except Exception:
        # Fallback: gaengige Pfade
        for _dev in ["/dev/ttyUSB0", "/dev/ttyACM0", "/dev/ttyS0",
                     "/dev/cu.usbserial-0001", "COM1", "COM2", "COM3", "COM4"]:
            if sys.platform == "win32" or os.path.exists(_dev):
                candidates.append(_dev)

    short_to = min(timeout, 3)
    for dev in candidates[:8]:
        try:
            ser = serial.Serial(dev, baudrate=9600, timeout=short_to)
            ser.write(b"AETHER_PING\n")
            deadline = time.time() + short_to
            response = b""
            while time.time() < deadline:
                chunk = ser.read(256)
                if chunk:
                    response += chunk
                    if b"AETHER_PONG" in response:
                        break
            ser.close()
            if b"AETHER_PONG" in response:
                dev_id = dev.replace("/", "_").replace("\\", "_").strip("_")
                connection_id = "usb:" + dev_id
                relay_url = ""
                if _jloads is not None:
                    try:
                        if sys.version_info[0] >= 3:
                            txt = response.decode("utf-8", "ignore")
                        else:
                            txt = response
                        for line in txt.split("\n"):
                            if "AETHER_PONG" in line:
                                idx = line.index("AETHER_PONG") + len("AETHER_PONG")
                                trailer = line[idx:].strip()
                                if trailer:
                                    pong = _jloads(trailer)
                                    relay_url = _safe_url(str(pong.get("relay_url", "") or ""))
                                break
                    except Exception:
                        pass
                return connection_id, relay_url
        except Exception:
            continue

    return "", ""


# ── Haupt-Dispatcher ─────────────────────────────────────────────────────── #

def discover_entry(relay_pool=None, dns_seeds=None, timeout=15):
    """Versucht alle verfuegbaren Einsprung-Kanaele und gibt ersten Treffer zurueck.

    Reihenfolge (Geschwindigkeit / Wahrscheinlichkeit):
      1. LAN      — UDP Multicast, kein Config, sehr schnell
      2. Relay    — bekannter Pool, direkt erreichbar
      3. Clearnet — oeffentliche IP + DNS-Seeds (braucht Internetzugang)
      4. Bluetooth— pybluez optional
      5. USB/Serial — pyserial optional

    Gibt (connection_id, relay_url, medium) zurueck.
    Offline-Fallback: ("local:offline", "", "unknown")
    Die connection_id wird immer zurueckgegeben — auch wenn kein relay_url
    gefunden wurde. Sie reicht fuer die Identitaets-Ableitung.
    """
    try:
        from modules import universal_identity as _uid
        _med = _uid
    except ImportError:
        # Fallback: lokale Konstanten
        class _med:
            MEDIUM_LAN      = "lan"
            MEDIUM_RELAY    = "relay"
            MEDIUM_CLEARNET = "clearnet"
            MEDIUM_BT       = "bluetooth"
            MEDIUM_USB      = "usb_serial"
            MEDIUM_UNKNOWN  = "unknown"

    if relay_pool is None:
        relay_pool = []
    if dns_seeds is None:
        dns_seeds = list(_DEFAULT_DNS_SEEDS)

    # 1. LAN
    cid, rurl = try_lan_entry(timeout=2.0)
    if cid:
        return cid, rurl, _med.MEDIUM_LAN

    # 2. Bekannter Relay-Pool
    for rel in relay_pool:
        u = _safe_url(rel)
        if u and _relay_alive(u, timeout=4):
            h = _url_hash(u)
            return "relay:" + h, u, _med.MEDIUM_RELAY

    # 3. Clearnet (oeffentliche IP + DNS-Seeds)
    inet_to = max(4, timeout - 4)
    cid, rurl = try_clearnet_entry(relay_pool, dns_seeds, timeout=inet_to)
    if cid:
        medium = _med.MEDIUM_CLEARNET if cid.startswith("clearnet:") else _med.MEDIUM_RELAY
        return cid, rurl, medium

    # 4. Bluetooth
    cid, rurl = try_bluetooth_entry(timeout=min(timeout - 2, 8))
    if cid:
        return cid, rurl, _med.MEDIUM_BT

    # 5. USB/Serial
    cid, rurl = try_usb_serial_entry(timeout=min(timeout - 2, 5))
    if cid:
        return cid, rurl, _med.MEDIUM_USB

    # Fallback: Offline
    return "local:offline", "", _med.MEDIUM_UNKNOWN


# ── Standalone-Test ────────────────────────────────────────────────────────── #

if __name__ == "__main__":
    print("[entry_channels] Starte Discovery (timeout=6)...")
    cid, rurl, medium = discover_entry(relay_pool=[], timeout=6)
    print("[entry_channels] Ergebnis:")
    print("  connection_id : " + str(cid))
    print("  relay_url     : " + str(rurl))
    print("  medium        : " + str(medium))
    print("[entry_channels] Test abgeschlossen.")
