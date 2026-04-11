"""
universal_identity.py — Einheitliche Identitaets-Ableitung fuer alle Aether-Teilnehmer
========================================================================================

FORMEL:
  hw_signals       = alle verfuegbaren Hardware-Merkmale (MachineGuid, BT-MAC, etc.)
  hw_fingerprint   = sha256(sorted(hw_signals))

  priv_equiv       = sha256("aether.entry-priv.v1|hw_fp|medium|connection_id")
                     -> bleibt lokal — NIEMALS teilen

  pub_equiv        = sha256("aether.entry-pub.v1|priv_equiv")
                     -> oeffentlich, prüfbar, equivalent zu Public Key

  node_id          = pub_equiv[:16]

  network_entry_id = "peer-" + sha256("aether.net-entry-id.v2|medium|hw_fp|connection_id")[:32]

  identity_lock    = sha256("aether.dht-hw-user-lock.v1|user|node_id||hw_fp|net_entry_id")

EINSTIEGS-MEDIEN (connection_id je Medium):
  clearnet   -> "clearnet:<public_ip>"  oder "relay:<sha256[:16]>"
  bluetooth  -> "bt:<local_bt_mac>"
  lan        -> "lan:<subnet>"   (erste 3 Oktette des LAN-Interface)
  usb_serial -> "usb:<devpath_normalized>"
  relay      -> "relay:<sha256[:16]-of-relay_url>"
  unknown    -> "local:offline"

KEYPAIR-AEQUIVALENT fuer Legacy-Hardware ohne Ed25519:
  private component: priv_equiv (sha256 von HW+Netz — lokal, hw-gebunden)
  public  component: pub_equiv  (sha256 von priv_equiv — teilbar, pruefbar)

  Gleiche HW + gleicher Einstiegspunkt  = gleicher Keypair (deterministic)
  Gleiche HW + anderer Einstiegspunkt   = anderer Keypair  (Sybil-Schutz)
  Andere HW  + beliebiger Einstiegspunkt = anderer Keypair

Python 2.6+ kompatibel: keine f-strings, keine Type-Hints, keine pathlib, keine walrus-ops.
"""
from __future__ import print_function

import hashlib
import os
import socket
import sys

SCHEMA_HW_FP      = "aether.hw-fp.v1"
SCHEMA_ENTRY_PRIV = "aether.entry-priv.v1"
SCHEMA_ENTRY_PUB  = "aether.entry-pub.v1"
SCHEMA_LOCK       = "aether.dht-hw-user-lock.v1"
SCHEMA_NET_ENTRY  = "aether.net-entry-id.v2"

# Medium-Tags — werden in node.json und account_claim.json gespeichert
MEDIUM_LAN       = "lan"
MEDIUM_CLEARNET  = "clearnet"
MEDIUM_BT        = "bluetooth"
MEDIUM_RELAY     = "relay"
MEDIUM_USB       = "usb_serial"
MEDIUM_UNKNOWN   = "unknown"


# ── Hardware-Signal-Sammlung ──────────────────────────────────────────────── #

def collect_hw_signals():
    """Sammelt alle verfuegbaren Hardware-Merkmale dieser Maschine.

    Python 2.6+ kompatibel. Schlaegt nie fehl — gibt mindestens Hostname zurueck.
    Unterstuetzt: Windows (9x bis 11), Linux, macOS, Android, Raspberry Pi,
                  jede Plattform mit Python 2.6+.

    Gibt Liste von (label, value) Tupeln zurueck.
    """
    signals = []

    # ── Windows MachineGuid (WinNT 4.0+, Win9x via _winreg) ─────────────── #
    try:
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
        signals.append(("win_guid", str(guid).strip()))
    except Exception:
        pass

    # ── Windows Volume Serial Number (C:\ — Win9x ohne MachineGuid) ──────── #
    try:
        import ctypes
        vol_serial = ctypes.c_ulong(0)
        if ctypes.windll.kernel32.GetVolumeInformationW(
            u"C:\\", None, 0, ctypes.byref(vol_serial), None, None, None, 0
        ):
            if vol_serial.value:
                signals.append(("win_vol_serial", "%08x" % vol_serial.value))
    except Exception:
        pass

    # ── Windows Product ID (Win9x Registry Fallback) ─────────────────────── #
    try:
        try:
            import winreg as _reg2
        except ImportError:
            import _winreg as _reg2
        key2 = _reg2.OpenKey(
            _reg2.HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        )
        pid = _reg2.QueryValueEx(key2, "ProductId")[0]
        _reg2.CloseKey(key2)
        if pid:
            signals.append(("win_product_id", str(pid).strip()))
    except Exception:
        pass

    # ── Linux machine-id ──────────────────────────────────────────────────── #
    for _mid_path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
        try:
            f = open(_mid_path, "r")
            try:
                mid = f.read().strip()
            finally:
                f.close()
            if mid:
                signals.append(("linux_mid", mid))
                break
        except Exception:
            pass

    # ── Linux DMI Board Serial (if root or readable) ─────────────────────── #
    for _dmi_path in [
        "/sys/class/dmi/id/board_serial",
        "/sys/class/dmi/id/product_uuid",
        "/sys/class/dmi/id/product_serial",
    ]:
        try:
            f = open(_dmi_path, "r")
            try:
                val = f.read().strip()
            finally:
                f.close()
            if val and val not in ("None", "Not Specified", "0", ""):
                label = _dmi_path.split("/")[-1]
                signals.append(("dmi_" + label, val))
                break
        except Exception:
            pass

    # ── Raspberry Pi / Embedded CPU Serial (/proc/cpuinfo) ──────────────── #
    try:
        f = open("/proc/cpuinfo", "r")
        try:
            lines = f.readlines()
        finally:
            f.close()
        for line in lines:
            if "Serial" in line and ":" in line:
                serial = line.split(":")[-1].strip()
                if serial and serial not in ("0000000000000000", ""):
                    signals.append(("cpu_serial", serial))
                    break
    except Exception:
        pass

    # ── macOS IOPlatformUUID (ioreg) ─────────────────────────────────────── #
    try:
        import subprocess
        devnull = open(os.devnull, "w")
        try:
            out = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=devnull,
            )
        finally:
            devnull.close()
        if sys.version_info[0] >= 3:
            out = out.decode("utf-8", "ignore")
        for line in out.split("\n"):
            if "IOPlatformUUID" in line:
                parts = line.split('"')
                if len(parts) >= 4:
                    uid = parts[-2].strip()
                    if uid:
                        signals.append(("mac_ioplatformUUID", uid))
                        break
    except Exception:
        pass

    # ── Android build serial (getprop ro.serialno) ──────────────────────── #
    try:
        import subprocess
        devnull2 = open(os.devnull, "w")
        try:
            out2 = subprocess.check_output(
                ["getprop", "ro.serialno"],
                stderr=devnull2,
            )
        finally:
            devnull2.close()
        if sys.version_info[0] >= 3:
            out2 = out2.decode("utf-8", "ignore")
        serial = out2.strip()
        if serial and serial != "unknown":
            signals.append(("android_serialno", serial))
    except Exception:
        pass

    # ── Android Build.ID via Python Android API ──────────────────────────── #
    try:
        import android  # noqa: F401
        import jnius
        Build = jnius.autoclass("android.os.Build")
        android_id = str(Build.SERIAL or "").strip()
        if android_id and android_id.lower() != "unknown":
            signals.append(("android_build_serial", android_id))
    except Exception:
        pass

    # ── Network Adapter MAC (Python 2.5+, uuid.getnode) ──────────────────── #
    try:
        if sys.version_info >= (2, 5):
            import uuid as _uuid
            mac = _uuid.getnode()
            # getnode() kann zuweilen eine zufaellige ID zurueckgeben
            # wenn kein MAC gefunden — dann nicht verwenden
            if mac and mac != 0 and mac < (1 << 48):
                signals.append(("net_mac", "%012x" % mac))
    except Exception:
        pass

    # ── Hostname (immer verfuegbar) ───────────────────────────────────────── #
    try:
        signals.append(("hostname", socket.gethostname()))
    except Exception:
        signals.append(("hostname", "unknown"))

    # ── Python-Executable-Pfad (stabil bei fester Installation) ─────────── #
    try:
        signals.append(("py_path", os.path.abspath(sys.executable)))
    except Exception:
        pass

    return signals


def hw_fingerprint(signals=None):
    """Stabiler Hardware-Fingerprint aus allen verfuegbaren Signalen.

    Gibt 64-stellige Hex-Zeichenkette (sha256) zurueck.
    Deterministisch: gleiche Hardware = immer gleicher Fingerprint.
    """
    if signals is None:
        signals = collect_hw_signals()
    parts = sorted([str(k) + ":" + str(v) for k, v in signals])
    raw = SCHEMA_HW_FP + "|" + "|".join(parts)
    if sys.version_info[0] >= 3:
        raw = raw.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# ── Keypair-Aequivalent ───────────────────────────────────────────────────── #

def entry_keypair_seed(device_fp, connection_id, medium=MEDIUM_UNKNOWN):
    """Hardware + Netzwerk-Einstieg -> deterministischer Keypair-Seed.

    Gibt (priv_equiv, pub_equiv) zurueck:
      priv_equiv — Privater Seed (Hardware-gebunden, NIEMALS teilen)
      pub_equiv  — Oeffentlicher Verifizierer (teilbar, entspricht Public Key)

    Beide sind SHA-256-Hashes. Fuer Hardware ohne Ed25519 dient dieses
    Konstrukt als kryptografisches Identitaets-Pair:
      - priv_equiv an Hardware und Netzwerk gebunden (unveraenderbar ohne HW-Wechsel)
      - pub_equiv prüfbar ohne Kennntnis von priv_equiv

    Gleiche HW + gleicher Einstieg  = gleicher Keypair
    Gleiche HW + anderer Einstieg   = anderer Keypair (Sybil-Schutz)
    Andere HW   + beliebiger Einstieg = anderer Keypair
    """
    raw_priv = SCHEMA_ENTRY_PRIV + "|" + str(device_fp) + "|" + str(medium) + "|" + str(connection_id)
    if sys.version_info[0] >= 3:
        raw_priv = raw_priv.encode("utf-8")
    priv_equiv = hashlib.sha256(raw_priv).hexdigest()

    raw_pub = SCHEMA_ENTRY_PUB + "|" + priv_equiv
    if sys.version_info[0] >= 3:
        raw_pub = raw_pub.encode("utf-8")
    pub_equiv = hashlib.sha256(raw_pub).hexdigest()

    return priv_equiv, pub_equiv


# ── Identitaets-Ableitung ────────────────────────────────────────────────── #

def build_network_entry_id(device_fp, connection_id, medium=MEDIUM_UNKNOWN):
    """Leitet network_entry_id ab — kompatibel mit aether.dht-hw-user-lock.v1.

    Einheitliche Formel fuer ALLE Medien (LAN, BT, Clearnet, Relay, USB).
    Gibt "peer-<32 Hex>" zurueck — identisches Format wie legacy_bootstrap.py.
    """
    raw = SCHEMA_NET_ENTRY + "|" + str(medium) + "|" + str(device_fp) + "|" + str(connection_id)
    if sys.version_info[0] >= 3:
        raw = raw.encode("utf-8")
    return "peer-" + hashlib.sha256(raw).hexdigest()[:32]


def derive_node_id_from_fp(device_fp, network_entry_id):
    """Leitet node_id aus Hardware-Fingerprint + Network-Entry-ID ab.

    Ohne Ed25519: 16-stellige Hex-ID, gebunden an Hardware UND Netzwerk-Einstieg.
    Deterministisch: selbe HW + selber Einstieg = immer selbe node_id.
    """
    raw = "aether.node-id.v2|" + str(device_fp) + "|" + str(network_entry_id)
    if sys.version_info[0] >= 3:
        raw = raw.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def derive_identity_lock(alias_username, node_id, device_fp, network_entry_id):
    """SHA-256 Identity Lock — kompatibel mit auth.rs aether.dht-hw-user-lock.v1.

    Das ist der Keypair-Aequivalent fuer Legacy-Knoten:
      device_fp (hw_id)          -> Hardware-Bindung (unveraenderbar ohne HW-Wechsel)
      network_entry_id (net_id)  -> Netzwerk-Bindung (Einstiegspunkt)
      Zusammen                   -> unloesbarer identity_lock

    Die Kombination aus hw_id und net_id ergibt einen kryptografischen Anker,
    der ohne Kenntnis beider Komponenten nicht reproduzierbar ist.
    """
    raw = (
        SCHEMA_LOCK + "|"
        + str(alias_username) + "|"
        + str(node_id) + "||"
        + str(device_fp) + "|"
        + str(network_entry_id)
    )
    if sys.version_info[0] >= 3:
        raw = raw.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def build_full_identity(alias_username, connection_id, medium=MEDIUM_UNKNOWN, existing_node_id=None):
    """Vollstaendige Identitaet aus einem Aufruf ableiten.

    Wird von allen Einstiegspfaden (LAN, BT, Clearnet, Relay, USB) verwendet.
    Einmal eingerichtet, bleibt die Identitaet stabil solange Hardware und
    Einstiegspunkt gleich bleiben.

    Gibt dict zurueck:
      node_id          — 16-stellige Hex-ID
      device_fp        — Hardware-Fingerprint (64 Hex)
      network_entry_id — Netzwerk-Einstiegs-ID ("peer-<32 Hex>")
      identity_lock    — Kryptografischer Identitaetsanker (64 Hex)
      priv_equiv       — Privater Seed (LOKAL BEHALTEN — niemals teilen)
      pub_equiv        — Oeffentlicher Verifizierer (teilbar)
      medium           — Einstiegsmedium-Tag (lan/clearnet/bluetooth/relay/usb_serial)
    """
    signals = collect_hw_signals()
    device_fp = hw_fingerprint(signals)
    network_entry_id = build_network_entry_id(device_fp, connection_id, medium)
    node_id = existing_node_id or derive_node_id_from_fp(device_fp, network_entry_id)
    priv_equiv, pub_equiv = entry_keypair_seed(device_fp, connection_id, medium)
    identity_lock = derive_identity_lock(alias_username, node_id, device_fp, network_entry_id)
    return {
        "node_id": node_id,
        "device_fp": device_fp,
        "network_entry_id": network_entry_id,
        "identity_lock": identity_lock,
        "priv_equiv": priv_equiv,
        "pub_equiv": pub_equiv,
        "medium": medium,
    }


# ── Standalone-Test ────────────────────────────────────────────────────────── #

if __name__ == "__main__":
    signals = collect_hw_signals()
    print("[universal_identity] Hardware-Signale gesammelt: %d Quellen" % len(signals))
    for label, value in signals:
        print("  %-22s : %s" % (label, value[:40] if len(str(value)) > 40 else value))

    fp = hw_fingerprint(signals)
    print("[universal_identity] hw_fingerprint: " + fp)

    cid_lan  = "lan:192.168.1"
    cid_inet = "clearnet:203.0.113.42"
    cid_bt   = "bt:aa:bb:cc:dd:ee:ff"

    ident_lan  = build_full_identity("aether_test", cid_lan,  MEDIUM_LAN)
    ident_inet = build_full_identity("aether_test", cid_inet, MEDIUM_CLEARNET)
    ident_bt   = build_full_identity("aether_test", cid_bt,   MEDIUM_BT)

    print("[universal_identity] --- LAN entry ---")
    print("  node_id         : " + ident_lan["node_id"])
    print("  network_entry_id: " + ident_lan["network_entry_id"])
    print("  identity_lock   : " + ident_lan["identity_lock"])
    print("  pub_equiv       : " + ident_lan["pub_equiv"])

    print("[universal_identity] --- Clearnet entry ---")
    print("  node_id         : " + ident_inet["node_id"])
    print("  network_entry_id: " + ident_inet["network_entry_id"])

    print("[universal_identity] --- Bluetooth entry ---")
    print("  node_id         : " + ident_bt["node_id"])
    print("  network_entry_id: " + ident_bt["network_entry_id"])

    assert ident_lan["node_id"] != ident_inet["node_id"], "LAN und Clearnet muessen unterschiedliche IDs liefern"
    assert ident_lan["node_id"] != ident_bt["node_id"],   "LAN und BT muessen unterschiedliche IDs liefern"
    assert ident_lan["device_fp"] == ident_inet["device_fp"], "device_fp muss gleich sein (selbe HW)"
    assert len(ident_lan["priv_equiv"]) == 64, "priv_equiv muss 64 Hex-Zeichen haben"
    assert len(ident_lan["pub_equiv"]) == 64,  "pub_equiv muss 64 Hex-Zeichen haben"
    assert ident_lan["priv_equiv"] != ident_lan["pub_equiv"], "priv und pub muessen verschieden sein"

    print("[universal_identity] Alle Tests bestanden.")
