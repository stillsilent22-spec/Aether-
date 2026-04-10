"""One-shot Yggdrasil activation script.
Downloads binary, bakes in genesis private key, updates hw_capability, starts process.
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
BIN_DIR = ROOT / "bin"
DATA_DIR = ROOT / "data"
GENESIS_KEY_PATH = DATA_DIR / "keys" / "genesis_node.key"
HW_CAP_PATH = DATA_DIR / "interbus" / "hw_capability.json"
YGG_CONF_PATH = DATA_DIR / "yggdrasil.conf"
YGG_PID_PATH = DATA_DIR / "yggdrasil.pid"
TARGET_BINARY = BIN_DIR / "yggdrasil.exe"

MSI_URL = "https://github.com/yggdrasil-network/yggdrasil-go/releases/download/v0.5.8/yggdrasil-0.5.8-x64.msi"
MSI_SHA256 = "e91b2e3b0ec0cf2410feeddcb29290a65f5442129f057f34a7df73c6477fc4f1"

DEFAULT_PEERS = [
    "tls://ygg.maru.hk:18395",
    "tls://vpn1.ht4.ca:5122",
    "tls://s1.geo.trnsz.com:655",
]


# ---------------------------------------------------------------------------
# Step 1 — download MSI
# ---------------------------------------------------------------------------
def _download_msi() -> Path:
    downloads_dir = BIN_DIR / "downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    msi_path = downloads_dir / "yggdrasil-0.5.8-x64.msi"
    if msi_path.is_file():
        print(f"[ygg] MSI already downloaded: {msi_path}")
        return msi_path
    print(f"[ygg] Downloading {MSI_URL} ...")
    hasher = hashlib.sha256()
    tmp = msi_path.with_suffix(".tmp")
    with urllib.request.urlopen(MSI_URL) as resp, tmp.open("wb") as fh:
        total = int(resp.headers.get("Content-Length", "0") or 0)
        downloaded = 0
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            fh.write(chunk)
            hasher.update(chunk)
            downloaded += len(chunk)
            if total:
                pct = int(downloaded * 100 / total)
                print(f"\r[ygg] {downloaded}/{total} bytes ({pct}%)", end="", flush=True)
    print()
    digest = hasher.hexdigest().lower()
    if digest != MSI_SHA256.lower():
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"[ygg] SHA256 mismatch: expected {MSI_SHA256}, got {digest}")
    tmp.replace(msi_path)
    print(f"[ygg] Download OK — {msi_path}")
    return msi_path


# ---------------------------------------------------------------------------
# Step 2 — extract .exe from MSI via msiexec /a
# ---------------------------------------------------------------------------
def _extract_from_msi(msi_path: Path) -> Path:
    if TARGET_BINARY.is_file():
        print(f"[ygg] Binary already present: {TARGET_BINARY}")
        return TARGET_BINARY
    print("[ygg] Extracting yggdrasil.exe from MSI ...")
    TARGET_BINARY.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aether-ygg-msi-") as tmp_dir:
        result = subprocess.run(
            ["msiexec", "/a", str(msi_path), "/qn", f"TARGETDIR={tmp_dir}"],
            capture_output=True,
            timeout=90,
        )
        print(f"[ygg] msiexec exit code: {result.returncode}")
        candidates = sorted(Path(tmp_dir).glob("**/yggdrasil.exe"))
        if not candidates:
            # list what's there for diagnostics
            all_files = list(Path(tmp_dir).rglob("*"))
            print(f"[ygg] No yggdrasil.exe found. Files in temp dir ({len(all_files)}):")
            for f in all_files[:40]:
                print(f"  {f}")
            raise RuntimeError("[ygg] Could not find yggdrasil.exe in MSI extraction")
        shutil.copy2(candidates[0], TARGET_BINARY)
    print(f"[ygg] Binary extracted: {TARGET_BINARY}")
    return TARGET_BINARY


# ---------------------------------------------------------------------------
# Step 3 — build genesis PrivateKey hex for Yggdrasil config
# ---------------------------------------------------------------------------
def _genesis_private_key_hex() -> str:
    """Returns the 128-char hex PrivateKey for Yggdrasil config (seed + pubkey)."""
    raw = GENESIS_KEY_PATH.read_bytes()
    if len(raw) != 32:
        raise ValueError(f"genesis_node.key is {len(raw)} bytes, expected 32")
    private_key = Ed25519PrivateKey.from_private_bytes(raw)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # Yggdrasil PrivateKey = seed (32 bytes) + public key (32 bytes) → 64 bytes → 128 hex chars
    return (raw + public_bytes).hex()


def _derive_ygg_addr(raw_seed: bytes) -> str:
    """Re-derive the Yggdrasil address from the genesis seed."""
    private_key = Ed25519PrivateKey.from_private_bytes(raw_seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    inverted = bytes((~b) & 0xFF for b in public_key)
    addr = bytearray(16)
    addr[0] = 0x02
    done = False
    ones = 0
    packed_bytes = bytearray()
    current_bits = 0
    bit_count = 0
    for index in range(8 * len(inverted)):
        bit = (inverted[index // 8] & (0x80 >> (index % 8))) >> (7 - (index % 8))
        if not done and bit != 0:
            ones += 1
            continue
        if not done and bit == 0:
            done = True
            continue
        current_bits = (current_bits << 1) | bit
        bit_count += 1
        if bit_count == 8:
            packed_bytes.append(current_bits)
            current_bits = 0
            bit_count = 0
    addr[1] = ones & 0xFF
    payload = bytes(packed_bytes)
    addr[2:] = payload[: max(0, 14)]
    return str(ipaddress.IPv6Address(bytes(addr)))


# ---------------------------------------------------------------------------
# Step 4 — generate yggdrasil.conf with genesis key
# ---------------------------------------------------------------------------
def _generate_conf(binary: Path) -> None:
    import re

    if YGG_CONF_PATH.is_file():
        print(f"[ygg] Config already exists: {YGG_CONF_PATH}")
        return
    print("[ygg] Generating yggdrasil.conf ...")
    result = subprocess.run(
        [str(binary), "-genconf"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(f"[ygg] -genconf failed: {result.stderr}")
    conf_text: str = result.stdout

    # Yggdrasil emits HJSON (with comments), not strict JSON.
    # Replace PrivateKey value inline via regex.
    priv_hex = _genesis_private_key_hex()
    conf_text, n = re.subn(
        r"(PrivateKey:\s*)[0-9a-fA-F]+",
        r"\g<1>" + priv_hex,
        conf_text,
    )
    if n == 0:
        raise RuntimeError("[ygg] Could not find PrivateKey field in generated config")
    print(f"[ygg] Genesis PrivateKey injected ({len(priv_hex)} hex chars)")

    # Inject public peers (replace empty Peers: [])
    settings_path = DATA_DIR / "settings.json"
    custom_peers: list[str] = []
    try:
        raw_s = json.loads(settings_path.read_text(encoding="utf-8"))
        custom_peers = [str(p) for p in (raw_s.get("yggdrasil_peers") or []) if p]
    except Exception:
        pass
    peers = custom_peers or DEFAULT_PEERS
    peers_str = "[\n    " + ",\n    ".join(f'"{p}"' for p in peers) + "\n  ]"
    conf_text, m = re.subn(r"(Peers:\s*)\[\s*\]", r"\g<1>" + peers_str, conf_text)
    if m > 0:
        print(f"[ygg] Peers injected: {peers}")

    YGG_CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
    YGG_CONF_PATH.write_text(conf_text, encoding="utf-8")
    print(f"[ygg] Config written: {YGG_CONF_PATH}")

    # Verify derived address matches what's in node.json
    seed = GENESIS_KEY_PATH.read_bytes()
    derived = _derive_ygg_addr(seed)
    node_json_path = DATA_DIR / "swarm" / "node.json"
    stored_addr = ""
    try:
        stored_addr = json.loads(node_json_path.read_text(encoding="utf-8")).get("yggdrasil_addr", "")
    except Exception:
        pass
    if stored_addr and derived.lower() != stored_addr.lower():
        print(f"[ygg] WARNING: derived addr {derived} != stored addr {stored_addr}")
    else:
        print(f"[ygg] Address verified: {derived}")


# ---------------------------------------------------------------------------
# Step 5 — update hw_capability.json to Tier 3
# ---------------------------------------------------------------------------
def _update_hw_capability() -> None:
    hw = {}
    try:
        hw = json.loads(HW_CAP_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    hw["network_tier"] = "YggdrasilP2P"
    hw["tier_rank"] = 3
    hw["yggdrasil"] = True
    hw["lan_p2p"] = True
    hw["lan_beacon"] = True
    hw["dht"] = True
    hw["note"] = "Tier 3 — Yggdrasil P2P aktiv. Genesis-Knoten."
    HW_CAP_PATH.parent.mkdir(parents=True, exist_ok=True)
    HW_CAP_PATH.write_text(json.dumps(hw, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[ygg] hw_capability updated → tier_rank=3, yggdrasil=true")


# ---------------------------------------------------------------------------
# Step 6 — start Yggdrasil subprocess
# ---------------------------------------------------------------------------
def _start_process(binary: Path) -> None:
    # Check if already running via PID file
    if YGG_PID_PATH.is_file():
        try:
            pid = int(YGG_PID_PATH.read_text(encoding="utf-8").strip())
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, check=False,
            )
            if result.stdout.strip() and "No tasks" not in result.stdout:
                print(f"[ygg] Yggdrasil already running (PID {pid})")
                return
        except Exception:
            pass
        YGG_PID_PATH.unlink(missing_ok=True)

    print("[ygg] Starting Yggdrasil ...")
    proc = subprocess.Popen(
        [str(binary), "-useconffile", str(YGG_CONF_PATH)],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    YGG_PID_PATH.parent.mkdir(parents=True, exist_ok=True)
    YGG_PID_PATH.write_text(str(proc.pid), encoding="utf-8")
    print(f"[ygg] Yggdrasil started — PID {proc.pid}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print("=== Aether Yggdrasil Activation ===")
    print(f"Root: {ROOT}")

    # 1 — download
    msi = _download_msi()

    # 2 — extract binary
    binary = _extract_from_msi(msi)

    # 3+4 — generate config with genesis key
    _generate_conf(binary)

    # 5 — update hw_capability
    _update_hw_capability()

    # 6 — start
    _start_process(binary)

    print("=== Done ===")
    seed = GENESIS_KEY_PATH.read_bytes()
    addr = _derive_ygg_addr(seed)
    print(f"Genesis Yggdrasil address: {addr}")
    print(f"PID file: {YGG_PID_PATH}")


if __name__ == "__main__":
    main()
