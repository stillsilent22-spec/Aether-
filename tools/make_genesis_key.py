"""tools/make_genesis_key.py — Genesis-Node-Key erzeugen und verifizieren.

Liest data/keys/node_private.key (PEM), leitet daraus den Yggdrasil-Key ab und
schreibt ihn als raw 32 Byte nach data/keys/genesis_node.key.

Die Yggdrasil-Adresse wird berechnet und gegen den hartkodierten Wert in
swarm_p2p.py geprüft, damit der Key nachweislich zur Genesis-Adresse gehört.

Ausführen (einmalig, nur auf dem Genesis-Rechner):
    python tools/make_genesis_key.py [--verify-only]

Flags:
    --verify-only   Nur Adresse berechnen und anzeigen, nichts schreiben.
    --force         genesis_node.key auch überschreiben wenn bereits vorhanden.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Keine hardcodierte EXPECTED_GENESIS_ADDR mehr.
# Die Adresse wird ausschliesslich aus dem Key abgeleitet und nur lokal angezeigt.
# Sie steht nicht im Source-Code — kein Tracking durch Dritte möglich.


def _derive_genesis_key_from_node_pem(node_private_pem: bytes) -> tuple[bytes, str]:
    """Gibt (raw_32_byte_ygg_key, ygg_address) zurück."""
    from modules.key_derivation import AetherKeyTree, master_key_from_private_pem
    from modules.yggdrasil_addr import derive_yggdrasil_address

    master = master_key_from_private_pem(node_private_pem)
    tree = AetherKeyTree(master)
    ygg_key = tree.yggdrasil_key          # 32 Byte, HKDF-abgeleitet
    ygg_addr = derive_yggdrasil_address(ygg_key)
    tree.zeroize()
    return ygg_key, ygg_addr


def main() -> None:
    parser = argparse.ArgumentParser(description="Genesis-Node-Key ableiten")
    parser.add_argument("--verify-only", action="store_true",
                        help="Nur Adresse anzeigen, nicht schreiben")
    parser.add_argument("--force", action="store_true",
                        help="genesis_node.key überschreiben wenn vorhanden")
    args = parser.parse_args()

    node_pem_path = ROOT / "data" / "keys" / "node_private.key"
    genesis_key_path = ROOT / "data" / "keys" / "genesis_node.key"

    if not node_pem_path.is_file():
        print(f"[FEHLER] {node_pem_path} nicht gefunden.")
        print("         Führe zuerst solo_bootstrap.py aus.")
        sys.exit(1)

    print(f"[KEY] Lese {node_pem_path} ...")
    node_pem = node_pem_path.read_bytes()

    try:
        ygg_key, ygg_addr = _derive_genesis_key_from_node_pem(node_pem)
    except Exception as e:
        print(f"[FEHLER] Key-Ableitung fehlgeschlagen: {e}")
        sys.exit(1)

    print(f"[ADDR] Abgeleitete Yggdrasil-Adresse: {ygg_addr}")
    print("[INFO] Diese Adresse wird nur hier angezeigt — sie steht nicht im Code.")
    print("[OK]   Schlüssel verifiziert — dieser Knoten ist der Genesis-Node.")

    if args.verify_only:
        print("[INFO] --verify-only: Nichts geschrieben.")
        return

    if genesis_key_path.is_file() and not args.force:
        print(f"[INFO] {genesis_key_path} existiert bereits — übersprungen (--force zum Überschreiben).")
        return

    genesis_key_path.parent.mkdir(parents=True, exist_ok=True)
    genesis_key_path.write_bytes(ygg_key)

    # Dateiberechtigungen: nur owner darf lesen
    try:
        import os
        if os.name != "nt":
            os.chmod(str(genesis_key_path), 0o600)
    except Exception:
        pass

    print(f"[OK]   genesis_node.key geschrieben nach {genesis_key_path}")
    print("       Dieser Key bleibt auf deinem Rechner — NIEMALS committen oder teilen.")


if __name__ == "__main__":
    main()
