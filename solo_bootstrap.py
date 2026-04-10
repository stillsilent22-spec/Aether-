"""
Einmaliger Bootstrap für jeden neuen Node.
Läuft VOR dem Module-Load — importiert nichts aus modules/.

GENESIS-INVARIANTE (NIE BRECHEN):
    GENESIS_NODE_ID = "7a280b7e3ab3e042"
  solo_genesis_mode wird hier NIEMALS auf True gesetzt.
  Die genesis-Rolle wird hier NIEMALS vergeben.

Pfade sind relativ zu Path(__file__).parent (testbar via monkeypatch).
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

GENESIS_NODE_ID = "7a280b7e3ab3e042"


def is_yggdrasil_available() -> bool:
    """Prüft ob Yggdrasil erreichbar ist. Kann in Tests mit monkeypatch überschrieben werden."""
    try:
        import socket
        s = socket.create_connection(("localhost", 9001), timeout=0.5)
        s.close()
        return True
    except OSError:
        return False


def _base() -> Path:
    """Basispfad: Verzeichnis dieser Datei (testbar via monkeypatch von __file__)."""
    return Path(__file__).parent


def _local_genesis_binding_present(base: Path) -> bool:
    """Erlaubt das reservierte Genesis-Keypair nur auf einer autorisierten Genesis-Installation."""
    if (base / "data" / "keys" / "genesis_node.key").exists():
        return True
    node_json_path = base / "data" / "swarm" / "node.json"
    try:
        payload = json.loads(node_json_path.read_text(encoding="utf-8"))
        return str(payload.get("role", "") or "").strip().lower() == "genesis"
    except Exception:
        return False


def run_bootstrap(dry_run: bool = False) -> dict:
    """
    Idempotent: zweimaliger Aufruf ändert nichts wenn Node-Daten schon existieren.
    Gibt {"node_id": str, "role": str, "created_at": str} zurück.

    dry_run=True: berechnet node_id ohne etwas zu schreiben.
    """
    base = _base()
    node_json_path = base / "data" / "swarm" / "node.json"
    private_key_path = base / "data" / "keys" / "node_private.key"
    public_key_path = base / "data" / "keys" / "node_public.key"

    # SCHRITT 2 — Idempotenz-Check: bereits bootstrapped?
    if node_json_path.exists() and private_key_path.exists():
        try:
            payload = json.loads(node_json_path.read_text(encoding="utf-8"))
            existing_id = payload.get("node_id", "")
            if existing_id:
                return {
                    "node_id": existing_id,
                    "role": payload.get("role", "peer"),
                    "created_at": payload.get("registered_at", ""),
                }
        except (json.JSONDecodeError, OSError):
            pass  # Korrupte Datei → neu generieren

    # SCHRITT 3 — Ed25519 Keypair generieren oder vorhandenen laden
    if private_key_path.exists():
        raw_pem = private_key_path.read_bytes()
        private_key = load_pem_private_key(raw_pem, password=None)
    else:
        private_key = Ed25519PrivateKey.generate()

    # SCHRITT 4 — node_id und DHT peer-id berechnen
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    node_id = hashlib.sha256(pub_bytes).hexdigest()[:16]
    # Deterministischer DHT-Identifikator: gleichwertig zur Yggdrasil-Adresse
    network_entry_id = "peer-" + hashlib.sha256(pub_bytes).hexdigest()[:32]

    # SCHRITT 5 — Genesis-Kollisions-Check
    if node_id == GENESIS_NODE_ID and not _local_genesis_binding_present(base):
        raise RuntimeError(
            "Keypair kollidiert mit der reservierten Genesis-Identitaet. Dieses Geraet ist nicht als Genesis autorisiert."
        )

    if dry_run:
        return {"node_id": node_id, "role": "peer", "created_at": ""}

    # SCHRITT 6 — Keys speichern (nur wenn noch nicht vorhanden)
    (base / "data" / "keys").mkdir(parents=True, exist_ok=True)
    if not private_key_path.exists():
        private_pem = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        private_key_path.write_bytes(private_pem)
        if os.name != "nt":
            os.chmod(str(private_key_path), 0o600)

    if not public_key_path.exists():
        public_pem = private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        public_key_path.write_bytes(public_pem)

    # SCHRITT 6b — Hardware-Bindung (device_fingerprint, privacy-preserving SHA-256)
    device_fingerprint = ""
    try:
        from modules.device_lock import initialize_binding
        device_fingerprint = initialize_binding(node_id)
    except Exception:
        # Fallback wenn modules/ noch nicht verfügbar (z.B. erster Bootstrap vor pip install)
        import socket as _sock
        _seed = f"{_sock.gethostname()}|{node_id}".encode("utf-8")
        device_fingerprint = hashlib.sha256(_seed).hexdigest()

    # SCHRITT 7 — node.json schreiben (aether.swarm.node.v2)
    (base / "data" / "swarm").mkdir(parents=True, exist_ok=True)
    registered_at = datetime.now(timezone.utc).isoformat()
    pub_pem_str = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # Alias-Username: deterministisch aus node_id, änderbar später via GUI/Registrierung.
    # Gilt als "alias" (claim_mode=alias) bis der Nutzer sich im Netz registriert.
    alias_username = f"aether_{node_id[:8]}"

    node_payload = {
        "schema": "aether.swarm.node.v2",
        "node_id": node_id,
        "public_key_pem": pub_pem_str,
        "registered_at": registered_at,
        "role": "peer",
        "relay": False,
        "yggdrasil_addr": None,
        "device_fingerprint": device_fingerprint,
        "alias_username": alias_username,
        "network_entry_id": network_entry_id,
    }
    node_json_path.write_text(
        json.dumps(node_payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # Auch in nodes/-Verzeichnis schreiben
    nodes_dir = base / "data" / "swarm" / "nodes"
    nodes_dir.mkdir(parents=True, exist_ok=True)
    (nodes_dir / f"{node_id}.json").write_text(
        json.dumps(node_payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # SCHRITT 7b — Account-Claim schreiben (alias-Modus bis zur Netz-Registrierung)
    # Wird von swarm_p2p._refresh_local_account_claim() gelesen.
    # claim_mode=alias: Netz kennt diesen Username noch nicht → nur lokale Bindung.
    # claim_mode=registered: nach erfolgreicher Netz-Registrierung (Rust-Shell oder Relay).
    claim_path = base / "data" / "swarm" / "account_claim.json"
    if not claim_path.exists():
        claim_path.write_text(
            json.dumps({
                "schema": "aether.account_claim.v1",
                "node_id": node_id,
                "alias_username": alias_username,
                "account_username": alias_username,
                "device_fingerprint": device_fingerprint,
                "claim_mode": "alias",
                "relay_bridge_mode": True,
                "ygg_addr": "",
                "identity_lock": "",
                "network_entry_id": network_entry_id,
                "native_ygg_bound": False,
                "created_at": registered_at,
            }, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    # SCHRITT 8 — trusted_publishers.json aktualisieren
    _update_trusted_publishers(base, node_id, registered_at)

    # SCHRITT 9 — Ausgabe
    print("[BOOTSTRAP] Neuer Node registriert.")
    print(f"[BOOTSTRAP] node_id       : {node_id}")
    print(f"[BOOTSTRAP] Alias         : {alias_username}")
    print(f"[BOOTSTRAP] HW-Fingerprint: {device_fingerprint[:16]}…")
    print(f"[BOOTSTRAP] Rolle         : peer")
    print(f"[BOOTSTRAP] Genesis       : {GENESIS_NODE_ID} (unveraendert, exklusiv)")

    return {"node_id": node_id, "role": "peer", "created_at": registered_at}


def build_node_record(
    node_id: str,
    public_key_pem: str,
    yggdrasil_addr: Optional[str],
    relay: bool = False,
    registered_at: Optional[str] = None,
) -> dict:
    """
    Erstellt ein node.v2-Payload-Dict für tests/test_node_json_schema.py.
    Vergibt NIE role="genesis".
    """
    created = registered_at or datetime.now(timezone.utc).isoformat()
    return {
        "schema": "aether.swarm.node.v2",
        "node_id": node_id,
        "public_key_pem": public_key_pem,
        "registered_at": created,
        "role": "peer",
        "relay": relay,
        "yggdrasil_addr": yggdrasil_addr,
    }


# ── Interne Hilfsfunktion ────────────────────────────────────────────────────

def _update_trusted_publishers(base: Path, node_id: str, created_at: str) -> None:
    """
    Fügt diesen Node in data/trusted_publishers.json ein.
    Berührt vorhandene Einträge (insbesondere tryharder997) nicht.
    Vergibt NIE role="genesis".
    """
    trusted_path = base / "data" / "trusted_publishers.json"
    data: dict = {"publishers": {}}

    if trusted_path.exists():
        try:
            data = json.loads(trusted_path.read_text(encoding="utf-8"))
            if "publishers" not in data or not isinstance(data["publishers"], dict):
                data["publishers"] = {}
        except (json.JSONDecodeError, OSError):
            data = {"publishers": {}}

    if node_id not in data["publishers"]:
        data["publishers"][node_id] = {
            "node_id": node_id,
            "role": "peer",
            "enabled": True,
            "created_at": created_at,
        }

    trusted_path.parent.mkdir(parents=True, exist_ok=True)
    trusted_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )


if __name__ == "__main__":
    result = run_bootstrap()
    print(result)
