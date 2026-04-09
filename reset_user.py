"""
NOT A PASSWORD RECOVERY TOOL.

Dieses Skript kann NUR den Passwort-Hash eines Peer-Accounts (role=peer/operator)
aendern — und NUR wenn der Aufruf auf exakt derselben Hardware erfolgt, die den
Account urspruenglich erstellt hat (Hardware-Fingerprint-Vergleich).

Fuer Genesis-Accounts (role=genesis, genesis_bound=True) ist jede Aenderung
permanent gesperrt. Wenn das Passwort vergessen wurde, gibt es keine Wiederherstellung.
Das ist gewollt: Kein Account kann auf mehreren Geraeten existieren.

Starte mit: python reset_user.py
"""
import hashlib, json, os, secrets, getpass, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(ROOT, "data", "rust_shell", "users.json")


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def hash_password(username: str, salt_hex: str, password: str) -> str:
    return sha256_hex(f"{username}|{salt_hex}|{password}|aether-rust-shell")


def _current_device_fingerprint() -> str:
    """Berechnet den Hardware-Fingerprint der aktuellen Maschine."""
    try:
        sys.path.insert(0, ROOT)
        from modules.device_lock import compute_device_fingerprint
        return compute_device_fingerprint()
    except Exception as e:
        print(f"FEHLER: Hardware-Fingerprint konnte nicht berechnet werden: {e}")
        sys.exit(1)


def main():
    print("=== Aether – Account-Passwort aendern ===")
    print("HINWEIS: Passwort-Wiederherstellung existiert nicht.")
    print("         Kein Account kann auf mehreren Geraeten existieren.")
    print()

    if not os.path.exists(USERS_FILE):
        print("ABBRUCH: Keine users.json gefunden. Erst solo_bootstrap.py ausfuehren.")
        sys.exit(1)

    with open(USERS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    users = data.get("users", [])
    if not users:
        print("ABBRUCH: Keine Accounts gefunden.")
        sys.exit(1)

    username = input("Benutzername: ").strip()
    if not username:
        print("ABBRUCH: Kein Benutzername eingegeben.")
        sys.exit(1)

    # Account suchen
    match = next((u for u in users if u.get("username", "").lower() == username.lower()), None)
    if match is None:
        # Sicherheit: kein Hinweis ob Account existiert oder nicht
        print("ABBRUCH: Hardware-Verifizierung fehlgeschlagen.")
        sys.exit(1)

    # Genesis-Account: permanent gesperrt
    role = str(match.get("role", "") or "").strip().lower()
    genesis_bound = bool(match.get("genesis_bound", False))
    if role == "genesis" or genesis_bound:
        print()
        print("ABBRUCH: Genesis-Account kann nicht zurueckgesetzt werden.")
        print("         Wenn das Passwort vergessen wurde, gibt es keine Wiederherstellung.")
        print("         Der Account ist permanent an diese Hardware gebunden.")
        sys.exit(1)

    # Hardware-Fingerprint pruefen
    stored_fp = str(match.get("device_fingerprint", "") or "").strip()
    if not stored_fp:
        print("ABBRUCH: Dieser Account hat keinen Hardware-Fingerprint.")
        print("         Er muss erst ueber den normalen Bootstrap-Prozess gebunden werden.")
        sys.exit(1)

    current_fp = _current_device_fingerprint()
    # Timing-sicherer Vergleich
    import hmac as _hmac
    if not _hmac.compare_digest(stored_fp, current_fp):
        print("ABBRUCH: Hardware-Verifizierung fehlgeschlagen.")
        print("         Dieser Account gehoert zu einem anderen Geraet.")
        sys.exit(1)

    print(f"Hardware verifiziert. Neues Passwort fuer '{username}' setzen:")
    password = getpass.getpass("Neues Passwort: ")
    if not password:
        print("ABBRUCH: Kein Passwort eingegeben.")
        sys.exit(1)
    confirm = getpass.getpass("Passwort bestaetigen: ")
    if password != confirm:
        print("ABBRUCH: Passwoerter stimmen nicht ueberein.")
        sys.exit(1)

    # NUR Passwort-Hash aendern — alles andere (role, node_id, genesis_bound, fingerprint) bleibt
    import time
    salt_hex = secrets.token_hex(16)
    match["salt_hex"] = salt_hex
    match["password_hash_hex"] = hash_password(username, salt_hex, password)
    # Rolle wird niemals durch dieses Tool veraendert
    # device_fingerprint bleibt unveraendert

    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"\n Passwort fuer '{username}' geaendert. Rolle und Hardware-Bindung unveraendert.")


if __name__ == "__main__":
    main()
