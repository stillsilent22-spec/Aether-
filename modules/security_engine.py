"""Lokales Sicherheitsmodell mit Nutzerlogin und Live-Session-Keys."""

from __future__ import annotations

import hashlib
import secrets
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from tkinter import messagebox, ttk
from typing import Any
from uuid import uuid4


PASSWORD_ITERATIONS = 240_000
MIN_PASSWORD_LENGTH = 8
LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 5
PRIMARY_ALGO = "sha256"
SECONDARY_ALGO = "blake2b"


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    """XORt zwei Bytepuffer gleicher Laenge."""
    size = min(len(left), len(right))
    return bytes(left[index] ^ right[index] for index in range(size))


@dataclass(frozen=True)
class SecuritySession:
    """Beschreibt eine authentifizierte Nutzer-Session."""

    user_id: int
    username: str
    role: str
    session_id: str
    login_at: str
    live_session_key: str
    live_session_fingerprint: str
    algorithm_pair: tuple[str, str]
    session_seed: int
    raw_storage_key_hex: str
    raw_storage_fingerprint: str
    user_settings: dict[str, Any]


class SecurityManager:
    """Verwaltet lokale Nutzer, Login und Session-Audit."""

    def __init__(self, registry) -> None:
        self.registry = registry

    @staticmethod
    def _hash_password(password: str, salt_hex: str) -> str:
        """Leitet einen PBKDF2-Hash fuer ein Passwort ab."""
        return hashlib.pbkdf2_hmac(
            "sha256",
            str(password).encode("utf-8"),
            bytes.fromhex(str(salt_hex)),
            PASSWORD_ITERATIONS,
        ).hex()

    @staticmethod
    def _now() -> datetime:
        """Liefert die aktuelle UTC-Zeit."""
        return datetime.now(timezone.utc)

    @staticmethod
    def _normalize_username(username: str) -> str:
        """Normalisiert Nutzernamen fuer lokale Anmeldung."""
        return str(username).strip()

    def _build_live_session_key(
        self,
        username: str,
        password_hash: str,
        salt_hex: str,
        login_at: str,
    ) -> tuple[str, str]:
        """Erzeugt pro Login einen neuen Session-Key aus CSPRNG-Entropie plus Hashableitung."""
        nonce = uuid4().hex
        entropy_hex = secrets.token_hex(32)
        primary = hashlib.sha256(
            f"{username}|{password_hash}|{login_at}|{nonce}|{entropy_hex}".encode("utf-8")
        ).digest()
        secondary = hashlib.blake2b(
            f"{salt_hex}|{login_at}|{nonce}|{entropy_hex}".encode("utf-8"),
            digest_size=32,
        ).digest()
        live_key = _xor_bytes(primary, secondary).hex()
        fingerprint = hashlib.sha3_256(live_key.encode("ascii")).hexdigest()[:24].upper()
        return live_key, fingerprint

    @staticmethod
    def _build_raw_storage_key(
        username: str,
        password: str,
        salt_hex: str,
    ) -> tuple[str, str]:
        """Leitet einen stabilen lokalen Master-Key aus dem Nutzerpasswort ab."""
        salt = hashlib.sha256(
            f"{salt_hex}|{username}|dual-mode-storage-master".encode("utf-8")
        ).digest()
        key = hashlib.pbkdf2_hmac(
            "sha256",
            str(password).encode("utf-8"),
            salt,
            PASSWORD_ITERATIONS,
            dklen=32,
        )
        fingerprint = hashlib.sha256(key).hexdigest()[:24].upper()
        return key.hex(), fingerprint

    def register_user(self, username: str, password: str) -> SecuritySession:
        """Legt einen Nutzer an und meldet ihn direkt an."""
        normalized = self._normalize_username(username)
        if len(normalized) < 3:
            raise ValueError("Der Nutzername muss mindestens 3 Zeichen haben.")
        if len(str(password)) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Das Passwort muss mindestens {MIN_PASSWORD_LENGTH} Zeichen haben.")
        if self.registry.get_user_by_username(normalized) is not None:
            raise ValueError("Dieser Nutzername existiert bereits.")

        salt_hex = secrets.token_hex(16)
        password_hash = self._hash_password(str(password), salt_hex)
        role = "admin" if not self.registry.has_users() else "operator"
        user_id = self.registry.create_user(
            username=normalized,
            password_hash=password_hash,
            salt_hex=salt_hex,
            role=role,
            settings={"created_by": "local_security_model", "security_mode": "PROD"},
        )
        self.registry.save_security_event(
            user_id=user_id,
            username=normalized,
            event_type="register",
            severity="info",
            payload={"role": role},
        )
        return self.login_user(normalized, password)

    def login_user(self, username: str, password: str) -> SecuritySession:
        """Authentifiziert einen Nutzer und oeffnet eine neue Live-Session."""
        normalized = self._normalize_username(username)
        record = self.registry.get_user_by_username(normalized)
        if record is None:
            raise ValueError("Nutzername oder Passwort ist ungueltig.")
        if bool(record.get("disabled", False)):
            raise ValueError("Dieses Konto ist deaktiviert.")

        locked_until = str(record.get("locked_until", "")).strip()
        if locked_until:
            try:
                if datetime.fromisoformat(locked_until) > self._now():
                    raise ValueError("Dieses Konto ist temporaer gesperrt.")
            except ValueError:
                if "gesperrt" in locked_until.lower():
                    raise

        supplied_hash = self._hash_password(str(password), str(record["salt_hex"]))
        if supplied_hash != str(record["password_hash"]):
            failed_attempts = int(record.get("failed_attempts", 0)) + 1
            lock_value = ""
            if failed_attempts >= LOCKOUT_THRESHOLD:
                lock_value = (self._now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
            self.registry.update_user_security_state(
                user_id=int(record["id"]),
                failed_attempts=failed_attempts,
                locked_until=lock_value,
            )
            self.registry.save_security_event(
                user_id=int(record["id"]),
                username=normalized,
                event_type="login_failed",
                severity="warning",
                payload={"failed_attempts": failed_attempts, "locked_until": lock_value},
            )
            raise ValueError("Nutzername oder Passwort ist ungueltig.")

        self.registry.update_user_security_state(
            user_id=int(record["id"]),
            failed_attempts=0,
            locked_until="",
        )
        login_at = self._now().isoformat()
        session_id = str(uuid4())
        session_seed = secrets.randbits(32)
        live_key, fingerprint = self._build_live_session_key(
            username=normalized,
            password_hash=str(record["password_hash"]),
            salt_hex=str(record["salt_hex"]),
            login_at=login_at,
        )
        raw_storage_key_hex, raw_storage_fingerprint = self._build_raw_storage_key(
            username=normalized,
            password=str(password),
            salt_hex=str(record["salt_hex"]),
        )
        live_key_hash = hashlib.sha256(live_key.encode("ascii")).hexdigest()
        self.registry.open_user_session(
            session_id=session_id,
            user_id=int(record["id"]),
            username=normalized,
            role=str(record["role"]),
            login_at=login_at,
            live_key_hash=live_key_hash,
            live_key_fingerprint=fingerprint,
            algo_primary=PRIMARY_ALGO,
            algo_secondary=SECONDARY_ALGO,
            payload={"security_model": "local", "issued_at": login_at, "session_seed": int(session_seed)},
        )
        self.registry.save_security_event(
            user_id=int(record["id"]),
            username=normalized,
            event_type="login_success",
            severity="info",
            payload={"session_id": session_id, "live_key_fingerprint": fingerprint},
        )
        return SecuritySession(
            user_id=int(record["id"]),
            username=normalized,
            role=str(record["role"]),
            session_id=session_id,
            login_at=login_at,
            live_session_key=live_key,
            live_session_fingerprint=fingerprint,
            algorithm_pair=(PRIMARY_ALGO, SECONDARY_ALGO),
            session_seed=int(session_seed),
            raw_storage_key_hex=raw_storage_key_hex,
            raw_storage_fingerprint=raw_storage_fingerprint,
            user_settings=dict(record.get("settings_json", {}) or {}),
        )

    def logout_user(self, session: SecuritySession | None) -> None:
        """Schliesst eine offene Login-Session sauber ab."""
        if session is None:
            return
        self.registry.close_user_session(str(session.session_id))
        self.registry.save_security_event(
            user_id=int(session.user_id),
            username=str(session.username),
            event_type="logout",
            severity="info",
            payload={"session_id": session.session_id},
        )

    def prompt_login(self) -> SecuritySession:
        """Oeffnet einen lokalen Login-/Registrierungsdialog und liefert die Session."""
        root = tk.Tk()
        result: dict[str, Any] = {}
        dialog = _SecurityDialog(root, self, result)
        try:
            root.deiconify()
            root.update_idletasks()
            root.update()
        except Exception:
            pass
        try:
            root.mainloop()
        except Exception:
            pass
        try:
            root.destroy()
        except Exception:
            pass
        session = result.get("session")
        if not isinstance(session, SecuritySession):
            raise RuntimeError("Anmeldung abgebrochen.")
        return session


class _SecurityDialog:
    """Kleiner modaler Login-/Registrierungsdialog fuer den lokalen Start."""

    def __init__(self, root: tk.Tk, manager: SecurityManager, result_box: dict[str, Any]) -> None:
        self.root = root
        self.manager = manager
        self.result_box = result_box
        self.window = root
        self.window.title("Aether Anmeldung")
        self.window.geometry("520x380")
        self.window.resizable(False, False)
        self.window.configure(bg="#0A1022")
        self.window.protocol("WM_DELETE_WINDOW", self._close)

        self.status_var = tk.StringVar(value="Lokale Anmeldung erforderlich.")
        self.error_var = tk.StringVar(value="")
        self.login_user_var = tk.StringVar(value="")
        self.login_pass_var = tk.StringVar(value="")
        self.register_user_var = tk.StringVar(value="")
        self.register_pass_var = tk.StringVar(value="")
        self.register_confirm_var = tk.StringVar(value="")

        try:
            ttk.Style(self.window).theme_use("clam")
        except Exception:
            pass

        header = tk.Frame(self.window, bg="#101A33")
        header.pack(fill="x", padx=10, pady=(10, 8))
        tk.Label(
            header,
            text="Lokales Sicherheitsmodell",
            bg="#101A33",
            fg="#E9F2FF",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", padx=12, pady=(10, 2))
        tk.Label(
            header,
            textvariable=self.status_var,
            bg="#101A33",
            fg="#8DB7FF",
            font=("Segoe UI", 9),
            wraplength=410,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 10))
        tk.Label(
            header,
            textvariable=self.error_var,
            bg="#101A33",
            fg="#FF8C8C",
            font=("Segoe UI", 9, "bold"),
            wraplength=410,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 10))

        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.login_tab = tk.Frame(self.notebook, bg="#0E1730")
        self.register_tab = tk.Frame(self.notebook, bg="#0E1730")
        self.notebook.add(self.login_tab, text="Login")
        self.notebook.add(self.register_tab, text="Registrieren")

        self._build_login_tab()
        self._build_register_tab()
        self._build_footer()
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        if not self.manager.registry.has_users():
            self.notebook.select(self.register_tab)
            self.status_var.set("Noch kein Nutzer vorhanden. Der erste Account wird lokal als admin angelegt.")
        self._sync_primary_button()

        self._show_window()

    def _show_error(self, title: str, message: str) -> None:
        """Spiegelt Fehler sichtbar im Dialog und als MessageBox."""
        text = str(message or "Unbekannter Fehler")
        self.error_var.set(text)
        try:
            messagebox.showerror(title, text, parent=self.window)
        except Exception:
            pass

    def _show_window(self) -> None:
        """Erzwingt ein sichtbares, zentriertes Loginfenster beim Start."""
        try:
            self.window.update_idletasks()
            width = max(520, int(self.window.winfo_width() or 520))
            height = max(380, int(self.window.winfo_height() or 380))
            screen_width = max(1, int(self.window.winfo_screenwidth() or 1))
            screen_height = max(1, int(self.window.winfo_screenheight() or 1))
            pos_x = max(0, (screen_width - width) // 2)
            pos_y = max(0, (screen_height - height) // 3)
            self.window.geometry(f"{width}x{height}+{pos_x}+{pos_y}")
            self.window.deiconify()
            self.window.lift()
            self.window.attributes("-topmost", True)
            self.window.grab_set()
            self.window.focus_force()
            self.window.after(250, lambda: self.window.attributes("-topmost", False))
        except Exception:
            pass

    def _build_login_tab(self) -> None:
        """Baut das Login-Formular."""
        container = tk.Frame(self.login_tab, bg="#0E1730")
        container.pack(fill="both", expand=True, padx=14, pady=14)
        tk.Label(container, text="Nutzername", bg="#0E1730", fg="#D9E7FF").pack(anchor="w")
        user_entry = ttk.Entry(container, textvariable=self.login_user_var)
        user_entry.pack(fill="x", pady=(4, 10))
        user_entry.bind("<Return>", lambda _event: self._submit_login())
        tk.Label(container, text="Passwort", bg="#0E1730", fg="#D9E7FF").pack(anchor="w")
        pass_entry = ttk.Entry(container, textvariable=self.login_pass_var, show="*")
        pass_entry.pack(fill="x", pady=(4, 14))
        pass_entry.bind("<Return>", lambda _event: self._submit_login())
        tk.Label(
            container,
            text="Mit Enter oder dem unteren Button bestaetigen.",
            bg="#0E1730",
            fg="#8DB7FF",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(6, 0))
        user_entry.focus_set()

    def _build_register_tab(self) -> None:
        """Baut das Registrierungsformular."""
        container = tk.Frame(self.register_tab, bg="#0E1730")
        container.pack(fill="both", expand=True, padx=14, pady=14)
        tk.Label(container, text="Nutzername", bg="#0E1730", fg="#D9E7FF").pack(anchor="w")
        register_user_entry = ttk.Entry(container, textvariable=self.register_user_var)
        register_user_entry.pack(fill="x", pady=(4, 8))
        register_user_entry.bind("<Return>", lambda _event: self._submit_register())
        tk.Label(container, text=f"Passwort (mindestens {MIN_PASSWORD_LENGTH} Zeichen)", bg="#0E1730", fg="#D9E7FF").pack(anchor="w")
        register_pass_entry = ttk.Entry(container, textvariable=self.register_pass_var, show="*")
        register_pass_entry.pack(fill="x", pady=(4, 8))
        register_pass_entry.bind("<Return>", lambda _event: self._submit_register())
        tk.Label(container, text="Passwort wiederholen", bg="#0E1730", fg="#D9E7FF").pack(anchor="w")
        confirm_entry = ttk.Entry(container, textvariable=self.register_confirm_var, show="*")
        confirm_entry.pack(fill="x", pady=(4, 14))
        confirm_entry.bind("<Return>", lambda _event: self._submit_register())
        tk.Label(
            container,
            text="Mit Enter oder dem unteren Button bestaetigen.",
            bg="#0E1730",
            fg="#8DB7FF",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(6, 0))

    def _build_footer(self) -> None:
        """Baut einen immer sichtbaren Aktionsbalken unterhalb der Tabs."""
        footer = tk.Frame(self.window, bg="#101A33")
        footer.pack(fill="x", padx=10, pady=(0, 10))
        self.primary_button = tk.Button(
            footer,
            text="Weiter",
            command=self._submit_active_tab,
            bg="#2F7BF6",
            fg="#FFFFFF",
            activebackground="#1E63D2",
            activeforeground="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padx=18,
            pady=8,
            cursor="hand2",
        )
        self.primary_button.pack(side="left")
        tk.Button(
            footer,
            text="Abbrechen",
            command=self._close,
            bg="#5E6C84",
            fg="#FFFFFF",
            activebackground="#4D596E",
            activeforeground="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padx=18,
            pady=8,
            cursor="hand2",
        ).pack(side="right")

    def _active_tab_name(self) -> str:
        """Liefert den Namen des aktuell aktiven Reiters."""
        try:
            current = str(self.notebook.select())
        except Exception:
            return "login"
        if current == str(self.register_tab):
            return "register"
        return "login"

    def _sync_primary_button(self) -> None:
        """Passt die prominente Hauptaktion an den aktiven Reiter an."""
        label = "Weiter zur Registrierung" if self._active_tab_name() == "register" else "Weiter zum Login"
        try:
            self.primary_button.configure(text=label)
        except Exception:
            pass

    def _on_tab_changed(self, _event: object | None = None) -> None:
        """Synchronisiert den Footer nach einem Reiterwechsel."""
        self.error_var.set("")
        self._sync_primary_button()

    def _submit_active_tab(self) -> None:
        """Fuehrt die passende Hauptaktion fuer den aktiven Reiter aus."""
        if self._active_tab_name() == "register":
            self._submit_register()
            return
        self._submit_login()

    def _submit_login(self) -> None:
        """Authentifiziert bestehende Nutzer."""
        self.error_var.set("")
        try:
            session = self.manager.login_user(self.login_user_var.get(), self.login_pass_var.get())
        except Exception as exc:
            self._show_error("Login fehlgeschlagen", str(exc))
            return
        self.result_box["session"] = session
        try:
            self.window.quit()
        except Exception:
            pass
        self.window.destroy()

    def _submit_register(self) -> None:
        """Registriert einen neuen Nutzer und meldet ihn direkt an."""
        self.error_var.set("")
        if self.register_pass_var.get() != self.register_confirm_var.get():
            self._show_error("Registrierung fehlgeschlagen", "Die Passwoerter stimmen nicht ueberein.")
            return
        try:
            session = self.manager.register_user(self.register_user_var.get(), self.register_pass_var.get())
        except Exception as exc:
            self._show_error("Registrierung fehlgeschlagen", str(exc))
            return
        self.result_box["session"] = session
        try:
            self.window.quit()
        except Exception:
            pass
        self.window.destroy()

    def _close(self) -> None:
        """Schliesst den Dialog ohne Anmeldung."""
        try:
            self.window.quit()
        except Exception:
            pass
        self.window.destroy()
