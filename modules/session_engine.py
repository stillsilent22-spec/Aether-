"""Dart-Session-System mit dynamischem Algorithmus-Pool."""

from __future__ import annotations

import json
import hashlib
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Sequence, Tuple
from uuid import uuid4


def _ensure_bytes(data: Any) -> bytes:
    """Wandelt beliebige Eingaben robust in Bytes um."""
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-8", errors="replace")
    return str(data).encode("utf-8", errors="replace")


class XorVariantA:
    """XOR-Transformation mit seedbasiertem Schlüssel A."""

    def __init__(self, seed: int) -> None:
        """Initialisiert den Algorithmus mit deterministischem Schlüssel."""
        self.key = ((seed >> 3) ^ 0xA5) & 0xFF

    def transform(self, payload: bytes) -> bytes:
        """Verschlüsselt Bytes per XOR."""
        return bytes(byte ^ self.key for byte in payload)

    def inverse(self, payload: bytes) -> bytes:
        """Stellt den Originalzustand per XOR wieder her."""
        return self.transform(payload)


class XorVariantB:
    """XOR-Transformation mit seedbasiertem Schlüssel B."""

    def __init__(self, seed: int) -> None:
        """Initialisiert den Algorithmus mit deterministischem Schlüssel."""
        self.key = ((seed << 1) ^ 0x5A) & 0xFF

    def transform(self, payload: bytes) -> bytes:
        """Transformiert Bytes per XOR."""
        return bytes(byte ^ self.key for byte in payload)

    def inverse(self, payload: bytes) -> bytes:
        """Kehrt die XOR-Transformation exakt um."""
        return self.transform(payload)


class BitRotationLeft:
    """Rotiert alle Bits je Byte zyklisch nach links."""

    def __init__(self, seed: int) -> None:
        """Legt die Rotationsweite aus dem Seed fest."""
        self.shift = (seed % 7) + 1

    def transform(self, payload: bytes) -> bytes:
        """Führt die Linksrotation aus."""
        shift = self.shift
        return bytes(((byte << shift) & 0xFF) | (byte >> (8 - shift)) for byte in payload)

    def inverse(self, payload: bytes) -> bytes:
        """Führt die inverse Rechtsrotation aus."""
        shift = self.shift
        return bytes((byte >> shift) | ((byte << (8 - shift)) & 0xFF) for byte in payload)


class BitRotationRight:
    """Rotiert alle Bits je Byte zyklisch nach rechts."""

    def __init__(self, seed: int) -> None:
        """Legt die Rotationsweite aus dem Seed fest."""
        self.shift = (seed % 7) + 1

    def transform(self, payload: bytes) -> bytes:
        """Führt die Rechtsrotation aus."""
        shift = self.shift
        return bytes((byte >> shift) | ((byte << (8 - shift)) & 0xFF) for byte in payload)

    def inverse(self, payload: bytes) -> bytes:
        """Führt die inverse Linksrotation aus."""
        shift = self.shift
        return bytes(((byte << shift) & 0xFF) | (byte >> (8 - shift)) for byte in payload)


class FibonacciMask:
    """Maskiert Daten mit einer Fibonacci-basierten XOR-Sequenz."""

    def __init__(self, seed: int) -> None:
        """Initialisiert Startwerte für die Maskenfolge."""
        self.a = (seed % 251) + 1
        self.b = ((seed >> 8) % 251) + 1

    def _mask(self, length: int) -> bytes:
        """Erzeugt eine deterministische Maskenfolge."""
        a, b = self.a, self.b
        result = []
        for _ in range(length):
            result.append(a & 0xFF)
            a, b = b, (a + b) % 256
        return bytes(result)

    def transform(self, payload: bytes) -> bytes:
        """Maskiert die Nutzdaten per XOR."""
        mask = self._mask(len(payload))
        return bytes(byte ^ m for byte, m in zip(payload, mask))

    def inverse(self, payload: bytes) -> bytes:
        """Hebt die XOR-Maskierung verlustfrei auf."""
        return self.transform(payload)


class LcgScramble:
    """Mischt Daten über eine lineare Kongruenzfolge."""

    def __init__(self, seed: int) -> None:
        """Initialisiert die Folgeparameter."""
        self.seed = seed & 0xFFFFFFFF

    def _sequence(self, length: int) -> bytes:
        """Liefert eine deterministische Pseudozufallssequenz."""
        state = self.seed
        values = []
        for _ in range(length):
            state = (1664525 * state + 1013904223) & 0xFFFFFFFF
            values.append((state >> 16) & 0xFF)
        return bytes(values)

    def transform(self, payload: bytes) -> bytes:
        """Addiert die LCG-Sequenz modulo 256."""
        seq = self._sequence(len(payload))
        return bytes((byte + s) % 256 for byte, s in zip(payload, seq))

    def inverse(self, payload: bytes) -> bytes:
        """Subtrahiert die LCG-Sequenz modulo 256."""
        seq = self._sequence(len(payload))
        return bytes((byte - s) % 256 for byte, s in zip(payload, seq))


class ModuloFold:
    """Faltet Werte über einen indexabhängigen Modulo-Term."""

    def __init__(self, seed: int) -> None:
        """Initialisiert den Faltungsparameter."""
        self.fold = (seed % 13) + 3

    def transform(self, payload: bytes) -> bytes:
        """Verschiebt jedes Byte um den indexabhängigen Offset."""
        return bytes((byte + (idx % self.fold)) % 256 for idx, byte in enumerate(payload))

    def inverse(self, payload: bytes) -> bytes:
        """Entfernt den indexabhängigen Offset."""
        return bytes((byte - (idx % self.fold)) % 256 for idx, byte in enumerate(payload))


class CaesarShift:
    """Klassischer Caesar-Shift auf Byteebene."""

    def __init__(self, seed: int) -> None:
        """Legt die Shift-Stärke deterministisch fest."""
        self.shift = (seed % 25) + 1

    def transform(self, payload: bytes) -> bytes:
        """Verschiebt alle Bytes nach vorne."""
        return bytes((byte + self.shift) % 256 for byte in payload)

    def inverse(self, payload: bytes) -> bytes:
        """Verschiebt alle Bytes zurück."""
        return bytes((byte - self.shift) % 256 for byte in payload)


class MirrorFlip:
    """Spiegelt die Bytereihenfolge."""

    def __init__(self, seed: int) -> None:
        """Initialisiert den zustandslosen Spiegel-Algorithmus."""
        self.seed = seed

    def transform(self, payload: bytes) -> bytes:
        """Dreht die Bytereihenfolge um."""
        return payload[::-1]

    def inverse(self, payload: bytes) -> bytes:
        """Stellt die ursprüngliche Reihenfolge wieder her."""
        return payload[::-1]


class EntropyInvert:
    """Invertiert die Bitmuster aller Bytes."""

    def __init__(self, seed: int) -> None:
        """Initialisiert den zustandslosen Inverter."""
        self.seed = seed

    def transform(self, payload: bytes) -> bytes:
        """Invertiert jedes Byte bitweise."""
        return bytes(255 - byte for byte in payload)

    def inverse(self, payload: bytes) -> bytes:
        """Kehrt die Invertierung exakt um."""
        return bytes(255 - byte for byte in payload)


ALGORITHM_POOL = [
    XorVariantA,
    XorVariantB,
    BitRotationLeft,
    BitRotationRight,
    FibonacciMask,
    LcgScramble,
    ModuloFold,
    CaesarShift,
    MirrorFlip,
    EntropyInvert,
]


class SessionContext:
    """Kapselt die komplette Laufzeitsession samt Transformationslogik."""

    def __init__(self, seed: int | None = None, security_session: Any | None = None) -> None:
        """
        Erstellt eine neue Session mit drei zufällig gezogenen Algorithmen.

        Args:
            seed: Optionaler Seed für reproduzierbare Tests.
            security_session: Optionaler lokaler Login-Kontext.
        """
        self.user_id = int(getattr(security_session, "user_id", 0) or 0)
        self.username = str(getattr(security_session, "username", "local"))
        self.user_role = str(getattr(security_session, "role", "operator"))
        self.live_session_key = str(getattr(security_session, "live_session_key", ""))
        self.live_session_fingerprint = str(getattr(security_session, "live_session_fingerprint", ""))
        self.raw_storage_key_hex = str(getattr(security_session, "raw_storage_key_hex", ""))
        self.raw_storage_key_fingerprint = str(getattr(security_session, "raw_storage_fingerprint", ""))
        self.user_settings = dict(getattr(security_session, "user_settings", {}) or {})
        self.login_algorithms = tuple(getattr(security_session, "algorithm_pair", ("sha256", "blake2b")))
        self.session_id = str(getattr(security_session, "session_id", "") or uuid4())
        derived_seed = getattr(security_session, "session_seed", None)
        self.session_seed = int(
            seed if seed is not None else (
                derived_seed if derived_seed is not None else random.SystemRandom().randrange(0, 2**32)
            )
        ) & 0xFFFFFFFF
        self.seed = int(self.session_seed)
        self.created_at = str(getattr(security_session, "login_at", "") or datetime.now(timezone.utc).isoformat())
        self.raw_storage_enabled = bool(self.user_settings.get("store_raw_encrypted", False))
        self.security_mode = str(self.user_settings.get("security_mode", "PROD") or "PROD").upper()
        self.node_id = ""
        self.baseline_node_id = ""
        self.trust_state = "TRUSTED"
        self.maze_state = "NONE"
        self.security_summary = ""
        self.security_findings: list[dict[str, Any]] = []
        self.security_policy: dict[str, Any] = {}
        self.security_self_metrics: dict[str, Any] = {}
        self.security_checked_at = ""
        picked = random.sample(ALGORITHM_POOL, 3)
        self.active_algorithms = [cls((self.seed + idx * 977) & 0xFFFFFFFF) for idx, cls in enumerate(picked)]
        self.honeypot_clusters: List[dict[str, Any]] = []

    def get_seed(self) -> int:
        """Liefert den stabilen Session-Seed fuer diese Laufzeitsitzung."""
        return int(getattr(self, "session_seed", self.seed) or 0) & 0xFFFFFFFF

    def apply_security_state(self, state: dict[str, Any] | None) -> None:
        """Uebernimmt den aktuellen lokalen Sicherheitszustand in die Session."""
        snapshot = dict(state or {})
        self.node_id = str(snapshot.get("node_id", self.node_id or ""))
        self.baseline_node_id = str(snapshot.get("baseline_node_id", self.baseline_node_id or self.node_id))
        self.security_mode = str(snapshot.get("mode", self.security_mode or "PROD") or "PROD").upper()
        self.trust_state = str(snapshot.get("trust_state", self.trust_state or "TRUSTED") or "TRUSTED").upper()
        self.maze_state = str(snapshot.get("maze_state", self.maze_state or "NONE") or "NONE").upper()
        self.security_summary = str(snapshot.get("summary", self.security_summary or ""))
        self.security_findings = [dict(item) for item in list(snapshot.get("findings", [])) if isinstance(item, dict)]
        self.security_policy = {
            str(key): value for key, value in dict(snapshot.get("policy", {})).items()
        }
        self.security_self_metrics = {
            str(key): value for key, value in dict(snapshot.get("self_metrics", {})).items()
        }
        self.security_checked_at = str(snapshot.get("checked_at", self.security_checked_at or ""))
        self.user_settings["security_mode"] = self.security_mode

    def security_allows(self, capability: str, default: bool = True) -> bool:
        """Prueft eine benannte Sicherheitsfreigabe aus der aktuellen Policy."""
        if not capability:
            return bool(default)
        return bool(self.security_policy.get(str(capability), default))

    def raw_storage_key_bytes(self, storage_seed: int | None = None) -> bytes:
        """Leitet den lokalen AES-256-Schluessel fuer einen Storage-Seed ab."""
        key_hex = str(self.raw_storage_key_hex).strip()
        if len(key_hex) != 64:
            return b""
        try:
            master_key = bytes.fromhex(key_hex)
        except ValueError:
            return b""
        seed_value = int(self.seed if storage_seed is None else storage_seed) & 0xFFFFFFFF
        return hashlib.sha256(
            master_key + b"|" + str(seed_value).encode("ascii") + b"|dual-mode-storage"
        ).digest()

    def file_delta_key_bytes(
        self,
        file_hash: str,
        record_id: int,
        session_id: str | None = None,
    ) -> bytes:
        """Leitet einen eindeutigen lokalen Datei-Key fuer Delta-/Raw-Schutz ab."""
        key_hex = str(self.raw_storage_key_hex).strip()
        if len(key_hex) != 64:
            return b""
        try:
            master_key = bytes.fromhex(key_hex)
        except ValueError:
            return b""
        scoped_session_id = str(session_id or self.session_id or "")
        scoped_file_hash = str(file_hash or "")
        scoped_record_id = int(record_id)
        return hashlib.sha256(
            master_key
            + b"|"
            + scoped_session_id.encode("utf-8", errors="replace")
            + b"|"
            + scoped_file_hash.encode("ascii", errors="replace")
            + b"|"
            + str(scoped_record_id).encode("ascii")
            + b"|session-file-delta-key"
        ).digest()

    def file_delta_key_fingerprint(
        self,
        file_hash: str,
        record_id: int,
        session_id: str | None = None,
    ) -> str:
        """Liefert nur den nicht-sensitiven Fingerprint eines lokalen Datei-Keys."""
        key = self.file_delta_key_bytes(file_hash=file_hash, record_id=record_id, session_id=session_id)
        if len(key) != 32:
            return ""
        return hashlib.sha256(key).hexdigest()[:24].upper()

    @staticmethod
    def noise_from_seed(seed: int, length: int) -> bytes:
        """
        Erzeugt deterministisches Aether-Rauschen für einen Seed.

        Args:
            seed: Seed der Session.
            length: Gewünschte Länge in Bytes.
        """
        rng = random.Random(seed & 0xFFFFFFFF)
        return bytes(rng.getrandbits(8) for _ in range(max(0, length)))

    def generate_aether_noise(self, length: int) -> bytes:
        """
        Erzeugt aus dem Session-Seed deterministisches Aether-Rauschen.

        Für denselben Seed und dieselbe Länge ist das Ergebnis immer identisch.
        """
        return self.noise_from_seed(self.seed, length)

    def apply_session_transform(self, data: Any) -> bytes:
        """
        Wendet die drei aktiven Session-Algorithmen nacheinander auf Daten an.

        Args:
            data: Eingabedaten als Bytes, Bytearray, String oder anderes Objekt.
        """
        transformed = _ensure_bytes(data)
        for algorithm in self.active_algorithms:
            transformed = algorithm.transform(transformed)
        return transformed

    def generate_honeypots(self) -> list[dict[str, Any]]:
        """
        Erzeugt fünf synthetische Köder-Datensätze im Stil von AetherFingerprint-Objekten.

        Returns:
            Liste mit fünf Honeypot-Datensätzen.
        """
        if str(getattr(self, "security_mode", "PROD") or "PROD").upper() != "PROD":
            self.honeypot_clusters = []
            return []
        rng = random.Random((self.seed ^ 0xA3C59AC3) & 0xFFFFFFFF)
        honeypots: list[dict[str, Any]] = []
        for _ in range(5):
            coordinate = (rng.randint(0, 15), rng.randint(0, 15))
            synthetic = {
                "session_id": self.session_id,
                "file_hash": f"{rng.getrandbits(256):064x}",
                "file_size": rng.randint(128, 5_000_000),
                "entropy_mean": round(rng.uniform(0.5, 7.9), 5),
                "symmetry_score": round(rng.uniform(8.0, 98.0), 4),
                "periodicity": rng.choice([0, 2, 4, 8, 16, 32, 64]),
                "verdict": rng.choice(["CLEAN", "SUSPICIOUS", "CRITICAL"]),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "coordinate": coordinate,
            }
            honeypots.append(synthetic)
        self.honeypot_clusters = honeypots
        return honeypots

    def is_honeypot(self, coordinate: Sequence[int]) -> bool:
        """
        Prüft, ob eine Koordinate einem hinterlegten Honeypot entspricht.

        Args:
            coordinate: Koordinate als Tupel oder Liste im Format (x, y).
        """
        try:
            target = (int(coordinate[0]), int(coordinate[1]))
        except (TypeError, ValueError, IndexError):
            return False
        return any(tuple(item.get("coordinate", (-1, -1))) == target for item in self.honeypot_clusters)

    def trigger_honeypot_alert(self, coordinate: Tuple[int, int], reason: str = "Unerlaubter Zugriff erkannt") -> None:
        """
        Schreibt einen verschlüsselten Alert-Log und versucht zusätzlich einen HTTP-Beacon.

        Netzwerkfehler werden absichtlich still abgefangen, damit der Offline-Betrieb jederzeit
        ohne Unterbrechung weiterläuft.
        """
        payload = {
            "session_id": self.session_id,
            "seed_hint": (self.seed ^ 0x55AA55AA) & 0xFFFFFFFF,
            "coordinate": [int(coordinate[0]), int(coordinate[1])],
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        keystream = self.generate_aether_noise(len(raw))
        encrypted = bytes(a ^ b for a, b in zip(raw, keystream))

        try:
            project_root = Path(__file__).resolve().parents[1]
            log_dir = project_root / "data" / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = log_dir / "honeypot_alerts.log"
            with log_file.open("a", encoding="utf-8") as handle:
                handle.write(
                    f"{datetime.now(timezone.utc).isoformat()}|{encrypted.hex()}|session={self.session_id}\n"
                )
        except OSError:
            print("Warnung: Honeypot-Log konnte nicht gespeichert werden.")
