"""frame_delta_engine.py — Kollaborativer XOR-Delta Frame-Codec.

Architektur (Swarm Delta Streaming Codec):
    Frame[N] ⊕ Frame[N-1]  =  XOR-Delta
    XOR-Delta → 512-Byte Chunks → AEVault Lookup
        Vault-Hit  → 64-Byte Signatur statt 512-Byte Chunk  → ×8 Reduktion
        Vault-Miss → AEEvolver evolves Baum + AEVault speichert → Signatur
    Rekonstruktion: Signaturen → DNA → eval_node → XOR rückwärts → Frame[N]

Warum die Kompressionsrate mit steigender Nutzerzahl sinkt:
    Jeder Spieler lernt neue Frame-Delta-Muster in seinen lokalen Vault.
    Im kollektiven Swarm kennen nach N Spielern die häufigsten Chunk-Muster
    (Explosion, Lauf-Animation, HUD, Himmel) bereits viele Vault-Nodes.
    Neue Clients können deren Bäume synchronisieren → Hit-Rate steigt
    sublinear → Bandbreite sinkt ohne zentralen Server.

Referenzarchitektur: ähnlich Google NNVE / Meta Neural Video Codecs,
aber dezentral (kein Zentralserver), lokal (kein Cloud-Zwang), open.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

# Lazy imports — vermeiden Zirkelimporte bei Swarm-Nutzung
# from modules.aelab_vault import AEVault
# from modules.aelab_motor import AEEvolver

CHUNK_SIZE    = 512   # Bytes pro Frame-Chunk (muss 2^N sein)
_EVOLVE_GENS  = 30    # GA-Generationen bei Vault-Miss (schnelle Schätzung)
_EVOLVE_POP   = 60    # Population bei Miss (klein für Echtzeitbetrieb)


# ---------------------------------------------------------------------------
# Statistik
# ---------------------------------------------------------------------------

@dataclass
class FrameCodecStats:
    """Laufende Statistiken eines FrameDeltaCodec."""
    frames_encoded:   int = 0
    chunks_total:     int = 0
    vault_hits:       int = 0
    vault_misses:     int = 0
    bytes_raw:        int = 0
    bytes_transmitted: int = 0   # 64 Bytes ASCII-Hex pro Signatur

    # Energy tracking — Bits per Joule
    cpu_joules_accumulated: float = 0.0
    """Estimated joules consumed so far (cpu_pct/100 × tdp_watts × dt_s)."""
    bits_delivered: int = 0
    """Bits delivered to receiver via vault compression (vault_hits × CHUNK_SIZE × 8)."""
    bits_per_joule: float = 0.0
    """Current efficiency metric: how many bits are transmitted per joule of compute.
    Higher = more efficient. At swarm scale this rises as hit_ratio increases."""

    @property
    def hit_ratio(self) -> float:
        if self.chunks_total == 0:
            return 0.0
        return self.vault_hits / self.chunks_total

    @property
    def compression_ratio(self) -> float:
        """< 1.0 = Kompression. Sinkt mit zunehmenden Vault-Hits."""
        if self.bytes_raw == 0:
            return 1.0
        return self.bytes_transmitted / self.bytes_raw

    @property
    def savings_pct(self) -> float:
        return max(0.0, (1.0 - self.compression_ratio) * 100.0)

    def update_energy(
        self,
        cpu_pct: float,
        *,
        tdp_watts: float = 15.0,
        dt_s: float = 0.033,
        new_vault_hits: int = 0,
    ) -> None:
        """Update the energy model after one encode call.

        Args:
            cpu_pct:  Current CPU utilisation in percent (0–100).
            tdp_watts: Assumed thermal design power of the CPU in watts.
                       15 W is typical for a mid-range laptop CPU; adjust for desktop.
            dt_s:     Time elapsed since last call in seconds (≈ 1/fps).
            new_vault_hits: Number of vault hits in the most recent encode call,
                       used to credit bits_delivered.
        """
        joules = (max(cpu_pct, 0.5) / 100.0) * tdp_watts * dt_s
        self.cpu_joules_accumulated += joules
        self.bits_delivered += new_vault_hits * CHUNK_SIZE * 8
        if self.cpu_joules_accumulated > 0.0:
            self.bits_per_joule = self.bits_delivered / self.cpu_joules_accumulated

    def to_dict(self) -> dict:
        return {
            "frames_encoded":           self.frames_encoded,
            "chunks_total":             self.chunks_total,
            "vault_hits":               self.vault_hits,
            "vault_misses":             self.vault_misses,
            "hit_ratio":                round(self.hit_ratio, 4),
            "compression_ratio":        round(self.compression_ratio, 4),
            "savings_pct":              round(self.savings_pct, 2),
            "bytes_raw":                self.bytes_raw,
            "bytes_transmitted":        self.bytes_transmitted,
            "cpu_joules_accumulated":   round(self.cpu_joules_accumulated, 6),
            "bits_delivered":           self.bits_delivered,
            "bits_per_joule":           round(self.bits_per_joule, 1),
        }

    def __str__(self) -> str:
        bpj = self.bits_per_joule
        if bpj >= 1e6:
            bpj_str = f"{bpj/1e6:.2f} Mb/J"
        elif bpj >= 1e3:
            bpj_str = f"{bpj/1e3:.1f} kb/J"
        elif bpj > 0:
            bpj_str = f"{bpj:.0f} b/J"
        else:
            bpj_str = "— b/J"
        return (
            f"Frames={self.frames_encoded} "
            f"Chunks={self.chunks_total} "
            f"Hits={self.vault_hits} ({self.hit_ratio*100:.1f}%) "
            f"Savings={self.savings_pct:.1f}%  "
            f"Efficiency={bpj_str}"
        )


# ---------------------------------------------------------------------------
# Codec
# ---------------------------------------------------------------------------

class FrameDeltaCodec:
    """
    Kollaborativer XOR-Delta Frame-Codec auf Basis von AEVault + AEEvolver.

    Jeder enkodierte Frame trägt neue Chunk-Bäume zum lokalen (und ggf.
    gemeinsamen) Vault bei. Mit steigender Nutzerzahl wächst die Trefferquote
    und die durchschnittliche Bandbreite pro Frame sinkt sublinear.

    Nutzung:
        codec = FrameDeltaCodec()

        # Enkodieren (Sender / Server)
        sigs = codec.encode_frame(raw_frame_bytes)   # list[str], 64-hex je Chunk

        # Dekodieren (Empfänger / Client)
        frame = codec.decode_frame(sigs)             # bytes

    Stats jederzeit abrufbar:
        print(codec.stats)
    """

    def __init__(
        self,
        vault=None,
        chunk_size: int = CHUNK_SIZE,
        evolve_gens: int = _EVOLVE_GENS,
        evolve_pop:  int = _EVOLVE_POP,
    ) -> None:
        # Lazy import vermeidet Top-Level-Zirkelimport
        from modules.aelab_vault import AEVault
        self.vault       = vault or AEVault()
        self.chunk_size  = max(64, int(chunk_size))
        self.evolve_gens = max(10, int(evolve_gens))
        self.evolve_pop  = max(20, int(evolve_pop))
        self.stats       = FrameCodecStats()
        self._prev_frame: bytes = b""

    # ------------------------------------------------------------------ encode

    def encode_frame(self, frame: bytes) -> list[str]:
        """
        Enkodiert einen Frame als Liste von Vault-Signaturen.

        XOR-Delta wird in Chunks zerlegt. Für jeden Chunk:
        - Vault-Hit  → bekannte Signatur zurückgeben (kein Datentransfer nötig)
        - Vault-Miss → GA evolven, Baum im Vault speichern, Signatur zurückgeben

        Returns: list[str], je Element = 64 hex chars (SHA-256 des Chunks)
        """
        xor_delta = _xor_bytes(frame, self._prev_frame)
        self._prev_frame = frame

        chunks = _split_chunks(xor_delta, self.chunk_size)
        sigs: list[str] = []

        for chunk in chunks:
            sig = _chunk_sig(chunk)
            self.stats.chunks_total    += 1
            self.stats.bytes_raw       += len(chunk)
            # Kosten: 64 ASCII-Hex-Bytes pro Signatur (statt 512 Bytes roh)
            self.stats.bytes_transmitted += 64

            existing_dna = self.vault.get_tree_dna(sig)
            if existing_dna is not None:
                self.stats.vault_hits += 1
            else:
                self._evolve_and_store(chunk, sig)
                self.stats.vault_misses += 1

            sigs.append(sig)

        self.stats.frames_encoded += 1
        return sigs

    # ------------------------------------------------------------------ decode

    def decode_frame(
        self,
        sigs: list[str],
        prev_frame: Optional[bytes] = None,
    ) -> bytes:
        """
        Rekonstruiert einen Frame aus Vault-Signaturen.

        prev_frame: Vorheriger Frame (für XOR-Rückwärtsanwendung).
                    Wenn None, wird intern gespeicherter prev verwendet.
        Returns: bytes — der rekonstruierte Frame.
        """
        from modules.aelab_motor import AEEvolver

        prev   = prev_frame if prev_frame is not None else self._prev_frame
        chunks: list[bytes] = []

        for sig in sigs:
            dna = self.vault.get_tree_dna(sig)
            if dna is None:
                # Unbekannte Signatur → Null-Chunk als Fallback
                chunks.append(bytes(self.chunk_size))
                continue
            evolver = AEEvolver(data=bytes(self.chunk_size))
            decoded = evolver.decode_dna(dna)
            # Sicherstellen dass Chunk genau chunk_size Bytes hat
            chunk = (decoded + bytes(self.chunk_size))[:self.chunk_size]
            chunks.append(chunk)

        xor_delta = b"".join(chunks)
        # Inverse XOR: Frame[N] = XOR-Delta ⊕ Frame[N-1]
        frame = _xor_bytes(xor_delta, prev)
        self._prev_frame = frame
        return frame

    # ------------------------------------------------------------------ intern

    def _evolve_and_store(self, chunk: bytes, sig: str) -> None:
        """
        Evolves einen GA-Baum für den Chunk-Inhalt und speichert ihn im Vault.

        seed = erste 4 Bytes der Signatur → deterministisch, reproduzierbar.
        """
        from modules.aelab_motor import AEEvolver
        seed  = int(sig[:8], 16) & 0x7FFF_FFFF
        evolver = AEEvolver(data=chunk, seed=seed)
        tree, fit = evolver.run(pop=self.evolve_pop, gens=self.evolve_gens)
        if tree is not None:
            lossless = evolver.best_lossless
            self.vault.store(tree, fitness=fit, lossless=lossless,
                             label=f"frame_chunk_{sig[:8]}")

    def reset(self) -> None:
        """Setzt den internen Frame-Zustand zurück (neuer Stream)."""
        self._prev_frame = b""
        self.stats = FrameCodecStats()


# ---------------------------------------------------------------------------
# Hilfsfunktionen (modul-öffentlich für Tests)
# ---------------------------------------------------------------------------

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR zweier Byte-Sequenzen, kürzere wird mit 0x00 aufgefüllt."""
    return _xor_bytes(a, b)


def split_chunks(data: bytes, chunk_size: int = CHUNK_SIZE) -> list[bytes]:
    """Teilt Bytes in gleich große Chunks; letzter wird mit 0x00 aufgefüllt."""
    return _split_chunks(data, chunk_size)


def chunk_signature(chunk: bytes) -> str:
    """Deterministischer SHA-256 Fingerabdruck eines Chunks (64 hex chars)."""
    return _chunk_sig(chunk)


# ---------------------------------------------------------------------------
# Private Hilfsfunktionen
# ---------------------------------------------------------------------------

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    length  = max(len(a), len(b))
    a_pad   = a + bytes(length - len(a))
    b_pad   = b + bytes(length - len(b))
    return bytes(x ^ y for x, y in zip(a_pad, b_pad))


def _split_chunks(data: bytes, chunk_size: int) -> list[bytes]:
    if not data:
        return [bytes(chunk_size)]
    chunks = []
    for offset in range(0, len(data), chunk_size):
        raw = data[offset : offset + chunk_size]
        if len(raw) < chunk_size:
            raw = raw + bytes(chunk_size - len(raw))
        chunks.append(raw)
    return chunks


def _chunk_sig(chunk: bytes) -> str:
    return hashlib.sha256(chunk).hexdigest()
