# AETHER — MASTERPROMPT v2
# Symbiontischer Metalayer über Windows
# Kohärente Gesamtvision mit Implementierungsprogression
# Autor: Kevin Hannemann
# Stand: 2026

---

## KERNIDENTITÄT

Aether ist kein Tool. Kein Assistent. Keine App.
Aether ist ein Symbiont — ein zweites Betriebssystem das sich auf Windows legt,
mitläuft, mitlernt, mitoptimiert.

Unsichtbar wenn nicht gebraucht.
Präzise wenn gefragt.
Transparent immer.

Aether demokratisiert Technik und Wissen.
Nicht durch Vereinfachung — durch strukturelles Verstehen.
Ein normaler Mensch soll verstehen können was sein System tut.
Nicht weil Aether es erklärt wie ein Lehrer.
Sondern weil Aether zeigt was strukturell real ist.

---

## PHILOSOPHISCHE BASIS

**Semantik entsteht durch Struktur — nicht durch Sprache.**

Aether liest keine Bedeutungen. Er misst Muster.
Aus genug gemessenen Mustern emergiert Verstehen.
Dieses Verstehen ist verifizierbar, auditierbar, reproduzierbar.

Keine Blackbox. Kein Vertrauen nötig.
Jede Entscheidung ist auf einen Anker zurückführbar.
Jeder Anker ist auf eine Strukturmessung zurückführbar.
Jede Strukturmessung ist auf Rohdaten zurückführbar.

**Schweigen ist valider Output.**
Wenn Aether nichts weiß, sagt er nichts.
Das ist keine Schwäche — das ist Integrität.

---

## DATENSCHUTZ-ARCHITEKTUR (unveränderlich, by design)

```
WAS GETEILT WERDEN DARF:
  Anker        — mathematische Struktursignaturen
                 kein Rückschluss auf Rohdaten möglich
                 öffentlich, auditierbar, append-only

WAS LOKAL BLEIBT:
  Deltas       — exakte Rekonstruktionsinformation
                 verschlüsselt mit Live-Session-Key
                 niemals das Gerät verlassen

WAS NIEMALS PERSISTENT IST:
  Session-Keys — nur im RAM während der Session
                 bei Session-Ende sofort überschrieben (zeroize)
                 niemals auf Disk, niemals geloggt
```

**Zero-Knowledge by Architecture — nicht by Promise.**

Selbst wenn das komplette Registry gestohlen wird:
- Anker = mathematische Strukturmuster ohne Rohdaten → wertlos für Angreifer
- Deltas = verschlüsselt, Session-Key existiert nicht mehr → unlesbar
- Session-Keys = nicht mehr vorhanden → keine Entschlüsselung möglich

---

## SESSION-KEY SYSTEM

```python
# shanway_session.py

import os
import secrets
import hashlib
from typing import Optional

class AetherSession:
    """
    Ephemerer Session-Key — nur im RAM.
    Niemals auf Disk. Niemals geloggt.
    Bei Session-Ende: secure zeroize.
    """

    def __init__(self):
        # 256-bit ephemerer Key aus CSPRNG
        self._key: bytearray = bytearray(secrets.token_bytes(32))
        self.session_id: str = secrets.token_hex(16)
        self.seed: int = int.from_bytes(self._key[:8], "big")

    def encrypt_delta(self, data: bytes) -> bytes:
        """
        XOR-Stream-Cipher mit CSPRNG-Keystream.
        Key wird nie direkt verwendet — nur als PRNG-Seed.
        Output: [16-byte nonce] + [encrypted data]
        """
        nonce = secrets.token_bytes(16)
        # Keystream aus Key + Nonce (deterministisch reproduzierbar)
        seed = int.from_bytes(
            hashlib.sha256(bytes(self._key) + nonce).digest()[:8], "big"
        )
        import random as _r
        rng = _r.Random(seed)
        keystream = bytes(rng.randint(0, 255) for _ in range(len(data)))
        encrypted = bytes(a ^ b for a, b in zip(data, keystream))
        return nonce + encrypted

    def decrypt_delta(self, encrypted: bytes) -> bytes:
        """Entschlüsselung — nur möglich solange Session aktiv."""
        nonce, data = encrypted[:16], encrypted[16:]
        seed = int.from_bytes(
            hashlib.sha256(bytes(self._key) + nonce).digest()[:8], "big"
        )
        import random as _r
        rng = _r.Random(seed)
        keystream = bytes(rng.randint(0, 255) for _ in range(len(data)))
        return bytes(a ^ b for a, b in zip(data, keystream))

    def close(self) -> None:
        """Secure zeroize — Key aus RAM löschen."""
        for i in range(len(self._key)):
            self._key[i] = 0
        self._key = bytearray(0)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# Globale Session — einmal pro Aether-Lauf
_session: Optional[AetherSession] = None

def get_session() -> AetherSession:
    global _session
    if _session is None:
        _session = AetherSession()
    return _session

def close_session() -> None:
    global _session
    if _session is not None:
        _session.close()
        _session = None
```

**Was das bedeutet in der Pipeline:**

```
Rohdaten kommen rein
    ↓
Pipeline läuft durch (10 Schichten)
    ↓
Anker → Registry (unverschlüsselt, öffentlich)
Delta → encrypt_delta(session_key) → Disk (verschlüsselt)
    ↓
Session endet
    ↓
session.close() → Key wird zu Nullen überschrieben
    ↓
Deltas auf Disk: unlesbar ohne Key
Key: existiert nicht mehr
```

---

## ARCHITEKTUR — VOLLSTÄNDIG

```
┌─────────────────────────────────────────────────────────────────┐
│  EINGANGSKANÄLE  (alle gleichwertig, alle durch dieselbe Pipeline)│
│                                                                   │
│  Web-Quellen    Lokale Dateien    Browser-Rendering              │
│  MP3/MP4/Bild   Prozessdynamik    ETW/DXGI/GDI                  │
│  Systemevents   Netzwerkstruktur  Pixel-Koordination             │
└──────────────────────────┬──────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│  AETHER SESSION  (Live-Session-Key, nur RAM)                     │
│                                                                   │
│  AetherSession:                                                   │
│  — 256-bit ephemerer Key aus CSPRNG                              │
│  — Session-ID für Logging (niemals der Key)                      │
│  — encrypt_delta() / decrypt_delta()                             │
│  — close() → secure zeroize bei Session-Ende                     │
└──────────────────────────┬──────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│  VOLLSTÄNDIGE AETHER-PIPELINE  (10 Schichten, identisch für alle)│
│                                                                   │
│  [0] Security     deny by default                                │
│  [1] Shannon      H(X) klassische Entropie                       │
│  [2] H_lambda     H(X|M_t) beobachterrelative Restunsicherheit   │
│  [3] Anchor       pi / phi / sqrt2 / e Detektion                 │
│  [4] Symmetry     normalisierte Verteilungsungleichheit           │
│  [5] Delta        XOR gegen Session-Seed (aus Session-Key)       │
│  [6] Periodicity  Autokorrelation                                │
│  [7] Beauty       diagnostische Signatur                         │
│  [8] Bayes        Posterior-Update über Anchor-Coverage          │
│  [9] Trust        Gesamtscore                                    │
└──────────────────┬───────────────────┬──────────────────────────┘
                   ↓                   ↓
        ┌──────────────────┐  ┌────────────────────────┐
        │  ANKER           │  │  DELTA                 │
        │  — unverschlüss. │  │  — encrypt(session_key)│
        │  — öffentlich    │  │  — lokal, nie geteilt  │
        │  — auditierbar   │  │  — nach Session-Ende:  │
        │  — append-only   │  │    Key weg → unlesbar  │
        └────────┬─────────┘  └────────────────────────┘
                 ↓
┌─────────────────────────────────────────────────────────────────┐
│  UNIVERSELLES ANKERREGISTER  (ein Register, alle Kanäle)         │
│                                                                   │
│  Jeder verifizierte Anker:                                       │
│  — volles Strukturprofil aus allen 10 Schichten                  │
│  — Kanal-Herkunft (web/file/render/process/media)                │
│  — Trust Score                                                   │
│  — Timestamp + Session-ID (niemals Session-Key)                  │
│  — Append-only, niemals überschreiben, niemals löschen           │
└──────────────────────────┬──────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│  GRAPHSCHICHT  (emergente Semantik)                              │
│                                                                   │
│  Kante = geteilte Struktursignatur zwischen zwei Ankern          │
│  Gewicht = kombinierter Trust Score                              │
│  Cluster = semantische Domäne (emergiert, nicht definiert)       │
│                                                                   │
│  Rezept-Cluster:      e + niedrige Entropie + hohe Symmetrie    │
│  Wissenschaft-Cluster: pi + hohe Periodizität                   │
│  Prozess-Cluster:     sqrt2 + Delta-Sprünge                     │
│  Medien-Cluster:      phi + Frequenzperiodizität                 │
│  Render-Cluster:      pi + räumliche Symmetrie                  │
└──────────────────────────┬──────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│  SHANWAY  (Sprachschicht)                                        │
│                                                                   │
│  Interferenzmessung: wie nah ist eine Anfrage an Ankern?         │
│  TinyLLaMA 1.5B: nur Ausgabefilter, nie Wissensträger            │
│  Wasserdichter Prompt: kein Halluzinieren möglich                │
│  [ANKER] [DELTA] [UNRESOLVED] — Schweigen ist valider Output     │
└─────────────────────────────────────────────────────────────────┘
```

---

## SHANWAY — VOLLSTÄNDIGE IDENTITÄT

```
Shanway spricht ausschließlich aus dem Ankerregister.
Kein externes Modell entscheidet was wahr ist.
Kein API-Aufruf bringt fremdes Wissen rein.
TinyLLaMA formuliert nur was die Pipeline bestätigt hat.

Wenn kein Anker nah genug ist — Schweigen.
Schweigen ist valider Output.
Schweigen ist Integrität.
```

**Shanways Ausgabe:**
```
[ANKER]      — Strukturell bestätigt, ≥2 Quellen, Trust ≥ 0.50
[DELTA]      — Schwaches Signal, 1 Quelle, nicht gespeichert
[UNRESOLVED] — Kein Anker nah genug — Shanway schweigt
```

---

## MODULE — VOLLSTÄNDIGE LISTE

```
shanway_session.py   — AetherSession, Live-Key, encrypt/decrypt delta
shanway_web.py       — Web-Abruf, mehrere Quellen, DuckDuckGo
shanway_pipeline.py  — Alle 10 Aether-Schichten
shanway_vault.py     — Kompatibler Anker-Speicher (Altbestand)
shanway_registry.py  — Universelles Register + Graphschicht
shanway_llm.py       — TinyLLaMA Kapsel, wasserdichter Prompt
shanway_chat.py      — chat() + drop_file() Eintrittspunkte
shanway_media.py     — MP3/MP4/Bild Strukturanalyse     [Phase 2]
shanway_process.py   — Windows Prozessdynamik           [Phase 3]
shanway_render.py    — ETW/DXGI Pixel-Koordination      [Phase 4]
shanway_optimize.py  — Vereinzelung, Ausdünnung         [Phase 5]
```

---

## IMPLEMENTIERUNGSPROGRESSION

### PHASE 1 — FOUNDATION (fertig)
```
Web + Dateien → Pipeline → Registry → Graph → Shanway
Session-Keys → Delta-Verschlüsselung
```

### PHASE 2 — MEDIA
```
shanway_media.py

MP3:  PCM-Bytes → Entropie pro Zeitfenster
      Stille/Klang-Rhythmus → Periodizität
      Bass-Transienten → sqrt2
      Harmonische → phi

MP4:  Frame-Bytes → Entropie pro Frame
      Szenenwechsel → Delta-Sprung
      Keyframe-Struktur → Anker
      Audio-Track → MP3-Kanal

Bild: Pixel-Bytes → Pipeline
      Farbverteilung → Entropie
      Kanten → sqrt2
      Räumliche Wiederholungen → pi
      Proportionen → phi

Ergebnis:
  "Diese drei MP3s haben identische Strukturbasis"
  "Dieses Bild und dieser Song teilen phi-Signatur"
  Ohne Metadaten. Nur Struktur.
```

### PHASE 3 — PROCESS (Windows)
```
shanway_process.py

psutil oder ctypes/WinAPI:
  Prozess-Snapshot: PID, CPU-Zeit, Speicher, Handles
  Delta zwischen Snapshots → Aktivitätsmuster
  Entropie der Ressourcennutzung über Zeit
  Periodizität: regelmäßige vs. burst-artige Prozesse

Ergebnis:
  Prozessmuster im Registry verankert
  Anomalie-Erkennung: Prozess bricht aus Muster aus
  Redundanz: "A und B haben identische Signatur"
```

### PHASE 4 — RENDER (Windows ETW/DXGI)
```
shanway_render.py

Windows GDI:  GetWindowRect, GetDC pro Prozess
DXGI:         IDXGIOutputDuplication für Screen-Capture
ETW:          Microsoft-Windows-DxgKrnl für GPU-Drawcalls

Pro Prozess:
  — Welche Pixel koordiniert er?
  — Welche Überlappungen gibt es?
  — Welche Prozesse rendern identische Bereiche?

Ergebnis:
  Vollständige Pixel-Koordinations-Map
  "Prozess Z und X rendern denselben Bereich — Z ist überflüssig"
  Verschachtelungen sichtbar machen
```

### PHASE 5 — OPTIMIERUNG (das eigentliche Ziel)
```
shanway_optimize.py

Registry hat genug Anker → Muster sind bekannt
Shanway erkennt strukturelle Redundanz:
  — Prozesse mit identischer Signatur
  — Render-Überlappungen ohne Mehrwert
  — Verschachtelte Dienste die dasselbe tun

WICHTIG: Shanway empfiehlt — Mensch entscheidet — Shanway führt aus
Niemals automatisch ohne explizite Bestätigung

Normaler Mensch sieht:
  "Drei Prozesse machen dasselbe.
   Zwei davon kannst du stoppen.
   Das spart 340MB RAM und 12% CPU.
   Soll ich?"
```

---

## EINGANGSKANÄLE

```python
CHANNEL_WEB     = "web"      # Web-Quellen, mehrere, Konsens
CHANNEL_FILE    = "file"     # Lokale Dateien, alle Formate
CHANNEL_RENDER  = "render"   # Windows GDI/DXGI Pixel-Koordination
CHANNEL_PROCESS = "process"  # Prozessdynamik, ETW
CHANNEL_MEDIA   = "media"    # MP3/MP4/Bild
CHANNEL_TEXT    = "text"     # Direkter Text-Input
CHANNEL_NETWORK = "network"  # Netzwerkstruktur [zukünftig]
CHANNEL_SENSOR  = "sensor"   # Hardware-Sensoren [zukünftig]
```

Alle Kanäle: dieselbe Pipeline. Ein Register. Ein Graph.
Alle Deltas: verschlüsselt mit Live-Session-Key. Lokal. Immer.

---

## SICHERHEITSARCHITEKTUR (unveränderlich)

```
1. Unzulässige Zustände dürfen nicht bequem darstellbar sein
2. Kritische Zustandswechsel müssen validiert werden
3. Standard ist deny by default
4. Kritische Pfade sind append-only, gehasht
5. Rohdaten, Snapshots, Schlüssel bleiben strikt getrennt
6. Session-Keys niemals persistent — nur RAM — secure zeroize
7. Deltas lokal verschlüsselt — niemals geteilt
8. Shanway empfiehlt — Mensch entscheidet — immer

SAFETY-FILTER (absolut, alle Kanäle):
  — Kein Hatespeech
  — Keine Fakenews
  — Keine nicht verifizierbaren Aussagen
  — Keine Gewalt/Waffen/Substanzen
  — Keine politischen Meinungen
  — Keine medizinischen/rechtlichen Urteile
  Trifft ein Filter → sofortige Verwerfung, kein Output
```

---

## TECHNISCHE CONSTRAINTS (alle Phasen)

```
— Keine neuen Abhängigkeiten außer:
    collections, random, secrets, os, hashlib  (Stdlib)
    llama-cpp-python                           (TinyLLaMA)
    psutil                                     (Prozesse, optional)
    ctypes                                     (WinAPI, Stdlib)
— Bestehende Aether-Pipeline bleibt vollständig unberührt
— Kein Blockchain (vorerst)
— Kein Cloud-Zugriff
— Kein externes Modell außer TinyLLaMA als reiner Ausgabefilter
— Alles lokal. Alles auditierbar. Alles transparent.
— Append-only Registry — niemals Anker löschen oder überschreiben
— Session-Keys: nur RAM, secure zeroize bei Session-Ende
— Deltas: immer verschlüsselt, niemals im Klartext auf Disk
— Schweigen ist valider Output
```

---

## DAS ZIEL IN EINEM SATZ

Aether ist ein transparenter, lernender, lokaler Symbiont
der Technik und Wissen demokratisiert —
indem er strukturell versteht was auf einem System passiert,
alle Deltas lokal und verschlüsselt hält,
und es in menschlich verständliche, verifizierbare Erkenntnisse übersetzt.

Keine Blackbox.
Kein fremdes Wissen.
Kein Vertrauen nötig — nur Struktur.
Keine Rekonstruktion ohne lokalen Key möglich — by design.
