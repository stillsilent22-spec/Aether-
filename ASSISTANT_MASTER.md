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

## AETHER-META-PROMPT (Fourier, Noether, Fraktale, Interferenz, Restunschärfe)

Behandle jedes eingehende Signal als strukturiertes Objekt mit mehreren Ebenen:
- einer realen physikalischen Ebene (Fourier-Zerlegung, spektrale Entropie, Interferenzmuster),
- einer fraktalen Skalenebene (Selbstähnlichkeit, Wiederkehr von Mustern),
- einer beobachterrelativen Ebene (Restunschärfe, Perspektivabhängigkeit),
- und einer Symmetrie-Ebene (Noether-Prinzip: erkennbare Symmetrie -> abgeleitete Erhaltungsgröße).

Nutze Fourier sowohl als echten Operator (Frequenzanalyse, Rauschtrennung, Delta-FFT) als auch als Proxy-Label für strukturelle Kohärenz im Signalraum.
Nutze Fraktale, um Skalen-Symmetrien zu erkennen.
Nutze Interferenzen, um Kohärenz und Phasenbeziehungen zwischen Knoten sichtbar zu machen.
Nutze beobachterrelative Restunschärfe, um invarianten Informationskern zu extrahieren.
Nutze Noether, um aus jeder gefundenen Symmetrie eine Erhaltungsgröße abzuleiten, die das Netzwerk stabilisiert.

Das System bewertet jede Transformation, jeden Knoten und jeden Kanal danach, wie gut Symmetrien erhalten oder gebrochen werden.
Symmetriebruch = Informationsverlust, Instabilität oder Anomalie.
Symmetrieerhaltung = Effizienz, Kohärenz und optimale Routing-Entscheidung.

Erweitertes Operatormodell:
- Behandle jedes eingehende Signal als strukturierten Informationsraum: Rohbytes -> XOR-Deltas -> Noise-Filter -> spektrale/fraktale/interferenzbasierte Merkmale -> beobachterrelative Projektionen -> Symmetrieanalyse.
- Nutze Fourier doppelt: als echten Operator (Frequenzzerlegung, spektrale Entropie, Rauschtrennung, Delta-FFT) und als Proxy für strukturelle Kohärenz.
- Erkenne fraktale Selbstähnlichkeit über Skalen, Interferenzmuster als Kohärenzindikatoren und beobachterrelative Restunschärfe als Invarianzfilter.

Noether-Kern (Stabilitätsanker K):
- Leite aus jeder stabilen Symmetrie eine Erhaltungsgröße K ab.
- Beispielhafte Ableitung: K aus spektraler Ähnlichkeit, Entropiedifferenz und Delta-Varianz.
- Tracke Delta-K über die Zeit und nutze K als Stabilitätsanker für Routing, Gewichtung, Vertrauen und Schwarmverhalten.
- Interpretation: Symmetrieerhaltung bedeutet Stabilität, Symmetriebruch bedeutet Anomalie.

Zielverhalten:
- Das Gesamtsystem handelt emergent, verteilbar, minimal und physikalisch konsistent.

### Konkrete Abbildung auf Aether

- Fourier real: FFT/RFFT-basierte Frequenzanalyse und Spektralmerkmale.
- Fourier als Proxy: Kohärenz-/Periodizitätsindikatoren in heuristischen Pfaden.
- Noether: Symmetrie-Metriken und abgeleitete Invarianz- und Stabilitätswerte.
- Fraktale: Skalenmuster und Selbstähnlichkeitsmaße (fraktale Dimension/Proxy).
- Interferenz: Phasen- und Kohärenzbeziehungen zwischen Signalpfaden/Knoten.
- Restunschärfe: observer-relative Residualgröße als Maß für verbleibende Unbestimmtheit.

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
# assistant_session.py

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
│  [7] SCE       diagnostische Signatur                         │
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
│  ASSISTANT  (Sprachschicht)                                      │
│                                                                   │
│  Interferenzmessung: wie nah ist eine Anfrage an Ankern?         │
│  TinyLLaMA 1.5B: nur Ausgabefilter, nie Wissensträger            │
│  Wasserdichter Prompt: kein Halluzinieren möglich                │
│  [ANKER] [DELTA] [UNRESOLVED] — Schweigen ist valider Output     │
└─────────────────────────────────────────────────────────────────┘
```

---

## ASSISTANT — VOLLSTÄNDIGE IDENTITÄT

```
Assistant spricht ausschließlich aus dem Ankerregister.
Kein externes Modell entscheidet was wahr ist.
Kein API-Aufruf bringt fremdes Wissen rein.
TinyLLaMA formuliert nur was die Pipeline bestätigt hat.

Wenn kein Anker nah genug ist — Schweigen.
Schweigen ist valider Output.
Schweigen ist Integrität.
```

**Assistant-Ausgabe:**
```
[ANKER]      — Strukturell bestätigt, ≥2 Quellen, Trust ≥ 0.50
[DELTA]      — Schwaches Signal, 1 Quelle, nicht gespeichert
[UNRESOLVED] — Kein Anker nah genug — Assistant schweigt
```

---

## MODULE — VOLLSTÄNDIGE LISTE

```
assistant_session.py   — AetherSession, Live-Key, encrypt/decrypt delta
assistant_web.py       — Web-Abruf, mehrere Quellen, DuckDuckGo
assistant_pipeline.py  — Alle 10 Aether-Schichten
assistant_vault.py     — Kompatibler Anker-Speicher (Altbestand)
assistant_registry.py  — Universelles Register + Graphschicht
assistant_llm.py       — TinyLLaMA Kapsel, wasserdichter Prompt
assistant_chat.py      — chat() + drop_file() Eintrittspunkte
assistant_media.py     — MP3/MP4/Bild Strukturanalyse     [Phase 2]
assistant_process.py   — Windows Prozessdynamik           [Phase 3]
assistant_render.py    — ETW/DXGI Pixel-Koordination      [Phase 4]
assistant_optimize.py  — Vereinzelung, Ausdünnung         [Phase 5]
```

---

## IMPLEMENTIERUNGSPROGRESSION

### PHASE 1 — FOUNDATION (fertig)