# Aether Delta Engine

**Strukturelle Invarianten-Analyse · Datenschutzkonforme Kompression · Verteiltes Vault-Lernen**

> **Status: Alpha — April 2026**
> Die Kern-Pipeline ist deterministisch und testabgedeckt. Das Swarm befindet sich in früher Peer-Integration.
> Kein Server erforderlich. Keine Accounts. Keine Rohdaten verlassen das Gerät.
> Die Schwarm-Adaption ist durch strikte Stage-/Level- und Konvergenz-Konsenszustände gegated; bei fehlender Konsistenz aktiviert die Blindspot-Engine kollektive Gap-Behebung.

---

## Was Aether macht

Aether misst mathematische Strukturinvarianten in beliebigen Byte-Streams und nutzt
diese Invarianten — niemals die Rohdaten — als Grundlage für Kompression, verteilten
Vergleich und Peer-Vertrauensbewertung.

Jeder Byte-Stream besitzt eine strukturelle Signatur unabhängig von seinem Inhalt.
Aether extrahiert diese Signatur über einen deterministischen 9-Metrik-Durchlauf,
speichert sie als Ausdrucksbaum in einem lokalen Vault und teilt nur den 64-Byte
SHA-256-Hash von Strukturankern mit Peers — nach Bestätigung durch mindestens 3 unabhängige Knoten.
Algo-Token-Sharing hingegen ist ein direkter Peer-Austausch: empfangene Tokens werden
lokal auf Struktur-Integrität, `source_node_id` und Fitness-Schwelle geprüft.
Rohdaten, Session-Keys und Deltas verlassen das Gerät niemals.

---

## Architekturübersicht

```
                 ┌───────────────────────────────┐
                 │         Rust / iced UI         │
                 │  Analyse · Gaming · Live Render │
                 │  Kolmogorov · Rekonstruktion    │
                 └──────────────┬────────────────┘
                                │ Rust Shell → Python via subprocess
                 ┌──────────────▼────────────────┐
                 │       Python-Pipeline          │
                 │  9-Metrik-Durchlauf            │
                 │  AELab (adaptive Evolution)    │
                 │  GP-Vault (Ausdrucksbäume)     │
                 │  Frame-Delta-Codec (XOR)       │
                 │  Symbiont / Blindspot Engine   │
                 └──────────────┬────────────────┘
                                │ Einwilligungsgesteuert, nur Hash
                 ┌──────────────▼────────────────┐
                 │        Swarm / P2P             │
                 │  LAN-Beacon → Gossip → DHT     │
                 │  Yggdrasil IPv6-Overlay        │
                 │  Quorum-Gate: ≥ 3 Knoten       │
                 └───────────────────────────────┘
```

**Determinismus-Regel:** Der vollständige Analyse-Durchlauf wird ausschließlich über
die Rust-Shell ausgelöst. Direkter Python-Aufruf umgeht die Integritätsgarantien
und ist in der Produktion gesperrt.

---

## Der 9-Metrik-Durchlauf

Metriken werden in fester Reihenfolge berechnet. Die Reihenfolge ist unveränderlich.

| # | Metrik | Formel | Bereich |
|---|--------|--------|---------|
| 1 | Shannon-Entropie | H(X) = −Σ p(x) log₂ p(x) | [0, 8] |
| 2 | Boltzmann-Entropie | S = −Σ pᵢ ln pᵢ / ln 256, orthogonale Basis | [0, 1] |
| 3 | Zipf-Alpha | Potenzgesetz-Exponent via Log-Log-Regression | ℝ⁺ |
| 4 | Benford-Score | Führungsziffern vs. log₁₀(1 + 1/d) | [0, 1] |
| 5 | Fourier-Periodizität | Dominante Spektralperiode über Block-RFFT | [0, 1] |
| 6 | Katz-Dimension | D = log(n) / (log(n) + log(d/L)) | [1, ∞) |
| 7 | Permutations-Entropie | Bandt & Pompe (2002), Ordnung m=3, normiert | [0, 1] |
| 8 | Delta-Konvergenz | ‖Φ_norm(t) − Φ_norm(t−1)‖₂ / √8 | [0, 1] |
| 9 | Noether-Konsistenz | Symmetrieerhaltung vorwärts/rückwärts | [0, 1] |

**Trust Score:** gewichtete Summe aller 9 Metriken, Bayes-Posterior und physikalische
Plausibilität (Heisenberg-Proxy). Teilnahmeschwelle: `trust_score ≥ 0.65`.
Kein Einladesystem. Keine Accounts. Das Kaskaden-Ergebnis ist der Proof of Work.

---

## Datenschutz-Architektur

```
LOKAL (Gerät)                NETZWERK (Swarm)
────────────────────         ────────────────────────────────
Rohdaten        →  NIEMALS → Netzwerk
Deltas          →  NIEMALS → Netzwerk
Session-Keys    →  NIEMALS → Netzwerk (nur RAM, nach Session gelöscht)
Tastenanschläge /
Eingaberhythmus →  NIEMALS → gespeichert oder passiv beobachtet
                                   ↕  (einwilligungsgesteuert)
Strukturanker   → SHA-256-Hash, nach ≥ 3-Knoten-Quorum, nicht invertierbar
```

Dies ist auf Code-Ebene durchgesetzt (`privacy_registry.py`, `privacy_observer.py`,
`session_guard.py`) — nicht durch Policy.

---

## Vault und Kompression

### Frame-Delta-Codec
```
XOR_Δ_N = Frame_N ⊕ Frame_{N-1}
→ 512-Byte-Chunks → SHA-256-Vault-Lookup
  Vault-Treffer:  64-Byte-DNA-Signatur (8× Größenreduktion)
  Vault-Fehler:   GP-Evolution findet kompakten Ausdrucksbaum → gespeichert
```

### Genetischer Programmier-Vault (GP-Vault)
Ausdrucksbäume ("DNA-Format") werden evolviert, um 512-Byte-Strukturmuster verlustfrei
darzustellen. Mathematische Konstanten (π, e, φ) entstehen wenn strukturell sinnvoll —
sie werden nie hardcodiert, immer hergeleitet.

### AELab — Adaptive Evolution Laboratory
Interne Lernschicht. Analysiert jeden Byte-Stream vor dem Vault-Commit und
prüft ob das strukturelle Ergebnis die Qualitätsgates erfüllt:

| Gate | Schwellenwert | Effekt bei Unterschreitung |
|------|--------------|--------------------------|
| `lossless` | ≥ 0.95 | Vault-Commit gesperrt |
| `trust_score` | ≥ 0.65 | Kein Swarm-Beitrag |
| `has_anchor` | `true` | Pflicht für Commit |
| `commit_allowed` | kombiniert | Steuert gesamten Pipeline-Commit |

### Vault-Konvergenz (theoretische Schranke)
Für einen Vault der Größe n und eine Quelle mit Shannon-Entropie H(X):

```
Erwarteter Übertragungsaufwand je Chunk:   C(n) = h(n) · 64 + (1 − h(n)) · 512   [Byte]
Untere Schranke Trefferrate:               h(n) ≥ 1 − e^(−λn)
Grenzwert:                                 lim_{n→∞} C(n) = 64 Byte
```

Dies ist eine theoretische Schranke. Empirische Verifikation erfordert einen
laufenden Swarm mit ausreichender Vault-Diversität.

---

## Gödelstop — Selbstreferenz-Schutz

Die Live-Render-Analyseschleife enthält einen Gödelstop-Mechanismus:

- Die innere GP-Probe misst wie stark sich die eigene Analyseausgabe von Tick zu Tick
  ändert (Delta < 1% = "konvergiert").
- Erkennt die äußere Schleife ≥ 5 stabile innere Proben in Folge, wird die
  äußere Analyse für diesen Tick pausiert.
- Verhindert dass das System endlos seine eigene stabile Ausgabe analysiert.
- Der Zähler setzt sich automatisch zurück sobald sich das Signal wieder ändert.

Die Live-Render-Statusleiste zeigt den aktuellen Gödelstop-Level zusammen mit
XOR-Delta-Rate, gespeicherten Mustern und — wenn ein Spiel aktiv ist — den
mss-Pixel-Capture-Metriken.

---

## Live Render — Pixel-Capture

Wenn Live Render aktiv ist und ein Spielprozess verfolgt wird (Gaming-Tab):

1. Die Rust-Shell feuert `analyze_live_signal_for_shell` je Tick mit `game_label`.
2. Python löst die PID des Spiels via psutil auf und ruft
   `RenderCoordinator.capture_process_render(pid, window_title=game_label)` auf.
3. Der mss-Screenshot wird strukturell analysiert (Shannon-Entropie, Symmetrie, Resonanz).
4. Ergebnisse fließen als `pixel_entropy / pixel_symmetry / pixel_source` zurück in die Rust-UI.

Die eigene PID ist immer gesperrt (Gödel-Selbstreferenz-Lock in `RenderCoordinator`).
Ein Vollbild-Capture findet nie statt — immer auf ein spezifisches Prozessfenster begrenzt.

---

## Gaming-Tab — Quorum-gesteuerte Einblicke

Geteilte strukturelle Einblicke für ein Spiel werden erst freigeschaltet wenn **≥ 3
verschiedene Spieler** dasselbe Spiel unabhängig analysiert haben. Einzelknoten-
Beobachtungen bleiben im Wartestatus. Das verhindert dass das strukturelle Profil
eines einzigen Spielers als allgemeines Spielmuster gilt.

---

## Swarm-Netzwerktier

Aether leitet den möglichen Netzwerktier automatisch aus der lokalen Hardware ab.
Keine manuelle Konfiguration — der Tier emergiert.

| Tier | Name | Mindestvoraussetzung | Funktionen |
|------|------|---------------------|------------|
| 0 | LocalOnly | < 256 MB RAM, Win 9x | Nur lokale Analyse, kein Netz |
| 1 | LanBeacon | ≥ 256 MB, Win 2000+ | UDP-Announce im LAN, passiv |
| 2 | LanP2P | ≥ 512 MB, ≥ 2 Kerne | Gossip + Leader-Election im LAN |
| 3 | YggdrasilP2P | ≥ 1 GB, Win Vista+, RPi 3+ | Yggdrasil IPv6-Overlay, geräteübergreifend |
| 4 | FullDht | ≥ 4 GB, ≥ 4 Kerne, modern | Kademlia-DHT, Relay-Knoten |

Erkannte Plattformen: Windows 9x/ME/2000/XP/Vista/7/8/10/11,
Linux (Kernel < 4: LanP2P max; Kernel ≥ 4: bis FullDht),
Raspberry Pi 1/Zero (LanBeacon) bis Pi 4/5 (YggdrasilP2P),
Android (natives APK, API 21+, kein Python erforderlich).

Ein Tier-Watchdog prüft alle 90 s ob Ressourcen frei geworden sind.
Bei Tier-Upgrade startet P2P automatisch — kein Neustart nötig.
Nach 10 erfolglosen Checks beendet der Watchdog sich; das Gerät bleibt auf StealthBeacon.

---

## Boot-Pfade — faire Integration für ältere Hardware

| Pfad | Einstiegspunkt | Ziel |
|------|---------------|------|
| Vollständiger Stack | `start.py` | Modernes Windows/Linux/macOS |
| Headless-Daemon | `daemon_headless.py` | Win 2000/XP, schwaches Vista/7 32-bit, Server |
| Legacy lokal | `legacy_bootstrap.py` | Win 9x-Klasse, Python < 3.7 |

`start.py` schreibt `data/interbus/startup_route.json` bevor ein Runtime-Pfad
gewählt wird. Der Capability Score (`progression_track`, `progression_mode`) spiegelt
diese Entscheidung wider — schwache Knoten wachsen sichtbar von `ultra-legacy-local`
zu stärkeren Swarm-Rollen, anstatt bei der Installation still zu scheitern.

---

## Symbiont-Engine

Eine Overlay-Analyseschicht die parallel zur Hauptpipeline läuft:

- **Blindspot Engine:** erkennt Muster die die Hauptkaskade strukturell konsequent verpasst
  (Blindstellen durch Metrik-Korrelationslücken).
- **Invariant Observer:** verfolgt welche Strukturinvarianten über aufeinanderfolgende
  Vault-Durchläufe für dieselbe Quelle persistieren; fließt in den Trust Score ein.
- **Attractor Engine:** identifiziert Konvergenz-Attraktoren im GP-Suchraum.
- **Ethics Engine:** markiert auffällige Muster (Benford-Abweichung, ungewöhnlich hohe
  Noether-Asymmetrie) zur Überprüfung — ohne die Pipeline zu blockieren.

---

## Build

```bash
# Python-Backend (vollständiger Stack)
pip install -r requirements.txt
python start.py

# Headless- / Legacy-Paketprofil
pip install -r requirements_legacy.txt
python daemon_headless.py

# Ultra-Legacy (lokal)
python legacy_bootstrap.py

# Rust-UI (erfordert Rust-Toolchain)
cargo build --release
```

---

## Metrik-Referenz

| Metrik | Methode | Standardanwendung |
|--------|---------|------------------|
| Shannon-Entropie | H(X) = −Σ p(x) log₂ p(x) | Informationsdichte, Zufälligkeit |
| Boltzmann-Entropie | normierte Shannon auf [0,1] | Thermodynamisches Analogon |
| Zipf-Alpha | Potenzgesetz-Exponent f ∝ r^−α | Rank-Frequency-Verteilung |
| Benford-Score | Führungsziffern vs. log₁₀(1+1/d) | Statistische Natürlichkeit |
| Fourier-Periodizität | FFT über Block-Entropie-Sequenz | Rhythmische Muster |
| Katz-Dimension | normierte fraktale Kurvenlänge | Selbstähnlichkeit, Komplexität |
| Permutations-Entropie | PE = 1 − H_perm / log₂(m!) | Ordinalstruktur (Bandt & Pompe 2002) |
| Delta-Konvergenz | Euklidische Distanz zum Vorgänger-Run | Strukturelle Stabilität über Zeit |
| Noether-Konsistenz | Symmetrieerhaltung vorwärts/rückwärts | Symmetriebruch als Manipulationsindikator |

Keine proprietären Algorithmen. Kein Black-Box-Modell.
Jede Komponente ist mathematisch definiert und reproduzierbar.

---

## Literatur

- Shannon, C.E. (1948). A Mathematical Theory of Communication.
- Bandt, C. & Pompe, B. (2002). Permutation Entropy.
- Katz, M.J. (1988). Fractals and the Analysis of Waveforms.
- Benford, F. (1938). The Law of Anomalous Numbers.
- Zipf, G.K. (1949). Human Behavior and the Principle of Least Effort.
- Noether, E. (1915). Invariante Variationsprobleme.
- Gödel, K. (1931). Über formal unentscheidbare Sätze.

---

## Lizenz

AGPL-3.0 — Kevin Hannemann, 2024–2026

## Whitepaper

[WHITEPAPER.md](WHITEPAPER.md) — formale Behandlung des Vault-Konvergenzsatzes,
Trust-Kaskade als Proof-of-Work und Swarm-Amplifikationsschranken.

## Roadmap

[ROADMAP.md](ROADMAP.md) — 30/60/90-Tage-Umsetzungs-Tracks.
