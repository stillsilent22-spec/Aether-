# Aether Delta Engine

**Distributed Structural Invariant Analysis and Privacy-Preserving Compression**

Aether is an open-source framework for measuring mathematical structural
invariants in arbitrary byte streams and transmitting only those invariants
across a peer-to-peer network — never raw data.

## Core Principle

Every byte stream possesses a measurable structural signature independent
of its semantic content. Aether extracts this signature via a deterministic
9-metric cascade and uses it as the sole basis for distributed comparison,
compression, and trust evaluation.

The framework's central invariant: **structural deltas converge toward the
Shannon entropy limit as the collective vault grows**, without any node
transmitting raw data or receiving data from other nodes' private streams.

## The 9-Metric Cascade

Metrics are computed in fixed order. Order must never change.

| # | Metric | Definition | Range |
|---|--------|------------|-------|
| 1 | Shannon Entropy | H(X) = -Σ p(x) log₂ p(x) | [0, 8] |
| 2 | Boltzmann Entropy | S = -Σ pᵢ ln pᵢ / ln(256), orthogonal to Shannon | [0, 1] |
| 3 | Zipf Alpha | Rank-frequency exponent via log-log regression | ℝ⁺ |
| 4 | Benford Score | Leading-digit conformance to log₁₀(1 + 1/d) | [0, 1] |
| 5 | Fourier Period | Dominant spectral period from RFFT over entropy blocks | [0, 1] |
| 6 | Katz Dimension | D = log(n) / (log(n) + log(d/L)) | [1, ∞) |
| 7 | Permutation Entropy | Bandt & Pompe (2002), order m=3, normalized | [0, 1] |
| 8 | Delta Convergence | Euclidean distance to previous run / √8 | [0, 1] |
| 9 | Noether Consistency | Symmetry preservation across signal halves | [0, 1] |

**Trust Score:** Weighted composite of all 9 metrics.
Threshold: `trust_score ≥ 0.65` → swarm participation.
No invite system. No accounts. The cascade result is the proof of work.

## Privacy Architecture

```
LOCAL (device)              NETWORK (swarm)
─────────────────────       ──────────────────
Raw data      → NEVER  →   Network
Deltas        → NEVER  →   Network
Session keys  → NEVER  →   Network (RAM-only, zeroed on session end)
                                ↕
Structural anchors  → SHA-256 hashed, consent-gated, not invertible
```

This is enforced at the code level, not by policy.

## Swarm Quorum

An anchor is only published to the swarm after **3 independent nodes**
have found the same structural hash independently. Single-node observations
are held in a pending pool until quorum is reached.

Swarm scaling property:
```
h(n) ≈ 1 − e^(−λn)
```
Hit rate rises sub-linearly with node count. Transmission cost per chunk
falls toward the 64-byte DNA signature floor as the collective vault grows.

## Frame Delta Codec

```
XOR-Delta_N = Frame_N ⊕ Frame_{N-1}
→ 512-byte chunks → SHA-256 vault lookup
  Vault hit:  64-byte DNA signature (8× reduction)
  Vault miss: GP evolution finds compact expression tree → stored
```

Efficiency metric: η = B_saved / E_tick (bits per joule)
Classical codecs (H.264, AV1): ~1–15 Mb/J
Aether (warm vault): >50 Mb/J

## Genetic Programming Engine

Expression trees (DNA format) are evolved via a genetic algorithm
to losslessly represent 512-byte structural patterns.
π, e, φ emerge naturally when structurally useful — never hardcoded.

## AELab — Adaptive Evolution Laboratory

AELab ist die interne Lernschicht von Aether. Sie analysiert jeden Byte-Stream
vor dem Vault-Commit und entscheidet ob der strukturelle Befund ausreicht.

### Funktionen

| Funktion | Beschreibung |
|----------|-------------|
| `analyze(raw)` | Führt den vollständigen 9-Metrik-Durchlauf aus und gibt `commit_allowed` zurück |
| `initialize(vault_path)` | Lädt bestehende AELab-Session oder erstellt neue |
| `_DeltaSession` | Hält XOR-Delta-Zustand für einen laufenden Stream |
| `build_algo_token()` | Baut ein signierbares Token aus dem AELab-Ergebnis |

### Metriken und Schwellenwerte (AELab-intern)

| Metrik | Schwellenwert | Effekt bei Unterschreitung |
|--------|--------------|--------------------------|
| `lossless` | ≥ 0.95 | Commit gesperrt — Anker nicht vault-würdig |
| `trust_score` | ≥ 0.65 | Kein Swarm-Beitrag für diesen Anker |
| `has_anchor` | `true` | Pflicht für Vault-Commit |
| `commit_allowed` | kombiniertes Gate | Steuert gesamten Pipeline-Commit |

AELab arbeitet **vor** der Kompression. Erst wenn `commit_allowed = true` wird
der Anker gespeichert und der Algo-Token weitergegeben. Das verhindert dass
strukturell schwache Daten das Vault kontaminieren.

### Genesis-Invarianten (Prior für neue Knoten)

Neue Knoten erhalten beim ersten Start einen eingeimpften Prior:

| Invariante | Wert | Quelle |
|-----------|------|--------|
| Benford conformance | 0.85 | Empirischer Mittelwert natürlicher Daten |
| Zipf α | 1.07 | Klassischer Sprachexponent (Piantadosi 2014) |
| Mandelbrot β | 1.40 | Fraktale Selbstähnlichkeit |
| Fourier period | 24.0 | Circadianisches Tagesmuster |
| invariant_strength | 0.72 | Startgewicht (niedrig, damit eigene Messungen dominieren) |

Der Prior wird automatisch durch eigene Messungen ersetzt sobald ≥ 32 Samples
vorliegen (`source: measured` überschreibt `source: genesis_prior`).

---

## Emergentes Netzwerk — Hardware-abgeleitete P2P-Freischaltung

Aether leitet aus der lokalen Hardware automatisch ab welcher Netzwerk-Tier
möglich ist. Es gibt keine manuelle Konfiguration — die Ebene emergiert.

### Netzwerk-Tiers

| Tier | Name | Voraussetzung | Funktionen |
|------|------|--------------|------------|
| 0 | LocalOnly | < 256 MB RAM, Win 9x | Nur lokale Analyse, kein Netz |
| 1 | LanBeacon | ≥ 256 MB, Win 2000+ | UDP-Announce im LAN, passiv sichtbar |
| 2 | LanP2P | ≥ 512 MB, ≥ 2 Kerne | Gossip + Leader-Election im LAN |
| 3 | YggdrasilP2P | ≥ 1 GB, Win Vista+, RPi 3+ | Yggdrasil IPv6-Overlay, geräteübergreifend |
| 4 | FullDht | ≥ 4 GB, ≥ 4 Kerne, modern | Kademlia-DHT, Relay-Knoten |

### Plattform-Erkennung

| Plattform | Erkennung | Mindest-Tier |
|-----------|----------|-------------|
| Windows 9x / ME | NT-Registry `CurrentVersion` 4.x | LocalOnly |
| Windows 2000 | NT 5.0 | LanBeacon |
| Windows XP | NT 5.1/5.2 | LanBeacon → LanP2P (≥ 512 MB) |
| Windows Vista/7 | NT 6.0/6.1 | LanP2P → YggdrasilP2P (≥ 2 GB) |
| Windows 8/10/11 | NT 6.2+ | YggdrasilP2P → FullDht |
| Raspberry Pi Zero/1 | `/proc/cpuinfo` Model | LanBeacon |
| Raspberry Pi 2/3 | `/proc/cpuinfo` Model | LanP2P |
| Raspberry Pi 4/5 | `/proc/cpuinfo` Model | YggdrasilP2P |
| Linux Legacy (Kernel < 4) | `/proc/version` | LanP2P (max) |
| Linux Modern (Kernel ≥ 4) | `/proc/version` | bis FullDht |

### Startbooster (Tier-Watchdog)

Geräte die beim Start nicht für P2P qualifiziert sind laufen nicht einfach stumm:

1. **StealthBeacon** startet sofort — Gerät ist im LAN sichtbar ohne Gossip-Overhead
2. **Tier-Watchdog** (One-Shot-Pattern) prüft alle 90 Sekunden ob RAM/CPU freier geworden ist
3. Bei Tier-Upgrade → P2P startet automatisch nach, kein Neustart nötig
4. Nach 10 erfolglosen Checks → Watchdog beendet sich, Gerät bleibt auf StealthBeacon

### Yggdrasil-Integration

Yggdrasil v0.5.8 wird automatisch verwaltet wenn `tier_rank ≥ 3`:
- Ed25519-Key → deterministisch abgeleitete IPv6-Adresse (200::/7)
- Genesis-Node-Adresse als fester Einstiegspunkt eingebaut
- Auf schwacher Hardware wird Yggdrasil übersprungen — kein erzwungener Start
- DHT (Tier 4) erweitert die Peer-Tabelle via Kademlia-ähnlichem Lookup

## Network Transport

- LAN-first: UDP beacon discovery on port 7386
- Overlay: Yggdrasil v0.5.8 (Ed25519 → IPv6 in 200::/7, deterministic)
- DHT: Kademlia-style peer table on Tier 4 nodes
- Fallback: GitHub as anchor bootstrap layer

## Hardware Targets

Desktop: Windows 8/10/11, Linux, macOS (x86-64, ARM64)
Legacy: Windows Vista/7 32-bit, Windows XP (LanP2P max), Raspberry Pi 1/Zero/2/3/4
Android: Native APK (Kotlin, API 21+, no Python required)
Headless: `daemon_headless.py` — Python 3.6+, stdlib-only core, no numpy/GUI required
Ultra-Legacy: `legacy_bootstrap.py` — local-only fairness path for Win9x / very old Python runtimes

## Fair Inclusion Boot Paths

Aether now writes `data/interbus/startup_route.json` before the runtime path is chosen.

- `start.py` keeps the full desktop/runtime path for modern systems.
- `daemon_headless.py` is selected automatically for Windows 2000/XP and weak Vista/7 32-bit systems, with `requirements_legacy.txt` as the lightweight package profile.
- `legacy_bootstrap.py` provides the ultra-legacy local path for Win9x-class environments or Python runtimes too old for the normal headless daemon.

The capability score mirrors this decision in `progression_track` and `progression_mode`, so weak nodes visibly grow from `ultra-legacy-local` or `legacy-headless-vault-first` toward stronger swarm roles instead of failing at install time.

LAN ist dabei nur eine Zwischenstufe. Das eigentliche Ziel bleibt die Aufnahme ins P2P-Aethernet:

- Tier 1/2 liefern Sichtbarkeit, lokale Kooperation und erste Gossip-Reife.
- Tier 3 bedeutet native Yggdrasil-Kompatibilität und echtes Overlay-P2P.
- Tier 4 bedeutet emergente DHT-Rolle: mit genug Mitgliedern und Reichweite entsteht aus Aether + Yggdrasil eine eigene, verteilte Peer-Struktur.
- Schwache Legacy-Knoten bleiben trotzdem kompatibel, aber eher als symbiotische Relay-/Overlay-Kandidaten statt als isolierte LAN-Endpunkte.

## Build

```bash
# Python backend
pip install -r requirements.txt
python start.py

# Legacy / headless package profile
pip install -r requirements_legacy.txt
python start.py

# Ultra-legacy local bootstrap
python legacy_bootstrap.py

# Rust UI
cargo build --release
```

## License

AGPL-3.0 — Kevin Hannemann, 2024–2026

## Whitepaper

See [WHITEPAPER.md](WHITEPAPER.md)

## Technische Grundlage

Alle verwendeten Metriken sind etablierte Verfahren der Informationstheorie und Statistik:

| Metrik | Methode | Typische Anwendung |
|--------|---------|-------------------|
| Shannon-Entropie | H(X) = −Σ p(x) log₂ p(x) | Informationsdichte, Zufälligkeit |
| Boltzmann-Entropie | Normierte Shannon auf [0,1] | Thermodynamisches Analogon |
| Zipf-Alpha | Potenzgesetz-Exponent f ∝ r^−α | Rank-Frequency-Verteilung |
| Benford-Score | Führungsziffern vs. log₁₀(1+1/d) | Statistische Natürlichkeit numerischer Daten |
| Fourier-Periodizität | FFT über Block-Entropie-Sequenz | Rhythmische Muster, Saisonalität |
| Katz-Dimension | Normierte fraktale Kurvenlänge | Selbstähnlichkeit, Komplexität |
| Permutation Entropy | PE = 1 − H_perm / log₂(order!) | Ordnungsstruktur im Byte-Stream (Bandt & Pompe 2002) |
| Delta-Konvergenz | Euklidische Distanz zum Vorgänger-Run | Strukturelle Stabilität über Zeit |
| Noether-Konsistenz | Symmetrieerhaltung vorwärts/rückwärts | Symmetriebruch als Manipulationsindikator |
| Trust Score | Composite aus Metriken 1–9 | Swarm-Teilnahme-Schwellenwert ≥ 0.65 |

Keine proprietären Algorithmen, kein Black-Box-Modell. Jede Komponente ist mathematisch definiert
und reproduzierbar.
