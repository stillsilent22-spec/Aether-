# Aether Delta Engine

**Structural Invariant Analysis · Privacy-Preserving Compression · Distributed Vault Learning**

> **Status: Alpha — April 2026**
> Core pipeline is deterministic and test-covered. Swarm is in early peer integration.
> No servers required. No accounts. No raw data leaves the device.

---

## What Aether does

Aether measures mathematical structural invariants in arbitrary byte streams and uses
those invariants — never the raw data — as the basis for compression, distributed
comparison, and peer trust evaluation.

Every byte stream has a structural signature independent of its content.
Aether extracts that signature via a deterministic 9-metric cascade, stores it as an
expression tree in a local vault, and shares only the 64-byte SHA-256 hash with peers
after 3-node quorum confirmation. The raw data, session keys, and deltas never leave
the device.

---

## Architecture overview

```
                 ┌───────────────────────────────┐
                 │         Rust / iced UI         │
                 │  Analyse · Gaming · Live Render │
                 │  Kolmogorov · Rekonstruktion    │
                 └──────────────┬────────────────┘
                                │ Rust Shell → Python via subprocess
                 ┌──────────────▼────────────────┐
                 │       Python Pipeline          │
                 │  9-Metric Cascade              │
                 │  AELab (adaptive evolution)    │
                 │  GP Vault (expression trees)   │
                 │  Frame Delta Codec (XOR)       │
                 │  Symbiont / Blindspot Engine   │
                 └──────────────┬────────────────┘
                                │ consent-gated, hashed only
                 ┌──────────────▼────────────────┐
                 │        Swarm / P2P             │
                 │  LAN Beacon → Gossip → DHT     │
                 │  Yggdrasil IPv6 overlay        │
                 │  Quorum gate: ≥ 3 nodes        │
                 └───────────────────────────────┘
```

**Determinism rule:** The full analysis pipeline is only triggered via the Rust shell.
Direct Python invocation bypasses integrity guarantees and is blocked in production.

---

## The 9-Metric Cascade

Metrics are computed in fixed order. The order is invariant.

| # | Metric | Formula | Range |
|---|--------|---------|-------|
| 1 | Shannon Entropy | H(X) = −Σ p(x) log₂ p(x) | [0, 8] |
| 2 | Boltzmann Entropy | S = −Σ pᵢ ln pᵢ / ln 256, orthogonal basis | [0, 1] |
| 3 | Zipf Alpha | rank-frequency power-law exponent via log-log regression | ℝ⁺ |
| 4 | Benford Score | leading-digit conformance to log₁₀(1 + 1/d) | [0, 1] |
| 5 | Fourier Period | dominant spectral period over entropy-block RFFT | [0, 1] |
| 6 | Katz Dimension | D = log(n) / (log(n) + log(d/L)) | [1, ∞) |
| 7 | Permutation Entropy | Bandt & Pompe (2002), order m=3, normalized | [0, 1] |
| 8 | Delta Convergence | ‖Φ_norm(t) − Φ_norm(t−1)‖₂ / √8 | [0, 1] |
| 9 | Noether Consistency | symmetry preservation across signal halves | [0, 1] |

**Trust score:** weighted composite of all 9 metrics, Bayes posterior, and physical
plausibility (Heisenberg proxy). Participation threshold: `trust_score ≥ 0.65`.
No invite system. No accounts. The cascade result is the proof of work.

---

## Privacy architecture

```
LOCAL (device)               NETWORK (swarm)
────────────────────         ────────────────────────────────
Raw data        →  NEVER  →  network
Deltas          →  NEVER  →  network
Session keys    →  NEVER  →  network (RAM-only, zeroed on session end)
Keystrokes /
input rhythm    →  NEVER  →  stored or observed passively
                                   ↕  (consent-gated)
Structural anchors  →  SHA-256 hash, after ≥ 3-node quorum, not invertible
```

This is enforced at the code level (privacy\_registry.py, privacy\_observer.py,
session\_guard.py), not by policy.

---

## Vault and compression

### Frame Delta Codec
```
XOR_Δ_N = Frame_N ⊕ Frame_{N-1}
→ 512-byte chunks → SHA-256 vault lookup
  Vault hit:  64-byte DNA signature (8× size reduction)
  Vault miss: GP evolution finds compact expression tree → stored for future hits
```

### Genetic Programming (GP) Vault
Expression trees ("DNA format") are evolved to losslessly represent 512-byte structural
patterns. Mathematical constants (π, e, φ) emerge when structurally useful —
they are never hardcoded, always derived.

### AELab — Adaptive Evolution Laboratory
Internal learning layer. Analyses every byte stream before vault commit and
evaluates whether the structural result meets quality gates:

| Gate | Threshold | Effect if not met |
|------|-----------|-------------------|
| `lossless` | ≥ 0.95 | Vault commit blocked |
| `trust_score` | ≥ 0.65 | No swarm contribution |
| `has_anchor` | `true` | Required for commit |
| `commit_allowed` | composite | Controls full pipeline commit |

### Vault Convergence (theoretical bound)
For a vault of size n and a source with Shannon entropy H(X):

```
Expected cost per chunk:   C(n) = h(n) · 64 + (1 − h(n)) · 512   [bytes]
Hit rate lower bound:      h(n) ≥ 1 − e^(−λn)
Limit:                     lim_{n→∞} C(n) = 64 bytes
```

This is a theoretical bound. Empirical verification requires a running swarm
with sufficient vault diversity.

---

## Gödelstop — Self-reference guard

The Live Render analysis loop includes a Gödelstop mechanism:

- The inner GP probe measures how much the system's own analysis output changes
  on successive ticks (delta < 1% = "converged").
- When the outer loop detects ≥ 5 stable inner probes in a row, the outer analysis
  is paused for that tick.
- This prevents the system from endlessly analysing its own stable output.
- The counter resets automatically when the signal changes again.

The Live Render status bar shows the current Gödelstop level alongside the XOR delta
rate, saved patterns, and (when a game is active) the mss pixel-capture metrics.

---

## Live Render — Pixel capture

When Live Render is active and a game process is being tracked (Gaming tab):

1. The Rust shell fires `analyze_live_signal_for_shell` each tick with `game_label`.
2. Python resolves the game's PID via psutil and calls
   `RenderCoordinator.capture_process_render(pid, window_title=game_label)`.
3. The mss screenshot is analysed structurally (Shannon entropy, symmetry, resonance).
4. Results flow back into the Rust UI as `pixel_entropy / pixel_symmetry / pixel_source`.

Own PID is always blocked (Gödel self-reference lock in `RenderCoordinator`).
Full-screen capture never happens — always scoped to a specific process window.

---

## Gaming tab — Quorum-gated insights

Shared structural insights for a game unlock only when **≥ 3 distinct players**
have independently analysed the same game. Single-node observations are held in a
pending pool. This prevents one player's structural profile from being attributed
to the game's general pattern.

---

## Swarm network tiers

Aether derives the eligible network tier from local hardware automatically.
No manual configuration required — the tier emerges.

| Tier | Name | Minimum requirement | Features |
|------|------|---------------------|----------|
| 0 | LocalOnly | < 256 MB RAM, Win 9x | Local analysis only, no network |
| 1 | LanBeacon | ≥ 256 MB, Win 2000+ | UDP announce in LAN, passive |
| 2 | LanP2P | ≥ 512 MB, ≥ 2 cores | Gossip + leader election on LAN |
| 3 | YggdrasilP2P | ≥ 1 GB, Win Vista+, RPi 3+ | Yggdrasil IPv6 overlay, cross-device |
| 4 | FullDht | ≥ 4 GB, ≥ 4 cores, modern | Kademlia-style DHT, relay nodes |

Platforms detected: Windows 9x/ME/2000/XP/Vista/7/8/10/11,
Linux (kernel < 4: LanP2P max; kernel ≥ 4: up to FullDht),
Raspberry Pi 1/Zero (LanBeacon) through Pi 4/5 (YggdrasilP2P),
Android (via native APK, API 21+, no Python required).

A tier-watchdog checks every 90 s whether resources have freed up.
On tier upgrade, P2P starts automatically — no restart needed.
After 10 unsuccessful checks the watchdog exits; the device stays on StealthBeacon.

---

## Boot paths — fair inclusion for legacy hardware

| Path | Entry point | Target |
|------|-------------|--------|
| Full stack | `start.py` | Modern Windows/Linux/macOS |
| Headless daemon | `daemon_headless.py` | Win 2000/XP, weak Vista/7 32-bit, servers |
| Legacy local | `legacy_bootstrap.py` | Win 9x-class, Python < 3.7 runtimes |

`start.py` writes `data/interbus/startup_route.json` before any runtime path is
chosen. The capability score (`progression_track`, `progression_mode`) mirrors
the boot decision, so weak nodes grow visibly from `ultra-legacy-local` toward
stronger swarm roles rather than silently failing at install time.

---

## Symbiont engine

An overlay analysis layer that runs alongside the main pipeline:

- **Blindspot engine:** detects patterns the main cascade consistently misses
  (structural blind spots due to metric correlation gaps).
- **Invariant observer:** tracks which structural invariants persist across
  successive vault runs for the same source, feeding back into the trust score.
- **Attractor engine:** identifies convergence attractors in the GP search space.
- **Ethics engine:** flags anomalous patterns (Benford deviation, unusually high
  Noether asymmetry) for review without blocking the pipeline.

---

## Build

```bash
# Python backend (full stack)
pip install -r requirements.txt
python start.py

# Headless / legacy package profile
pip install -r requirements_legacy.txt
python daemon_headless.py

# Ultra-legacy local only
python legacy_bootstrap.py

# Rust GUI (requires Rust toolchain)
cargo build --release
```

---

## Metric reference

| Metric | Method | Standard use |
|--------|--------|-------------|
| Shannon entropy | H(X) = −Σ p(x) log₂ p(x) | Information density, randomness |
| Boltzmann entropy | normalised Shannon on [0,1] | Thermodynamic analogue |
| Zipf alpha | power-law exponent f ∝ r^−α | Rank-frequency distribution |
| Benford score | leading digits vs. log₁₀(1 + 1/d) | Statistical naturalness |
| Fourier periodicity | FFT over block-entropy sequence | Rhythmic patterns |
| Katz dimension | normalised fractal curve length | Self-similarity, complexity |
| Permutation entropy | PE = 1 − H_perm / log₂(m!) | Ordinal structure (Bandt & Pompe 2002) |
| Delta convergence | Euclidean distance to prior run | Structural stability over time |
| Noether consistency | symmetry preservation fwd/bwd | Symmetry break as manipulation signal |

No proprietary algorithms. No black-box models.
Every component is mathematically defined and reproducible.

---

## References

- Shannon, C.E. (1948). A mathematical theory of communication.
- Bandt, C. & Pompe, B. (2002). Permutation entropy.
- Katz, M.J. (1988). Fractals and the analysis of waveforms.
- Benford, F. (1938). The law of anomalous numbers.
- Zipf, G.K. (1949). Human behavior and the principle of least effort.
- Noether, E. (1915). Invariante Variationsprobleme.
- Gödel, K. (1931). Über formal unentscheidbare Sätze.

---

## License

AGPL-3.0 — Kevin Hannemann, 2024–2026

## Whitepaper

[WHITEPAPER.md](WHITEPAPER.md) — formal treatment of the Vault Convergence Theorem,
trust cascade proof-of-work, and swarm amplification bounds.

## Roadmap

[ROADMAP.md](ROADMAP.md) — 30/60/90-day execution tracks.


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
