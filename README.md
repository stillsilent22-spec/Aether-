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

## Network Transport

- LAN-first: UDP beacon discovery on port 7386
- Overlay: Yggdrasil v0.5.8 (Ed25519 → IPv6 in 200::/7, deterministic)
- Fallback: GitHub as anchor bootstrap layer

## Hardware Targets

Desktop: Windows, Linux, macOS (x86-64, ARM64)
Legacy: Windows Vista/7 32-bit, Raspberry Pi 1/Zero, Python 3.6+
Android: Native APK (Kotlin, API 21+, no Python required)

## Build

```bash
# Python backend
pip install -r requirements.txt
python start.py

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
