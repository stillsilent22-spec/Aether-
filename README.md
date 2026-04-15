# Aether Delta Engine

**Structural Invariant Analysis · Privacy-Preserving Compression · Distributed Vault Learning**  
**Strukturelle Invarianzanalyse · Datenschutzerhaltende Kompression · Verteiltes Vault-Lernen**

> **Status: Alpha — April 2026**  
> Core pipeline is deterministic and test-covered. Swarm is in early peer integration.  
> No servers required. No accounts. No raw data leaves the device.  
> Kein Server erforderlich. Keine Konten. Keine Rohdaten verlassen das Gerät.

---

## One sentence / Ein Satz

**EN:** The Shannon limit has not moved since 1948. Global data center energy consumption has grown by several orders of magnitude since then. One of these facts is a ceiling. The other is a choice.

**DE:** Das Shannon-Limit hat sich seit 1948 nicht bewegt. Der globale Energieverbrauch für Rechenzentren ist seither um Größenordnungen gestiegen. Eine dieser Tatsachen ist eine physikalische Grenze. Die andere ist eine Designentscheidung.

---

## What Aether is / Was Aether ist

**EN:**  
Aether is a decentralized framework that measures mathematical structural invariants in arbitrary byte streams and uses those invariants — never the raw data — as the basis for compression, distributed comparison, hypothesis generation, and peer trust evaluation. It runs on hardware from 1995 to 2026. It requires no cloud, no accounts, and no minimum hardware tier for participation.

**DE:**  
Aether ist ein dezentrales Framework das mathematische Strukturinvarianten in beliebigen Byte-Strömen misst und diese Invarianten — niemals die Rohdaten — als Grundlage für Kompression, verteilten Vergleich, Hypothesengenerierung und Peer-Vertrauensbewertung verwendet. Es läuft auf Hardware von 1995 bis 2026. Es erfordert keine Cloud, keine Konten und keine Mindesthardwareanforderung für die Teilnahme.

---

## The observed problem / Das beobachtete Problem

**EN:**  
Hardware manufactured before 2010 is not computationally insufficient for most workloads. It is excluded by dependency chains, binary bloat, and minimum-version policies — none of which derive from physical constraints.

A 3 GHz CPU performs approximately 10⁹ simple operations per second. A machine from 2004 can sustain this rate today. The median data center consumes 10–50 MW to perform tasks that, under compression-optimal conditions, could run on a fraction of that infrastructure. The gap between theoretical information density (Shannon, 1948) and operational practice has not narrowed since the theorem was published. It has widened, proportionally to revenue.

Cross-domain structural invariants — patterns that appear identically across unrelated signal types — are a measurable property of any sufficiently large corpus. They are not a hypothesis. The question is not whether they exist, but why the dominant architecture for processing data does not exploit them.

**DE:**  
Hardware aus der Zeit vor 2010 ist für die meisten Workloads rechnerisch nicht unzureichend. Sie ist durch Abhängigkeitsketten, Binary-Bloat und Mindestversionsrichtlinien ausgeschlossen — keine davon folgt physikalischen Zwängen.

Skalierung durch Fläche (mehr Rechenzentren) ist kein Äquivalent zu Skalierung durch Effizienz (weniger Information zu übertragen). Die Industrie hat sich für ersteres entschieden. Das Shannon-Limit ist ehrlich. Es bewegt sich nicht.

---

## What Aether does — technically / Was Aether tut — technisch

**EN:**  
Aether operates as a distributed digital research laboratory and compression system simultaneously. Every node — from a 1999 Windows 98 machine to a modern workstation — participates in the same pipeline:

1. **Structural extraction:** A deterministic 9-metric cascade extracts a structural signature Φ(X) from any byte stream — file, genomic sequence, EEG recording, network packet, pixel frame, financial time series, sensor reading.

2. **Delta encoding:** Only changes between successive states are computed and stored. A frame at time t is represented as `XOR_Δ_N = Frame_N ⊕ Frame_{N-1}`. The delta, not the frame, enters the vault.

3. **GP vault compression:** Genetic programming evolves compact expression trees that losslessly represent 512-byte structural patterns. Mathematical constants (π, e, φ) emerge when structurally useful — never hardcoded.

4. **Algo tokenization:** Recurring delta patterns are assigned algorithmic tokens. AlgoTokens are source-node-bound metadata objects that carry only structural fingerprints and fitness metrics; they contain no raw data, deltas, or session keys. Each receiving peer validates a token locally on structure, `source_node_id`, and fitness score — token acceptance does not require a global quorum.

5. **Swarm broadcast (structural only):** Only SHA-256 hashes of structural anchors are shared, after ≥ 3-node quorum confirmation. Raw data, deltas, and session keys never leave the device.

6. **Blindspot relay:** When a node cannot reconstruct a structural pattern, it broadcasts a structural class request (not the data). The swarm returns reconstruction hints via epidemic flood relay (max 3 hops). Every node learns every solution. The node that needed help first benefits most.

7. **Stage & convergence gating:** Global swarm adaptation is only allowed once peer stage/level consensus and convergence consistency are confirmed. If either fails, the blindspot engine treats it as a collective gap and drives swarm-wide remediation.

**DE:**  
Aether funktioniert gleichzeitig als dezentrales digitales Forschungslabor und Kompressionssystem. Jeder Knoten — von einer Windows-98-Maschine aus 1999 bis zur modernen Workstation — nimmt an derselben Pipeline teil: Strukturextraktion → Delta-Encoding → GP-Vault-Kompression → Algo-Tokenisierung → Swarm-Broadcast (nur Struktur) → Blindspot-Relay.

---

## Architecture overview / Architekturübersicht

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
                 │  Delta Convergence Tracker     │
                 └──────────────┬────────────────┘
                                │ consent-gated, hashed only
                 ┌──────────────▼────────────────┐
                 │        Swarm / P2P             │
                 │  LAN → Clearnet → BT → USB     │
                 │  Kademlia DHT · Yggdrasil IPv6 │
                 │  Flood Relay · Quorum: ≥ 3     │
                 │  Legacy Bootstrap (Win 9x+)    │
                 └───────────────────────────────┘
```

**Determinism rule:** The full analysis pipeline is only triggered via the Rust shell. Direct Python invocation bypasses integrity guarantees and is blocked in production.

---

## The 9-Metric Cascade

Metrics are computed in fixed order. The order is invariant.

| # | Metric | Formula | Range | What it detects |
|---|--------|---------|-------|-----------------|
| 1 | Shannon Entropy | H(X) = −Σ p(x) log₂ p(x) | [0, 8] | Information density, randomness |
| 2 | Boltzmann Entropy | S = H_S / 8, normalized | [0, 1] | Thermodynamic structural analogue |
| 3 | Zipf Alpha | rank-frequency power-law exponent | ℝ⁺ | Token-frequency distribution shape |
| 4 | Benford Score | leading-digit conformance to log₁₀(1+1/d) | [0, 1] | Statistical naturalness; anomaly signal |
| 5 | Fourier Periodicity | dominant period over entropy-block RFFT | [0, 1] | Rhythmic / cyclical structure |
| 6 | Katz Dimension | D = log(n)/(log(n)+log(d/L)) | [1,∞) | Self-similarity, fractal complexity |
| 7 | Permutation Entropy | Bandt & Pompe (2002), m=3, normalized | [0, 1] | Ordinal structure, independent of #1 |
| 8 | Delta Convergence | ‖Φ_norm(t)−Φ_norm(t−1)‖₂/√8 | [0, 1] | Structural stability over time |
| 9 | Noether Consistency | symmetry preservation across signal halves | [0, 1] | Manipulation signal; asymmetry = anomaly |

**Trust score:** weighted composite of all 9 metrics, Bayes posterior, and Heisenberg plausibility proxy. Participation threshold: `trust_score ≥ 0.65`. No invite system. No accounts. The cascade result is the proof of work.

**Domain applicability / Domänenanwendbarkeit:**  
The cascade operates on raw bytes. Domain is irrelevant to the computation. Validated signal types include: arbitrary files, EEG time series, ECG/EKG recordings, genomic sequences (DNA base-pair encodings), chromosome structural data, audio PCM, video frames, network packet payloads, financial OHLC series, environmental sensor readings, forensic disk images, process memory snapshots.

---

## Cross-domain structural matching / Domänenübergreifender Strukturvergleich

**EN:**  
Two byte streams from entirely different domains may share structural invariants. An ECG recording and a seismic time series may produce near-identical Fourier periodicity and Katz dimension vectors. A genomic sequence and a network traffic capture may share Zipf distribution shape. These are structural observations, not semantic claims.

The system identifies three classes of structural overlap:

| Class | Description | Example |
|---|---|---|
| **Intra-signal** | Invariants within a single data stream over time | Recurring pattern in EEG across sessions |
| **Intra-domain meta** | Invariants shared across different signal types within one domain | EEG + ECG + genomic sequence showing same periodicity |
| **Cross-domain** | Invariants shared across unrelated domains | Water quality time series + white blood cell count series with identical Katz dimension |

In all cases: the system reports structural topology. Semantic interpretation is the operator's responsibility. The system has no mechanism to make semantic claims because it has no representation of meaning.

**DE:**  
Zwei Byte-Ströme aus völlig unterschiedlichen Domänen können strukturelle Invarianten teilen. Das System identifiziert diese Überschneidungen in drei Klassen: intra-signal (innerhalb eines Datenstroms), intra-domain meta (verschiedene Signaltypen innerhalb einer Domäne), cross-domain (zwischen unverwandten Domänen). In allen Fällen berichtet das System strukturelle Topologie. Semantische Interpretation obliegt dem Betreiber.

**Invariant labels / Invarianten-Labels:**  
Labels assigned by uploaders are human-readable metadata. They are not parsed, weighted, or used as features by any algorithmic component. Structural matching occurs on metric vectors only. Whether a match is meaningful is a question the system explicitly does not answer. The human is the semantic interface.

---

## Application domains / Anwendungsdomänen

| Domain | What Aether observes | What becomes possible |
|---|---|---|
| **Medical — EEG/ECG** | Periodicity, permutation entropy, Katz dimension of neural/cardiac signals | Structural similarity across patients without sharing recordings; cross-signal invariant discovery |
| **Genomics** | Zipf distribution of base-pair frequencies; Benford conformance of codon lengths | Structural comparison of sequences without sequence exposure; anomaly detection |
| **Epidemiology** | Time-series delta convergence across geographic cohorts | Structural correlation hypothesis generation across populations |
| **Environmental** | Fourier periodicity in sensor time series; Noether symmetry breaks | Detection of structural discontinuities in water, air, soil measurements |
| **Forensics** | Benford deviation, Noether asymmetry, Shannon entropy in file / disk images | Tampering signal without content exposure; structural provenance |
| **Financial** | Zipf + Katz on price/volume series | Structural regime change detection |
| **Video / Gaming** | Frame delta XOR + GP vault | Decentralized cloud rendering on legacy hardware via delta reconstruction |
| **Process / System** | ETW process deltas, memory snapshots | Behavioral fingerprinting without content logging |
| **Industrial IoT** | Sensor stream delta compression | Sub-kbps transmission of high-frequency sensor data |

---

## Privacy architecture / Datenschutzarchitektur

```
LOCAL (device)               NETWORK (swarm)
────────────────────         ────────────────────────────────
Raw data        →  NEVER  →  network
Deltas          →  NEVER  →  network
Session keys    →  NEVER  →  network (RAM-only, zeroed on session end)
Keystrokes /
input rhythm    →  NEVER  →  stored or observed passively
Invariant labels→  NEVER  →  used by algorithmic components
                                   ↕  (consent-gated)
Structural anchors  →  SHA-256 hash, after ≥ 3-node quorum, not invertible
```

Enforced at code level (`privacy_registry.py`, `privacy_observer.py`, `session_guard.py`), not by policy.

---

## Radical hardware inclusion / Radikale Hardware-Inklusion

**EN:**  
Every hardware tier has a defined participation path. Exclusion is not a Tier 0 condition — it is the absence of a path. Aether defines the path.

| Tier | Hardware | Entry path | Grows toward |
|------|----------|------------|--------------|
| 0 | Win 9x, < 256 MB | `legacy_bootstrap.py` + UDP/BT/USB/clearnet | Tier 1 as vault grows |
| 1 | Win 2000+, 256 MB | LAN beacon + relay | Tier 2 via gossip learning |
| 2 | Win XP+, 512 MB, 2 cores | LAN P2P + gossip | Tier 3 via DHT |
| 3 | Vista+/RPi3+, 1 GB | Yggdrasil IPv6 overlay | Tier 4 via sustained uptime |
| 4 | Modern, 4 GB, 4 cores | Full Kademlia DHT, relay node | Contributes to all tiers |

The progression is automatic. No reinstall. No manual config. The capability score (`progression_track`) reflects the actual tier and the path to the next one.

**Entry channels (no pre-configured relay required):**  
LAN (UDP Multicast) → Relay Pool → Clearnet (public IP reflection + DNS seeds) → Bluetooth (RFCOMM, pybluez) → USB/Serial (pyserial)  
Any single channel is sufficient to enter the network permanently.

**DE:**  
Hardware-Ausschluss ist kein Naturgesetz. Es ist eine Designentscheidung. Aether definiert für jede Hardwarestufe einen Teilnahmepfad. Der Fortschritt ist automatisch. Kein Neustart. Keine manuelle Konfiguration. Jeder Einstiegskanal genügt für dauerhafte Netzwerkmitgliedschaft.

---

## Algo tokenization and logarithmic scaling / Algo-Tokenisierung und logarithmische Skalierung

**EN:**  
Delta patterns that recur across nodes are progressively compressed into algorithmic tokens. As swarm exposure grows, the per-reconstruction cost decreases:

| Swarm observations | Representation | Cost |
|--------------------|---------------|------|
| 1 | Full delta computation | ~500 bytes, ~40 ms |
| 10 | Pattern recognized, candidate token | ~50 bytes |
| 100 | Token in local vault | ~2 bytes, ~1 ms |
| 10,000+ across swarm | Base algo — distributed to all nodes | ~0 marginal cost |

This is not linear scaling. It is logarithmic: doubling node count does not double cost — it reduces cost per node. The efficiency gain is proportional to the diversity of patterns observed, not to raw compute capacity.
AlgoTokens are source-node-bound. A receiving peer accepts them only after local structural validation and a local fitness gate; no swarm-wide vote is required for token acceptance. This keeps token propagation peer-to-peer while preserving privacy.
A Windows 98 node playing a game it has played before locally reconstructs ~95% of frames from its vault without relay involvement. The remaining 5% triggers a structural hint request. The hint is returned via flood relay (3 hops maximum). The node stores the shortcut. Next session: ~97%.

**DE:**  
Delta-Muster die knotenübergreifend wiederkehren werden progressiv in algorithmische Tokens komprimiert. Die Effizienzsteigerung ist logarithmisch: doppelte Knotenanzahl bedeutet nicht doppelte Kosten — sie reduziert die Kosten pro Knoten. Eine Windows-98-Maschine die ein bekanntes Spiel startet rekonstruiert nach ausreichend Sessions ~95% der Frames lokal aus ihrem Vault — ohne Relay-Beteiligung.

---

## Vault and compression / Vault und Kompression

### Frame Delta Codec
```
XOR_Δ_N = Frame_N ⊕ Frame_{N-1}
→ 512-byte chunks → SHA-256 vault lookup
  Vault hit:  64-byte DNA signature (8× size reduction)
  Vault miss: GP evolution finds compact expression tree → stored for future hits
```

### Vault Convergence (theoretical bound)
```
C(n) = h(n) · 64 + (1 − h(n)) · 512   [bytes per chunk]
h(n) ≥ 1 − e^(−λn)
lim_{n→∞} C(n) = 64 bytes
```

### Genetic Programming Vault
Expression trees evolved to losslessly represent 512-byte patterns. π, e, φ emerge when structurally useful — never hardcoded, always derived.

---

## AELab — Adaptive Evolution Laboratory

| Gate | Threshold | Effect |
|------|-----------|--------|
| `lossless` | ≥ 0.95 | Vault commit blocked |
| `trust_score` | ≥ 0.65 | No swarm contribution |
| `has_anchor` | `true` | Required for commit |
| `commit_allowed` | composite | Controls full pipeline commit |

---

## Swarm network tiers / Schwarm-Netz-Stufen

| Tier | Name | Minimum | Features |
|------|------|---------|----------|
| 0 | LocalOnly | < 256 MB, Win 9x | Local analysis only |
| 1 | LanBeacon | ≥ 256 MB, Win 2000+ | UDP LAN announce |
| 2 | LanP2P | ≥ 512 MB, ≥ 2 cores | Gossip + leader election |
| 3 | YggdrasilP2P | ≥ 1 GB, Vista+/RPi 3+ | Yggdrasil IPv6 overlay |
| 4 | FullDht | ≥ 4 GB, ≥ 4 cores | Kademlia DHT, relay node |

---

## Symbiont engine / Symbiont-Engine

- **Blindspot engine:** detects structural patterns the 9-metric cascade consistently misses; flood-relays hints across the swarm (epidemic broadcast, max 3 hops)
- **Invariant observer:** tracks which invariants persist across successive vault runs; feeds back into trust score
- **Attractor engine:** identifies convergence attractors in GP search space
- **Delta convergence tracker:** measures structural stability over time; provides empirical Shannon convergence signal
- **Ethics engine:** flags Benford deviation and Noether asymmetry anomalies for review

---

## Gödelstop — Self-reference guard

The Live Render loop detects when the system's own analysis output stabilizes (delta < 1% for ≥ 5 successive inner probes) and pauses the outer analysis for that tick. Prevents infinite self-analysis of stable output. Resets automatically when the signal changes.

---

## Gaming tab — Quorum-gated insights

Shared structural game insights unlock only when **≥ 3 distinct players** have independently analysed the same game. Prevents single-player structural profiles from being attributed to general game patterns.

---

## Boot paths / Boot-Pfade

| Path | Entry point | Target |
|------|-------------|--------|
| Full stack | `start.py` | Modern Windows/Linux/macOS |
| Headless daemon | `daemon_headless.py` | Win 2000/XP, weak Vista/7 32-bit, servers |
| Legacy local | `legacy_bootstrap.py` | Win 9x-class, Python < 3.7 runtimes |

---

## Build

```bash
# Python backend (full stack)
pip install -r requirements.txt
python start.py

# Headless / legacy
pip install -r requirements_legacy.txt
python daemon_headless.py

# Ultra-legacy (Win 9x, Python 2.4+)
python legacy_bootstrap.py

# Rust GUI
cargo build --release
```

---

## Metric reference / Metrikenreferenz

| Metric | Method | Cross-domain applicability |
|--------|--------|---------------------------|
| Shannon entropy | H(X) = −Σ p(x) log₂ p(x) | Universal — any byte stream |
| Boltzmann entropy | normalized Shannon | Universal |
| Zipf alpha | power-law f ∝ r^−α | Text, genomics, network traffic, financial |
| Benford score | leading digits vs. log₁₀(1+1/d) | Numeric time series, financial, forensics |
| Fourier periodicity | FFT over block-entropy sequence | EEG, ECG, seismic, audio, IoT sensor |
| Katz dimension | normalized fractal curve length | EEG, ECG, seismic, financial volatility |
| Permutation entropy | Bandt & Pompe (2002) | EEG, ECG, any temporal sequence |
| Delta convergence | Euclidean distance to prior run | Process stability, vault growth signal |
| Noether consistency | symmetry preservation fwd/bwd | Manipulation detection, anomaly signal |

No proprietary algorithms. No black-box models. Every component is independently re-implementable.

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

## License / Lizenz

AGPL-3.0 — Kevin Hannemann, 2024–2026

[WHITEPAPER.md](WHITEPAPER.md) · [ROADMAP.md](ROADMAP.md) · [core_axioms.md](core_axioms.md)