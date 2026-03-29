# Aether Whitepaper (English)

Date: March 2026
Author: Kevin Hannemann
Status: Technical Whitepaper for Source-Available Release

??? [Deutsche Version: WHITEPAPER.md](WHITEPAPER.md)

---

## 1. Introduction

This whitepaper describes the technical foundations and architecture of Aether — a local structural analysis layer for deterministic data analysis with integrated privacy.

Aether is not a classifier, not an AI model, and not an interpreter. It is a measurement instrument: it computes structural characteristics of arbitrary data and makes them comparable — without labels, without training, without revealing sensitive content.

**Core principle:** Structural similarity is an observation, not a statement. Whether it is relevant is decided by domain experts or further investigation — not by the system.

> **Note on metric names:** Some metrics carry names from physics and mathematics
> (Noether score, Heisenberg score, interference score). These names are **pedagogical
> shorthand** — they describe the intuitive concept behind the metric, not a physical
> analogy. The underlying computations are formally defined in Section 3.6 and are
> grounded in statistical properties, not physical laws.

---

## 2. Technical Classification

Aether treats files, byte streams, and system processes as local states that can be described and compared by measurable structure. The technical core:

- **Analysis pipeline**: measures entropy, symmetry, periodicity, fractal dimension, Fourier spectrum, Permutation Entropy (Bandt & Pompe), Benford distribution
- **Reconstruction layer**: snapshots, deltas, lossless reconstruction
- **Persistence layer**: local SQLite database, append-only audit log
- **Governance layer**: fail-closed access rules, consent-bound releases
- **Assistant**: local language path ??? formulates only verified structural findings
- **Aethernet**: optional decentralized anchor path (consent-bound, no raw data export)

---

## 3. Domain-Specific Pattern Recognition

### 3.1 Methodology

Within a domain, Aether detects anomalies through deviation from the observed structural baseline ??? without thresholds, without domain-specific training, without interpreting data content.

**Measured metrics:**

| Metric | Formula / Method | Interpretation |
|---|---|---|
| Shannon entropy | `H(X) = -?? p(x) log??? p(x)` | Information density, randomness |
| Symmetry (Gini) | Normalized distribution inequality | Inner balance of byte distribution |
| Fractal dimension | Katz dimension | Self-similarity, complexity level |
| Dominant frequency | FFT, strongest spectrum | Periodicity, rhythmic recurrence |
| Benford score | Leading digit distribution vs. log??????(1+1/d) | Naturalness of number distribution |
| Permutation Entropy | PE = 1 − H_perm / log₂(order!) | Ordinal structure in the byte stream (Bandt & Pompe 2002). Measures pattern order distribution, orthogonal to Shannon entropy. |
| Observer I_obs | `H(X) - H(X|M_t)` | Observer's learning gain |

### 3.2 Bioinformatics

Genome sequences have characteristic entropy and periodicity profiles. Aether detects:
- Entropy outliers (possible mutation clusters, insertions)
- Benford deviations (unexpected codon frequency distributions)
- Periodicity patterns (regulatory sequences, repetitive elements)

**Privacy:** The sequence never leaves the device. The fingerprint contains no sequence information ??? it is non-invertible.

### 3.3 Climate Research

Climate time series show characteristic structural patterns (seasonal periodicity, Permutation Entropy shifts in stable climate regimes). Aether detects:
- Structural breaks (regime changes without annotation)
- Abnormal frequency patterns (non-periodic event clusters)
- Permutation Entropy drift (shift of ordinal structure over time)

**Privacy:** Station data, coordinates, metadata stay local.

### 3.4 System Optimization

Running processes are described with the same metrics as other data sources:
- CPU burst clusters ??? periodicity analysis
- Memory usage → baseline Permutation Entropy drift
- I/O behavior ??? delta and frequency analysis
- Render events ??? GPU resonance, frame structure

Relevant modules: `modules/process_monitor.py`, `modules/efficiency_monitor.py`, `modules/preload_optimizer.py`, `modules/optimize_engine.py`

### 3.5 Software Analysis

Source code and binary structures have measurable structural properties:
- Complexity distribution (entropy density per module)
- Anomaly detection (deviations from the codebase baseline)
- Structural similarity between modules (without reading content)

### 3.6 Collaborative Frame Delta Codec

The `frame_delta_engine` module implements a swarm-based media compression architecture
built directly on the Aether structural analysis and vault infrastructure.

**Operating principle:**

$$\text{XOR-Delta}_N = \text{Frame}_N \oplus \text{Frame}_{N-1}$$

The delta stream is partitioned into 512-byte chunks. Each chunk is addressed by its
SHA-256 fingerprint. The AEVault is queried:

- **Vault-Hit:** a DNA-encoded expression tree already exists for this chunk pattern.
  Transmission cost: 64 bytes (hex signature) instead of 512 bytes raw → ×8 reduction.
- **Vault-Miss:** an AEEvolver GA run discovers a compact expression tree for the chunk.
  The tree is stored in DNA format; the 64-byte signature is transmitted.

**Swarm scaling property:**

Frame-chunk patterns (motion vectors, texture blocks, UI elements, particle systems)
recur deterministically across all players of the same title. The collective vault
hit-rate $h(n)$ grows with swarm size $n$:

$$h(n) \approx 1 - e^{-\lambda n}$$

where $\lambda$ depends on chunk diversity per game title. Average transmission cost
per chunk decreases sublinearly, without any central bottleneck or proprietary codec.

**Hardware requirements:** Python 3.9+, no GPU, no cloud access. Compatible with
constrained hardware (Raspberry Pi, decade-old consumer hardware) as passive vault nodes.

This constitutes an open, decentralized architecture in the research space occupied by
proprietary neural video codecs (Google NNVE, Meta VCT), with the distinction that
all computation, vault storage, and tree evolution remain local and auditable.

---

## 4. Cross-Domain Comparison

### 4.1 What Aether Does

When structural fingerprints from different domains are compared, Aether observes clusters. It does not interpret them.

**Three-stage model:**

```
Stage 1: Observation   ??? Two fingerprints are structurally similar
Stage 2: Accumulation  ??? Multiple independent datasets show the same cluster
Stage 3: Hypothesis    ??? Testable conjecture for domain experts
```

Aether outputs only Stage 1. Stage 2 emerges through accumulation in the local vault or Aethernet swarm. Stage 3 is the user's task.

### 4.2 What Aether Never Does

- Express structural similarity as causality
- Report cross-domain patterns as findings
- Formulate unvalidated observations as results (Assistant protection)
- Draw inferences about the content of compared data

### 4.3 When Cross-Domain Comparisons Become Relevant

Only when many independent structural hints accumulate does a reliable signal emerge:
- A genome sequence and a climate time series share the same periodicity fingerprint ??? single hint
- 200 independent genome sequences and 300 climate time series show the same cluster ??? testable hypothesis for domain experts

The system makes this distinction explicit: single hints are not formulated as findings.

---

## 5. Formal Base Model

**Lossless reconstruction condition:**
```
D(S_t, R_t) = X_t
```
- `X_t` = data state at time t
- `S_t` = snapshot (compact structural model)
- `R_t` = residual (remaining information)
- `D` = deterministic decoder

**Observer-relative residual uncertainty:**
```
H_lambda(X, t) = H(X | M_t)
I_obs(X, t) = H(X) - H_lambda(X, t)
```

This formulation is a working hypothesis of the project, not a new theorem of information theory.

---

## 6. Privacy by Architecture

**Zero-knowledge architecture:**

```
Local (device)              Network
??????????????????????????????????????????              ?????????????????????
Raw data        ??? NEVER  ??? Network
Deltas          ??? NEVER  ??? Network
File keys       ??? NEVER  ??? Network
Session seeds   ??? NEVER  ??? Network
Sequence content ??? NEVER ??? Network
                              ???
Structural anchors ??? Optional ??? Aethernet
                    (non-invertible, consent-bound)
```

**Anchor ??? technical explanation:**
An anchor is a SHA-256-based structural signature:
```
sig = f(entropy, dominant_freq, fractal_dim, benford_score, symmetry, signal_type, hash(chunk))
anchor_hash = sha256(sig)
```
Neither the chunk nor the content of the analyzed file can be reconstructed from `anchor_hash`.

**Consent layer before every release:**
- Option 1: No sharing (default)
- Option 2: Anonymous (anchor hash only, no user identity)
- Option 3: With signature (explicit creator identification)

---

## 7. Non-Hallucinating Architecture: Assistant

Assistant receives exclusively structurally verified data from the pipeline. The system prompt prevents speculation. On uncertainty, no output is produced.

**What this means in practice:**
- When `H_lambda` is high (much residual uncertainty): Assistant is silent or marks output accordingly
- When reconstruction condition `D(S_t, R_t) = X_t` is not met: Assistant produces no completeness statement
- When governance conditions break: Assistant produces no output

---

## 8. Security and Governance Model

**Internal security rules:**
1. Impermissible states are not conveniently representable
2. Critical state transitions are validated
3. Default: `deny by default`
4. Critical paths: append-only, hashed, signed
5. Raw data, snapshots, keys, and rights strictly separated

**Relevant modules:**
- `modules/security_engine.py` ??? `SecurityManager`, `secure_zeroize`
- `modules/security_monitor.py` ??? integrity check, baseline comparison
- `modules/session_engine.py` ??? `SessionContext`, ephemeral keys

---

## 9. Development Path: AELAB and Aether

AELAB was the first development impulse ??? an evolutionary path for extracting stable structural candidates. It proved too unbounded for the system's requirements.

Aether is the main architecture. AELAB is today an internal background path (`modules/ae_evolution_core.py`) that supplies additional structural anchors.

---

## 10. Limitations

- Structural patterns are observations, not causal statements
- The observer-relative extension is a working model, not a completed theory
- SEMS is a working term in the project, not a recognized scientific field
- Cross-domain clusters are not reported as findings ??? only accumulation makes them testable
- The historical pi finding (AELAB development history) is not reproducibly demonstrated in the current codebase

---

## Conclusion

Aether measures structure. It does not interpret. It measures, stores locally, reveals nothing that has not been explicitly released ??? and formulates only what the pipeline has measured.

**Aether is a tool for everyone who wants to find patterns in data without giving up control of that data. Help build it.**

---

Date: March 2026 ??? Author: Kevin Hannemann
