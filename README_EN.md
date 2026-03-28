# Aether

> **We are burning the future to simulate intelligence. Aether is the alternative: a local, deterministic, mathematically grounded instrument for measuring structure, not generating guesses. No labels. No training. No cloud. No hallucinations. Only information theory, executed locally, with privacy as an architectural principle.**

> **Wir verbrennen die Zukunft, um Intelligenz zu simulieren. Aether ist die Alternative: ein lokales, deterministisches, mathematisch fundiertes Instrument zur Messung von Struktur, nicht zur Erzeugung von Vermutungen. Keine Labels. Kein Training. Keine Cloud. Keine Halluzinationen. Nur Informationstheorie, lokal ausgeführt, mit Privatsphäre als Architekturprinzip.**

**Symbiotic proto-meta-layer OS for structural data analysis — no labels, no cloud, no hallucinations.**

Aether computes measurable structural properties of arbitrary data and makes them comparable:
Shannon entropy, Zipf compliance, Fourier periodicity, Benford score, fractal dimension (Katz),
attractor stability. All computation runs locally. No raw data leaves the device.

→ [Deutsche Version: README.md](README.md)

## Execution Artifacts (30/60/90)

- Operating Modes Contract: [contracts/aether_operating_modes_v1.json](contracts/aether_operating_modes_v1.json)
- KPI Contract: [contracts/aether_kpi_contract_v1.json](contracts/aether_kpi_contract_v1.json)
- Event/API Schema: [contracts/aether_event_schema_v1.json](contracts/aether_event_schema_v1.json)
- E2E Reference Scenarios: [contracts/aether_e2e_reference_scenarios_v1.json](contracts/aether_e2e_reference_scenarios_v1.json)
- Meta Signal Policy: [contracts/aether_meta_signal_policy_v1.json](contracts/aether_meta_signal_policy_v1.json)

## Module Organization

- Canonical Python implementations live under `modules/`.
- Root-level files are kept only as compatibility shims for legacy imports.
- Prefer new imports in the form `from modules.<name> import ...`.

## Why Aether matters

Aether is a local, deterministic analysis and reconstruction system.
It extracts structure from data without cloud services, without black-box models, and without hidden semantics.
Everything is transparent, reproducible, and audit-grade.

Aether is designed for people who need clarity where conventional pipelines fail:
researchers, analysts, forensic experts, scientists, engineers - anyone who works with complex signals that resist categorization.

### Efficiency

Aether does not rely on massive models or GPU clusters.
Its architecture is built around minimal rules, explicit transformations, and deterministic kernels.
This makes Aether extremely efficient: it runs on ordinary hardware while still revealing deep structural patterns.

### Democratization

Because Aether is lightweight and fully local, every user contributes to a distributed ecosystem of computation.
More users means more total available compute - not centralized, but spread across many independent machines.
Aether scales horizontally through people, not through data centers.

### Call for collaborators

Aether is built by one person - for now.
If you see potential in this paradigm and want to help push it to the next level (kernel, models, UI, visualization, theory, or tooling), reach out.
Aether is ready to grow.

---

## What Aether Is — and Is Not

Aether is a **local measurement instrument for data structure**. It computes statistically
defined signatures from raw data and flags deviations from observed baselines — without a
classifier, without training data, without content interpretation.

**Aether is not:**
- An AI model or neural network
- A substitute for domain expertise
- A semantic analysis or interpretation system
- A universal solution for arbitrary analytical questions

**Aether is:**
- A local anomaly detection tool based on measurable structural metrics
- A symbiotic operating system layer with integrated privacy guarantees and cryptographically non-invertible fingerprints
- A deterministic output filter (Assistant) for pipeline-verified structural findings
- A system optimization tool based on process structural profiles

---

## Technical Foundation

All metrics used are established methods from information theory and statistics:

| Metric | Method | Typical use |
|--------|--------|------------|
| Shannon entropy | H(X) = −Σ p(x) log₂ p(x) | Information density, randomness |
| Zipf compliance | Power law fit f ∝ r^−α | Naturalness of token distributions |
| Fourier periodicity | FFT over block entropy sequence | Rhythmic patterns, seasonality |
| Benford score | Leading digits vs. log₁₀(1+1/d) | Statistical naturalness of numeric data |
| Katz dimension | Normalized fractal curve length | Self-similarity, complexity |
| DBSCAN clustering | Density-based, ε-neighborhood | Grouping without label assignment |

No proprietary algorithms, no black-box models. Every component is mathematically defined
and reproducible.

---

## Realistic Use Cases

### 1. Anomaly Detection Without Training Data

Aether computes a structural profile (baseline) for each dataset. Deviations are flagged as
outliers — independent of domain and data type, without labeled examples.

**Concrete scenarios:**

- **System logs:** CPU burst clusters, I/O periodicity, memory drift — detectable as deviations
  from the process baseline without reading process content.
- **Time series:** climate measurements, financial prices, sensor data — regime shifts and
  periodicity breaks detectable without pre-annotation or training data.
- **Genomics:** entropy outliers in FASTA sequences, Benford deviations in codon frequencies —
  as low-cost structural pre-screening before expensive alignment procedures.

### 2. Obfuscation and Malware Detection

Obfuscated code shows consistent, measurable structural patterns: high byte entropy (H > 7.0 bit;
typical source code sits at 5–6 bit), high short-identifier ratio (> 60%), high hex literal
density (> 10%), Zipf violations in token distribution.

The `CodeEthicsEngine` detects these patterns **without a signature database and without network
access** — purely via measurable structural properties. This makes detection robust against new
obfuscation variants not yet captured in signature lists.

### 3. Document and Text Structure Analysis

The `EthicsEngine` computes language-neutral structural metrics on text without content
interpretation:

| Metric | What is measured | Indication at extreme values |
|--------|-----------------|------------------------------|
| Zipf compliance | Token frequency distribution vs. power law | Synthetically generated or highly repetitive text |
| Negation density | Negation words per total tokens | Extreme negative language or over-qualification |
| Absolute statement density | "always", "everyone", "never" etc. per sentence | Rhetorical absolutes — indicator of propaganda style |
| Noether score | cos(v_start, v_end) over core vocabulary | Thematic inconsistency within the text |

These are **structural observations**, not semantic judgments. No keyword matching, no labels,
no training. The metrics provide quantifiable indicators — interpretation is the user's
responsibility.

### 4. Privacy-Preserving Collaboration

Two teams can compare datasets structurally without exchanging raw data:

1. Team A computes the SHA-256 fingerprint of its structural profile (cryptographically
   non-invertible)
2. Team B does the same
3. Fingerprints are compared — structural similarity measurable, content remains hidden

The `PrivacyRegistry` implements granular consent layers: anonymous, ephemeral (TTL-bound),
immediately revocable.

### 5. System Optimization and Performance Profiling

Process structural profiles (CPU bursts, I/O patterns, memory deltas) are described with the
same metrics as any other data source. Deviations from process baselines are detected without
reading process content. On constrained hardware (< 2 GB RAM, HDD), Aether automatically
detects the hardware context and prioritizes low-resource optimizations with full rollback
capability.

---

## Privacy by Architecture

The zero-knowledge principle is not a configuration option — it is the architecture:

```
Local (device)             Network
─────────────────────────────────────────────
Raw data         ──> NEVER  ──> Network
Deltas           ──> NEVER  ──> Network
File keys        ──> NEVER  ──> Network
Session seeds    ──> NEVER  ──> Network

Structural anchors ──> Optional (consent-bound) ──> Aethernet
                       SHA-256(f(entropy, freq, fractal, benford, chunk_hash))
                       Non-invertible. No content recoverable.
```

An anchor is a mathematical signature with no recoverable content — comparable to a
cryptographic hash: it identifies without revealing anything.

---

## Assistant: Deterministic Output Filter

Assistant is not a language model that independently generates content. It is a **deterministic
renderer**: it translates exclusively pipeline-verified structural findings into language.

- **Input:** only data that has passed through the full Aether analysis pipeline
- **Filter chain:** blacklist → medical rule → determinism gate (h_lambda threshold) →
  consensus gate (min. 3 confirmed sources) → hedging check
- **Output:** verified finding or silence — no speculation, no interpretation

When data is insufficient, source consensus is missing, or residual uncertainty is too high:
no output.

---

## Technical Architecture

```
Raw data
   |
   v
analysis_engine        --> Entropy, symmetry, Fourier, Benford, attractor
   |
   +-> ethics_engine   --> Structural text integrity
   +-> delta_engine    --> XOR delta, session seed
   +-> bayes_engine    --> Bayesian posteriors
   +-> graph_engine    --> Graph and attractor analysis
   |
   v
reconstruction_engine  --> D(Snapshot, Residual) = Original
   |
   v
registry (SQLite, local) --> Vault, audit log, append-only
   |
   +-> assistant          --> Language output (verified data only)
   +-> aethernet        --> Anchor path (optional, consent-bound)
```

Stack: Python 3.9+ · Rust (pyo3) for performance-critical paths

---

## System Limitations

These are not caveats to be minimized — they are part of an honest system description:

- **Structural similarity does not imply causality.** When two datasets share the same
  fingerprint, that is an indicator, not a finding.
- **Cross-domain clustering is exploratory observation**, not a claim. Interpretation is
  the domain expert's responsibility.
- **H_lambda is a project-internal working model**, not an established information-theoretic
  concept.
- **Aether does not replace domain expertise.** It provides structural indicators, not diagnoses.
- **No external security audit** has been conducted.

---

## Quick Start

```bash
git clone https://github.com/stillsilent22-spec/Aether-
cd Aether-
pip install -r requirements.txt
python start.py
```

---

## Documentation

| Document | Content |
|----------|---------|
| [WHITEPAPER_EN.md](WHITEPAPER_EN.md) | Technical foundations and architecture (EN) |
| [WHITEPAPER.md](WHITEPAPER.md) | Technische Grundlagen und Architektur (DE) |
| [ROADMAP.md](ROADMAP.md) | Development phases and open questions |
| [SECURITY.md](SECURITY.md) | Security architecture |
| [core_axioms.md](core_axioms.md) | Formal base axioms |

---

*Source-available. March 2026 — Author: Kevin Hannemann*
