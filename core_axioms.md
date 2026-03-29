# Aether — Core Design Principles

Aether is an open-source, local analysis system that extracts and compares measurable structural
properties of arbitrary data. All computations are deterministic and reproducible. No raw data
leaves the device.

---

## Design Foundation

Modern analysis pipelines typically depend on labelled training data, cloud infrastructure, or
opaque statistical models. Aether is built on a different premise: many structurally relevant
properties of data can be measured directly from the raw byte stream, without content-level
interpretation and without any prior training.

These properties — byte-level Shannon entropy, Zipf-law fit, FFT-derived periodicity, Benford
leading-digit distribution, and Katz fractal dimension — are established information-theoretic
and statistical metrics. They are computable from any binary or text input, domain-agnostic, and
produce repeatable results on identical inputs.

---

## Operating Principles

### 1. Measurement over interpretation

Aether does not classify content. It computes numerical signatures from data. A high byte-entropy
value does not mean a file is encrypted — it means the byte distribution is approximately uniform.
The interpretation is the responsibility of the operator, who has domain context that Aether does not.

### 2. Structural comparison without content exposure

Two data objects can be compared via their structural signature vectors without either party
disclosing the underlying data. Distance metrics (cosine similarity, L2 norm) applied to signature
vectors yield a scalar that expresses structural proximity. Whether proximity implies semantic
similarity is a domain-specific question that Aether does not answer.

### 3. Deterministic output

Given the same input, Aether always produces the same structural signature. There is no sampling,
no randomised embedding, no non-deterministic inference step. This makes every result auditable
and reproducible by a third party with access to the same input.

### 4. Local execution and privacy by architecture

All computations run on the local machine. No raw data, delta, or intermediate result is
transmitted externally. Structural anchors stored in the public registry are derived via SHA-256;
the preimage (raw data) cannot be reconstructed from the anchor.

---

## Metric Reference

| Metric | Formula / Method | Measured property |
|---|---|---|
| Shannon entropy | H(X) = −Σ p(x) log₂ p(x) | Byte-distribution uniformity |
| Zipf α | Power-law fit f ∝ r^−α | Token-frequency distribution shape |
| FFT periodicity | Dominant peak in FFT of block-entropy sequence | Structural repetition / cyclicity |
| Benford score | KL-divergence from log₁₀(1+1/d) | Leading-digit naturalness in numeric data |
| Katz dimension | Normalised fractal curve length | Self-similarity, structural complexity |
| DBSCAN clusters | Density-based clustering, ε-neighbourhood | Group structure without label assignment |
| Permutation Entropy | PE = 1 − H_perm / log₂(order!) | Ordinal structure in the byte stream (Bandt & Pompe 2002). Orthogonal to Shannon H(X); measures pattern order distribution, not byte-value distribution. |

No proprietary elements. Each metric is mathematically defined, independently re-implementable,
and produces identical output for identical input.

---

## Scope and Limitations

- Aether's structural metrics provide necessary, not sufficient, conditions for conclusions.
  Elevated byte entropy is consistent with encryption, compression, and media — distinguishing
  between them requires additional context.
- The system does not perform semantic reasoning. Metric values do not carry inherent meaning;
  they are inputs to operator-level analysis.
- "Structurally Emergent Metadynamic Semantics" (SEMS) is a project-internal working label for
  the research direction. It is not a recognised scientific field and does not imply claims
  beyond what the implemented algorithms demonstrably compute.
- The analogy names used for some metrics (Noether score for cosine similarity of token vectors,
  Heisenberg score for absolute-statement density) are pedagogical shorthand, not physico-
  mathematical claims. The underlying computations are straightforward statistical operations.

---

*Aether is an independent software project. All claims about system behaviour are bounded by the
implemented algorithms documented in this repository. No correctness guarantees extend beyond
what is verifiable from the source code and test suite.*

