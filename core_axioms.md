# Core Design Axioms / Kerndesign-Axiome

These axioms govern every design decision in Aether. They are not goals — they are
constraints. Violations are bugs, not trade-offs.

---

## Axiom 1: Measurement over Interpretation
**EN:** The system measures structural properties. It does not interpret them.  
**DE:** Das System misst strukturelle Eigenschaften. Es interpretiert sie nicht.

The 9-metric cascade extracts Phi(X) from any byte stream. What Phi(X) means in
context is determined solely by the human operator. No label, annotation, or
domain hint is used by any algorithmic component. The system explicitly has no
opinion about whether a structural match is significant.

---

## Axiom 2: Structural Comparison Only
**EN:** Comparison is performed on structural signatures, never on raw data.  
**DE:** Vergleiche erfolgen auf strukturellen Signaturen, niemals auf Rohdaten.

Two byte streams are compared via ||Phi(X_A) - Phi(X_B)||. The raw streams are
not transmitted, stored outside the device, or required at comparison time.

---

## Axiom 3: Determinism
**EN:** Given identical input, the pipeline always produces identical output.  
**DE:** Bei identischen Eingaben produziert die Pipeline immer identische Ausgaben.

The cascade order is fixed. Metric formulas are deterministic. No stochastic element
exists in the core pipeline. The Rust shell is the sole authorized trigger for the
full pipeline. Direct Python invocation bypasses integrity guarantees.

---

## Axiom 4: Local Execution — Privacy by Architecture
**EN:** No raw data, session keys, or deltas leave the device.  
**DE:** Keine Rohdaten, Session-Schlüssel oder Deltas verlassen das Gerät.

Enforced in code: `privacy_registry.py`, `privacy_observer.py`, `session_guard.py`.
Session keys are RAM-only and zeroed on session end. This is an architectural
constraint, not a policy.

Additionally:
- Passive observation of private local files, accounts, passwords, keystrokes, or
  input order/rhythm is explicitly prohibited.
- Explicit render/runtime signals (user-enabled) may use the analysis pipe only when
  the user has actively enabled this feature.

---

## Axiom 5: Structural Matching Without Semantic Inference
**EN:** Labels are for humans. The algorithm sees topology only.  
**DE:** Labels sind für Menschen. Der Algorithmus sieht nur Topologie.

Invariant labels assigned by uploaders or operators are human-readable metadata stored
locally. They are never:
- Parsed by the cascade
- Weighted in the trust score
- Used as features in any matching algorithm
- Shared with the swarm

Structural matching always means: ||Phi(X_A) - Phi(X_B)|| < epsilon. Whether this is
meaningful in a given domain is a question for the domain expert, not the system.

---

## Axiom 6: Radical Hardware Inclusion
**EN:** No minimum hardware tier excludes a device from structural analysis.  
**DE:** Kein Mindest-Hardware-Tier schließt ein Gerät von der Strukturanalyse aus.

The 9-metric cascade can be executed on hardware from 1995. The execution is
mathematically identical regardless of hardware tier. Tier constraints apply only to:
- Network participation level (Tier 0 = LocalOnly, Tier 4 = FullDHT)
- Relay node eligibility
- Gossip protocol capacity

Phi(X) produced on a Win 9x machine equals Phi(X) produced on a modern workstation
for the same input. This is not an approximation. It is the specification.

Hardware-tier progression is automatic, monotone, and requires no reinstall.

---

## Axiom 7: Algo Tokens Belong to No Entity
**EN:** Algo tokens are contributed anonymously to collective compression knowledge.  
**DE:** Algo-Tokens werden anonym zum kollektiven Kompressionswissen beigetragen.

When a recurring delta pattern is tokenized, the resulting token is distributed to
the swarm without attribution. No node owns a token. No entity receives credit or
compensation for contributing a token. The collective vault is a commons.

Token contribution is consent-gated: the user controls whether their node contributes
to the swarm. Local-only analysis is always available, always full-fidelity.

---

## Metric Reference / Metrikenreferenz

| # | Metric | Formula | Range | Cross-domain use | Forensic relevance |
|---|--------|---------|-------|------------------|--------------------|
| 1 | Shannon Entropy | H(X) = -sum p(x) log2 p(x) | [0,8] | Universal | High entropy in compressed/encrypted data |
| 2 | Boltzmann Entropy | S = H/8, normalized | [0,1] | Universal | Thermodynamic distance from structured state |
| 3 | Zipf Alpha | f(r) ~ r^-alpha | R+ | Text, genomics, finance, network | Unnatural distributions deviate from power-law |
| 4 | Benford Score | log10(1+1/d) conformance | [0,1] | Numeric time series | Fabricated data deviates from Benford |
| 5 | Fourier Periodicity | dominant RFFT period | [0,1] | EEG, ECG, seismic, audio | Artificial signals may lack natural periodicity |
| 6 | Katz Dimension | log(n)/(log(n)+log(d/L)) | [1,inf) | EEG, ECG, genomics | Self-similarity loss indicates structural change |
| 7 | Permutation Entropy | Bandt & Pompe (2002), m=3 | [0,1] | EEG, DNA, any temporal | Entropy collapse indicates synthetic ordering |
| 8 | Delta Convergence | ||Phi(t)-Phi(t-1)||/sqrt(8) | [0,1] | Any time series | Sudden spike indicates structural discontinuity |
| 9 | Noether Consistency | symmetry fwd/bwd | [0,1] | Any signal | Asymmetry is a manipulation signal |

---

## Scope and Limitations / Geltungsbereich und Grenzen

**What Aether is:**
- A structural measurement and compression system
- A distributed research environment for structural pattern discovery
- A hardware-inclusive P2P network with formal trust evaluation
- A privacy-preserving framework for structural similarity hypotheses

**What Aether is not:**
- A trained machine learning model — no weights, no backpropagation
- A black-box classifier — every metric formula is publicly defined and independently re-implementable
- A semantic reasoning system — it makes no claims about what structural matches mean
- A surveillance system — passive collection of private data, keystrokes, or input rhythm is architecturally prohibited
- A content analysis system — the system does not parse, index, or store file contents

**Limitations:**
- Vault convergence is a theoretical bound; empirical convergence depends on source entropy and pattern diversity
- Cross-domain structural matches are hypotheses, not proofs of causation or correlation
- Swarm trust requires >= 3 independent nodes; single-node observations are held pending
- Hardware Tier 0 has no network participation; analysis is local-only until resources permit upgrade
