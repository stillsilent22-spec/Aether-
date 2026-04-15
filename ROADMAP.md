# Aether Roadmap

**EN:** Implementation status, research direction, and forward planning.  
**DE:** Implementierungsstand, Forschungsrichtung und Vorausplanung.

---

## 30/60/90 Execution Tracks

Die folgenden Track sind als verbindlicher Umsetzungs-Track definiert.
Stand: April 2026.

### Track 1: Productized Operating Modes (Analyze, Guard, Sync, Evolve)

**Ziel:** Kern-Workflows als klar erkennbare Betriebsmodi mit stabilen Ein-/Ausgaben.

- 30 Tage: Modus-Vertrag fixieren (Input, Gate, Output, Failure Rules). UI + CLI auf dieselben vier Modi normalisieren.
- 60 Tage: Standardisierte Run-Summaries je Modus (status, reason, metrics, next_action). Deterministische Mode-Transitions mit Audit-Eintrag.
- 90 Tage: Mode-Chaining fur End-to-End-Laeufe. Regression-Suite je Modus + Integrationssuite fur Chaining.

### Track 2: Hard SLO/KPI Contract per Cycle

**Ziel:** Messbare Betriebsqualitat statt impliziter Aussagen.

- 30 Tage: KPI-Set fixieren: Determinism Rate, Safety Coverage, Consensus Latency, False-Positive Budget, Throughput. Baseline erfassen.
- 60 Tage: Warn- und Fehler-Schwellen in Runtime und Reports. KPI-Drift zwischen Releases automatisch vergleichen.
- 90 Tage: SLO-Gates fur Release-Freigabe (No-Gate, Soft-Gate, Hard-Gate). KPI-Historie als Audit-Artifact.

### Track 3: Standardized Interfaces (CLI/API/Event Schema)

**Ziel:** Aether als integrierbare Plattform statt isolierter Toolchain.

- 30 Tage: Einheitliches Event-Schema v1 fur alle Modus-Ausgaben. CLI-Entry-Points auf konsistentes Command-Muster.
- 60 Tage: API-konforme Response-Objekte. Kompatibilitatsmatrix fur Versionen dokumentieren.
- 90 Tage: Integrationsleitfaden fur externe Orchestratoren. Contract-Tests in CI.

### Track 4: End-to-End Reference Scenarios

**Ziel:** Real nutzbare, nachstellbare Praxispfade.

- 30 Tage: Vier Referenzpfade definieren: Input→Analyze→Guard→Decision, Input→Analyze→Sync→Consensus, Input→Analyze→Evolve→Re-check, Input→Full Chain→Audit Export.
- 60 Tage: Jede Pipeline mit Gold-Output und erwarteten KPI-Korridoren hinterlegen. Automatisierte Smoke-Runs.
- 90 Tage: Oeffentliche Reproduzierbarkeitsr-Reports je Szenario. Standardisierte Incident-Playbooks.

### Track 5: Research Use Cases — Cross-Domain Structural Atlas

**Ziel:** Aether als wissenschaftliche Infrastruktur fur domainenubergreifende Strukturhypothesen.

- 30 Tage: Dokumentation der 10 Metriken mit Signaltyp-Coverage (EEG, ECG, Genomsequenzen, Chromosome, Umweltsensoren, Forensik). Ingest-API fur Time-Series-Formate (CSV, HDF5, JSONL).
- 60 Tage: Cross-domain matching proof-of-concept: EEG + ECG struktureller Vergleich unter selber Domane. Benford/Noether-Forensikpipeline fur numerische Datensatze.
- 90 Tage: Hypothesis-Generation-API (strukturell, nicht semantisch). Offentlicher Referenz-Atlas fur bekannte strukturelle Muster je Signaltyp. Reproduzierbarkeitstest fur alle funf empirischen Vorhersagen (WHITEPAPER §10).

---

## Implementierungsstand / Implementation Status

| Phase | Inhalt | Status |
|-------|--------|--------|
| 1 | Foundation: Web + Dateien + Registry + Graph + Session-Keys | Fertig |
| 2 | Media: MP3 / MP4 / Bilder + Datei-Register + Filekeys | Fertig |
| 3 | Process: Windows Prozessdynamik + ReconstructionEngine + Attractor-Tracking | Fertig |
| 4 | Render: ETW/DXGI Pixel-Koordination pro Prozess + UI + Runtime | Fertig |
| 5 | Optimize: Vereinzelung, Ausdunnung, Empfehlung + Effizienzmonitor | Fertig |
| 6 | Aethernet: dezentrale Knoten, P2P-Transport, DHT, Tier-System, Clearnet/BT/USB-Entry | Fertig (April 2026) |
| 7 | Cross-Domain Atlas: Signaltyp-Dokumentation, Ingest-API, EEG/ECG/Genomik-Tests, Forensikpipeline | Geplant |
| 8 | Research Lab API: Hypothesengenerierung, offentlicher Anchor-Atlas, reproduzierbare Szenarien | Geplant |
| 9 | Governance & Community: Anchor-Verifizierungsnetz, Publisher-Vertrauen | Vision |
| 10 | Platform Expansion: native Linux .deb/.AppImage, macOS .dmg, iOS, Mobile-App | Vision |

---

## Phase 1 — Foundation (Fertig)

- Assistant v1-v4 Integration
- Session-Key Management + Secure Zeroize
- Registry + Graph-Engine (lokale Wissensstruktur)
- Web-Analyse + Dateianalyse
- Tamper-Detection, Audit-Logging, Invarianten-Prufung

## Phase 2 — Media (Fertig)

- MP3 / MP4 / Bildanalyse (UniversalAdapter)
- Datei-Register + einmalige Filekeys
- Delta-Generierung uber Session-Seed (XOR + noise)
- Privacy: Signaturen reisen, Rohdaten bleiben lokal

## Phase 3 — Process (Fertig)

- Windows-Prozessdynamik (ETW, Prozessbaum, Ressourcendelta)
- ReconstructionEngine: Snapshots, Residuals, lossless-Rekonstruktion
- Attractor-Tracking: Attraktor-Detektion aus Prozessdynamik
- Security: Session-Isolation, Consent-gebundener Relay-Pfad

## Phase 4 — Render (Fertig)

- ETW/DXGI Pixel-Koordination pro Prozess
- RenderFingerprint (Pixel-Signatur je Fenster)
- UI-Integration (Iced, Slint, CLI)
- Runtime-Loop + Monitoring + Persistence-Engine

## Phase 5 — Optimize (Fertig)

- Prozess-Vereinzelung: gleiche Arbeit, weniger Prozesse
- Ressourcen-Empfehlung mit Bestatigung
- Effizienzmonitor + Delta-Konvergenz-Tracking

## Phase 6 — Aethernet (April 2026: Fertig)

Implementierte Kernkomponenten:

- `modules/universal_identity.py` — Hardware-Fingerprint fur Win9x/Linux/macOS/Android/RPi; Medium-bewusstes Keypair-Equivalent (LAN/Clearnet/BT/USB); Sybil-Schutz
- `modules/entry_channels.py` — Discover-Dispatcher: LAN (UDP Multicast) → Relay Pool → Clearnet (öffentliche IP-Reflexion + DNS Seeds) → Bluetooth (RFCOMM) → USB/Serial → Offline-Fallback
- `legacy_bootstrap.py` — entry_pub_equiv + entry_medium in account_claim.json; Backfill fur bestehende Nodes; discover_entry() Fallback
- `modules/swarm_p2p.py` — Gossip + Leader Election + Blindspot Flood Relay (max 3 Hops)
- `modules/dht_bootstrap.py` — Kademlia DHT, K-Buckets
- `modules/aethernet_transport.py` — HTTP-Transport mit strukturellem Anchor-Schema
- Yggdrasil IPv6 Overlay (Tier 3+)
- Quorum: >= 3 unabhangige Knoten fur Anchor-Commit

Swarm-Tier-Progression (automatisch, kein Neustart):
- Tier 0: LocalOnly (Win 9x, < 256 MB)
- Tier 1: LAN Beacon (Win 2000+, 256 MB)
- Tier 2: LAN P2P (Win XP+, 512 MB, 2 Kerne)
- Tier 3: Yggdrasil P2P (Vista+/RPi3+, 1 GB)
- Tier 4: Full DHT (modern, 4 GB, 4 Kerne)

## Phase 7 — Cross-Domain Atlas (Geplant)

Forschungswerkzeuge fur strukturelle Signaltyp-Analyse:

**Signaltyp-Dokumentation:**
- EEG: M7 Permutation Entropy (Ordinalstruktur), M6 Katz-Dimension (fraktale Komplexitat), M5 Fourier Periodizitat (Frequenzbanderstruktur), M8 Delta Convergence (Zustandsubergange)
- ECG/EKG: M5 Fourier Periodizitat (Herzrhythmus), M4 Benford Score (Amplituden-Naturalness), M9 Noether Consistency (Signalintegrat)
- DNA / Genomsequenzen: M3 Zipf Alpha (Codon-Frequenzverteilung), M7 Permutation Entropy (Nukleotid-Ordnung), M1 Shannon Entropy (Informationsdichte je Locus)
- Chromosome: M5 Fourier (Bandierungsmuster), M4 Benford (Repeat-Count Naturalness), M6 Katz (Strukturkomplexitat)
- Umweltsensoren: M8 Delta Convergence (Basisdrift), M9 Noether Consistency (Messkonsistenz), M5 Fourier (saisonale/tagliche Zyklen)
- Forensische Daten: M4 Benford Abweichung (Fabrikationssignal), M9 Noether Asymmetrie (Manipulationssignal), M1 Shannon Collapse (synthetische Daten = maximale Entropie)

**Ingest-API:**
- CSV, HDF5, JSONL Time-Series Input
- Automatische Chunk-Segmentierung
- Batch-Cascade-Ausfuhrung
- Struktursignatur-Export (Phi-Vektor, kein Rohdaten-Export)

**Cross-Domain Matching Proof-of-Concept:**
- EEG + ECG structural comparison (gleicher Patient)
- Genomsequenz + Netzwerktraffic Zipf-Verteilungsvergleich
- Umweltsensor-Zeitreihe + klinische Laborergebnisse Delta-Convergence-Vergleich

**Forensik-Pipeline:**
- Benford/Noether-Anomalie-Scan fur numerische Datensatze
- Strukturelle Provenanzmarkierung ohne Inhaltsexposition

## Phase 8 — Research Lab API (Geplant)

- Hypothesis-Generation-API: strukturelle Treffer als maschinenlesbare JSON-Antworten (kein semantischer Inhalt)
- Offentlicher Referenz-Anchor-Atlas fur bekannte strukturelle Muster je Signaltyp
- Reproduzierbarkeits-Suite fur alle funf empirischen Vorhersagen (WHITEPAPER Section 10)
- Wissenschaftliche Peer-Verifikation: jede Prediction testbar mit oeffentlichen Datensatzen

## Phase 9 — Governance & Community (Vision)

- Anchor-Verifizierungsnetz (dezentrale Signaturprufer)
- Publisher-Vertrauen (verifizierbarer Beitragspfad ohne Identitatsexposition)
- Community-Editierrechte fur Referenz-Atlas (Quorum-gebunden)
- Transparenter Token-Commons ohne Eigentum

## Phase 10 — Platform Expansion (Vision)

- Native Linux .deb / .AppImage
- macOS .dmg
- iOS (structural analysis, local-only, no swarm by default)
- Android APK ausbauen (API 21+, aktuell: native APK ohne Python)
- LoRa Sub-1-GHz-Mesh: strukturelle Signaturen offline-first fur Umgebungen ohne Internetverbindung

---

**Author:** Kevin Hannemann  
**License:** AGPL-3.0  
**Last updated:** April 2026

Forschungsrichtung: Strukturell Emergente Metadynamische Semantik (SEMS) —
projektinternes Arbeitslabel, kein anerkanntes Wissenschaftsfeld.
