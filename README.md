# Aether

## Quick Start

```bash
python solo_bootstrap.py   # first-time setup (genesis node, keypair, anchor pack)
python start.py            # launch Aether
```

Solo genesis mode is supported — no second node required to start.

> **We are burning the future to simulate intelligence. Aether is the alternative: a local, deterministic, mathematically grounded instrument for measuring structure, not generating guesses. No labels. No training. No cloud. No hallucinations. Only information theory, executed locally, with privacy as an architectural principle.**

> **Wir verbrennen die Zukunft, um Intelligenz zu simulieren. Aether ist die Alternative: ein lokales, deterministisches, mathematisch fundiertes Instrument zur Messung von Struktur, nicht zur Erzeugung von Vermutungen. Keine Labels. Kein Training. Keine Cloud. Keine Halluzinationen. Nur Informationstheorie, lokal ausgeführt, mit Privatsphäre als Architekturprinzip.**

**Symbiotischer Proto-Meta-Layer-OS für strukturelle Datenanalyse — ohne Labels, ohne Cloud, ohne Halluzinationen.**

Aether berechnet messbare Struktureigenschaften beliebiger Daten und macht sie vergleichbar:
Shannon-Entropie, Zipf-Konformität, Fourier-Periodizität, Benford-Score, fraktale Dimension (Katz),
Attraktor-Stabilität. Alle Berechnungen laufen lokal. Keine Rohdaten verlassen das Gerät.

→ [English version: README_EN.md](README_EN.md)

## Execution Artifacts (30/60/90)

- Operating Modes Contract: [contracts/aether_operating_modes_v1.json](contracts/aether_operating_modes_v1.json)
- KPI Contract: [contracts/aether_kpi_contract_v1.json](contracts/aether_kpi_contract_v1.json)
- Event/API Schema: [contracts/aether_event_schema_v1.json](contracts/aether_event_schema_v1.json)
- E2E Reference Scenarios: [contracts/aether_e2e_reference_scenarios_v1.json](contracts/aether_e2e_reference_scenarios_v1.json)
- Meta Signal Policy: [contracts/aether_meta_signal_policy_v1.json](contracts/aether_meta_signal_policy_v1.json)

## Module Organization

- Kanonische Python-Implementierungen liegen unter `modules/`.
- Root-Level-Dateien bleiben nur als Kompatibilitaets-Shims fuer Legacy-Imports bestehen.
- Bevorzuge neue Imports in der Form `from modules.<name> import ...`.

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

## Was Aether ist — und was nicht

Aether ist ein **lokales Messinstrument für Datenstruktur**. Es berechnet statistisch definierte
Signaturen aus Rohdaten und erkennt Abweichungen von beobachteten Baselines — ohne Klassifikator,
ohne Trainingsdaten, ohne inhaltliche Interpretation.

**Aether ist nicht:**
- Ein KI-Modell oder neuronales Netz
- Ein Ersatz für Domänenexpertise
- Ein semantisches Analyse- oder Interpretationssystem
- Eine universelle Lösung für beliebige analytische Fragestellungen

**Aether ist:**
- Ein lokales Anomalieerkennungs-Werkzeug auf Basis messbarer Strukturmetriken
- Ein symbiotischer Betriebssystem-Layer mit integrierten Datenschutzgarantien und kryptografisch nicht invertierbaren Fingerprints
- Ein deterministischer Ausgabefilter (Assistant) für pipeline-verifizierte Strukturbefunde
- Ein Systemoptimierungswerkzeug auf Basis von Prozess-Strukturprofilen

---

## Technische Grundlage

Alle verwendeten Metriken sind etablierte Verfahren der Informationstheorie und Statistik:

| Metrik | Methode | Typische Anwendung |
|--------|---------|-------------------|
| Shannon-Entropie | H(X) = −Σ p(x) log₂ p(x) | Informationsdichte, Zufälligkeit |
| Zipf-Konformität | Potenzgesetz-Fit f ∝ r^−α | Natürlichkeit von Token-Verteilungen |
| Fourier-Periodizität | FFT über Block-Entropie-Sequenz | Rhythmische Muster, Saisonalität |
| Benford-Score | Führungsziffern vs. log₁₀(1+1/d) | Statistische Natürlichkeit numerischer Daten |
| Katz-Dimension | Normierte fraktale Kurvenlänge | Selbstähnlichkeit, Komplexität |
| DBSCAN-Clustering | Dichtebasiert, ε-Nachbarschaft | Gruppenbildung ohne Labelzuweisung |

Keine proprietären Algorithmen, kein Black-Box-Modell. Jede Komponente ist mathematisch definiert
und reproduzierbar.

---

## Realistische Anwendungsfälle

### 1. Anomalieerkennung ohne Trainingsdaten

Aether berechnet für jeden Datensatz ein Strukturprofil als Baseline. Abweichungen werden als
Ausreißer markiert — unabhängig von Domäne und Datentyp, ohne gelabelte Beispiele.

**Konkrete Szenarien:**

- **Systemlogs:** CPU-Burst-Cluster, I/O-Periodizität, Speicher-Drift — messbar als Abweichung
  von der Prozess-Baseline, ohne Prozessinhalte zu lesen.
- **Zeitreihen:** Klimamessungen, Finanzkurse, Sensordaten — Regime-Wechsel und Periodizitätsbrüche
  werden erkannt, ohne Vorannotation oder Trainingsdaten.
- **Genomdaten:** Entropieausreißer in FASTA-Sequenzen, Benford-Abweichungen bei Codon-Häufigkeiten —
  als kostengünstiges strukturelles Pre-Screening vor aufwendigen Alignment-Verfahren.

### 2. Obfuscation- und Malware-Erkennung

Obfuskierter Code zeigt konsistente, messbare Strukturmuster: hohe Byte-Entropie (H > 7,0 bit;
normaler Quellcode liegt typischerweise bei 5–6 bit), kurze Bezeichner-Quote (> 60 %),
hohe Hex-Literal-Dichte (> 10 %), Zipf-Verletzungen in der Token-Verteilung.

Die `CodeEthicsEngine` erkennt diese Muster **ohne Signaturdatenbank und ohne Netzwerkzugriff** —
rein über messbare Struktureigenschaften. Das macht die Erkennung robust gegenüber neuen
Obfuskierungsvarianten, die noch nicht in Signaturlisten erfasst sind.

### 3. Dokumenten- und Textstrukturanalyse

Die `EthicsEngine` berechnet sprachstrukturelle Metriken ohne inhaltliche Interpretation:

| Metrik | Was gemessen wird | Bedeutung bei Extremwert |
|--------|------------------|--------------------------|
| Zipf-Konformität | Token-Häufigkeit vs. Potenzgesetz | Synthetisch generierter oder stark repetitiver Text |
| Negationsdichte | Negationswörter pro Gesamttoken | Extrem negative oder übermäßig relativierende Sprache |
| Absolutaussagendichte | „immer", „alle", „nie" etc. pro Satz | Rhetorische Absolutsetzungen (Propaganda-Indikator) |
| Noether-Score | cos(v_Anfang, v_Ende) über Kernvokabular | Thematische Inkonsistenz im Textverlauf |

Das sind **strukturelle Beobachtungen**, keine semantischen Urteile. Kein Keyword-Matching,
kein Label, kein Training. Die Metriken liefern quantifizierbare Hinweise — die Interpretation
obliegt dem Nutzer.

### 4. Privacy-preserving Kollaboration

Zwei Teams können Datensätze strukturell vergleichen, ohne Rohdaten auszutauschen:

1. Team A berechnet den SHA-256-Fingerprint seines Strukturprofils (kryptografisch nicht invertierbar)
2. Team B desgleichen
3. Fingerprints werden verglichen — strukturelle Ähnlichkeit messbar, Inhalt bleibt verborgen

Die `PrivacyRegistry` implementiert granulare Consent-Schichten: anonym, ephemer (TTL-gebunden),
sofort widerrufbar.

### 5. Systemoptimierung und Performance-Profiling

Prozess-Strukturprofile (CPU-Bursts, I/O-Muster, Speicher-Deltas) werden mit denselben Metriken
beschrieben wie beliebige andere Datenquellen. Abweichungen von der Prozess-Baseline werden erkannt,
ohne Prozessinhalte zu lesen. Auf schwacher Hardware (< 2 GB RAM, HDD) erkennt Aether automatisch
den Hardware-Kontext und priorisiert Low-Resource-Optimierungen mit vollständigem Rollback-Pfad.

### 6. Medizinische Datensätze — struktureller Vergleich ohne Datenweitergabe

Zwei Institutionen können Patientendaten und Befundreihen strukturell vergleichen, ohne Rohdaten auszutauschen:

1. Institution A berechnet einen Strukturanker: `SHA-256(f(H_entropy, zipf_α, benford_score, katz_dim, chunk_hash))`
2. Institution B berechnet das Gleiche für den eigenen Bestand
3. Ankerdistanz < Schwelle δ → strukturell ähnliche Profile messbar — kein medizinischer Inhalt übertragen

**Konkrete Anwendungsfälle:**
- **Anomalie in Laborzeitreihen** — Ausreißer in Blutbild, Vitalwerten oder Sensordaten ohne Offenlegung von Patientenidentitäten
- **Diagnose-Konsistenzprüfung** — strukturell inkonsistente Befundcodierung ist messbar ohne Inhaltszugriff
- **Manipulationsnachweis** — nachträglich eingefügte Datenpunkte brechen Benford- und Katz-Signatur charakteristisch
- **Epidemiologische Strukturclusterung** — Populationsähnlichkeit messbar ohne Individualisierung

**Datenschutzgarantie durch Mathematik:** Weder Patientenname noch Diagnose noch Messwert sind aus dem Anker rekonstruierbar — nicht durch technische Vorkehrungen, sondern weil die SHA-256-Funktion es strukturell ausschließt.

### 7. Datenforensik — Authentizität und Manipulationsnachweis

| Forensische Frage | Messmethode |
|-------------------|-------------|
| Wurde dieser Datensatz nachträglich modifiziert? | Benford-Score + Katz-Dimension brechen bei manuellen Eingriffen charakteristisch |
| Stammen zwei Datensätze aus derselben Quelle? | Ankerdistanz < δ → gemeinsamer Ursprung statistisch nachweisbar |
| Ist diese Zeitreihe konsistent? | Fourier-Periodizität bricht bei rückwirkend eingefügten Einträgen |
| Chain-of-Custody-Nachweis | Append-only SQLite-Audit-Log pro Session — nachträgliche Änderungen strukturell sichtbar |

Alle Aussagen sind domänenunabhängig, reproduzierbar und ohne inhaltliche Interpretation des Datensatzes möglich.

### 8. Demokratisierung analytischer Werkzeuge

Strukturanalytische Methoden sind in der Praxis oft an Institutionszugänge, Cloud-Abonnements oder spezialisierte Hardware gebunden. Aether beseitigt diese Zugangshürden:

| Umgebung | Status |
|----------|--------|
| < 2 GB RAM, HDD | vollständig unterstützt — Low-Resource-Modus automatisch aktiv |
| Offline, kein Internet | alle Funktionen verfügbar, by design |
| Consumer-Hardware (Laptop, Mini-PC) | keine Leistungseinbuße bei Strukturanalyse |
| Kein institutioneller Zugang | keine Lizenzkosten, kein Vendor-Lock-in, keine Cloud-Abhängigkeit |

Wer keinen Zugang zu Cloud-APIs oder Institutionslizenzen hat, bekommt dasselbe Werkzeug ohne Einschränkung. Keine eingeschränkte "Community Edition". Keine Daten als impliziter Preis für die Nutzung.

**Teilhabe durch Architektur:** Die Methoden hinter Aether — Shannon, Zipf, Benford, Katz — sind öffentlich dokumentierte Mathematik. Erklärbar, reproduzierbar, kritisierbar. Kein proprietäres Modell, kein erforderliches Vertrauen in eine Black Box.

---

## Datenschutz durch Architektur

Das Zero-Knowledge-Prinzip ist keine Einstellung — es ist die Architektur:

```
Lokal (Gerät)              Netz
─────────────────────────────────────────────
Rohdaten        ──> NIEMALS ──> Netz
Deltas          ──> NIEMALS ──> Netz
Filekeys        ──> NIEMALS ──> Netz
Session-Seeds   ──> NIEMALS ──> Netz

Strukturanker   ──> Optional (consent-gebunden) ──> Aethernet
                    SHA-256(f(entropy, freq, fractal, benford, chunk_hash))
                    Nicht invertierbar. Kein Inhalt rekonstruierbar.
```

Ein Anker ist eine mathematische Signatur ohne rekonstruierbaren Inhalt — vergleichbar einem
kryptografischen Hash: er identifiziert, ohne etwas preiszugeben.

---

## Assistant: Deterministischer Ausgabefilter

Assistant ist kein Sprachmodell, das eigenständig Inhalte generiert. Es ist ein
**deterministischer Renderer**: Es übersetzt ausschließlich pipeline-verifizierte Strukturbefunde
in Sprache.

- **Eingang:** nur Daten, die die vollständige Aether-Analysepipeline durchlaufen haben
- **Filterkette:** Blacklist → Medical-Rule → Determinismus-Gate (h_lambda-Schwelle) →
  Konsens-Gate (mind. 3 bestätigte Quellen) → Hedging-Prüfung
- **Ausgabe:** verifizierter Befund oder Schweigen — keine Spekulation, keine Interpretation

Bei fehlender Datenlage, unzureichendem Quellenkonsens oder zu hoher Restunsicherheit:
keine Ausgabe.

---

## Technische Architektur

```
Rohdaten
   |
   v
analysis_engine        --> Entropie, Symmetrie, Fourier, Benford, Attraktor
   |
   +-> ethics_engine   --> Strukturelle Textintegrität
   +-> delta_engine    --> XOR-Delta, Session-Seed
   +-> bayes_engine    --> Bayesianische Posterioren
   +-> graph_engine    --> Graph und Attraktoranalyse
   |
   v
reconstruction_engine  --> D(Snapshot, Residuum) = Original
   |
   v
registry (SQLite, lokal) --> Vault, Audit-Log, append-only
   |
   +-> assistant          --> Sprachausgabe (nur verifizierte Daten)
   +-> aethernet        --> Ankerpfad (optional, consent-gebunden)
```

Stack: Python 3.9+ · Rust (pyo3) für performance-kritische Pfade

---

## AetherNet — Geplantes dezentrales Wissensnetz

AetherNet ist die geplante Netzwerkschicht von Aether: ein dezentrales Peer-Netz für den Austausch struktureller Anker zwischen Instanzen. Kein zentraler Server. Keine Telemetrie. Keine Rohdaten im Netz.

### Datenschutz durch Architektur — nicht durch Versprechen

Der Datenschutz ist keine Konfigurationsoption — er ist die Konsequenz der Architektur:

- Rohdaten, Deltas, Filekeys und Session-Seeds verlassen **niemals** das Gerät
- Strukturanker verlassen das Gerät nur mit **explizitem, widerrufbarem Consent**
- Aus einem Anker kann kein Originalinhalt rekonstruiert werden — das ist eine Eigenschaft der SHA-256-Funktion, kein Versprechen

Was nicht gebaut wurde, kann nicht missbraucht werden. Zentralisierte Rohdaten-Infrastruktur wurde bewusst nicht entworfen.

### Strukturanker: Herzstück der dezentralen Wissensbasis

```
anchor = SHA-256(H_entropy ‖ zipf_α ‖ benford_score ‖ katz_dim ‖ chunk_hash)
```

**Eigenschaften:**
- **Nicht invertierbar:** kein Verfahren kann Originalinhalt aus dem Anker extrapolieren
- **Reproduzierbar:** gleicher Datensatz → immer gleicher Anker (deterministisch)
- **Universell:** CSV, JSON, FASTA, Logs, Binärdaten, medizinische Datensätze — alle erzeugen einen Anker
- **Consent-gebunden:** kein Anker verlässt das Gerät ohne explizite Nutzerfreigabe

Anker ermöglichen kollektives Wissen ohne kollektive Datenweitergabe.

### Effizienz durch Logik: der Konvergenzeffekt

Mit wachsendem Ankerpool M_t gilt:

```
H_lambda(X, t) → H_min(X)
```

Delta schrumpft logarithmisch mit der Knotenzahl. Jeder neue Teilnehmer im Netz erhöht die Ankerdichte — was alle bestehenden Knoten strukturell effizienter macht. Mehr Symbionten → geringere Unsicherheit pro Analyse.

Das ist kein Marketing-Versprechen. Es ist die messbare Konsequenz des Shannon-Limits.

Gemessen: N=1 → Delta 0.355 · N=1000 → Delta 0.269 · Verlauf: logarithmisch konvergent.

---

## Empirischer Beweis: Delta-Konvergenz

`aether prove` misst den strukturellen Delta-Verlauf über N Knoten.

```bash
cargo run --bin aether-cli -- prove
```

**Ergebnis (20. März 2026, lokaler Vault):**

| Knoten N | Delta-Ratio | H_lambda |
|----------|-------------|----------|
| 1        | 0.355       | —        |
| 1000     | 0.269       | 0.2113   |

```
✓ KONVERGENZ NACHGEWIESEN
  Delta N=1 → N=1000: 0.355 → 0.269
  Shannon-Limit: ~0.2682
  Beweis: data/convergence_proof.json
  Plot:   data/convergence_plot.html
```

**Was das bedeutet:**

Mit wachsendem Anker-Pool M_t gilt:

```
H_lambda(X, t) → H_min(X)
```

Delta schrumpft logarithmisch mit der Knotenzahl —
exakt wie Shannon voraussagt. Jeder neue Knoten im Aethernet
macht alle anderen Knoten strukturell effizienter.

Das ist kein Versprechen. Es ist eine Messung.
Reproduzierbar. Falsifizierbar. Lokal ausführbar.

---

## Systemgrenzen

Diese Grenzen sind keine Einschränkungen, die minimiert werden sollen — sie sind Teil der
ehrlichen Systembeschreibung:

- **Strukturähnlichkeit impliziert keine Kausalität.** Wenn zwei Datensätze denselben Fingerprint
  zeigen, ist das ein Hinweis, kein Befund.
- **Cross-domain-Clustering ist explorative Beobachtung**, keine Aussage. Die Interpretation
  obliegt Domänenexperten.
- **H_lambda ist ein projektinternes Arbeitsmodell**, kein etabliertes informationstheoretisches
  Konzept.
- **Aether ersetzt keine Domänenexpertise.** Es liefert strukturelle Hinweise, keine Diagnosen.
- **Kein externer Sicherheitsaudit** wurde bisher durchgeführt.

---

## Schnellstart

```bash
git clone https://github.com/stillsilent22-spec/Aether-
cd Aether-
pip install -r requirements.txt
python start.py
```

---

## Dokumentation

| Dokument | Inhalt |
|----------|--------|
| [WHITEPAPER.md](WHITEPAPER.md) | Technische Grundlagen und Architektur (DE) |
| [WHITEPAPER_EN.md](WHITEPAPER_EN.md) | Technical foundations and architecture (EN) |
| [ROADMAP.md](ROADMAP.md) | Entwicklungsphasen und offene Fragen |
| [SECURITY.md](SECURITY.md) | Sicherheitsarchitektur |
| [core_axioms.md](core_axioms.md) | Formale Grundaxiome |

---

## Swarm Mode (Controller + Agent)

Der Swarm-Stack ist in diesem Repo lokal implementiert und standardmaessig sicher konfiguriert:

- Consent vor Aktivierung: ohne Einwilligung kein Netzwerk-Sharing
- Keine Rohframes auf Platte: gespeichert werden nur Metriken + SHA256-Fingerprints
- Desktop-Capture als Default (`mss`), GPU/API-Hooks nur Lab-Stub
- P2P-Fingerprint-Gossip ist opt-in und per Default deaktiviert

### Lokale Steuerung

```bash
python -m modules.swarm_ui_adapter status
python -m modules.swarm_ui_adapter consent
python -m modules.swarm_ui_adapter enable_swarm
python -m modules.swarm_ui_adapter disable_swarm
```

### Hintergrunddienst

- Linux/systemd: `service/aether-swarm.service`
- Windows/NSSM: `service/windows_service_instructions.md`

---

*Source-available. Stand: März 2026 — Autor: Kevin Hannemann*
