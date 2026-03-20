# Aether

**Lokales Framework für strukturelle Datenanalyse — ohne Labels, ohne Cloud, ohne Halluzinationen.**

Aether berechnet messbare Struktureigenschaften beliebiger Daten und macht sie vergleichbar:
Shannon-Entropie, Zipf-Konformität, Fourier-Periodizität, Benford-Score, fraktale Dimension (Katz),
Attraktor-Stabilität. Alle Berechnungen laufen lokal. Keine Rohdaten verlassen das Gerät.

→ [English version: README_EN.md](README_EN.md)

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
- Ein privacy-preserving Analyse-Framework mit kryptografisch nicht invertierbaren Fingerprints
- Ein deterministischer Ausgabefilter (Shanway) für pipeline-verifizierte Strukturbefunde
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

## Shanway: Deterministischer Ausgabefilter

Shanway ist kein Sprachmodell, das eigenständig Inhalte generiert. Es ist ein
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
   +-> shanway          --> Sprachausgabe (nur verifizierte Daten)
   +-> aethernet        --> Ankerpfad (optional, consent-gebunden)
```

Stack: Python 3.9+ · Rust (pyo3) für performance-kritische Pfade

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

*Source-available. Stand: März 2026 — Autor: Kevin Hannemann*
