# Aether

**Lokales Framework f??r strukturelle Datenanalyse ??? ohne Labels, ohne Cloud, ohne Halluzinationen.**

Aether misst Struktur in beliebigen Daten: Entropie, Symmetrie, fraktale Dimension, Periodizit??t, Benford-Verteilung, Attraktor-Zust??nde. Es erkennt Anomalien und erzeugt Hypothesen ??? lokal, label-frei, ohne dass sensitive Inhalte das Ger??t verlassen.

??? [English version: README_EN.md](README_EN.md)

---

## Was Aether ist

Aether ist ein **Messinstrument f??r Struktur**. Es wandelt Rohdaten in mathematische Metriken um und vergleicht diese dom??nen??bergreifend ??? ohne vorher zu wissen, wonach es sucht, ohne Labels, ohne Kategorien.

**Zentrale Klarstellung:**
> Strukturelle ??hnlichkeit ist eine **Beobachtung**, keine Bedeutung. Wenn zwei Datens??tze aus verschiedenen Dom??nen denselben Fingerprint zeigen, ist das ein Hinweis ??? kein Befund. Ob dieser Hinweis relevant ist, entscheidet der Nutzer, nicht das System.

Aether ist ein Spektrometer, kein Interpret.

---

## Die vier Kernst??rken

### 1. Dom??nenspezifische Mustererkennung ??? ohne sensitive Inhalte preiszugeben

Innerhalb einer Dom??ne erkennt Aether Anomalien und Muster strukturell ??? ohne die Daten zu kennen, zu verstehen oder nach au??en zu geben:

| Dom??ne | Was Aether strukturell misst |
|---|---|
| **Bioinformatik** | Entropieausrei??er in Genomsequenzen, Periodizit??tsmuster, Benford-Abweichungen ??? ohne Annotation, ohne Zugriffsrechte auf Sequenzinhalte |
| **Klimaforschung** | Wiederkehrende Frequenzmuster in Zeitreihen, Attraktor-Stabilit??t, Strukturbr??che ??? ohne Metadaten oder Messstationsdaten preiszugeben |
| **Systemoptimierung** | CPU-Burst-Cluster, I/O-Periodizit??t, Speicher-Attraktor ??? Abweichung von der Prozess-Baseline ohne Prozessinhalt zu lesen |
| **Softwareanalyse** | Komplexit??tsverteilung, Entropiedichte, Strukturanomalien im Code ??? ohne Quellcode ins Netz zu senden |
| **Finanzanalyse** | Strukturelle Muster in Kursdaten, Benford-Abweichungen als Auff??lligkeitsmarker ??? ohne Positionsdaten preiszugeben |

**Datenschutz-Mechanismus:** Aether analysiert nur die *Struktur* der Daten, nie ihren Inhalt. Rohdaten verlassen das Ger??t nie. Was nach au??en geht (optional, consent-gebunden), sind ausschlie??lich nicht-invertierbare Struktursignaturen ??? daraus lassen sich keine urspr??nglichen Daten rekonstruieren.

---

### 2. Dom??nen??bergreifender Vergleich ??? als Exploration, nicht als Aussage

Wenn strukturelle ??hnlichkeiten zwischen Dom??nen auftauchen, h??lt Aether sie fest ??? ohne eine Bedeutung zu behaupten.

**Wie das funktioniert:**
- Aether berechnet f??r jede Datei / jeden Datenstrom einen Strukturfingerprint (Entropie, Symmetrie, Fourier, Benford, fraktale Dimension)
- Fingerprints aus verschiedenen Dom??nen k??nnen verglichen werden
- Wenn mehrere unabh??ngige Datens??tze strukturell clustern, entsteht ein Hinweis
- Erst wenn sich viele unabh??ngige Hinweise h??ufen, wird daraus eine pr??fbare Hypothese

**Was Aether niemals tut:**
- Struktur??hnlichkeit als Kausalit??t ausdr??cken
- Dom??nen??bergreifende Muster als Befunde ausgeben
- Unvalidiertes als Ergebnis formulieren (??? Shanway-Schutzmechanismus)

---

### 3. Nicht-halluzinierende Ausgabe: Shanway

Shanway ist der lokale Sprachpfad. Er formuliert, was die Pipeline gemessen hat ??? nicht mehr.

| Schutzmechanismus | Wirkung |
|---|---|
| **Kontrollierter Eingang** | Nur pipeline-verifizierte Strukturdaten gelangen in Shanway |
| **Strikter System-Prompt** | Shanway darf nicht spekulieren, keine eigenen Schl??sse ziehen |
| **Schweigen als Option** | Bei Unsicherheit oder niedrigem Strukturscore: keine Ausgabe |

> Shanway ist ein ??bersetzer von Messwerten in Sprache ??? kein wissendes System, kein Interpret.

---

### 4. Datenschutz by Architecture

Das Zero-Knowledge-Prinzip ist keine Einstellung, sondern die Architektur.

```
Lokal (Ger??t)               Netz
???????????????????????????????????????               ????????????
Rohdaten        ??? NIEMALS ??? Netz
Deltas          ??? NIEMALS ??? Netz
Filekeys        ??? NIEMALS ??? Netz
Session-Seeds   ??? NIEMALS ??? Netz
Sequenzinhalte  ??? NIEMALS ??? Netz
                              ???
Strukturanker   ??? Optional ??? Aethernet (nicht invertierbar, consent-gebunden)
```

**Was ein Anker ist:** Eine stark komprimierte, mathematische Signatur der Struktur einer Datei. Kein Inhalt, kein Klartext, keine R??ckschl??sse auf das Original m??glich. Vergleichbar mit einem Fingerabdruck, der zwar identifiziert, aber keine Information ??ber den Menschen preisgibt.

---

## Ressourcen- und Softwareoptimierung

Aether analysiert laufende Prozesse mit denselben Strukturmetriken wie Genomdaten:

- **CPU-Muster**: Burst-Cluster, Periodizit??t, Attraktor-Stabilit??t
- **Speicher**: Baseline-Abweichung, Delta-Verhalten
- **I/O**: Leseburst-Clustering, strukturelle Anomalien
- **Render-Events**: GPU-Resonanz, Frame-Struktur

Erkennung erfolgt durch Abweichung von der strukturellen Baseline ??? keine festen Schwellwerte, keine hartcodierten Regeln.

Relevante Module: `efficiency_monitor` ?? `preload_optimizer` ?? `process_monitor` ?? `optimize_engine`

---

## Technische Architektur

```
Rohdaten
   ???
   ???
analysis_engine      ??? Entropie, Symmetrie, Fourier, Benford, Attraktor
   ???
   ?????? ethics_engine  ??? Strukturelle Textintegrit??t
   ?????? delta_engine   ??? XOR-Delta, Session-Seed
   ?????? bayes_engine   ??? Bayesianische Posterioren
   ?????? graph_engine   ??? Graph- und Attraktorzustand
   ???
   ???
reconstruction_engine ??? D(Snapshot, Residuum) = Original
   ???
   ???
registry (SQLite, lokal) ??? Vault, Audit-Log, append-only
   ???
   ?????? shanway        ??? Sprachausgabe (nur verifizierte Strukturdaten)
   ?????? aethernet      ??? Ankerpfad (optional, consent-gebunden)
```

---

## Mitmachen

Aether sucht:
- Entwickler, die an dezentralen, datenschutzkonformen Systemen arbeiten
- Wissenschaftler (Bioinformatik, Klima, Physik), die explorative Werkzeuge f??r ungelabelte Daten brauchen
- Menschen, die eine lokale Alternative zu Cloud-KI wollen
- Alle, die Kontrolle ??ber ihre Daten behalten wollen

**Aether ist ein Werkzeug f??r alle, die Muster in Daten finden wollen, ohne Kontrolle ??ber diese Daten aufzugeben. Hilf mit, es zu bauen.**

```bash
git clone https://github.com/stillsilent22-spec/Aether-
cd Aether-
pip install -r requirements.txt
python start.py
```

---

## Dokumentation

| Dokument | Inhalt |
|---|---|
| [WHITEPAPER.md](WHITEPAPER.md) | Technische Grundlagen und Architektur (DE) |
| [WHITEPAPER_EN.md](WHITEPAPER_EN.md) | Technical foundations and architecture (EN) |
| [ROADMAP.md](ROADMAP.md) | Entwicklungsphasen und offene Fragen |
| [SECURITY.md](SECURITY.md) | Sicherheitsarchitektur |
| [core_axioms.md](core_axioms.md) | Formale Grundaxiome |

---

*Source-available. Stand: M??rz 2026 ??? Autor: Kevin Hannemann*
