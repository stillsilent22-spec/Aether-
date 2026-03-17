# Aether Whitepaper

Stand: M??rz 2026
Autor: Kevin Hannemann
Status: Technisches Whitepaper zur source-available Ver??ffentlichung

??? [English version: WHITEPAPER_EN.md](WHITEPAPER_EN.md)

---

## 1. Einleitung

Dieses Whitepaper beschreibt die technischen Grundlagen und Architektur von Aether ??? einem lokalen Framework f??r strukturelle Datenanalyse mit integriertem Datenschutz.

Aether ist kein Klassifikator, kein KI-Modell und kein Interpreter. Es ist ein Messinstrument: Es berechnet strukturelle Merkmale beliebiger Daten und macht diese vergleichbar ??? ohne Labels, ohne Training, ohne sensitive Inhalte preiszugeben.

**Grundsatz:** Strukturelle ??hnlichkeit ist eine Beobachtung, keine Aussage. Ob sie relevant ist, entscheiden Dom??nenexperten oder weitere Untersuchungen ??? nicht das System.

---

## 2. Technische Einordnung

Aether behandelt Dateien, Bytestr??me und Systemprozesse als lokale Zust??nde, die ??ber messbare Struktur beschrieben und verglichen werden. Der technische Kern:

- **Analysepipeline**: misst Entropie, Symmetrie, Periodizit??t, fraktale Dimension, Fourier-Spektrum, Attraktorzust??nde, Benford-Verteilung
- **Rekonstruktionsschicht**: Snapshots, Deltas, verlustfreie Rekonstruktion
- **Persistenzschicht**: lokale SQLite-Datenbank, append-only Audit-Log
- **Governance-Schicht**: fail-closed Zugriffsregeln, consent-gebundene Freigaben
- **Shanway**: lokaler Sprachpfad ??? formuliert ausschlie??lich verifizierte Strukturbefunde
- **Aethernet**: optionaler dezentraler Ankerpfad (consent-bound, kein Rohdaten-Export)

---

## 3. Dom??nenspezifische Mustererkennung

### 3.1 Methodik

Innerhalb einer Dom??ne erkennt Aether Anomalien durch Abweichung von der beobachteten strukturellen Baseline ??? ohne Schwellwerte, ohne dom??nenspezifisches Training, ohne die Dateninhalte zu interpretieren.

**Gemessene Metriken:**

| Metrik | Formel / Methode | Interpretation |
|---|---|---|
| Shannon-Entropie | `H(X) = -?? p(x) log??? p(x)` | Informationsdichte, Musterlosigkeit |
| Symmetrie (Gini) | Normalisierte Verteilungsungleichheit | Innere Balance der Byte-Verteilung |
| Fraktale Dimension | Katz-Dimension | Selbst??hnlichkeit, Komplexit??tsstufe |
| Dominante Frequenz | FFT, st??rkstes Spektrum | Periodizit??t, rhythmische Wiederkehr |
| Benford-Score | F??hrungsziffernverteilung vs. log??????(1+1/d) | Nat??rlichkeit der Zahlenverteilung |
| Attraktorzustand | Graph-basierte Stabilisierung | Konvergenz, Langzeitstabilit??t |
| Observer I_obs | `H(X) - H(X|M_t)` | Lernzuwachs des Beobachters |

### 3.2 Bioinformatik

Genomsequenzen besitzen charakteristische Entropie- und Periodizit??tsprofile. Aether erkennt:
- Entropieausrei??er (m??gliche Mutationsh??ufungen, Insertionen)
- Benford-Abweichungen (unerwartete H??ufigkeitsverteilungen von Codons)
- Periodizit??tsmuster (regulatorische Sequenzen, Wiederholungselemente)

**Datenschutz:** Die Sequenz verl??sst das Ger??t nie. Der Fingerprint enth??lt keine Sequenzinformation ??? er ist nicht invertierbar.

### 3.3 Klimaforschung

Klimazeitreihen zeigen charakteristische Strukturmuster (saisonale Periodizit??t, Attraktor-Stabilit??t bei stabilen Klimaregimen). Aether erkennt:
- Strukturbr??che (Regime-Wechsel ohne Annotation)
- Abnorme Frequenzmuster (nicht-periodische Ereigniscluster)
- Attraktordrift (Verschiebung stabiler Zust??nde ??ber Zeit)

**Datenschutz:** Messstationsdaten, Koordinaten, Metadaten bleiben lokal.

### 3.4 Systemoptimierung

Laufende Prozesse werden mit denselben Metriken beschrieben wie andere Datenquellen:
- CPU-Burst-Cluster ??? Periodizit??tsanalyse
- Speicherbelegung ??? Baseline-Attractordrift
- I/O-Verhalten ??? Delta- und Frequenzanalyse
- Render-Events ??? GPU-Resonanz, Frame-Struktur

Relevante Module: `modules/process_monitor.py`, `modules/efficiency_monitor.py`, `modules/preload_optimizer.py`, `modules/optimize_engine.py`

### 3.5 Softwareanalyse

Quellcode und Bin??rstrukturen haben messbare Struktureigenschaften:
- Komplexit??tsverteilung (Entropiedichte pro Modul)
- Anomalie-Erkennung (Abweichungen von der Codebase-Baseline)
- Strukturelle ??hnlichkeit zwischen Modulen (ohne Inhalte zu lesen)

---

## 4. Dom??nen??bergreifender Vergleich

### 4.1 Was Aether tut

Wenn strukturelle Fingerprints aus verschiedenen Dom??nen verglichen werden, beobachtet Aether Cluster. Es interpretiert sie nicht.

**Dreistufiges Modell:**

```
Stufe 1: Beobachtung    ??? Zwei Fingerprints ??hneln sich strukturell
Stufe 2: H??ufung        ??? Mehrere unabh??ngige Datens??tze zeigen gleiches Cluster
Stufe 3: Hypothese      ??? Pr??fbare Vermutung f??r Dom??nenexperten
```

Aether gibt nur Stufe 1 aus. Stufe 2 entsteht durch Akkumulation im lokalen Vault oder im Aethernet-Schwarm. Stufe 3 ist Aufgabe des Nutzers.

### 4.2 Was Aether nicht tut

- Struktur??hnlichkeit als Kausalit??t ausgeben
- Dom??nen??bergreifende Muster als Befunde formulieren
- Unvalidierte Beobachtungen als Ergebnis darstellen (Shanway-Schutz)
- R??ckschl??sse auf den Inhalt der verglichenen Daten ziehen

### 4.3 Wann dom??nen??bergreifende Vergleiche relevant werden

Erst wenn sich viele unabh??ngige strukturelle Hinweise h??ufen, entsteht ein belastbarer Hinweis:
- Genomsequenz und Klimazeitreihe zeigen denselben Periodit????ts??fingerprint ??? Einzelhinweis
- 200 unabh??ngige Genomsequenzen und 300 Klimazeitreihen zeigen dasselbe Cluster ??? pr??fbare Hypothese f??r Dom??nenexperten

Das System macht diese Unterscheidung explizit: Einzelhinweise werden nicht als Befunde formuliert.

---

## 5. Formales Grundmodell

**Lossless-Rekonstruktionsbedingung:**
```
D(S_t, R_t) = X_t
```
- `X_t` = Datenzustand zum Zeitpunkt t
- `S_t` = Snapshot (kompaktes Strukturmodell)
- `R_t` = Residuum (verbleibende Information)
- `D` = deterministischer Dekoder

**Beobachterrelative Restunsicherheit:**
```
H_lambda(X, t) = H(X | M_t)
I_obs(X, t) = H(X) - H_lambda(X, t)
```

Diese Formulierung ist eine Arbeitshypothese des Projekts, kein neues Theorem der Informationstheorie.

---

## 6. Datenschutz by Architecture

**Zero-Knowledge-Architektur:**

```
Lokal (Ger??t)               Netz
???????????????????????????????????????               ????????????
Rohdaten        ??? NIEMALS ??? Netz
Deltas          ??? NIEMALS ??? Netz
Filekeys        ??? NIEMALS ??? Netz
Session-Seeds   ??? NIEMALS ??? Netz
Sequenzinhalte  ??? NIEMALS ??? Netz
                              ???
Strukturanker   ??? Optional ??? Aethernet
                  (nicht invertierbar, consent-gebunden)
```

**Anker ??? technisch erkl??rt:**
Ein Anker ist eine SHA-256-basierte Struktursignatur:
```
sig = f(entropy, dominant_freq, fractal_dim, benford_score, symmetry, signal_type, hash(chunk))
anchor_hash = sha256(sig)
```
Aus `anchor_hash` lassen sich weder der Chunk noch der Inhalt der analysierten Datei rekonstruieren.

**Consent-Schicht vor jeder Freigabe:**
- Option 1: Kein Teilen (Standard)
- Option 2: Anonym (nur Anchor-Hash, keine Nutzeridentit??t)
- Option 3: Mit Signatur (explizite Identifikation des Erstellers)

---

## 7. Nicht-halluzinierende Architektur: Shanway

Shanway empf??ngt ausschlie??lich strukturell verifizierte Daten aus der Pipeline. Der System-Prompt verhindert Spekulation. Bei Unsicherheit wird keine Ausgabe erzeugt.

**Was das in der Praxis bedeutet:**
- Wenn `H_lambda` hoch ist (viel Restunsicherheit): Shanway schweigt oder kennzeichnet die Ausgabe entsprechend
- Wenn Rekonstruktionsbedingung `D(S_t, R_t) = X_t` nicht erf??llt: Shanway gibt keine Vollst??ndigkeitsaussage aus
- Wenn Governance-Bedingungen brechen: Shanway gibt keine Ausgabe

---

## 8. Sicherheits- und Governance-Modell

**Interne Sicherheitsregeln:**
1. Unzul??ssige Zust??nde sind nicht bequem darstellbar
2. Kritische Zustandswechsel werden validiert
3. Standard: `deny by default`
4. Kritische Pfade: append-only, gehasht, signiert
5. Rohdaten, Snapshots, Schl??ssel und Rechte strikt getrennt

**Relevante Module:**
- `modules/security_engine.py` ??? `SecurityManager`, `secure_zeroize`
- `modules/security_monitor.py` ??? Integrit??tspr??fung, Baseline-Vergleich
- `modules/session_engine.py` ??? `SessionContext`, ephemere Schl??ssel

---

## 9. Entwicklungspfad: AELAB und Aether

AELAB war der erste Entwicklungsimpuls ??? ein evolutiver Pfad zur Extraktion stabiler Strukturkandidaten. Er erwies sich als zu ungebunden f??r den Anspruch des Systems.

Aether ist die Hauptarchitektur. AELAB ist heute ein interner Hintergrundpfad (`modules/ae_evolution_core.py`), der zus??tzliche Strukturanker liefert.

---

## 10. Begrenzungen

- Strukturmuster sind Beobachtungen, keine Kausalaussagen
- Die beobachterrelative Erweiterung ist ein Arbeitsmodell, keine abgeschlossene Theorie
- SEMS ist ein Arbeitsbegriff im Projekt, kein anerkanntes Wissenschaftsfeld
- Dom??nen??bergreifende Cluster werden nicht als Befunde ausgegeben ??? erst H??ufung macht sie pr??fbar
- Der historische Pi-Befund (AELAB-Entwicklungsgeschichte) ist in der aktuellen Codebasis nicht reproduzierbar belegt

---

## Schlussfolgerung

Aether misst Struktur. Es interpretiert nicht. Es misst, speichert lokal, gibt nichts preis, was nicht explizit freigegeben wurde ??? und formuliert nur, was die Pipeline gemessen hat.

**Aether ist ein Werkzeug f??r alle, die Muster in Daten finden wollen, ohne Kontrolle ??ber diese Daten aufzugeben. Hilf mit, es zu bauen.**

---

Stand: M??rz 2026 ??? Autor: Kevin Hannemann
