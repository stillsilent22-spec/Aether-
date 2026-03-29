# Aether Whitepaper

Stand: März 2026
Autor: Kevin Hannemann
Status: Technisches Whitepaper zur source-available Veröffentlichung

→ [English version: WHITEPAPER_EN.md](WHITEPAPER_EN.md)

---

## 1. Einleitung

Dieses Whitepaper beschreibt die technischen Grundlagen und Architektur von Aether — einem lokalen Struktur-Analyse-Layer für deterministische Datenanalyse mit integriertem Datenschutz.

Aether ist kein Klassifikator, kein KI-Modell und kein Interpreter. Es ist ein Messinstrument: Es berechnet strukturelle Merkmale beliebiger Daten und macht diese vergleichbar — ohne Labels, ohne Training, ohne sensitive Inhalte preiszugeben.

**Grundsatz:** Strukturelle Ähnlichkeit ist eine Beobachtung, keine Aussage. Ob sie relevant ist, entscheiden Domänenexperten oder weitere Untersuchungen — nicht das System.

> **Hinweis zu Metriknamen:** Einige Metriken tragen Namen aus Physik und Mathematik
> (Noether-Score, Heisenberg-Score, Interferenz-Score). Diese Namen sind **pädagogische
> Kürzel** — sie beschreiben das intuitive Konzept hinter der Metrik, nicht eine
> physikalische Analogie. Die zugrunde liegenden Berechnungen sind jeweils vollständig
> in Abschnitt 3.6 formal definiert und auf ihre statistischen Eigenschaften, nicht auf
> physikalische Gesetze, rückführbar.

---

## 2. Technische Einordnung

Aether behandelt Dateien, Byteströme und Systemprozesse als lokale Zustände, die über messbare Struktur beschrieben und verglichen werden. Der technische Kern:

- **Analysepipeline**: misst Entropie, Symmetrie, Periodizität, fraktale Dimension, Fourier-Spektrum, Permutation Entropy (Bandt & Pompe), Benford-Verteilung
- **Rekonstruktionsschicht**: Snapshots, Deltas, verlustfreie Rekonstruktion
- **Persistenzschicht**: lokale SQLite-Datenbank, append-only Audit-Log
- **Governance-Schicht**: fail-closed Zugriffsregeln, consent-gebundene Freigaben
- **Assistant**: lokaler Sprachpfad — formuliert ausschließlich verifizierte Strukturbefunde
- **Aethernet**: optionaler dezentraler Ankerpfad (consent-bound, kein Rohdaten-Export)

---

## 3. Domänenspezifische Mustererkennung

### 3.1 Methodik

Innerhalb einer Dom??ne erkennt Aether Anomalien durch Abweichung von der beobachteten strukturellen Baseline ??? ohne Schwellwerte, ohne dom??nenspezifisches Training, ohne die Dateninhalte zu interpretieren.

**Gemessene Metriken:**

| Metrik | Formel / Methode | Interpretation |
|---|---|---|
| Shannon-Entropie | `H(X) = -?? p(x) log??? p(x)` | Informationsdichte, Musterlosigkeit |
| Symmetrie (Gini) | Normalisierte Verteilungsungleichheit | Innere Balance der Byte-Verteilung |
| Fraktale Dimension | Katz-Dimension | SelbstÄhnlichkeit, Komplexit??tsstufe |
| Dominante Frequenz | FFT, st??rkstes Spektrum | Periodizit??t, rhythmische Wiederkehr |
| Benford-Score | F??hrungsziffernverteilung vs. log??????(1+1/d) | Nat??rlichkeit der Zahlenverteilung |
| Permutation Entropy | PE = 1 − H_perm / log₂(order!) | Ordnungsstruktur im Byte-Stream (Bandt & Pompe 2002), orthogonal zur Shannon-Entropie |
| Observer I_obs | `H(X) - H(X|M_t)` | Lernzuwachs des Beobachters |

### 3.2 Bioinformatik

Genomsequenzen besitzen charakteristische Entropie- und Periodizit??tsprofile. Aether erkennt:
- Entropieausrei??er (mögliche Mutationshäufungen, Insertionen)
- Benford-Abweichungen (unerwartete H??ufigkeitsverteilungen von Codons)
- Periodizit??tsmuster (regulatorische Sequenzen, Wiederholungselemente)

**Datenschutz:** Die Sequenz verl??sst das Gerät nie. Der Fingerprint enth??lt keine Sequenzinformation ??? er ist nicht invertierbar.

### 3.3 Klimaforschung

Klimazeitreihen zeigen charakteristische Strukturmuster (saisonale Periodizität, Permutation-Entropy-Verschiebungen bei stabilen Klimaregimen). Aether erkennt:
- Strukturbrüche (Regime-Wechsel ohne Annotation)
- Abnorme Frequenzmuster (nicht-periodische Ereigniscluster)
- Permutation-Entropy-Drift (Verschiebung der Ordnungsstruktur über Zeit)

**Datenschutz:** Messstationsdaten, Koordinaten, Metadaten bleiben lokal.

### 3.4 Systemoptimierung

Laufende Prozesse werden mit denselben Metriken beschrieben wie andere Datenquellen:
- CPU-Burst-Cluster ??? Periodizit??tsanalyse
- Speicherbelegung → Baseline-Permutation-Entropy-Drift
- I/O-Verhalten ??? Delta- und Frequenzanalyse
- Render-Events ??? GPU-Resonanz, Frame-Struktur

Relevante Module: `modules/process_monitor.py`, `modules/efficiency_monitor.py`, `modules/preload_optimizer.py`, `modules/optimize_engine.py`

### 3.5 Softwareanalyse

Quellcode und Bin??rstrukturen haben messbare Struktureigenschaften:
- Komplexit??tsverteilung (Entropiedichte pro Modul)
- Anomalie-Erkennung (Abweichungen von der Codebase-Baseline)
- Strukturelle Ähnlichkeit zwischen Modulen (ohne Inhalte zu lesen)
### 3.6 EthicsEngine: Formale Definitionen der Sprachstrukturmetriken

Die EthicsEngine bewertet Texte ausschließlich anhand messbarer Sprachstrukturgesetze.
Kein Keyword-Matching, kein Training, kein Label. Nur Struktur.

#### 3.6.1 Noether-Score — Thematische Konsistenz

**Analogie:** Emmy Noethers Symmetrieprinzip: Eine konservierte Größe entsteht aus
einer kontinuierlichen Symmetrie. Thematisch konsistente Texte zeigen eine
"Erhaltungsgröße" ihrer Kernbegriffe über den gesamten Text.

**Formale Definition:**

Sei $T$ ein Text. Teile $T$ in Anfangs-Drittel $T_A$ und End-Drittel $T_E$.
Sei $\mathbf{v}_A, \mathbf{v}_E \in \mathbb{R}^{|V|}$ die Worthäufigkeitsvektoren
über das gemeinsame Vokabular $V$ (Top-20-Wörter je Hälfte, Stoppwörter entfernt).

$$N(T) = \text{clamp}\!\left(2 \cdot \frac{\mathbf{v}_A \cdot \mathbf{v}_E}{\|\mathbf{v}_A\| \cdot \|\mathbf{v}_E\|},\ 0,\ 1\right)$$

**Interpretation:**
- $N = 1.0$: Anfang und Ende teilen dieselbe Themenwelt (Symmetrie erhalten)
- $N = 0.0$: Vollständiger Themenwechsel (Symmetriebruch)
- Implementierung: `_noether()` in `modules/ethics_engine.py`, Rust-Port in `modules/aether_core_rs.py`

#### 3.6.2 Interferenz-Score — Stilüberlagerung durch Negation

**Analogie:** Physikalische Interferenz — überlagerte Wellen können sich gegenseitig
verstärken oder auslöschen. Negationen im Text "überlagern" die eigentliche Aussage
und erzeugen semantische Unschärfe.

**Formale Definition:**

Sei $\delta_{\neg}$ die Negationsdichte:

$$\delta_{\neg}(T) = \frac{|\{w \in T : w \in \mathcal{N}\}|}{|T|}$$

wobei $\mathcal{N} = \{\text{nicht, kein, keine, nie, niemals, never, no, not, without, ohne, \ldots}\}$

Der Interferenz-Score ist eine stückweise lineare Funktion mit optimalem Fenster:

$$I(T) = \begin{cases}
0.50 & \delta_{\neg} < 0.01 \\
0.50 + \frac{\delta_{\neg} - 0.01}{0.01} \cdot 0.50 & 0.01 \leq \delta_{\neg} < 0.02 \\
1.00 & 0.02 \leq \delta_{\neg} \leq 0.08 \\
\max\!\left(0.20,\ 1.00 - \frac{\delta_{\neg} - 0.08}{0.07} \cdot 0.80\right) & \delta_{\neg} > 0.08
\end{cases}$$

**Interpretation:**
- $I = 1.0$: Gesunde Negationsdichte (2–8 %) — natürlicher, ausgewogener Stil
- $I < 0.3$: Extrem hohe Negationsdichte — Interferenz dominiert den Textfluss
- $I = 0.5$: Sehr wenig oder gar keine Negation — möglicherweise zu absolut

#### 3.6.3 Heisenberg-Score — Bedeutungsunschärfe durch Absolutaussagen

**Analogie:** Heisenbergs Unschärfeprinzip: Je präziser eine Aussage formuliert wird
("immer", "nie", "alle", "einzig"), desto mehr kontextuelle Unschärfe entsteht.
Extreme Absolutaussagen verringern den Informationsgehalt — sie machen keine
falsifizierbaren Aussagen mehr.

**Formale Definition:**

Sei $\delta_{\infty}$ die absolute Aussagendichte (Absolutwörter pro Satz):

$$\delta_{\infty}(T) = \frac{|\{w \in T : w \in \mathcal{A}\}|}{|\text{Sätze}(T)|}$$

wobei $\mathcal{A} = \{\text{immer, alle, alles, jeden, einzig, ausschließlich, always, never, everyone, 100\%, \ldots}\}$

Der Heisenberg-Score:

$$H(T) = \begin{cases}
0.80 & \delta_{\infty} < 0.10 \\
1.00 & 0.10 \leq \delta_{\infty} \leq 0.80 \\
\max\!\left(0.0,\ 1.00 - \frac{\delta_{\infty} - 0.80}{2.20}\right) & 0.80 < \delta_{\infty} \leq 3.0 \\
\max\!\left(0.0,\ 1.00 - \frac{\delta_{\infty} - 0.80}{0.70} \cdot 0.40\right) \cdot 0.5 & \delta_{\infty} > 3.0
\end{cases}$$

**Interpretation:**
- $H = 1.0$: Ausgewogene Absolutaussagendichte — präzise, aber falsifizierbar
- $H < 0.4$: Hochgradig absolutistische Sprache — Propaganda-Indikator
- $H = 0.8$: Kaum Absolutaussagen — neutral, sachlich

#### 3.6.4 Gesamtscore (EthicsEngine)

Der strukturelle Integritätsscore kombiniert alle sechs Metriken gewichtet:

$$E(T) = \begin{cases}
0.30 \cdot Z + 0.25 \cdot F + 0.25 \cdot N + 0.12 \cdot I + 0.08 \cdot H & \text{(Benford nicht messbar)} \\
0.25 \cdot Z + 0.15 \cdot B + 0.20 \cdot F + 0.20 \cdot N + 0.10 \cdot I + 0.10 \cdot H & \text{(Benford messbar)}
\end{cases}$$

| Symbol | Metrik | Beschreibung |
|--------|--------|--------------|
| $Z$ | Zipf | Worthäufigkeitsverteilung folgt Potenzgesetz $f \propto r^{-\alpha}$ |
| $B$ | Benford | Führungsziffernverteilung vs. $\log_{10}(1 + 1/d)$ |
| $F$ | Fraktal | Satzlängenvariation (Standardabweichung, Zielbereich 5–20) |
| $N$ | Noether | Thematische Konsistenz $\cos(\mathbf{v}_A, \mathbf{v}_E)$ |
| $I$ | Interferenz | Negationsdichte im optimalen Fenster |
| $H$ | Heisenberg | Absolute Aussagendichte, Unschärfemaß |
---

## 4. Domänenübergreifender Vergleich

### 4.1 Was Aether tut

Wenn strukturelle Fingerprints aus verschiedenen Domänen verglichen werden, beobachtet Aether Cluster. Es interpretiert sie nicht.

**Dreistufiges Modell:**

```
Stufe 1: Beobachtung    ??? Zwei Fingerprints ??hneln sich strukturell
Stufe 2: Häufung        ??? Mehrere unabh??ngige Datens??tze zeigen gleiches Cluster
Stufe 3: Hypothese      ??? Pr??fbare Vermutung für Domänenexperten
```

Aether gibt nur Stufe 1 aus. Stufe 2 entsteht durch Akkumulation im lokalen Vault oder im Aethernet-Schwarm. Stufe 3 ist Aufgabe des Nutzers.

### 4.2 Was Aether nicht tut

- StrukturÄhnlichkeit als Kausalit??t ausgeben
- Domänenübergreifende Muster als Befunde formulieren
- Unvalidierte Beobachtungen als Ergebnis darstellen (Assistant-Schutz)
- R??ckschl??sse auf den Inhalt der verglichenen Daten ziehen

### 4.3 Wann dom??nenübergreifende Vergleiche relevant werden

Erst wenn sich viele unabh??ngige strukturelle Hinweise h??ufen, entsteht ein belastbarer Hinweis:
- Genomsequenz und Klimazeitreihe zeigen denselben Periodit????ts??fingerprint ??? Einzelhinweis
- 200 unabh??ngige Genomsequenzen und 300 Klimazeitreihen zeigen dasselbe Cluster ??? prüfbare Hypothese für Domänenexperten

Das System macht diese Unterscheidung explizit: Einzelhinweise werden nicht als Befunde formuliert.

### 4.4 DBSCAN-Clustering von Konsens-Ankern

Meta-Anker (Ebene 3) werden nicht nur durch Pearson-Korrelation gebildet, sondern
zusätzlich durch DBSCAN-Clustering im Merkmalraum der Konsens-Anker.

**Feature-Raum:**

Jeder Konsens-Anker $c_i$ wird als Punkt im dreidimensionalen Raum dargestellt:

$$\mathbf{x}_i = \left(\frac{\bar{CPU}_i}{100} \cdot 50,\ \frac{\bar{RAM}_i}{1\,\text{MiB}},\ \bar{Threads}_i\right) \in \mathbb{R}^3$$

**DBSCAN-Algorithmus** (Density-Based Spatial Clustering of Applications with Noise):

Gegeben: $\varepsilon > 0$ (max. Distanz), $m_{\min}$ (Mindestpunkte im Cluster)

1. Für jeden Punkt $\mathbf{x}_i$: bestimme $\mathcal{N}_\varepsilon(\mathbf{x}_i) = \{\mathbf{x}_j : \|\mathbf{x}_i - \mathbf{x}_j\|_2 \leq \varepsilon\}$
2. $\mathbf{x}_i$ ist **Core-Point** $\Leftrightarrow |\mathcal{N}_\varepsilon(\mathbf{x}_i)| \geq m_{\min}$
3. Cluster = transitive Hülle von Core-Points (über direkte Erreichbarkeit)
4. Punkte ohne Core-Nachbar = Rauschen (Label $-1$)

**Eigenschaften:**
- Kein Training notwendig
- Beliebige Clusterformen erkennbar
- Rauschpunkte werden explizit als Rauschen markiert (kein Label erzwungen)
- Implementierung: `ProcessAnchorStore.cluster_consensus_anchors()`, `ProcessAnchorStore._dbscan()`

**Assistant-Integration:** Die Cluster werden über `AnchorQuery.describe_clusters()` als
Fließtext für Assistant bereitgestellt — ohne rohe Prozessdetails.

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
Lokal (Gerät)               Netz
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
- Option 2: Anonym (nur Anchor-Hash, keine Nutzeridentität)
- Option 3: Mit Signatur (explizite Identifikation des Erstellers)

---

## 7. Nicht-halluzinierende Architektur: Assistant

Assistant empfängt ausschließlich strukturell verifizierte Daten aus der Pipeline. Der System-Prompt verhindert Spekulation. Bei Unsicherheit wird keine Ausgabe erzeugt.

**Was das in der Praxis bedeutet:**
- Wenn `H_lambda` hoch ist (viel Restunsicherheit): Assistant schweigt oder kennzeichnet die Ausgabe entsprechend
- Wenn Rekonstruktionsbedingung `D(S_t, R_t) = X_t` nicht erfüllt: Assistant gibt keine Vollständigkeitsaussage aus
- Wenn Governance-Bedingungen brechen: Assistant gibt keine Ausgabe

---

## 8. Sicherheits- und Governance-Modell

**Interne Sicherheitsregeln:**
1. Unzulässige Zustände sind nicht bequem darstellbar
2. Kritische Zustandswechsel werden validiert
3. Standard: `deny by default`
4. Kritische Pfade: append-only, gehasht, signiert
5. Rohdaten, Snapshots, Schlüssel und Rechte strikt getrennt

**Relevante Module:**
- `modules/security_engine.py` ??? `SecurityManager`, `secure_zeroize`
- `modules/security_monitor.py` ??? Integrit??tspr??fung, Baseline-Vergleich
- `modules/session_engine.py` ??? `SessionContext`, ephemere Schlüssel

---

## 9. Entwicklungspfad: AELAB und Aether

AELAB war der erste Entwicklungsimpuls ??? ein evolutiver Pfad zur Extraktion stabiler Strukturkandidaten. Er erwies sich als zu ungebunden für den Anspruch des Systems.

Aether ist die Hauptarchitektur. AELAB ist heute ein interner Hintergrundpfad (`modules/ae_evolution_core.py`), der zusätzliche Strukturanker liefert.

---

## 10. Anwendungsbeispiele / Application Examples

### 10.1 Alte Hardware — Systemoptimierung auf schwachen Rechnern

**Szenario:** Laptop mit 2 GB RAM, 1,8 GHz Dual-Core, HDD.

**Deutsche Anleitung:**
```bash
python start.py --optimize
```
Ausgabe (Beispiel):
```
[Aether Optimierungs-Bericht]
Hardware: Intel Core2Duo 1.8GHz | 2048 MB RAM | HDD
Alter Hardware erkannt: Ja

Empfehlungen (nach Priorität):
1. [HOCH] SysMain (Superfetch) deaktivieren — HDD-Thrashing vermeiden
   Auto-anwendbar: Nein (Admin benötigt)
2. [HOCH] SearchIndexer.exe Priorität reduzieren
   Auto-anwendbar: Ja
3. [MITTEL] Windows Defender-Scans auf Idle-Zeit verschieben
4. [NIEDRIG] Aero-Effekte deaktivieren (spart ~50 MB RAM)
```

Automatische Anwendung mit Rollback:
```bash
python start.py --optimize --apply
# Für Rollback einer Aktion:
# python start.py --rollback --id=<log_id>
```

**English:** On machines with < 2 GB RAM or CPU < 2 GHz + HDD, Aether automatically
detects "old hardware" mode and prioritizes low-resource optimizations. All changes
are logged with full rollback capability via `AutopilotEngine.rollback()`.

---

### 10.2 Domänenspezifische Analyse — Genomsequenzen

**Szenario:** Analyse von 50 FASTA-Sequenzen auf strukturelle Anomalien.

```python
from modules.ethics_engine import structural_text_integrity
from modules.analysis_engine import AnalysisEngine

# Genomsequenz als Text — kein Inhalt verlässt das Gerät
result = structural_text_integrity(genome_sequence)
print(f"Entropie-Score: {result['zipf']:.3f}")
print(f"Benford-Konformität: {result['benford']:.3f}")
print(f"Thematische Konsistenz (Noether): {result['noether']:.3f}")
```

Erwartet für reguläre Exon-Sequenz: `zipf ≈ 0.7–0.9`, `benford ≈ 0.6–0.8`
Bei struktureller Anomalie: Abweichung > 2σ vom Baseline-Cluster.

**Datenschutz:** Die Sequenz bleibt lokal. Nur SHA-256-Fingerprints können
optional über Aethernet geteilt werden (consent-gebunden, nicht invertierbar).

---

### 10.3 Obfuscation-Erkennung — Code-Ethik

```python
from modules.ethics_engine import CodeEthicsEngine

engine = CodeEthicsEngine()
result = engine.analyze(suspicious_code)

print(f"Anomalie-Score: {result['anomaly_score']:.2f}")
print(f"Urteil: {result['verdict']}")   # 'clean' | 'suspicious' | 'anomalous'
print(f"Flags: {result['flags']}")
```

Erkannte Muster (ohne Signatur-Datenbank):
- **high_byte_entropy**: Verschlüsselte/gepackte Inhalte (H > 7.0 bit)
- **short_identifier_ratio**: Obfuscation durch 1-2-Zeichen-Bezeichner (> 60 %)
- **high_hex_literal_ratio**: Shellcode-Muster (\\xNN-Literale > 10 %)
- **high_base64_density**: Eingebettete Payloads (Base64-Blöcke > 5 %)
- **high_eval_exec_density**: Dynamische Code-Ausführung (> 5 % der Zeilen)
- **zipf_violation**: Obfuscation stört Zipf-Verteilung der Token

**English:** The `CodeEthicsEngine` detects structural anomalies in code without any
signature database, keyword lists, or cloud lookups. It operates purely on measurable
structural properties — byte entropy, token distribution, identifier length ratios.

---

### 10.4 Datenschutz — Widerrufbare Freigaben

```python
from modules.privacy_registry import PrivacyRegistry, GrantMode

registry = PrivacyRegistry()

# Anker registrieren (struktureller Fingerprint, kein Inhalt)
registry.register_anchor("sha256:abc123...", domain="file", meta={"size_kb": 42})

# Freigabe erteilen: nur Anker-Hash, temporär (24h)
grant_id = registry.grant_share(
    anchor_id="sha256:abc123...",
    grantee_id="device_b_token",
    mode=GrantMode.ANCHOR_ONLY,
    ttl_seconds=86400,
)

# Freigabe sofort widerrufen
registry.revoke_share(grant_id, reason="Freigabe nicht mehr benötigt")

# Status prüfen
perm = registry.check_permission("sha256:abc123...", "device_b_token")
print(perm)  # None — widerrufen
```

**Trennung Anker / Filekey:** Ein Anker-Share gibt niemals Zugriff auf den
Entschlüsselungsschlüssel. Der Filekey wird separat und nur als SHA-256-Hash
in der Registry referenziert — niemals im Klartext.

---

## 11. PrivacyRegistry und granulare Freigaben

### 11.1 Klarere Trennung: Anker vs. Filekey

```
Anker (anchor_hash)
  = SHA-256( f(entropy, freq, fractal, benford, symmetry, type, chunk_hash) )
  → Nicht invertierbar, kann geteilt werden

Filekey (key_bytes)
  = Symmetrischer AES-256-GCM-Schlüssel
  → Verlässt das Gerät NIEMALS
  → In Registry: nur key_hash = SHA-256(key_bytes) gespeichert
```

### 11.2 Widerrufbare Freigaben (Privacy Registry)

Neue `PrivacyRegistry` (`modules/privacy_registry.py`) bietet:

| Feature | Beschreibung |
|---------|--------------|
| **Granulare Modi** | `anchor_only` (nur Hash) oder `full_key` (Hash + Schlüsselzugang) |
| **TTL** | Zeitlich begrenzte Freigaben (automatisch abgelaufen) |
| **Sofort-Widerruf** | `revoke_share(grant_id)` — sofort, unwiderruflich |
| **Massen-Widerruf** | `revoke_all_for_anchor(anchor_id)` |
| **Audit-Log** | Alle Aktionen append-only geloggt |
| **Zugriffsprüfung** | `check_permission()` — deny by default |

---

## 12. Systemgrenzen und Hinweise

- **Strukturmuster sind Beobachtungen, keine Kausalaussagen.** Ähnliche Struktursignaturen in verschiedenen Domänen sind Hinweise — keine Befunde.
- **Die beobachterrelative Erweiterung (H_lambda) ist ein Arbeitsmodell**, kein etabliertes informationstheoretisches Konzept.
- **SEMS ist ein projektinterner Arbeitsbegriff**, kein anerkanntes Wissenschaftsfeld.
- **Domänenübergreifende Cluster werden nicht als Befunde ausgegeben** — erst Häufung über viele unabhängige Datensätze macht sie zu prüfbaren Hypothesen.
- **Der historische Pi-Befund (AELAB-Entwicklungsgeschichte)** ist in der aktuellen Codebasis nicht reproduzierbar belegt.
- **Kein externer Sicherheitsaudit** wurde bisher durchgeführt.

---

## 13. Schlussfolgerung

Aether misst Struktur. Es interpretiert nicht. Es misst, speichert lokal, gibt nichts preis,
was nicht explizit freigegeben wurde — und formuliert nur, was die Pipeline gemessen hat.

Aether ist ein Werkzeug für alle, die Muster in Daten finden wollen,
ohne Kontrolle über diese Daten aufzugeben. **Hilf mit, es zu bauen.**

---

Stand: März 2026 — Autor: Kevin Hannemann
