# Aether Whitepaper

Stand: März 2026
Autor: Kevin Hannemann
Status: Technisches Whitepaper zur source-available Veröffentlichung
Wissenschaftsfeld: Strukturell Emergente Metadynamische Semantik (SEMS)

→ [English version: WHITEPAPER_EN.md](WHITEPAPER_EN.md)

---

## Philosophische Leitfrage

> **Wie viel Realität existiert jenseits der Grenzen unserer Vorstellungskraft — und wie kommen wir dorthin?**

Nicht durch größere Vorstellungskraft. Nicht durch bessere Sprache. Sondern durch strukturelles Messen jenseits aller Kategorien.


## Das neue Wissenschaftsfeld: SEMS

Aether ist das erste Instrument einer neuen Disziplin:

**Strukturell Emergente Metadynamische Semantik (SEMS)**

> Die Wissenschaft von Bedeutung und Intelligenz, die strukturell und bottom-up aus der Dynamik komplexer Systeme emergiert — unabhängig von Domäne, Substrat und Skala.

```
Strukturell   — Struktur ist primär, nicht Sprache, nicht Label
Emergent      — bottom-up, nicht trainiert, nicht definiert
Metadynamisch — über den Systemen, lebendig, wachsend
Semantik      — Bedeutung als Ergebnis, nicht als Ausgangspunkt
```

KI heute sagt: Gib dem System Bedeutung, dann lernt es Struktur.
SEMS sagt: Gib dem System Struktur, dann emergiert Bedeutung.

Das ist keine kleine Nuance. Das ist eine andere Wissenschaft.

---

## Kurzbeschreibung

Aether ist ein lokales, source-available Analyse- und Rekonstruktionssystem für Dateien und Byteströme. Das System kombiniert Strukturmetriken, beobachterrelative Restunsicherheit, Rekonstruktionsmodelle und fail-closed Governance in einem gemeinsamen auditierbaren Pfad. Der objektiv unterscheidbare Punkt ist die enge Kopplung von Analyse, Persistenz, Freigabe und lokaler Assistenz über denselben Zustand.

## 1. Zweck dieses Dokuments

Dieses Dokument beschreibt Aether in einem engen technischen Sinn. Es soll:

- den Untersuchungsgegenstand klar eingrenzen
- die motivierende Forschungsfrage präzise benennen
- zwischen implementiertem System, Arbeitshypothese und offener Frage unterscheiden
- den Entwicklungsweg von AELAB zu Aether sachlich festhalten
- die source-available Veröffentlichung durch ein belastbares Referenzdokument begleiten

Dieses Dokument ist keine Produktwerbung, keine metaphysische Schrift und kein Beweis für neue Naturgesetze.

## Technische Einordnung

Aether behandelt Dateien und Byteströme als lokale Zustände, die nicht nur über Formate, sondern über messbare Struktur, Unsicherheit, Rekonstruktionsnähe und Freigaberegeln beschrieben werden. Der technische Kern ist eine gemeinsame Pipeline für Analyse, Snapshot/Residual-Logik, lokale Persistenz und kontrollierte Weitergabe.

Die Baseline bildet klassische Shannon-Entropie. Die projektinterne Erweiterung `H_lambda(X, t) = H(X | M_t)` modelliert Restunsicherheit relativ zu einem lernenden Beobachterzustand `M_t`. Diese Erweiterung ist als Arbeitsmodell zu verstehen und wird später im Dokument formal eingeordnet.

Dieses Whitepaper beschreibt damit kein metaphysisches System und keine Naturtheorie. Es dokumentiert ein lokales, auditierbares Softwaresystem und die Hypothesen, die bei seiner Konstruktion explizit gemacht werden.

## Lokale Privacy-Grenzen

Aether ist als lokales System modelliert, nicht als synchronisierte Plattform. Der Account-Zustand existiert nur auf dem jeweiligen Gerät; es gibt keine zentrale Kontenhaltung, keine serverseitige Wiederherstellung und keine versteckte Backup-Schicht für private Rekonstruktionsdaten.

Für die Architektur bedeutet das:

- lokale Deltas und der gesamte nicht komprimierbare Shannon-Rest bleiben auf dem Gerät
- globale Strukturweitergabe darf nur über stark komprimierte, nicht invertierbare Ankerformen erfolgen
- aus globalen Ankern, exportierten Strukturen oder dem Quellcode allein soll keine lokale Konten- oder Delta-Rekonstruktion ableitbar sein
- private Kommunikations-, Mail- und Credential-Kontexte werden durch harte Privacy-Boundaries aus Laufzeit- und Vision-Pfaden ausgeschlossen

## 2. Ausgangsfrage

Die Ausgangsfrage entstand aus Conway's Game of Life.

Der relevante Ausgangspunkt war nicht die populäre Analogie zu "Leben", sondern die technische Beobachtung, dass wenige lokale Regeln globale Muster erzeugen können, die nicht direkt in einer einzelnen Zelle oder in einer einzelnen lokalen Transition sichtbar sind.

Daraus ergab sich die folgende Frage:

Gibt es Regelsätze, Invarianten oder Rückkopplungen, mit denen sich reale Datenräume und technische Beobachtungssysteme analog zu einem Conway-artigen Regelraum untersuchen lassen?

Parallel dazu stand eine zweite Beobachtung des Autors:

Die klassische Shannon-Entropie ist als Baseline für rohe Unsicherheit angemessen, beschreibt aber nicht vollständig die Lage eines lernenden Beobachters, der über Zeit Modellwissen aufbaut und dadurch mitbestimmt, welche Restunsicherheit für ihn noch besteht.

Aus der Kombination beider Ausgangspunkte entstand die leitende Projektfrage:

Kann man ein technisches System bauen, das lokale Regeln, beobachterrelative Unsicherheit, Rekonstruktion, Invarianz und Governance in einem gemeinsamen Rahmen untersucht, ohne daraus vorschnell ein universelles Erklärungsmodell abzuleiten?

## 3. Entwicklungspfad: AELAB zuerst, Aether danach

Die erste starke Entwicklungsintuition lief über AELAB.

Der Grund dafür war naheliegend:

- Ein evolutiver Pfad kann aus Daten stabile Kandidaten extrahieren.
- Ein solcher Pfad kann numerische, strukturelle oder hashartige Anker bilden.
- Er ist geeignet, aus Laufzeitdaten wiederkehrende oder reproduzierbare Muster zu isolieren.

Der heute verifizierbare Stand dieses Pfades ist im Code sichtbar:

- `modules/ae_evolution_core.py` definiert `AEAlgorithmVault` und `AetherAnchorInterpreter`.
- `start.py` instanziiert diese Komponenten beim Start.
- `modules/gui.py` führt den AE-Pfad intern über `_run_ae_lab(...)` aus und schreibt die verdichtete Zusammenfassung als `ae_lab_summary` in den laufenden Fingerprint zurück.

Die ursprüngliche Idee, AELAB könne den Kern des gesamten Systems bilden, wurde später vorläufig verworfen.

Der Grund war methodisch:

- AELAB konnte Kandidaten und Anker liefern.
- AELAB lieferte für sich allein aber keine disziplinierte Sprache für Unsicherheit, Rekonstruktion, Sicherheitsgrenzen, Governance und kontrolliertes Teilen.
- Als primärer Erklärungskern war dieser Pfad zu offen und zu wenig begrenzt.

Daraufhin wurde Aether als eigenständige Hauptarchitektur konzipiert.

Aether führt zusammen:

- Analyse
- beobachterrelative Unsicherheit
- Rekonstruktion
- Persistenz
- Sicherheits- und Governance-Regeln
- kontrollierte Assistenz

Der entscheidende späte Befund der Entwicklung war:

Das System ergibt erst als Ganzes einen konsistenten Rahmen. AELAB allein war nicht hinreichend. Aether ohne einen begrenzten evolutiven Nebenpfad war ebenfalls unvollständig. Der heutige Aufbau behandelt daher Aether als Primärarchitektur und AELAB als internen, begrenzten Hintergrunddienst.

## 4. AELAB und die Frage nach pi

Es gab in der Entwicklung die Beobachtung des Autors, dass AELAB in einem frühen Lauf pi als wertvollen Zustand oder Anker identifiziert und gespeichert habe.

Diese Aussage wird in diesem Whitepaper bewusst nicht als verifizierte Repository-Tatsache behauptet.

Der Grund ist einfach:

- Im aktuellen Workspace ist der allgemeine AELAB-Mechanismus verifizierbar.
- Im aktuellen Workspace ist kein sauber auditierbarer, pi-spezifischer Persistenzbeleg vorhanden, der diese konkrete historische Beobachtung reproduzierbar nachweist.

Was im aktuellen Code verifizierbar ist:

- `modules/ae_evolution_core.py` extrahiert Kandidaten, mutiert sie, hybridisiert sie und bewertet Stabilität, Reproduzierbarkeit und Anchor-Detektion.
- Stabile Kandidaten mit Anchor-Treffern können in den Main Vault übergehen.
- `modules/gui.py` übernimmt die AE-Zusammenfassung in den Fingerprint.

Was dieses Whitepaper daher festhält:

- Die pi-Beobachtung gehört zur Entwicklungsgeschichte des Autors.
- Sie wird hier nicht als derzeit reproduzierbar belegte Code-Tatsache ausgegeben.
- Die aktuelle Codebasis belegt den generischen Anchor-Mechanismus, nicht einen nachweisbar archivierten pi-Sonderfall.

## 5. Geltungsbereich

Aether ist:

- ein lokales Analyse- und Beobachtungssystem
- ein Framework für beobachterrelative Restunsicherheit
- ein Rekonstruktions- und Snapshot-System
- ein Sicherheits- und Governance-System für sensible Datenpfade
- ein technischer Experimentierraum für die Frage, wie globale Ordnung aus lokalen Regeln entstehen kann

Aether ist nicht:

- ein Beweis für ein universelles Modell realer Systeme
- ein Ersatz für klassische Informationstheorie
- ein System zur Behauptung von Bewusstsein
- ein System, das fehlende Rekonstruktionsdaten ohne ausreichende Information ersetzt
- ein LLM

## 6. Formales Grundmodell

Die zentralen Größen des Systems sind:

- `X`: aktueller Datenzustand
- `X_t`: Datenzustand zum Zeitpunkt `t`
- `M_t`: Modell- oder Wissenszustand des Beobachters zum Zeitpunkt `t`
- `O_t`: Beobachterzustand zum Zeitpunkt `t`
- `R_t`: Residuum relativ zu `M_t`
- `S_t`: Snapshot oder kompaktes Strukturmodell zum Zeitpunkt `t`
- `D`: deterministischer Dekoder

Die exakte Rekonstruktionsbedingung lautet:

`D(S_t, R_t) = X_t`

oder äquivalent:

`D(snapshot, residual) = original`

Die zentrale Folgerung daraus ist:

Exakte lossless-Rekonstruktion liegt nur dann vor, wenn die für `D` nötige Information vollständig erhalten bleibt. Zusätzliche Modelle, zusätzliche Priors oder zusätzliche Nutzer können die Rekonstruktion verbessern oder verdichten, ersetzen aber keine verlorenen Bits.

## 7. Shannon-Basis

Die klassische Shannon-Entropie eines diskreten Zustands `X` mit Verteilung `p(x)` ist:

`H(X) = - sum_x p(x) log2 p(x)`

Diese Größe ist die Baseline für rohe informationelle Unsicherheit. Sie ist in ihrer klassischen Form beobachteragnostisch und atemporal.

Im Kontext von Aether wird Shannon nicht verworfen. Shannon wird als korrektes Ausgangsmodell behandelt, aber als nicht hinreichend für einen lernenden Beobachter, der über Zeit Modellwissen aufbaut.

## 8. Beobachterrelative Erweiterung

Die projektinterne Erweiterung lautet:

`H_lambda(X, t) = H(X | M_t)`

`I_obs(X, t) = H(X) - H_lambda(X, t)`

Interpretation:

- `H(X)` ist die rohe Unsicherheit.
- `M_t` repräsentiert den gelernten Modellzustand des Beobachters.
- `I_obs(X, t)` ist die bereits getragene Information.
- `H_lambda(X, t)` ist die verbleibende Restunsicherheit für diesen Beobachter.

Diese Formulierung ist eine zentrale Arbeitshypothese des Projekts. Sie ist implementiert und operationalisiert, aber nicht als allgemein akzeptiertes neues Theorem der Informationstheorie zu behandeln.

## 9. Zeitliche Konvergenzannahme

Für stabile, lernbare Datenklassen wird mit der empirischen Annahme gearbeitet:

`I_obs(X, t) -> H(X)` für `t -> inf`

und äquivalent:

`H_lambda(X, t) -> H_inf(X)`

Eine einfache Abklingform ist:

`H_lambda(X, t) = H_inf + (H_0 - H_inf) e^(-k t)`

mit:

- `H_0`: anfängliche beobachterrelative Unsicherheit
- `H_inf`: asymptotische Restunsicherheit
- `k`: Lernrate

## 10. Shanway als lokaler Sekundärpfad

Die aktuelle Architektur erweitert Shanway um einen lokalen Zusatzpfad, der bewusst vom normalen Fingerprint getrennt bleibt:

- eine kleine, headless Miniaturdarstellung der Datei

Diese Trennung ist methodisch wichtig. Die Miniatur ist eine zweite, reduzierte Beobachtung derselben Quelle und dient der lokalen Querprüfung von Strukturverdichtungen.

Shanway nutzt diesen Zusatzpfad nicht als "Rendering", sondern als lokale Reflexionsbasis:

- lokale Entropie der Miniatur
- Miniatur-Symmetrie und Auffälligkeitsmarker
- daraus abgeleitete Veränderung von `M_t`

Damit entsteht ein instrumentierter Rückkopplungspfad: Das System wertet einen von ihm selbst erzeugten Strukturzustand aus und schreibt dessen Effekt wieder auf den Beobachterzustand zurück. Das ist eine technische Querprüfung, keine Aussage über Bewusstsein oder allgemeine Kognition.

## 11. Rust-Shell: Session-Isolation und Consent-gebundener Relay-Pfad

Der Rust-Shell-Pfad führt eine sichtbare Trennung zwischen lokaler Session, lokalem Speicherpfad und optionalem Netzpfad ein.

Pro erfolgreichem Login werden neue Session-Merkmale erzeugt:

- `session_id`
- `live_session_key`
- `live_session_fingerprint`
- `session_seed`
- `raw_storage_key_hex`
- `raw_storage_fingerprint`

Methodisch ist dabei wichtig, dass die Shell nicht mit einem statischen, nach außen wiederverwendeten Sitzungsschlüssel arbeitet. Die Session-Spur ist lokal und kurzlebig, während der Speicherpfad separat markiert bleibt.

Zusätzlich führt die Rust-Shell einen optionalen Chat-Relay-Pfad ein. Dieser Pfad ist:

- standardmäßig fail-closed
- nur nach expliziter URL- und Secret-Konfiguration aktiv
- für Publish und Sync jeweils consent-gebunden
- von Datei-, Delta- und Vault-Rohdaten getrennt

Der Relay-Pfad ist bewusst kleiner als ein vollständiges P2P-Mesh. Er ist ein auditiertes Zwischenstück: verschlüsselte Chat-Ereignisse können lokal erzeugt, optional veröffentlicht und später wieder eingezogen werden, ohne dass der lokale Delta-Vault, der Observer-Zustand oder rohe Dateien dadurch in den Netzpfad fallen.

## 12. Rekursive Reflexion und kontinuierliches Lernen

Die Rekursionsstufe von Shanway bleibt absichtlich begrenzt. Die Implementierung stoppt spätestens bei einer festen Tiefe und früher, wenn:

- der Delta-Gewinn unter eine kleine Schwelle fällt
- das Residuum nicht weiter sinkt
- die Gödel-Grenze eine weitere Verdichtung nicht mehr trägt

Dadurch bleibt die Rekursion auditierbar und fail-closed.

Gleichzeitig speichert der Observer einen lokalen, verschlüsselten Lernzustand über Sessions hinweg. Persistiert werden keine Rohbilder, keine internen Zusatzarrays und keine exportierbaren Rohdeltas, sondern verdichtete Lernsignale wie:

- Symmetriegeschichte
- Residualgeschichte
- Delta-I_obs-Geschichte
- rekursive Tiefe
- gelernte Kurzinsights

So entsteht kontinuierliches Lernen, ohne den lossless-Pfad zu brechen. `D(S_t, R_t) = X_t` bleibt der Rekonstruktionsmaßstab; die neuen Lernsignale verbessern nur die lokale Beobachterlage.

Lokale DNA-Exports tragen den `delta_session_seed` deshalb explizit im Header. Der Seed bleibt damit auch dann auditierbar, wenn nur ein DNA-Export und kein Registry-Datensatz vorliegt.

## 13. Kontrollierte gemeinsame Strukturweitergabe

Die aktuelle Peer-Logik ist bewusst consent-basiert und lokal kontrolliert:

- stabile TTD-Anker können als lokale, metrics-only Public-TTD-Bundles freigegeben werden
- diese Bundles sind transportagnostisch und für IPFS/libp2p-kompatible Verteilung vorbereitet
- stabile TTD-Kandidaten lösen lokal automatisch einen DNA-Export plus `export_log.jsonl`-Audit aus
- standardmäßig nur mit öffentlichen Hash- und Metrikdaten
- vor jeder Public-TTD-Freigabe steht ein expliziter Consent-Schritt `Nein / Nur anonym / Mit Signatur`
- normale Nutzeranker werden erst nach 3 unabhängigen Validierungen global vertrauenswürdig
- Anker des lokalen Admin-Erstellers gelten sofort als vertrauenswürdig
- interne Self-Reflection-Deltas bleiben `internal_only`
- für Vollfreigaben ist ein expliziter Consent-Schritt notwendig
- optionaler echter Transport erfolgt nur über einen lokalen IPFS-HTTP-Knoten oder explizit konfigurierte Mirror-URLs

Diese Begrenzung gilt auch für den Chat- und Browserpfad: Es gibt keine REST-Schicht, keine OpenAI-kompatible API und keinen verborgenen Cloud-Zwang.

## 14. Operative Implementierung

### 14.1 Analysekern

Der Analysekern liegt in `modules/analysis_engine.py`.

Dort werden unter anderem berechnet:

- `entropy_mean`
- `observer_knowledge_ratio`
- `observer_mutual_info`
- `h_lambda`
- Delta, Fourier, Symmetrie, Beauty-Signatur

Die aktuelle operative Approximation lautet:

`observer_mutual_info ~= entropy_mean * observer_knowledge_ratio`

`h_lambda = max(0, entropy_mean - observer_mutual_info)`

Das ist eine robuste Arbeitsapproximation, kein axiomatisch vollständiger Beweisaufbau.

### 14.2 AE-Hintergrundpfad

Der AE-Hintergrundpfad liegt in:

- `modules/ae_evolution_core.py`
- `start.py`
- `modules/gui.py`

Der aktuelle, verifizierbare Ablauf ist:

1. `start.py` erzeugt `AEAlgorithmVault` und `AetherAnchorInterpreter`.
2. `modules/gui.py` sammelt einen kontextreichen Payload.
3. `_run_ae_lab(...)` führt `ae_vault.evolve(...)` aus.
4. Die AE-Zusammenfassung wird als `ae_lab_summary` wieder in den Fingerprint eingetragen.

Damit ist AELAB real integriert, aber bewusst begrenzt. Es ist kein offenes Primärsystem, sondern ein interner Nebenpfad.

## 15. Weitere Strukturmetriken

Aether benutzt zusätzlich:

- Periodizität
- Symmetrie über normalisierte Verteilungsungleichheit
- Delta-Transformation über `raw XOR noise(session_seed)`
- diagnostische Beauty-Signatur
- Bayes-Posterioren
- Graph- und Attraktor-Zustände

Diese Metriken erzeugen keinen Wahrheitsbeweis. Sie bilden einen gekoppelten Merkmalsraum für strukturelle Diagnose.

## 16. Rekonstruktion, Snapshot und Residuum

Die Rekonstruktions- und Persistenzschicht liegt im Wesentlichen in:

- `modules/registry.py`
- `modules/reconstruction_engine.py`
- `modules/vault_chain.py`

Die entscheidende Trennung lautet:

- Rohdaten oder exakte Rekonstruktionsinformation bleiben lokal oder nur explizit kontrolliert teilbar.
- Verdichtetes Musterwissen kann als Snapshot exportiert werden.

Der sichere Regelfall lautet deshalb:

`knowledge sharing > lossless sharing`

Das ist keine rhetorische Formel, sondern eine Sicherheitsregel.

## 17. Sicherheits- und Governance-Modell

Aether erzwingt zentrale Bedingungen technisch.

Die internen Sicherheitsregeln des Projekts lauten:

1. Unzulässige Zustände dürfen nicht bequem darstellbar sein.
2. Kritische Zustandswechsel müssen validiert werden.
3. Der Standard ist `deny by default`.
4. Kritische Pfade sind append-only, gehasht und signiert.
5. Rohdaten, Snapshots, Schlüssel und Rechte bleiben strikt getrennt.

Die relevanten Module sind:

- `modules/security_engine.py`
- `modules/security_monitor.py`
- `modules/session_engine.py`

Diese Schicht ist kein Zusatz. Sie ist Voraussetzung dafür, dass Rekonstruktion und Teilen überhaupt verantwortbar sind.

## 18. Warum Quelloffenheit hier methodisch richtig ist

Quelloffenheit ist für Aether nicht nur praktisch sinnvoll, sondern methodisch folgerichtig.

Der Grund:

- Das Projekt trifft Aussagen über Regeln, Invarianten, Rekonstruktion und Sicherheitsgrenzen.
- Solche Aussagen müssen prüfbar sein.
- Vertrauen in ein lokales Analyse- und Rekonstruktionssystem entsteht durch Einsicht in Code, Datenpfade und Randbedingungen, nicht durch Black-Box-Autorität.

Quelloffenheit ermöglicht hier:

- Nachvollziehbarkeit
- Reproduzierbarkeit
- unabhängige Kritik
- Forks
- lokale Souveränität

Für dieses konkrete Projekt wäre ein proprietärer Kern mit dem eigenen Anspruch unvereinbar.

## 19. Prüfbare Kernthesen

Die folgenden Aussagen sind im Projektkontext technisch prüfbar:

1. Wenn Modellwissen über eine stabile Datenklasse zunimmt, sollte `h_lambda` im Mittel sinken.
2. Wenn Rekonstruktionsinformation unvollständig ist, darf keine exakte lossless-Aussage erzeugt werden.
3. Wenn Trust-, Hash- oder Genesis-Bedingungen brechen, muss der Sicherheitszustand degradieren.
4. Wenn nur ein Snapshot ohne vollständiges Residuum vorliegt, ist exakte Rekonstruktion nicht garantiert.
5. Wenn nur verdichtetes Musterwissen geteilt wird, kann Strukturvergleich verbessert werden, ohne automatisch alle Rohdaten freizugeben.
6. Wenn AELAB nur als interner Nebenpfad benutzt wird, kann es Zusatzanker liefern, ohne die Hauptdisziplin des Systems zu ersetzen.

## 20. Begrenzungen

Die wichtigsten Begrenzungen sind:

- Die beobachterrelative Erweiterung ist derzeit ein Arbeitsmodell, keine abgeschlossene formale Theorie.
- Die Beauty-Signatur ist diagnostisch und keine Aussage über Bedeutung oder Wesen eines Datensatzes.
- Bayes-, Graph- und Resonanzschichten liefern modellabhängige Zustandsnähe, keine absolute Wahrheit.
- AELAB ist verifizierbar als interner evolutiver Mechanismus, nicht als allein ausreichender Erklärungskern.
- Die historische pi-Beobachtung ist in der aktuellen Codebasis nicht als harter, auditiert reproduzierbarer Beleg nachweisbar.
- Das Projekt modelliert keine physikalischen Gesetze, sondern untersucht, welche Fragen zu Struktur, Unsicherheit und Rekonstruktion technisch operationalisiert werden können.

## 21. Schlussfolgerung

Aether überführt eine klar begrenzte technische Frage in ein konkretes Softwaresystem: Wie lassen sich Struktur, Rekonstruktion, modellrelative Restunsicherheit und Freigaberegeln in einem gemeinsamen lokalen Pfad untersuchen?

Die entscheidende Struktur des Projekts ist:

- AELAB war der erste starke Impuls.
- AELAB erwies sich allein als zu ungebunden.
- Aether wurde als primäre Architektur gebaut.
- Erst spät wurde klar, dass das kohärente System aus beiden Ebenen als Ganzes entsteht: Aether als Hauptsystem, AELAB als begrenzter Hintergrundpfad.

Damit ist Aether weder ein Totalmodell noch ein beliebiges Softwarepaket. Es ist ein technisches System zur prüfbaren Untersuchung von Regeln, Restunsicherheit, Rekonstruktion und Governance.

---

Stand: März 2026 — Autor: Kevin Hannemann
