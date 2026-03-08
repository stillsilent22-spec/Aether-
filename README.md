# Aether

Autor und Stand: Kevin Hannemann, 08.03.2026

## Lizenzstatus

Dieses Repository ist fuer oeffentliche Einsicht, Audit, Forschung und nicht-kommerzielle Zusammenarbeit gedacht.

Der aktuelle Lizenzstatus ist source-available und nicht-kommerziell. Er ist bewusst **nicht** als OSI-konforme Open-Source-Lizenz formuliert. Details stehen in [LICENSE](LICENSE) und [SECURITY.md](SECURITY.md).

## Abstract

Aether ist ein lokales System zur strukturellen Analyse, Rekonstruktion, Beobachtung und Darstellung von Datenstroemen. Der methodische Ursprung des Projekts liegt in der Frage, die sich aus Conways Game of Life ergibt: Wenn wenige lokale Regeln globale Muster erzeugen koennen, die nicht trivial vorhersagbar sind, wie weit laesst sich dieses Prinzip auf Information, Beobachtung, Rekonstruktion und Systemgestaltung uebertragen?

Dieses Projekt behauptet nicht, eine neue Physik bewiesen zu haben. Es ist ein technisches Oekosystem, das lokale Metriken, Invarianten, beobachterrelative Unsicherheit, Rekonstruktionspfade, Bayes-Posterioren, Graphstrukturen und Governance-Regeln in einem gemeinsamen Rahmen zusammenfuehrt.

## Ausgangsfrage

Conways Game of Life war die Ausgangsinspiration dieses Projekts. Die Faszination bestand nicht primaer darin, dass das Spiel "wie Leben aussieht", sondern darin, dass drei lokale Regeln globale Muster hervorbringen, die weder offensichtlich noch direkt im Muster selbst eincodiert erscheinen.

Die daraus entstandene Leitfrage lautet:

Wenn einfache lokale Regeln ausreichen, um komplexe, teilweise unerwartete globale Formen zu erzeugen, welche minimalen Regeln, Invarianten und Rueckkopplungen beschreiben dann reale Datenraeume, Beobachterprozesse und Rekonstruktionspfade?

Diese Frage ist in Aether keine metaphysische Behauptung, sondern ein methodischer Ausgangspunkt.

## Ziel des Projekts

Ziel von Aether ist nicht die automatische Erzeugung von "Bedeutung", sondern die Untersuchung von:

- lokaler Struktur
- Erhaltung und Invarianz
- Invarianzbruch
- beobachterrelativer Restunsicherheit
- Rekonstruktionsbedingungen
- Governance und Verantwortung

Die Grundannahme ist:

Komplexe Semantik kann nicht sinnvoll untersucht werden, wenn ihre strukturellen, dynamischen und beobachterabhaengigen Voraussetzungen ignoriert werden.

## Was Aether ist und was nicht

Aether ist:

- ein lokales Analyse- und Beobachtungssystem
- ein Framework fuer beobachterrelative Information
- ein Rekonstruktions- und Snapshot-System
- ein Sicherheits- und Governance-System fuer sensible Datenpfade
- ein Experimentierraum fuer die Frage, wie lokale Regeln globale Ordnung erzeugen

Aether ist nicht:

- ein Beweis fuer eine universelle Zellautomaten-Theorie der Welt
- ein Ersatz fuer klassische Informationstheorie
- ein Beweis fuer Bewusstsein in Maschinen
- ein System, das verlorene Information magisch zurueckholt
- ein LLM

## Formale Grundgroessen

Die wichtigsten Groessen im System sind:

- `X`: der aktuelle Datenzustand
- `X_t`: ein Datenzustand zu Zeitpunkt `t`
- `M_t`: der Modell- oder Wissenszustand des Beobachters zu Zeitpunkt `t`
- `R_t`: ein Residuum relativ zu `M_t`
- `O_t`: der Beobachterzustand zu Zeitpunkt `t`
- `D`: ein deterministischer Dekoder

Lossless-Rekonstruktion liegt genau dann vor, wenn ein Dekoder existiert, so dass:

`D(M_t, R_t) = X`

oder aequivalent:

`D(snapshot, residual) = original`

Ohne vollstaendige Rekonstruktionsinformation ist keine echte lossless-Rekonstruktion moeglich.

## Klassische Shannon-Basis

Die klassische Shannon-Entropie eines diskreten Zustands `X` mit Verteilung `p(x)` ist:

`H(X) = - sum_x p(x) log2 p(x)`

Diese Groesse ist in ihrer klassischen Form bewusst beobachteragnostisch. Sie beschreibt die Unsicherheit eines Zufallsobjekts relativ zu einer Verteilung, nicht relativ zu einem lernenden individuellen Beobachter mit Historie, Modellreife und Zeitentwicklung.

Wichtig:

Shannon ist deshalb nicht "falsch" oder "naiv" im pejorativen Sinn. Shannon ist die korrekte Baseline fuer rohe informationelle Unsicherheit. Im Kontext von Aether ist Shannon aber absichtlich unvollstaendig, weil Aether zusaetzlich modelliert, dass Beobachter nicht statisch sind, sondern ueber Zeit lernen.

## Die projektinterne Erweiterung von Shannon

Die zentrale theoretische Ergaenzung dieses Projekts ist die Hypothese, dass fuer reale technische Beobachtungssysteme nicht nur `H(X)`, sondern die beobachterrelative Restunsicherheit relevant ist.

Die projektinterne Erweiterung lautet daher:

`H_lambda(X, t) = H(X | M_t)`

also:

Die relevante Restunsicherheit eines Zustands `X` ist die Unsicherheit von `X` relativ zum aktuell gelernten Modellzustand `M_t`.

Daraus folgt als projektinterne beobachterrelative Informationsgroesse:

`I_obs(X, t) = H(X) - H(X | M_t)`

also:

`I_obs(X, t) = H(X) - H_lambda(X, t)`

Interpretation:

- `H(X)` bleibt die rohe Unsicherheit des Datenzustands.
- `I_obs(X, t)` ist die Information, die der Beobachter zu Zeitpunkt `t` bereits ueber `X` traegt.
- `H_lambda(X, t)` ist die verbleibende Luecke.

### Wichtige Praezisierung

Diese Erweiterung ist eine projektinterne Arbeits- und Modellhypothese. Sie ist in Aether implementiert und experimentell operationalisiert, aber nicht als allgemein akzeptiertes neues Theorem der Informationstheorie zu behandeln.

## Zeit und asymptotische Annaeherung

Der lernende Beobachter fuehrt eine zeitliche Komponente ein. Aether arbeitet mit der empirischen Hypothese, dass in stabil lernbaren Datenklassen die beobachtergetragene Information asymptotisch zunimmt und die Restunsicherheit sinkt.

Projektinterne Konvergenzannahme:

`I_obs(X, t) -> H(X)` fuer `t -> inf`

und aequivalent:

`H_lambda(X, t) -> H_inf(X)`

wobei `H_inf(X)` fuer vollstaendig modellierbare Klassen gegen `0` gehen kann und fuer irreduzible Unsicherheit positiv bleibt.

Wenn die empirische Annaeherung nicht linear, sondern abklingend verlaeuft, ist eine sinnvolle Hypothese:

`H_lambda(X, t) = H_inf + (H_0 - H_inf) e^(-k t)`

mit:

- `H_0`: anfaengliche beobachterrelative Unsicherheit
- `H_inf`: asymptotische Restunsicherheit
- `k`: Lernrate des Modells

Praezise gesagt naehert sich hier nicht "Shannon selbst" an irgendetwas an. Vielmehr naehert sich die beobachtergetragene Information `I_obs(X, t)` der Shannon-Grenze `H(X)` an, waehrend `H_lambda(X, t)` asymptotisch abnimmt.

## Implementierte Operationalisierung in Aether

Im aktuellen Code wird die obige Idee nicht in voller theoretischer Strenge, sondern als robuste Approximation umgesetzt.

In [analysis_engine.py](modules/analysis_engine.py) werden dazu berechnet:

- `entropy_mean` als rohe Unsicherheitsnahe
- `observer_knowledge_ratio` als normierte Wissensnahe des Beobachters
- `observer_mutual_info` als angenaeherte gewonnene Information
- `h_lambda` als verbleibende Restunsicherheit

Die aktuelle Systemnahe lautet:

`observer_mutual_info ~= entropy_mean * observer_knowledge_ratio`

`h_lambda = max(0, entropy_mean - observer_mutual_info)`

Diese Approximation ist bewusst einfach und operational, nicht axiomatisch vollstaendig.

## Weitere implementierte Strukturmetriken

Neben Shannon und `H_lambda` nutzt Aether weitere Metriken:

### 1. Periodizitaet

Periodizitaet wird ueber wiederkehrende lokale Musterabstaende geschaetzt.

### 2. Symmetrie

Symmetrie wird ueber einen normalisierten Gini-Ansatz der Byteverteilung beschrieben:

`symmetry = 100 * (1 - G / G_max)`

mit:

- `G`: Gini-Koeffizient der Verteilung
- `G_max`: maximal moeglicher Gini fuer die betrachtete Dimension

### 3. Delta-Modell

Der datenabhaengige Delta-Pfad lautet:

`delta = raw XOR noise(session_seed)`

und die resultierende Kompressionsnahe:

`delta_ratio = |zlib(delta)| / |raw|`

### 4. Beauty-Signatur

Die Beauty-Signatur ist eine diagnostische Mehrkomponentenmetrik aus:

- `alpha_1f`
- `lyapunov`
- `mandelbrot_d`
- `kolmogorov_k`
- `benford_b`
- `zipf_z`
- `symmetry_phi`

Sie ist keine Aesthetik im subjektiven Sinn, sondern ein strukturierender Merkmalsraum.

### 5. Bayes- und Graph-Schicht

Aether baut zusaetzlich:

- Bayes-Posterioren fuer Prior, Phase, Alarm und Muster
- Graph-/Attraktor-Zustaende fuer lokale und globale Strukturstabilitaet

Diese Schichten erweitern die Analyse von "statistischem Zustand" zu "dynamischem Zustand".

## Architektur des Oekosystems

Das Oekosystem besteht aus mehreren Schichten:

### 1. Analysekern

Der Analysekern verarbeitet Dateien, Byte-Stroeme, Browser-HTML und Voxel-Daten und erzeugt AetherFingerprints.

Wesentliche Datei:

- [analysis_engine.py](modules/analysis_engine.py)

### 2. Ethik- und Integritaetsschicht

Die Ethik-Schicht ist keine moralphilosophische Instanz, sondern eine Integritaetslogik fuer:

- Symmetrie
- Kohaerenz
- Resonanz
- Spannungs- und Anomaliezustaende

Wesentliche Datei:

- [ethics_engine.py](modules/ethics_engine.py)

### 3. Beobachter-, Bayes- und Graph-Schicht

Diese Schichten modellieren:

- Priors
- Attraktoren
- Phasenwechsel
- Beobachterwissen
- Alarmkonfidenz

Wesentliche Dateien:

- [observer_engine.py](modules/observer_engine.py)
- [bayes_engine.py](modules/bayes_engine.py)
- [graph_engine.py](modules/graph_engine.py)

### 4. Rekonstruktion und Persistenz

Diese Schicht verwaltet:

- Registry
- Historie
- Vault
- Chain
- Snapshots
- Rekonstruktion

Wesentliche Dateien:

- [registry.py](modules/registry.py)
- [reconstruction_engine.py](modules/reconstruction_engine.py)
- [vault_chain.py](modules/vault_chain.py)

### 5. Sicherheits- und Governance-Schicht

Diese Schicht erzwingt die innere Systemphysik:

- unzulaessige Zustaende nicht darstellbar
- zentrale Validierung
- deny by default
- append-only fuer kritische Pfade
- Hash- und Signaturpflicht
- strikte Trennung von Rohdaten, Snapshots, Schluesseln und Rechten

Wesentliche Dateien:

- [security_engine.py](modules/security_engine.py)
- [security_monitor.py](modules/security_monitor.py)

### 6. Darstellung

Aether kann denselben Zustand multimodal darstellen:

- 3D/4D-Raumzeitfeld
- synchrone Audio-/Visual-Rueckkopplung
- Browser-Analyse
- Chat- und Statusoberflaeche

Wesentliche Dateien:

- [spacetime_renderer.py](modules/spacetime_renderer.py)
- [audio_engine.py](modules/audio_engine.py)
- [gui.py](modules/gui.py)

## Aether und Shanway

Aether und Shanway sind nicht dasselbe.

Aether ist das Gesamtsystem:

- Analyse
- Beobachtung
- Bayes
- Graph
- Persistenz
- Rekonstruktion
- Sicherheit
- Snapshot-Logik

Shanway ist die lokale Assistenzschicht ueber diesem System.

Praezise:

- Shanway ist kein LLM.
- Shanway ist kein autonomes Weltmodell.
- Shanway ist eine lokale Antwort- und Verdichtungsschicht, die auf den bereits berechneten Aether-Zustaenden arbeitet.

Shanway verhaelt sich zu Aether wie eine interpretierende Oberflaeche zu einem tieferen Mess- und Regelsystem.

## Ethik, KI und Verantwortung

Das zentrale Problem dieses Projekts mit Bezug auf Ethik und KI ist nicht die Frage, ob eine Maschine "gut" sein kann. Das waere fuer dieses Oekosystem zu unscharf.

Die praezisere Frage lautet:

Wie verhindert man, dass ein technisches System Strukturen behauptet, Rekonstruktionen verspricht, Daten teilt oder Entscheidungen trifft, fuer die es keine ausreichende Rechtfertigung, keine Auditierbarkeit und keine Verantwortungszuordnung gibt?

Darauf antwortet Aether mit mehreren Prinzipien:

- Keine unkontrollierten lossless-Behauptungen
- Kein Teilen sensibler Daten ohne explizite Governance
- Keine Verwechslung von Musterwissen und Originalwahrheit
- Keine stillen privilegierten Uebergaenge
- Keine Sicherheitslogik, die heuristischen oder evolutiven Modulen ueberlassen wird

Verantwortungsbewusstsein bedeutet hier:

- Nachvollziehbarkeit vor Eindruck
- Audit vor Behauptung
- Freigabe vor Export
- deterministische Sicherheitslogik vor kreativer Heuristik
- menschliche Verantwortung fuer kritische Freigaben

## Innere Systemphysik

Wenn Aether als geschlossenes Oekosystem funktionieren soll, braucht es eigene harte Regeln. Diese Regeln sind keine Behauptung ueber die Aussenwelt, sondern interne Erhaltungssaetze des Systems.

Sie lauten:

- Unzulaessige Zustaende duerfen im Datenmodell gar nicht darstellbar sein.
- Jede Zustandsaenderung muss durch einen zentralen Validator.
- Standard ist immer `deny by default`.
- Alles Kritische ist append-only, gehasht und signiert.
- Rohdaten, Pattern-Snapshots, Schluessel und Freigaberechte bleiben strikt getrennt.

Das ist die systeminterne Form dessen, was in physikalischer Sprache Invarianz, Erhaltung und unzulaessiger Uebergang heissen wuerde.

## Lossless, Sicherheit und Datenschutz

Lossless ist nur dann real, wenn die Rekonstruktionsinformation vollstaendig vorliegt. Ohne Modell plus Residuum oder Original plus Dekoder gibt es keine exakte Wiederherstellung.

Deshalb gilt:

- Pattern-Snapshots sind nicht automatisch lossless.
- Bayes-Posterioren sind nicht automatisch Wahrheitsgarantien.
- Ein starker Graph- oder Attraktorzustand ist nicht automatisch ein exakter Rekonstruktionspfad.

Wenn Daten fuer andere lossless zugaenglich gemacht werden, entstehen gleichzeitig:

- Sicherheitsrisiken
- Datenschutzrisiken
- Verantwortungsfragen

Der sichere Regelfall ist daher:

`knowledge sharing > lossless sharing`

also:

verdichtetes Strukturwissen teilen, aber nicht standardmaessig die vollstaendige Rekonstruktionsinformation.

## Open Source

Open Source gehoert zu diesem Projekt nicht nur aus praktischen Gruenden, sondern aus einem erkenntnistheoretischen und politischen Grundsatz.

Wenn das Projekt sich mit Regeln, Beobachtung, Struktur, Rekonstruktion und Macht ueber Information beschaeftigt, dann waere ein proprietaeres Black-Box-Modell mit diesem Anspruch unvereinbar.

Open Source bedeutet hier:

- Regeln bleiben sichtbar.
- Modelle bleiben kritisierbar.
- Ableitungen bleiben pruefbar.
- Technik wird nicht nur verteilt, sondern verstehbar.

Die grundlegende Haltung dahinter ist die Demokratisierung von Wissen und Technik.

### Warum Open Source fuer Aether genau richtig ist

Open Source ist fuer dieses Programm nicht nur eine Verteilungsform, sondern die technisch richtige Form.

Der Grund ist einfach:

- Aether arbeitet mit Regeln, Invarianten, Rekonstruktionspfaden, Priors, Governance und Sicherheitsannahmen.
- Solche Systeme muessen pruefbar sein, weil ihre Aussagen sonst nur Behauptungen bleiben.
- Ein lokales Analyse- und Rekonstruktionssystem gewinnt Vertrauen nicht durch Marketing, sondern durch Einsicht in Code, Datenpfade und Grenzen.

Fuer Aether bedeutet Open Source deshalb konkret:

- Die Ableitung von Metriken wie `H_lambda`, Delta, Resonanz, Bayes und Graph ist nachvollziehbar.
- Sicherheits- und Sharing-Grenzen bleiben sichtbar und kritisierbar.
- Lokale Nutzer koennen das System selbst betreiben, aendern und absichern.
- Forschung, Kritik, Forks und Reproduzierbarkeit bleiben moeglich.
- Das Projekt bleibt ein offener Untersuchungsraum statt einer Black Box mit unbeweisbaren Anspruechen.

Gerade fuer ein Programm, das sich mit Struktur, Beobachtung, Rekonstruktion und Vertrauen beschaeftigt, ist Offenheit kein Zusatz, sondern Teil der methodischen Konsistenz.

## Philosophischer Schlusspunkt

Das Projektmotiv laesst sich in drei Saetzen zusammenfassen:

1. Nicht jede Ordnung beginnt mit Bedeutung.
2. Viele stabile Bedeutungen koennen aus lokalen Regeln emergieren.
3. Beobachtung ist kein neutraler Nullpunkt, sondern selbst Teil der Dynamik.

Darum steht am Ende dieses Projekts nicht einfach der klassische Satz `ich denke, also bin ich`, sondern eine andere Akzentsetzung:

`Ich bin, also denke ich.`

Das bedeutet in diesem Kontext:

- Zustand geht dem Begriff voraus.
- Beobachtung geht der fertigen Interpretation voraus.
- Struktur geht der spaeteren Semantik voraus.

## Inspirationen und offene Fragen

Die wichtigsten methodischen Inspirationen hinter Aether sind:

- Conway: lokale Regeln, globale Emergenz
- Shannon: formale Unsicherheit
- Noether: Invarianz und Erhaltung
- Bayes: lernende Aktualisierung unter Unsicherheit
- Rekonstruktionstheorie: Modell plus Residuum

Die offenen Fragen sind:

- Wie weit laesst sich observerrelative Information mathematisch strenger fassen?
- Welche Klassen von Daten erlauben asymptotisch vollstaendige Modellierung?
- Wo bleibt eine irreduzible Restunsicherheit bestehen?
- Welche Invarianten muessen fuer sichere Rekonstruktionssysteme hart erzwungen werden?
- Wie kann man Erkenntnis teilen, ohne Datenschutz, Sicherheit und Verantwortung zu verletzen?

## Hauptmotiv

Das Hauptmotiv dieses Projekts ist einfach:

Nicht zuerst eine grosse Weltformel behaupten.
Sondern ein System bauen, in dem man lokal, messbar und nachvollziehbar untersuchen kann, wie Regeln, Invarianten, Beobachtung, Lernen und Rekonstruktion zusammen globale Ordnung erzeugen.
