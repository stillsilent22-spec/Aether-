# Aether

Aether ist ein lokales, source-available Analyse- und Rekonstruktionssystem fuer Dateien und Bytestroeme. Das System kombiniert Strukturmetriken, beobachterrelative Restunsicherheit, Rekonstruktionspfade und fail-closed Governance in einem gemeinsamen auditierbaren Workflow. Objektiv ungewoehnlich ist nicht ein einzelnes Modell, sondern die Kopplung dieser Ebenen: Analyse, Persistenz, Freigabeentscheidungen und lokale Assistenz arbeiten auf demselben Zustand statt in getrennten Werkzeugketten.

Stand: 08.03.2026
Autor: Kevin Hannemann

## Lizenzstatus

Dieses Repository ist fuer oeffentliche Einsicht, Audit, Forschung und nachvollziehbare technische Pruefung gedacht.

Der aktuelle Lizenzstatus ist source-available und restriktiv. Der Code darf gelesen, heruntergeladen und geprueft werden. Er soll aber nicht frei veraendert, weiterverteilt oder kommerziell verwertet werden. Er ist bewusst **nicht** als OSI-konforme Open-Source-Lizenz formuliert. Details stehen in [LICENSE](LICENSE) und [SECURITY.md](SECURITY.md).

## Warum der Code lesbar sein soll

Bei Aether ist die Lesbarkeit des Quellcodes kein Nebenaspekt, sondern Teil des Konzepts:

- die Strukturmetriken, Sicherheitsregeln und Fail-Closed-Pfade muessen auditierbar sein
- die Behauptung lokaler Rekonstruktion und lokaler Governance ist nur glaubwuerdig, wenn der Implementierungspfad sichtbar ist
- sicherheitsrelevante Aussagen sollen pruefbar sein und nicht auf Black-Box-Vertrauen beruhen

Die Lesbarkeit ist deshalb gewollt. Die freie Veraenderbarkeit ist es nicht.

## Kurzprofil

Aether ist kein einzelnes Spezialtool und kein generisches Chat-System. Es ist ein lokales System fuer strukturelle Analyse, Rekonstruktion, Beobachtung und kontrollierte Weitergabe von Datenzustaenden. Im Zentrum stehen auditierbare Metriken, explizite Rekonstruktionsgrenzen und deterministische Sicherheitsregeln.

Das Projekt fuehrt mehrere sonst getrennte Ebenen zusammen: Dateianalyse, Delta- und Snapshot-Logik, beobachterrelative Unsicherheit, lokale Wissensverdichtung und kontrollierte Exportpfade. Dadurch lassen sich Aussagen ueber Struktur, Rekonstruierbarkeit und Teilbarkeit im selben technischen Kontext pruefen.

## Lokale Privacy-Grenzen

Aether ist ein vollstaendig lokales System. Accounts, Deltas, rekonstruktive Restzustaende und lokale Lernsignale bleiben auf dem Geraet und werden weder zentral gespeichert noch still synchronisiert.

Wichtige Grundregeln:

- es gibt keine eingebaute Wiederherstellung fuer Benutzername oder Passwort
- Aether speichert keine cloudbasierten Backups und keine serverseitigen Recovery-Daten
- lokale Deltas und der nicht komprimierbare Shannon-Rest bleiben strikt lokal
- global teilbar sind hoechstens stark komprimierte, nicht invertierbare Strukturanker
- private Kontexte wie Chat, E-Mail und Passwortfelder sind durch harte Privacy-Boundaries vom Bus- und Vision-Pfad ausgeschlossen

## Was das Programm praktisch kann

Aether ist kein einzelnes Spezialtool, sondern ein lokales Analyse- und Beobachtungssystem mit mehreren gekoppelten Pfaden. Im aktuellen Stand kann es unter anderem:

- Dateien und Byte-Stroeme per Drag-and-Drop strukturell analysieren
- Delta-Pfade bilden und lokale Rekonstruktionsbedingungen abschaetzen
- Analysezustaende, Deltas und Strukturverlaeufe visualisieren
- visuelle Quellen und Laufzeitdaten als dynamische Strukturquellen verarbeiten
- Anker, Frequenzmuster, Symmetrie, Entropie, Kohaerenz und Resonanz messen
- Bayes-, Graph- und Beobachterzustaende gemeinsam in einen Fingerprint ueberfuehren
- Vault-, Chain- und Snapshot-Pfade lokal und kontrolliert fuehren
- bestaetigte Anker als DNA-Share- und Public-Anchor-Library-Buendel ohne Rohdaten bereitstellen
- mit Shanway eine lokale schriftliche Assistenz ueber die berechneten Zustaende bereitstellen

Das Programm ist damit weder nur Visualisierung noch nur Analyse noch nur Assistenz. Es verbindet diese Ebenen in einem gemeinsamen lokalen Regelraum.

## Rust-Shell: Relay und Live-Session-Keys

Der aktuelle Rust-Shell-Pfad fuehrt drei Sicherheits- und Koordinationsideen sichtbar zusammen:

- lokale Anmeldung erzeugt pro Login einen neuen Live-Session-Key und einen separaten Storage-Key-Fingerprint
- Chat-Relay bleibt standardmaessig fail-closed und wird erst mit expliziter URL- und Secret-Konfiguration aktiv
- Netzschritte fuer Browser-Probe, Public-TTD und Chat-Relay laufen nur nach explizitem Consent

Wichtig dabei:

- der Live-Session-Key wird nicht als rekonstruierbarer Langzeitschluessel nach aussen gegeben
- der Storage-Key-Fingerprint ist nur eine lokale Kontrollspur, kein exportierter Rohschluessel
- ohne Relay-URL und Shared Secret bleibt der gesamte Chat-Pfad lokal
- Relay-Nachrichten werden nur als verschluesselte Ereignisse behandelt; Dateien, Deltas und Rohinhalte des lokalen Vaults werden dadurch nicht freigegeben

Der Rust-Shell-Pfad ersetzt damit noch nicht die gesamte Python-Codebasis, bildet aber bereits einen eigenstaendigen, auditierten UI-, Session-, Consent- und Strukturpfad fuer Datei-, Browser-, Public-TTD- und Chat-Arbeit.

## Was Aether anders macht als herkoemmliche Software

Herkoemmliche Werkzeuge trennen diese Bereiche meist strikt:

- Dateianalyse-Tools messen Signaturen oder bekannte Muster
- Visualisierungstools zeigen Daten, ohne sie rekonstruktiv oder governance-seitig einzuordnen
- Chat- oder KI-Systeme erzeugen Sprache, ohne denselben Datenpfad wie das eigentliche Messsystem zu teilen
- Sicherheitswerkzeuge bewerten oft nur Bedrohungen, nicht Invarianz, Rekonstruktion und Beobachterlage zugleich

Aether geht einen anderen Weg:

- es behandelt Daten primaer als Struktur und Zustandsraum, nicht nur als Dateiformat
- es koppelt Analyse, Beobachtung, Rekonstruktion, Governance und Darstellung direkt
- es trennt lokale Rohdaten strikt von teilbaren Anchor-/Strukturbuendeln fuer gemeinsame Bibliotheken und Chain-Attestierung
- es fuehrt keine freie Modellmagie ein, sondern bindet kritische Pfade an Validatoren, Fail-Closed-Regeln und lokale Auditierbarkeit
- es versucht nicht, Bedeutung sofort semantisch zu labeln, sondern leitet zunaechst Struktur, Anker, Symmetriebruch und Restunsicherheit ab
- Shanway ist keine vom System getrennte Sprach-KI, sondern eine lokale Schriftoberflaeche ueber denselben berechneten Zustaenden

Der praktische Unterschied ist: Aether arbeitet nicht zuerst mit fertigen Kategorien, sondern mit messbarer Struktur, Invarianz und Rekonstruktionsnaehe.

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

- ein Beweis fuer ein universelles Modell realer Systeme
- ein Ersatz fuer klassische Informationstheorie
- ein System zur Behauptung von Bewusstsein
- ein System, das fehlende Rekonstruktionsdaten ohne ausreichende Information ersetzt
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
Geteilte Anchor- und Strukturpakete koennen lokale Rekonstruktion verbessern oder priorisieren, ersetzen aber keinen vollstaendigen lokalen Rekonstruktionspfad.

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

Der Analysekern verarbeitet Dateien, Byte-Stroeme, Browser-HTML und andere lokale Strukturquellen und erzeugt AetherFingerprints.

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
- oeffentliche AELAB-DNA-Exports unter `data/aelab_vault/`

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

- lokale Struktur-, Delta- und Statusansichten
- synchrone Audio-/Visual-Rueckkopplung
- Chat- und Statusoberflaeche

Wesentliche Dateien:

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

Fuer Aether bedeutet das konkret:

- Rohdaten und Deltas bleiben lokal.
- Geteilt werden nur Anchor-Daten, Frequenzsignaturen, Strukturmuster und attestierte Zusammenfassungen.
- `CONFIRMED lossless` ist eine lokale Herkunftseigenschaft eines Datensatzes, keine Eigenschaft des exportierten Share-Bundles.
- Exakte Rekonstruktion bleibt lokal und kann hoechstens durch geteilte Anchor-Daten besser vorbereitet werden.

## Tests & Verifikation

Fuer den ersten echten lokalen Roundtrip-Test gibt es jetzt einen direkten Smoke-Test-Pfad:

- CLI: `python start.py --test-roundtrip`
- Direktes Testskript: `python tests/test_lossless_roundtrip.py`
- Pytest-kompatibel: `python -m pytest tests/test_lossless_roundtrip.py`

Der Test fuehrt bewusst einen kleinen End-to-End-Pfad aus:

- ein stabiler Bytezustand wird analysiert
- der erzeugte `AetherFingerprint` wird auf `reconstruction_verification` und `verdict_reconstruction` geprueft
- der `session_seed` wird explizit gespeichert
- ein neuer `SessionContext` simuliert den Reload
- Delta plus persistierter Seed werden erneut zu Bytes dekodiert
- SHA-256 und Dateigroesse muessen danach exakt mit dem Original uebereinstimmen
- lokale DNA-Exports tragen den verwendeten `delta_session_seed` jetzt direkt im Header (`delta_session_seed=...`)

Erwartetes Verhalten:

- `CONFIRMED`: `verified == True`, SHA-256 stimmt, Groesse stimmt, `anchor_coverage_ratio > 0.85`, `unresolved_residual_ratio < 0.15`
- `FAILED`: mindestens eine Bedingung ist gebrochen, zum Beispiel zu wenig Coverage, zu grosses Residuum oder verlorener `session_seed`

Wichtig:

- Lossless bleibt in Aether immer konditional.
- Pattern-Snapshots oder Anchors allein sind nicht automatisch verlustfrei.
- Lossless ist nur dann belastbar, wenn Anchors, Residual und Seed-Persistenz gemeinsam die Rekonstruktion tragen.

## Shanway Miniatur und lokales Lernen

Shanway kann jetzt zusaetzlich zur normalen Strukturmetrik eine rein lokale Zusatzebene nutzen:

- eine separate low-res Miniatur der geoeffneten Datei als zweite, kleine Repraesentation

Die Miniatur dient als reduzierte Kontrollansicht fuer:

- `[Miniatur-Reflexion]`
- rekursive lokale Reflexionsstufen bis zu einer festen Tiefe
- TTD-Vorschlaege fuer stabile Anker
- `learned_insight` als verdichtete Schlussfolgerung aus Symmetrie-, Residual- und Rekursionsverlauf
- optional einen geschlossenen lokalen Folgepfad: Analyse -> Shanway-Befund -> Browser-Kontextsuche -> neue Analyse

Die daraus entstehenden Self-Reflection-Deltas gelten strikt lokal:

- sie werden append-only gespeichert
- sie tragen `internal_only`
- sie werden nie automatisch exportiert
- bei Freigabe erscheint immer ein Consent-Dialog

Beispiel fuer den Consent-Pfad:

- `Nein`
- `Nur öffentliche Anker`
- `Alle inkl. Self-Deltas`

Standard ist fail-closed: keine Freigabe ohne explizite Entscheidung.

## Shanway Chat und Netzfreigabe

Die Chat-Oberflaeche ist lokal-first und baut auf denselben Aether-Zustaenden auf wie Analyse, Observer und Vault. Im aktuellen Stand gilt:

- private Chats mit Shanway bleiben lokal verschluesselt
- Gruppenkanale koennen Shanway gezielt einbeziehen und behalten ihren Verlauf lokal bzw. im consentierten Relay-Sync
- Schreiben und Tastatur bleiben die primaere Interaktion; Mikrofonpfade sind bewusst deaktiviert
- optionale Netz-Kontexte werden nicht still gezogen, sondern nur nach expliziter Freigabe

Der neue Netzpfad ist bewusst begrenzt:

- `Netz-Kontext an` erlaubt nur, dass Shanway bei freien Fragen optional eine Suchverdichtung anfragen darf
- vor jedem Netzschritt erscheint ein Consent-Dialog `Netz nutzen?`
- geladen wird nur ein kurzer Such-/HTML-Kontext fuer die Antwortverdichtung
- Rohdateien, Deltas, private Chatinhalte und interne Zusatzdaten verlassen den Rechner nicht

Dadurch kann Shanway auf Fragen wie `Was ist AGI?` oder browserbezogene Rueckfragen lesbarer antworten, ohne den lokalen, auditierbaren Kern aufzugeben.

## Browser- und URL-Pruefung

Der Browserpfad kann jetzt nicht nur HTML laden, sondern auch eine URL vor dem Oeffnen lokal pruefen:

- ueber `Analyse URL` oder per Rechtsklick im Adressfeld `Analyse mit Aether`
- die Probe laedt nur eine begrenzte Stichprobe der Ressource, nicht den vollen Interaktionszustand
- Frontend-Signale werden als kleine Miniatur/Heatmap verdichtet
- Backend-Signale werten Header, MIME-Typ, Scriptlast, Obfuskation und einfache Sprachmuster aus
- Shanway schreibt danach eine kurze Verdichtung wie `URL-Pruefung fuer ...: SUSPICIOUS ... Oeffnen trotzdem: Nein.`
- danach fragt die GUI explizit, ob die Seite trotzdem im Companion-Browser geoeffnet werden soll

Damit bleibt die Analyse lokal, consent-basiert und auditierbar. Es gibt keine stille Browser-Extension und keinen ungefragten Netzverkehr.

## Persoenliches Register

Im `VERIFY`-Tab gibt es jetzt ein persoenliches lokales Register:

- letzte Analysen pro Nutzer sichtbar
- Eintrag laden -> Analysezustand, Shanway und Integritaetsstatus werden wiederhergestellt
- `Original oeffnen` und `Exportieren` greifen auf denselben lokalen Rekonstruktionspfad zu, falls der Eintrag eine echte Datei referenziert
- Browser-/Probe-Eintraege ohne rekonstruierbare Datei bleiben trotzdem lokal ladbar und auditierbar

## Verbundenheit und demokratisiertes Lernen

Aether fuehrt keine Cloud-Pflicht und keine versteckte Plattformbindung ein. Der aktuelle Peer-Pfad ist bewusst lokal, auditable und consent-basiert:

- stabile TTD-Anker koennen als lokale, metrics-only Public-TTD-Bundles freigegeben werden
- diese Bundles bleiben transportagnostisch und koennen ueber IPFS/libp2p-kompatible Spiegel verbreitet werden, ohne Rohdaten zu leaken
- stabile TTD-Kandidaten loesen lokal automatisch einen DNA-Export plus `data/export_log.jsonl`-Eintrag aus
- standardmaessig werden nur oeffentliche Hash-/Metrikdaten geteilt
- die GUI fragt vor jeder Public-TTD-Freigabe explizit nach `Nein / Nur anonym / Mit Signatur`
- normale Nutzeranker werden erst nach 3 unabhaengigen Validierungen global vertrauenswuerdig
- Anker des lokalen Admin-Erstellers gelten sofort als vertrauenswuerdig und duerfen direkt in globales Lernen einfliessen
- interne Self-Reflection-Deltas bleiben ohne explizite Vollfreigabe lokal
- importierte oeffentliche Anker fliessen nur lokal in den Observer-Lernzustand ein
- optionaler echter Netztransport laeuft ueber einen lokalen IPFS-Knoten oder explizit konfigurierte HTTP-Mirror-URLs
- ohne konfigurierte Transportziele bleibt der Pool strikt lokal und fail-closed

Shanway kann dadurch sagen:

- `Gelernte Insight aus vorheriger Session: Symmetrie-Delta verbessert um X%.`
- `Von globalem Netz gelernt: +Y% Symmetrie-Delta durch importierte öffentliche Anker.`
- `Anker von 3 Peers validiert -> globales Lernen: +1.2% Symmetrie-Delta, I_obs +0.8%.`

Der zentrale Governance-Punkt bleibt:

- Aether ist kein Cloud-Agent und keine zentrale AGI-Plattform
- Aether ist kein Baustein fuer fremde Plattformarchitekturen oder zentralisierte AGI-Sammelsysteme
- Wissen wird lokal getragen, lokal bewertet und nur in consentierten, kompakten Anchor-Formen geteilt
- das System bleibt source-available, fail-closed und append-only

## Anchor Packs

Der Rust-Pfad fuehrt jetzt einen zusaetzlichen Beschleuniger-Layer fuer spezialisierte Anchor-Sammlungen ein:

- `.aep` steht fuer `Aether Anchor Pack`
- Packs enthalten nur bestaetigte mathematische Anchor-Records, keine Rohdateien und keine Deltas
- der lokale `PackRegistry`-Index ist optional und nur Metadaten-getrieben
- `ShanwayPackAdvisor` empfiehlt Packs nur dann, wenn fuer die aktuelle Domaene ein realer Hit-Rate- oder Kompressionsgewinn zu erwarten ist
- `PackManager` installiert Packs nur nach expliziter Nutzerbestaetigung
- jeder Pack-Anker wird lokal erneut durch die Vault-/Trust-Pruefung geschickt
- `AutoPackGenerator` kann aus bereits bestaetigten lokalen Ankern einer Domaene einen `.aep` erzeugen
- `OfflineCacheManager` kann aus installierten Packs einen kleinen Offline-Cache fuer geplante Aktivitaeten vorbereiten

Wichtig:

- Download ist kein Zwang
- ein Pack ersetzt nicht den lokalen Delta-Pfad
- ohne bestaetigte Signatur und lokale Verifikation kommt kein Pack-Anker in den lokalen Vault
- die Rust-Shell kann jetzt empfohlene Packs direkt lokal installieren, Packs aus der aktiven Domaene generieren und einen kleinen Offline-Cache vorbereiten

## Theory of Mind

Der Rust-Shell-Schnitt fuehrt jetzt einen kleinen observer-relativen Kommunikationslayer ein:

- `MindModelEngine` fuehrt pro Session ein anonymes Gegenueber-Modell
- gespeichert werden nur Anchor-Familiarity, Domaenenniveau und Kommunikationsstil
- Default bleibt `SessionOnly`
- `ObserverDelta = O1 - O2` bestimmt die empfohlene Erklaertiefe
- `ComprehensionDetector` liest aus dem lokalen Texteingang nur grobe Verstaendnissignale wie `Confusion`, `AlreadyFamiliar` oder `Understood`
- `ToMOutputAdapter` passt nur Tiefe und Brueckenhinweise an, nicht die Faktenbasis
- die Shell kann das Observer-Modell nun auf Wunsch von `SessionOnly` nach `PersistentLocal` heben oder wieder lokal loeschen

Das bedeutet praktisch:

- Shanway erklaert auf Peer-Level, wenn die kommunikative Luecke klein ist
- Shanway bleibt grundlegender, wenn dieselbe Struktur fuer das Gegenueber noch neu ist
- es entsteht kein Personenprofil, sondern nur ein lokaler, fluechtiger Beobachterzustand

## Anti-Puzzle Grenze

Die neue Rust-Schicht verhaelt sich weiterhin absichtlich nicht wie ein generischer AGI-Baustein:

- keine offene API fuer fremde Plattformen
- keine automatische Einbettung in zentralisierte Dienste
- keine Rohdaten- oder Delta-Exports ueber Packs oder Observer-Modelle
- Aether bleibt ein eigenstaendiges, dezentrales Paradigma und kein Puzzle-Teil fuer zentralisierte AGI-Systeme

## Windows ZIP Build

Fuer die Windows-Auslieferung ohne Installer ist der vorgesehene Pfad jetzt:

- Abhaengigkeiten fuer den Build installieren: `python -m pip install pyinstaller winshell pywin32`
- Build starten: `pyinstaller --noconfirm --clean Aether.spec`
- Ergebnis zippen: den Ordner `dist\Aether\` komplett als `Aether-App.zip` verpacken

Hinweise zum Build:

- Die Spec baut bewusst im `--onedir`-Modus.
- `Aether.exe` startet ohne Konsole.
- Falls eine `icon.ico` im Projektwurzelordner liegt, wird sie automatisch fuer die EXE verwendet.
- Beim ersten Start der gefrorenen App wird automatisch ein Desktop-Shortcut `Aether.lnk` angelegt, wenn noch keiner existiert.

Kurzanleitung fuer Endnutzer:

1. `Aether-App.zip` herunterladen und entpacken.
2. Den Ordner `Aether` oeffnen.
3. `Aether.exe` doppelklicken. Beim ersten Start erscheint automatisch `Aether.lnk` auf dem Desktop.

## Quelloffenheit und Auditierbarkeit

Die Sichtbarkeit des Codes gehoert zu diesem Projekt nicht nur aus praktischen Gruenden, sondern aus einem erkenntnistheoretischen Grundsatz.

Wenn das Projekt sich mit Regeln, Beobachtung, Struktur, Rekonstruktion und Kontrolle ueber Information beschaeftigt, dann waere ein vollstaendig intransparenter Black-Box-Ansatz mit diesem Anspruch unvereinbar.

Quelloffenheit bedeutet hier:

- Regeln bleiben sichtbar.
- Modelle bleiben kritisierbar.
- Ableitungen bleiben pruefbar.
- Technik wird nicht nur verteilt, sondern verstehbar.

Die grundlegende Haltung dahinter ist technische Nachvollziehbarkeit statt bloßem Vertrauensanspruch.

### Warum lesbarer Code fuer Aether richtig ist

Lesbarer Code ist fuer dieses Programm nicht nur eine Verteilungsform, sondern die technisch richtige Form.

Der Grund ist einfach:

- Aether arbeitet mit Regeln, Invarianten, Rekonstruktionspfaden, Priors, Governance und Sicherheitsannahmen.
- Solche Systeme muessen pruefbar sein, weil ihre Aussagen sonst nur Behauptungen bleiben.
- Ein lokales Analyse- und Rekonstruktionssystem gewinnt Vertrauen nicht durch Marketing, sondern durch Einsicht in Code, Datenpfade und Grenzen.

Fuer Aether bedeutet das konkret:

- Die Ableitung von Metriken wie `H_lambda`, Delta, Resonanz, Bayes und Graph ist nachvollziehbar.
- Sicherheits- und Sharing-Grenzen bleiben sichtbar und kritisierbar.
- Lokale Nutzer koennen das System selbst pruefen und absichern.
- Forschung, Kritik und Reproduzierbarkeit bleiben moeglich.
- Das Projekt bleibt ein offener Untersuchungsraum statt einer Black Box mit unbeweisbaren Anspruechen.

Gerade fuer ein Programm, das sich mit Struktur, Beobachtung, Rekonstruktion und Vertrauen beschaeftigt, ist Einsicht in den Code kein Zusatz, sondern Teil der methodischen Konsistenz.

## Methodischer Schlusspunkt

Das Projektmotiv laesst sich in drei Punkten zusammenfassen:

1. Struktur wird vor Semantik analysiert.
2. Stabile Merkmale sollen aus lokalen Regeln und Messgroessen abgeleitet werden.
3. Der Beobachterzustand wird explizit modelliert und nicht implizit vorausgesetzt.

Aether priorisiert deshalb:

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

Nicht mit unbelegten Totalmodellen beginnen.
Sondern ein System bauen, in dem man lokal, messbar und nachvollziehbar untersuchen kann, wie Regeln, Invarianten, Beobachtung, Lernen und Rekonstruktion zusammenwirken.

## Rust-Pfad: Public Vault, Inter-Layer-Bus, Observation

Der aktuelle Rust-Schnitt erweitert Aether um drei technische Bausteine, ohne den lokalen Sicherheitskern aufzugeben:

- `src/vault_access.rs` fuehrt einen `VaultAccessLayer` ein. Der Vault bleibt intern; Schreiben und Lesen laufen ueber eine signierende Shanway-Pipeline. Oeffentliche Records enthalten nur mathematische Signaturen und Trust-Metadaten, keine Rohdaten.
- `src/delta_vault.rs` trennt den privaten Delta-Layer physisch vom oeffentlichen Ankerpfad. Deltas werden lokal AES-basiert abgelegt; `.gitignore` blockiert versehentliche Commits.
- `src/inter_layer_bus.rs`, `src/runtime_signal.rs` und `src/observation.rs` bilden den begonnenen Echtzeitpfad: Event-Bus, Laufzeit-Signalrahmen und Observation-Quarantaene fuer strukturell gefaehrliche Signale.

Diese Rust-Module sind bewusst lokal-first:

- oeffentliche Anchor-Exporte enthalten nur Hashes, mathematische Signaturen und Trust-Felder
- private Deltas bleiben lokal
- Observation lernt gefaehrliche Muster nur als 16-dimensionale Strukturvektoren
- kein Rohinhalt aus dem Quarantaenepfad verlaesst den lokalen Speicher

Der Rust-Pfad ist damit architektonisch vorhanden, auch wenn der eigentliche Toolchain-Build auf diesem Rechner separat abgeschlossen werden muss.

### Rust-Binaries fuer Public Vault und Quarantaene

Der Rust-Schnitt enthaelt jetzt zusaetzlich zwei eigene Binaries:

- `aether-cli`
  - `verify-anchor <path>`
  - `verify-signatures <dir>`
  - `pipeline-check --threshold 0.65`
  - `sync-vault [repo_root] [since_vault_version]`
- `sandbox_worker`
  - separater Quarantaene-Worker fuer das isolierte Gefahrenwissen
  - eigener Store unter `data/rust_shell/quarantine/`
  - Integritaetspruefung, Klassifikation und strukturierter Store-Pfad

Fuer Pull Requests auf `vault/anchors/**` gibt es zusaetzlich den Workflow
`.github/workflows/vault-pr-check.yml`, der Signaturen und Trust-Pipeline
ueber `aether-cli` prueft.

## Rust-Pfad: Browser-Probe und Public-TTD-Pool

Der aktuelle Rust-Schnitt fuehrt zwei weitere lokale-first Pfade ein:

- `src/browser.rs`
  - lokale URL-Probe mit begrenztem Bytebudget
  - strukturelle Risikoheuristiken fuer Obfuskation, Scam-, Fake- und Hate-Muster
  - kurzer Suchkontext fuer Shanway, ohne Rohdatenpersistenz
- `src/public_ttd.rs`
  - fail-closed Public-TTD-Pool fuer Hash-und-Metrik-Anker
  - Quorum-Logik fuer `candidate` vs. `trusted`
  - optionaler IPFS-/Mirror-Transport mit lokaler Cache- und Summary-Datei

Die Rust-Shell zeigt damit jetzt:

- Consent vor Browser-Probe und Suchkontext
- lokalen Public-TTD-Poolstatus
- TTD-Kandidatenpruefung gegen Residual-, Symmetrie-, I_obs- und Rekursionsschwellen
- metrics-only Sharing ohne Rohdaten oder Deltas
