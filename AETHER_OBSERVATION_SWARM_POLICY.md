# Aether Observation, Performance, and Swarm Policy

## Zweck

Diese Policy trennt vier Dinge strikt voneinander:

1. lokale, private Signalverarbeitung
2. oeffentliche Leistungsartefakte fuer globale Beschleunigung
3. passive globale Feldbeobachtung bereits oeffentlicher Artefakte
4. zustimmungspflichtige Broadcast-, Such- und Kontaktvorgaenge

Die deterministische Analysepipeline bleibt unberuehrt. Neue Logik sitzt davor, daneben oder darueber, nicht im Kern der bestehenden Pipeline.

## Nicht verhandelbare Architekturgrenzen

- Die produktive Pipeline bleibt an den Rust-Shell-Trigger gebunden.
- Es gibt kein passives Beobachten lokaler Nutzerdateien.
- Es gibt kein Beobachten oder Speichern von Konten, Passwoertern, Tasteneingaben, Eingabereihenfolgen oder Eingaberhythmik.
- Es gibt kein Keylogging, keine private UI-Inhaltsauswertung und keine stille Hintergrundueberwachung.
- Rohdaten, lokale Deltas, Residuals und rekonstruierende Nutzerspuren verlassen das Geraet nicht.
- Ein vom Nutzer explizit zur Analyse freigegebenes Artefakt darf lokal und fluechtig im RAM verarbeitet werden. Das ist keine passive Beobachtung.
- Render- und Laufzeitsignale duerren nur dann in dieselbe Pipe wie Datei-Signale gehen, wenn die entsprechende Einstellung aktiv ist und der Privacy-Block greift.

## Artefaktklassen

### 1. Private Signal Artifacts

Beispiele:

- explizit gedroppte Dateien
- explizit freigegebene Render-Signale
- explizit freigegebene Runtime-Bitstroeme
- lokale Segmentfenster grosser Artefakte

Eigenschaften:

- lokale Verarbeitung erlaubt
- RAM-only oder lokal verschluesselte Residualhaltung
- nicht auto-pushbar
- nicht broadcastbar ohne gesonderte Ableitung in andere Klassen

### 2. Public Performance Route Artifacts

Beispiele:

- permutationsalgo maps
- rekonstruktive Abkuerzungsrouten
- transformations- oder routing-landkarten
- anwendbarkeitsgrenzen fuer Strukturklassen
- kostenprofile und proof-checksums

Eigenschaften:

- keine Rohdaten
- keine lokalen Deltas
- keine privaten Labels
- keine per-user Nutzungsspur
- auto-pushbar nach Trust plus Quorum
- Genesis-Ausnahme: Trust allein reicht fuer globale Freigabe, wenn der lokale Node Genesis ist

Diese Klasse ist die globale Leistungsakkumulation. Sie ist keine soziale Anfrage und braucht keine Nutzerbestaetigung.

### 3. Collaborative Discovery Artifacts

Beispiele:

- seltene lokale Dynamiken
- wissenschaftlich heikle Einzelbefunde
- lokale Aehnlichkeiten mit moeglicher externer Resonanz
- gezielte Kontakt- oder Suchanfragen

Eigenschaften:

- nie auto-pushbar
- Broadcast nur als Vorschlag
- Versand immer nach expliziter Nutzerbestaetigung
- Kontakt oder Chat erst nach manueller Annahme der Anfrage

### 4. Public Field Observation Artifacts

Beispiele:

- bereits bestaetigte und oeffentliche Invarianten
- bestaetigte TTD-/Anchor-Pool-Eintraege
- bestaetigte Quorum-Zustaende
- bestaetigte Leistungsrouten

Eigenschaften:

- duerfen immer passiv gelesen und lokal ausgewertet werden
- keine erneute Zustimmung notwendig
- keine neue Aussenwirkung
- dienen der globalen Feldbeobachtung und Priorisierung

## Unified Signal Pipe

Alle explizit freigegebenen Quellen muessen in dieselbe deterministische Intake-Pipe ueberfuehrt werden.

Quellen:

- File drop
- explizit aktivierter Render-Pfad
- explizit aktivierter Runtime-/Bitstrom-Pfad
- spaeter Segment-Scheduler fuer grosse Artefakte

Gemeinsame Envelopesemantik:

- source_type
- source_scope
- privacy_class
- source_label
- size_bytes
- time_window
- manifest_hash oder parent_manifest_hash
- segment_manifest_hash falls segmentiert

Regel:

- dieselbe Pipe bedeutet dieselben Privacy-Grenzen
- dieselbe Pipe bedeutet nicht dieselben Exportrechte

Wenn die Render-Einstellung aktiv ist, gehen Render-Signal und die dabei laufenden Bitstroeme durch dieselbe Pipe wie Datei-Signale. Dadurch entstehen keine zusaetzlichen Beobachtungsrechte.

## Segment-Scheduler vor der Pipeline

Grosse Artefakte werden vor der Pipeline deterministisch in Segmente zerlegt.

Pflichtregeln:

- die Pipeline selbst bleibt unveraendert
- derselbe Input ergibt dieselbe Segmentliste
- jedes Segment hat festen Offset, feste Laenge, parent_manifest_hash und segment_index
- Segment-Metadaten sind auditierbar
- nur Segmente, nicht die globale Datei, duerfen bei Last priorisiert oder spaeter offloaded werden

Die Grunddarstellung bleibt lokal auf Artefakt- oder Session-Ebene. Segmente sind Zoom- oder Unterstruktur, nicht der primaere Benutzergegenstand.

## Auto-Push-Regeln fuer Leistungsartefakte

Auto-push ist ausschliesslich fuer Public Performance Route Artifacts erlaubt.

Pflichtbedingungen:

- trust_score erfuellt
- quorum_count >= quorum_threshold
- oder Genesis-Override aktiv
- Artefakt ist nicht invertierbar gegen private Nutzerdaten
- Artefakt ist klassenbezogen und nicht benutzerbezogen

Zulaessige Felder fuer Public Performance Route Artifacts:

- schema_version
- artifact_class
- route_id
- invariant_core_hash
- route_hash
- route_program oder route_signature
- applicability_bounds
- cost_profile
- proof_checksum
- reconstruction_quality
- trust_score
- quorum_count
- quorum_threshold
- genesis_override_used
- promoted_at

Nicht zulaessig:

- raw bytes
- raw pixels
- local delta
- local residual payload
- chat content
- account or credential fields
- private key material
- per-user input traces
- input order or rhythm

Wichtige Regel:

- globale Leistungsakkumulation ist von Broadcast- und Kontaktzustimmungen unabhaengig
- globale Leistungsakkumulation ist nicht unabhaengig von Trust und Quorum

## Lokale Vollnachvollziehbarkeit

Ockham-style Ziel:

- global wird nur die allgemeine Route, Landkarte oder Transformationsabkuerzung geteilt
- lokal darf die vollstaendige Replay- und Pruefspur bis zur Pixelkoordination oder Segmentkoordinate nachvollziehbar bleiben

Regel:

- full replay trace bleibt lokal
- proof, checksum, bounds und route class duerfen global werden

## Passive lokale und globale Beobachtung

Es gibt drei dauerhafte Schleifen:

### 1. Lokale Selbstbeobachtung

Jeder Node beobachtet lokal:

- neue Dynamiken
- Drift
- Rekonstruktionspfade
- Scheduler-Kosten
- wiederkehrende Strukturklassen
- Residual- und Rauschanteile

### 2. Globale Feldbeobachtung

Jeder Node beobachtet unabhaengig von Zustimmung oder Broadcast permanent:

- bereits oeffentliche bestaetigte Invarianten
- bestaetigte Leistungsartefakte
- bestaetigte Quorum-Zustaende
- passive Resonanzen und Trendverschiebungen
- relevante Peers und Anwendungsgrenzen oeffentlicher Routen

### 3. Zustimmungspflichtige Intervention

Nur diese Dinge brauchen Nutzerbestaetigung:

- neue Broadcastanfrage aus lokalem Fund
- gezielte externe Suche
- Kontaktanfrage
- privater Chat

## Broadcast- und Kontaktpolitik

Broadcast ist Suchsignal, nicht Wahrheit.

Regeln:

- lokale Dynamik darf sofort einen Broadcast-Vorschlag erzeugen
- Versand erfolgt nie automatisch
- der Nutzer wird informiert, wenn neue Folgezusammenhaenge oder neue Dynamiken auftauchen
- der Nutzer kann jederzeit erneut anfragen, wenn neue Evidenz vorliegt
- anti-spam gates sind Pflicht

Spam-Schutz:

- nur eine offene Broadcastanfrage pro invariant_core_hash
- cooldown window nach Versand
- erneuter Versand nur bei novelty gain, new_relation_count > 0 oder manuellem override

Kontakt:

- eingehende oder ausgehende Anfragen muessen bestaetigt werden
- privater Chat wird erst nach Annahme geoeffnet

## Privacy-Denylist

Diese Dinge duerfen weder passiv beobachtet noch gespeichert noch exportiert werden:

- accounts
- usernames fremder Dienste
- passwords
- passphrases
- credentials
- tokens
- private keys
- keystrokes
- input order
- input rhythm
- private chat content
- email content
- private notes
- biometrics

## Privacy-Allowlist

Diese Dinge duerfen lokal strukturell verarbeitet werden, wenn sie explizit freigegeben wurden:

- vom Nutzer gedroppte Dateien
- vom Nutzer freigegebene Render-Signale
- vom Nutzer freigegebene Runtime-/Bitstroeme
- daraus abgeleitete nicht semantische Strukturmetriken

Diese Dinge duerfen global und automatisch gepusht werden, wenn Trust plus Quorum erfuellt sind:

- nicht invertierbare Leistungslandkarten
- permutationsalgorithmen auf Klassenebene
- route proofs
- applicability bounds
- cost profiles

## Repo Integration Map

### Bestehende Kernpfade beibehalten

- modules/analysis_capsule.py
  - bleibt der gemeinsame Signal-Envelope fuer file und live signals
  - hier source_scope und privacy_class erweitern, nicht die Messlogik aendern

- aether_pipeline.py
  - bleibt der deterministische Kern
  - keine Policy-Verzweigungen in die Pipeline selbst einbauen
  - neue Intake-, Scheduler- und Consent-Logik davor oder daneben halten

- modules/render_coordinator.py
  - scoped capture beibehalten
  - nur bei expliziter Einstellung denselben Pipe-Einstieg wie file drops nutzen
  - kein neuer Sonderexportpfad fuer Render-Daten

- src/inter_layer_bus.rs
  - als Event-Rueckgrat fuer observation, optimization und vault write nutzen
  - neue Eventfamilien fuer performance_route_candidate und public_field_observed anschliessen

### Leistungsartefakte automatisch pushen

- modules/unified_cascade.py
  - aus Cascade-Ergebnissen route candidates ableiten
  - keine Rohdaten in den Push-Pfad geben

- modules/vault_chain.py
  - build und append fuer Public TTD/Anchor-Bundles erweitern
  - auto-push nur fuer performance artifacts nach Trust plus Quorum
  - full replay traces lokal halten

- src/public_ttd.rs
  - Zustandsmodell fuer pending, provisional, quorum_met und promoted sauber fuehren
  - performance artifacts von collaborative requests unterscheiden

- modules/consensus_engine.py
  - quorum 1/3, 2/3, 3/3 fuer auto-pushbare Leistungsartefakte fuehren
  - Promotion erst bei Quorum oder Genesis-Override

- src/swarm_loop.rs
  - bestaetigte signierte Reports und Aggregation fuer globale Promotion nutzen

### Broadcast und Kontakt getrennt halten

- modules/swarm_overlap.py
  - metrische Resonanz fuer collaborative discovery nutzen
  - keine automatische globale Promotion daraus ableiten

- src/iced_shell.rs
  - Broadcast nur als Vorschlag, Versand nur nach Zustimmung
  - Kontaktanfrage pending -> accepted/declined -> private chat
  - Nutzer ueber neue Folgezusammenhaenge seit letzter Anfrage informieren

- modules/swarm_controller.py
  - gossip fuer Liveness, Sichtbarkeit und kleine Suchsignale beibehalten
  - targeted query path spaeter getrennt von consented contact requests fuehren

- modules/aethernet_transport.py
  - quorum- und gossip-verteilte Sichtbarkeit beibehalten
  - keine Vermischung mit consented scientific requests

### Privacy hart halten

- src/runtime_signal.rs
  - harte private-context-Grenze beibehalten
  - kein privates Signal erreicht den Bus

- modules/privacy_observer.py
  - nur strukturelle Prozess-, Netzwerk- und Systemsignale
  - keine private Inhaltsbeobachtung

- modules/session_engine.py
  - live_session_key bleibt RAM-only Schutz fuer lokale sensitive Reste

- modules/aelab_motor.py
  - lokale Deltas bleiben lokal und sessiongebunden
  - exportiert werden nur gehashte Invarianten

## Einbau-Reihenfolge

1. Policy enums und artifact classes einfuehren
2. unified pipe um source_scope und privacy_class erweitern
3. performance route artifact class im Cascade/Vault-Pfad ableiten
4. consensus/public_ttd um auto-push fuer performance artifacts erweitern
5. broadcast/contact Schicht explizit als separate consent policy modellieren
6. scheduler vor der Pipeline fuer grosse Artefakte einfuehren
7. globale Feldbeobachtung ueber bestaetigte oeffentliche Artefakte standardisieren

## Entscheidende Trennung

- global beobachten: immer fuer bereits oeffentliche Artefakte
- global beschleunigen: automatisch fuer verifizierte Leistungsartefakte
- global nach aussen fragen oder kontaktieren: nur mit Zustimmung

Diese Trennung ist verbindlich.