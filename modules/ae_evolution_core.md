# AE Evolution Core

`ae_evolution_core.py` ist kein loses Experiment mehr, sondern ein interner AETHER-Dienst.

## Aktueller Zweck

Der AE-Core erzeugt aus echten Laufzeitdaten einen kleinen evolutiven Nebenpfad:

1. Kontextdaten aus Fingerprint, Anchors, Graph, Bayes, Pattern, Ontologie und Lernstand werden gesammelt.
2. `AEAlgorithmVault.evolve(...)` extrahiert, mutiert und hybridisiert einfache Kandidaten.
3. `AetherAnchorInterpreter` liest daraus stabile AE-Anker.
4. Die verdichtete AE-Zusammenfassung wird wieder in den laufenden Fingerprint zurueckgeschrieben.

## Reale Integration

- `start.py` erzeugt `AEAlgorithmVault` und `AetherAnchorInterpreter` beim Bootstrap.
- `modules/gui.py` fuehrt AELAB intern ueber `_run_ae_lab(...)` aus.
- `_register_final_modules(...)` ruft diesen Pfad nach der normalen Analysepipeline auf.
- Die Ergebnisse landen als `ae_lab_summary` am Fingerprint und laufen in Vault-, Chain- und Shanway-Kontext mit.

## Was AELAB heute nicht ist

- kein eigener Nutzer-Workflow
- kein separates Fenster
- kein externer Plugin-Runner
- kein autonomer Hauptanalysator statt `analysis_engine.py`

## Operative Rolle im Oekosystem

AELAB dient aktuell als interner Evolutions- und Ankerverdichter. Es erweitert:

- Strukturhinweise
- Anker-Typisierung
- interne Zusatzsemantik fuer Shanway
- Fingerprint-Metadaten fuer Persistenz und Nachverfolgung

Kurz: Der AE-Core ist aktiv, aber bewusst begrenzt und dem Hauptsystem untergeordnet.
