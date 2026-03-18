# Aether Roadmap

Stand: März 2026 | Author: Kevin Hannemann
Wissenschaftsfeld: Strukturell Emergente Metadynamische Semantik (SEMS)

---

## Implementierungsstand

| Phase | Inhalt | Status |
|-------|--------|--------|
| 1 | Foundation: Web + Dateien + Registry + Graph + Session-Keys | ✓ Fertig |
| 2 | Media: MP3 / MP4 / Bilder + Datei-Register + Filekeys | ✓ Fertig |
| 3 | Process: Windows Prozessdynamik + ReconstructionEngine + Attractor-Tracking | ✓ Fertig |
| 4 | Render: ETW/DXGI Pixel-Koordination pro Prozess + UI + Runtime | ✓ Fertig |
| 5 | Optimize: Vereinzelung, Ausdünnung, Empfehlung + Effizienzmonitor | ✓ Fertig |
| 6 | Aethernet: dezentrale Knoten, verteilte Anchor Packs, P2P-Transport | In Arbeit |
| 7 | Cross-Domain Atlas: SEMS-Forschungswerkzeuge, domänenübergreifende Signaturvergleiche | Geplant |
| 8 | Governance & Community: Anchor-Verifizierungsnetz, Publisher-Vertrauen | Vision |

---

## Phase 1 — Foundation ✓

- Shanway v1–v4 Integration
- Session-Key Management + Secure Zeroize
- Registry + Graph-Engine (lokale Wissensstruktur)
- Web-Analyse + Dateianalyse
- Tamper-Detection, Audit-Logging, Invarianten-Prüfung

## Phase 2 — Media ✓

- MP3 / MP4 / Bildanalyse (UniversalAdapter)
- Datei-Register + einmalige Filekeys
- Delta-Generierung über Session-Seed (XOR + noise)
- `domain_delta` + `validate_domain_operation`
- Privacy: Signaturen reisen, Rohdaten bleiben lokal

## Phase 3 — Process ✓

- Windows-Prozessdynamik (ETW, Prozessbaum, Ressourcendelta)
- Multi-Modalität: Kamera, Audio, Dateien
- ReconstructionEngine: Snapshots, Residuals, lossless-Rekonstruktion
- Attractor-Tracking: Attraktor-Detektion aus Prozessdynamik
- Integration mit Shanway, Vault, Rust-Shell
- Security: Session-Isolation, Consent-gebundener Relay-Pfad

## Phase 4 — Render ✓

- ETW/DXGI Pixel-Koordination pro Prozess
- RenderFingerprint (Pixel-Signatur je Fenster)
- UI-Integration (Iced, Slint, CLI)
- Runtime-Loop + Monitoring + Persistence-Engine
- Scene-Renderer, Voxel-Grid, Spacetime-Renderer (strukturelle Visualisierung)

## Phase 5 — Optimize ✓

- Prozess-Vereinzelung: gleiche Arbeit, weniger Prozesse
- Ausdünnung: Ressourcen-Empfehlung mit Bestätigung
- Effizienzmonitor: Live-Tracking von CPU/RAM-Gewinn
- Preload-Optimierer: Anchor Packs bei Bedarf vorladen
- Benutzerprompt: keine Aktion ohne explizite Zustimmung
- Ziel: auch alter Hardware vollen Nutzen geben

## Phase 6 — Aethernet (In Arbeit)

**Ziel:** Dezentraler Schwarm aus lokalen Aether-Instanzen die Strukturwissen teilen ohne Rohdaten zu übertragen.

Aktueller Stand:
- GitHub als temporärer Anchor-Transport (öffentliche `.dna`-Dateien)
- Lokale P2P-Pool-Infrastruktur (`modules/p2p_anchor_pool.py`)
- Public-TTD-Transport (`modules/public_ttd_transport.py`)
- Consent-Schicht: `Nein / Nur anonym / Mit Signatur` vor jeder Freigabe

Nächste Schritte:
- IPFS/libp2p Integration für transportagnostische Anker-Verteilung
- Knoten-Verifizierung ohne zentrale Instanz
- Dreifach-unabhängige Validierung für globale Anker
- Offline-First: Packs lokal gecacht, Synch optional

## Phase 7 — Cross-Domain Atlas (Geplant, Q3–Q4 2026)

**Ziel:** Das erste öffentliche Atlas-Werkzeug für strukturelle Ähnlichkeiten über Domänen hinweg.

Geplante Inhalte:
- Domänenübergreifende Signaturvergleiche (Klimadaten ↔ Genomik ↔ Marktdynamik)
- Visualisierung von Attraktor-Konvergenzen
- SEMS-Forschungsinterface für externe Wissenschaftler
- Öffentliche Anchor-Bibliothek: kuratiertes Strukturwissen
- API-frei: keine zentralisierte Cloud, kein SaaS

## Phase 8 — Governance & Community (Vision, 2027)

**Ziel:** Selbsttragendes Ökosystem mit wissenschaftlicher Governance.

Vision:
- Dezentrales Publisher-Vertrauensnetz (kein zentraler Trust-Provider)
- Community-Anchor-Verifizierung: Beiträge aus Domänenexperten
- SEMS-Forschungsgemeinschaft: Issues, Papers, Replications
- Aether als Infrastruktur für andere Werkzeuge

---

## Technische Prinzipien (unveränderlich)

```
Lokal first — Cloud nur mit expliziter Zustimmung
Silence is valid output — kein Raten, kein Erfinden
Lossless bleibt Lossless — D(S_t, R_t) = X_t immer
Kein Label — nur Struktur
Kein Vertrauen nötig — nur Nachschauen
Mensch entscheidet — immer
```

---

## Forschungsfragen (offen)

Diese Fragen treibt Aether an. Sie sind nicht beantwortet — sie sind der Grund für die Arbeit:

1. Konvergiert `h_lambda(X, t)` für stabile Datenklassen gegen einen stabilen Wert?
2. Gibt es domänenübergreifende Attraktoren die unabhängig entdeckt werden können?
3. Wie klein kann ein Anker sein und noch strukturell informativ bleiben?
4. Wann kollabiert ein dezentraler Schwarm auf fundamentale Strukturprinzipien?
5. Ist pi wirklich ein stabiler Anker in evolutiven Suchräumen — oder war das Rauschen?

---

Letzte Aktualisierung: März 2026

---

## Gesamtkonzept & Entwicklungs-Roadmap (Master-Plan)

### Philosophie und Grundprinzipien

Aether ist ein lokales, datenschutzzentriertes Framework für strukturelle Datenanalyse:

- **Zero-Knowledge-Architektur**: Rohdaten verlassen niemals das Gerät. Nur nicht-invertierbare Struktursignaturen (Anker) werden optional geteilt.
- **Struktur statt Semantik**: Aether erkennt Muster, interpretiert sie aber nicht. Bedeutung entsteht erst durch den Nutzer.
- **Emergenz durch Schwarmintelligenz**: Muster gewinnen an Relevanz, wenn sie mehrfach unabhängig auftreten.
- **Selbstverantwortung**: Nutzer verwalten ihre Schlüssel selbst; es gibt keine zentrale Wiederherstellung.
- **Wissenschaftliche Bescheidenheit**: Alle Ergebnisse sind Hypothesen, keine Wahrheiten.

### Erststart & Nutzerführung (Phase A.1) ✓ Implementiert

- **Shanway-Erststart-Hinweis (DE/EN)**: Beim allerersten Start erscheint ein klarer Hinweis:
  - Konto existiert nur lokal; privater Schlüssel wird auf dem Gerät erzeugt
  - Keine Passwort-Wiederherstellung, kein Support
  - Zero-Knowledge-Sicherheitsphilosophie (kein Bug)
  - Backup-Pflicht: `%USERPROFILE%\.aether` (Windows) / `~/.aether` (Linux/macOS)
- Anzeige als Konsolen-Dialog (CLI) und modaler Tkinter-Dialog (GUI)
- Einmalig — nach Bestätigung in `data/settings.json` gespeichert, nicht wiederholt

### Domänenübergreifende Muster (Phase C.1) ✓ Implementiert

- **`modules/cross_domain_engine.py`**: CrossDomainEngine mit DBSCAN-Clustering
  - Pure-Python DBSCAN (kein sklearn erforderlich), O(n²)
  - Merkmalsraum-Normalisierung auf [0, 1]
  - Relevanzbewertung: `relevance = (n^α · m^β · (1+g)) / (d + ε)`
  - Wachstumsrate (letzte 7 Tage), Multi-Domänen-Filter
  - SQLite-Persistenz: `cd_anchors`, `cd_clusters`, `cd_cluster_members`
  - Shanway-Benachrichtigung bei Relevanz ≥ 70
  - Meta-Anker-Export (kein Rohdaten-Austausch)
- **GUI-Tab „DOMÄNEN"** in `modules/gui.py`:
  - Persistenter Disclaimer (⚠️) immer sichtbar
  - Konfigurierbare Parameter (eps, min_samples, Zeitfenster)
  - Scrollbare Cluster-Liste mit Relevanz-Score
  - Detail-Ansicht bei Selektion
  - Export-Funktion nach `data/meta_anchors/`
- **Jeder Eintrag enthält:**
  > ⚠️ Strukturelle Auffälligkeit – keine gesicherte Erkenntnis. Dieses Muster basiert ausschließlich auf mathematischen Ähnlichkeiten.

---

## Detaillierter Entwicklungsplan

### Phase A — Kurzfristig (1–2 Monate)

- [x] Erststart-Hinweis (keine Kontowiederherstellung) — Shanway DE/EN
- [x] Domänenübergreifende Muster-Engine (CrossDomainEngine)
- [x] GUI-Tab „DOMÄNEN" mit Disclaimer
- [ ] Automatische Ordnerüberwachung + Anker-Generierung (watchdog-Bibliothek)
- [ ] Live-Session-Keys und widerrufbare Freigaben (PrivacyRegistry-Integration)
- [ ] Tutorial-Modus (einfache Version: Datei-Analyse mit Shanway-Führung)

### Phase B — Mittelfristig (3–6 Monate)

- [ ] Gruppenchats: Ordner als Anker-Listen teilen
- [ ] Vergleichsfunktion im Chat (Clustering, Heatmap-Visualisierung)
- [ ] Automatische Konsens-Anker (Ebene 2): Schwelle 3 unabhängige Quellen
- [ ] Aethernet-Erweiterung: neue Nachrichtentypen
  - `ANCHOR_BATCH` — mehrere Anker auf einmal
  - `ANCHOR_CONSENSUS` — promovierte Konsens-Anker mit Metadaten
  - `SESSION_KEY` — temporäre Zugriffsrechte
- [ ] Öffentliche Anker als Datenquelle für domänenübergreifende Cluster
- [ ] Domänen-Tags (Freitext oder vordefiniert) mit Opt-in-Freigabe

### Phase C — Langfristig (6–12 Monate)

- [x] Domänenübergreifender Tab mit Clustering und Relevanzbewertung
- [x] Meta-Anker-Exportfunktion
- [ ] Ähnlichkeitsmatrix-Visualisierung (Heatmap) in Detailansicht
- [ ] Fortgeschrittenes Tutorial (Prozessanalyse, Live-Demos)
- [ ] Annäherungssuche für >1 Mio. Anker (annoy / faiss Vorfilter)
- [ ] Umfassende Sicherheitsaudits (Penetrationstests Aethernet-Protokoll)
- [ ] Cross-Domain Atlas: öffentliche kuratierte Anker-Bibliothek

---

## Technische Spezifikationen

### Algorithmen und Bibliotheken

| Aufgabe | Bibliothek | Status |
|---------|------------|--------|
| Clustering (klein) | Pure-Python DBSCAN | ✓ Implementiert |
| Clustering (groß) | scikit-learn DBSCAN / hdbscan | Geplant |
| Ähnlichkeitssuche (>1M Anker) | annoy / faiss | Phase C |
| Ordnerüberwachung | watchdog | Phase A |
| CLI-UI (Tabs, Farben) | rich / textual | Phase B |
| Rust-Beschleunigung | PyO3 / maturin | ✓ Grundgerüst |

### Datenbankerweiterungen (Registry)

| Tabelle | Zweck | Status |
|---------|-------|--------|
| `cd_anchors` | Anker-Eingangsdaten | ✓ Cross-Domain-DB |
| `cd_clusters` | Cluster-Metadaten | ✓ Cross-Domain-DB |
| `cd_cluster_members` | Cluster-Mitglieder | ✓ Cross-Domain-DB |
| `consensus_candidates` | Zählung ähnlicher Anker | Geplant Phase B |
| `consensus_anchors` | Promovierte Konsens-Anker | Geplant Phase B |
| `tutorial_state` | Tutorial-Fortschritt | Geplant Phase A |

### Datenschutz-Invarianten (unveränderlich)

| Eigenschaft | Garantie |
|------------|----------|
| Rohdaten | Verlassen niemals das Gerät |
| Anker | SHA-256 nicht-invertierbar |
| Filekeys | Nur Hash gespeichert, nie Klartext |
| Cluster | Nur Strukturzusammenfassung exportiert |
| Metadaten | Opt-in, nie an Identität geknüpft |

### Offene Fragen (zur Diskussion)

- Wie granular sollen Domänen-Tags sein? (Freitext, vordefinierte Liste, automatische Erkennung aus Ordneramen?)
- Sollen Konsens-Anker nach einmaliger Zustimmung dauerhaft geteilt werden oder ist jede Übertragung ein neuer Opt-in?
- Wie verhindert man Missbrauch des Aethernet (Flooding mit sinnlosen Ankern)? — Reputation, Proof-of-Work, manuelle Kurierung?
- Soll es einen globalen „Ignore"-Filter für bestimmte Anker-Cluster geben (ähnlich Spam-Filter)?

