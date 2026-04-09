# Aether Roadmap

## 30/60/90 Execution Track (Operationalized)

Die folgenden vier Hebel sind ab sofort als verbindlicher Umsetzungs-Track definiert.

### Track 1: Productized Operating Modes (Analyze, Guard, Sync, Evolve)

- Ziel: Kern-Workflows als klar erkennbare Betriebsmodi mit stabilen Ein-/Ausgaben.
- 30 Tage:
  - Modus-Vertrag in Konfiguration fixieren (Input, Gate, Output, Failure Rules).
  - UI- und CLI-Benennung auf dieselben vier Modi normalisieren.
- 60 Tage:
  - Jeder Modus liefert standardisierte Run-Summaries (status, reason, metrics, next_action).
  - Deterministische Mode-Transitions mit Audit-Eintrag je Wechsel.
- 90 Tage:
  - Mode-Chaining fuer End-to-End-Laeufe ohne manuelle Glue-Logik.
  - Regression-Suite je Modus plus Integrationssuite fuer Chaining.

### Track 2: Hard SLO/KPI Contract per Cycle

- Ziel: Messbare Betriebsqualitaet statt impliziter "funktioniert"-Aussagen.
- 30 Tage:
  - KPI-Set fixieren: Determinism Rate, Safety Coverage, Consensus Latency, False-Positive Budget, Throughput.
  - Baseline-Messung auf Referenzdaten erfassen und versionieren.
- 60 Tage:
  - Warn- und Fehler-Schwellen in Runtime und Reports ausgeben.
  - KPI-Drift zwischen Releases automatisch vergleichen.
- 90 Tage:
  - SLO-Gates fuer Release-Freigabe etablieren (No-Gate, Soft-Gate, Hard-Gate).
  - KPI-Historie als reproduzierbares Audit-Artifact publizieren.

### Track 3: Standardized Interfaces (CLI/API/Event Schema)

- Ziel: Aether als integrierbare Plattform statt isolierter Toolchain.
- 30 Tage:
  - Einheitliches Event-Schema v1 fuer alle relevanten Modus-Ausgaben definieren.
  - CLI-Entry-Points auf ein konsistentes Command-Muster bringen.
- 60 Tage:
  - API-konforme Response-Objekte angleichen (status/data/errors/metrics).
  - Kompatibilitaetsmatrix fuer Versionen (v1 guarantees) dokumentieren.
- 90 Tage:
  - Stabiler Integrationsleitfaden fuer externe Orchestratoren und Agenten.
  - Contract-Tests fuer Event-Schema und API-Antworten in CI.

### Track 4: End-to-End Reference Scenarios

- Ziel: Real nutzbare, nachstellbare Praxispfade statt isolierter Einzelmodule.
- 30 Tage:
  - Vier Referenzpfade definieren:
    - Input -> Analyze -> Guard -> Decision
    - Input -> Analyze -> Sync -> Consensus
    - Input -> Analyze -> Evolve -> Re-check
    - Input -> Full Chain -> Audit Export
- 60 Tage:
  - Jede Pipeline mit Gold-Output und erwarteten KPI-Korridoren hinterlegen.
  - Automatisierte Smoke-Runs fuer alle Referenzpfade.
- 90 Tage:
  - Oeffentliche Reproduzierbarkeits-Reports je Szenario.
  - Standardisierte Incident-Playbooks pro Szenario.

Stand: März 2026 | Author: Kevin Hannemann
Forschungsrichtung: Strukturell Emergente Metadynamische Semantik (SEMS) — projektinternes Arbeitslabel, kein anerkanntes Wissenschaftsfeld

---

## Implementierungsstand

| Phase | Inhalt | Status |
|-------|--------|--------|
| 1 | Foundation: Web + Dateien + Registry + Graph + Session-Keys | ✓ Fertig |
| 2 | Media: MP3 / MP4 / Bilder + Datei-Register + Filekeys | ✓ Fertig |
| 3 | Process: Windows Prozessdynamik + ReconstructionEngine + Attractor-Tracking | ✓ Fertig |
| 4 | Render: ETW/DXGI Pixel-Koordination pro Prozess + UI + Runtime | ✓ Fertig |
| 5 | Optimize: Vereinzelung, Ausdünnung, Empfehlung + Effizienzmonitor | ✓ Fertig |
| 6 | Aethernet: dezentrale Knoten, verteilte Anchor Packs, P2P-Transport, emergentes Tier-System | In Arbeit |
| 7 | Cross-Domain Atlas: SEMS-Forschungswerkzeuge, domänenübergreifende Signaturvergleiche | Geplant |
| 8 | Governance & Community: Anchor-Verifizierungsnetz, Publisher-Vertrauen | Vision |
| 9 | LoRa Transport: Sub-1-GHz-Mesh, strukturelle Signaturen offline-first | Vision |
| 10 | Platform Expansion: native Linux .deb/.AppImage, macOS .dmg, iOS, Mobile-App | Vision |

---

## Phase 1 — Foundation ✓

- Assistant v1–v4 Integration
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
- Integration mit Assistant, Vault, Rust-Shell
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

### Implementiert ✓

- GitHub als temporärer Anchor-Transport (öffentliche `.dna`-Dateien)
- Lokale P2P-Pool-Infrastruktur (`modules/p2p_anchor_pool.py`)
- Public-TTD-Transport (`modules/public_ttd_transport.py`)
- Consent-Schicht: `Nein / Nur anonym / Mit Signatur` vor jeder Freigabe
- **Emergentes Tier-System** (NetworkTier 0–4): Hardware-abgeleitete P2P-Freischaltung
  - `derive_network_tier()` liest RAM, Kerne und Betriebssystem-Version
  - OsPlatform-Erkennung: Win9x → WinModern, LinuxLegacy, LinuxModern, RaspberryPi
  - Tier-Mapping: LocalOnly (0) → LanBeacon (1) → LanP2P (2) → YggdrasilP2P (3) → FullDht (4)
- **StealthBeacon**: Geräte die noch nicht für Gossip qualifiziert sind werden passiv sichtbar
- **Tier-Watchdog** (One-Shot-Pattern): prüft alle 90 s ob Tier-Upgrade möglich ist (max 10 Versuche)
- **Genesis-Node-Key** (`data/keys/genesis_node.key`): Ed25519/HKDF-abgeleiteter Identitätsanker
  - Feste IPv6-Adresse `200:ca77:8d5c:10b2:e3c0:d06c:6af4:dd5e` eingebaut
  - Spoofing-Schutz: `GENESIS_NODE_YGG_ADDR` wird beim Start verifiziert
- **Genesis-Invarianten** (`data/interbus/genesis_invariants.json`): Benford 0.85 / Zipf α 1.07 / Mandelbrot β 1.40 / Fourier 24.0
  - Werden neuen Knoten als Prior eingeimpft
  - Automatische Überschreibung nach ≥ 32 eigenen Messungen
- Yggdrasil v0.5.8 automatisch verwaltet bei Tier ≥ 3; auf Schwachgeräten übersprungen ohne Fehler
- DHT (Tier 4): Kademlia-ähnliches Peer-Lookup für vollvernetzte Knoten

### Nächste Schritte

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

## Phase 9 — LoRa Transport (Vision, 2027)

**Ziel:** Strukturelle Signaturen auch ohne Internet-Infrastruktur übertragen — offline-first bis in die letzte Meile.

Kernidee:
- LoRa (Sub-1-GHz, 250–5500 bps) als Transportkanal für komprimierte Anchor-Packs
- Strukturelle Signaturen sind klein genug für LoRa: ein 64-Byte-Anker ≈ 1 LoRa-Paket
- Mesh-fähig: Knoten reichen Ankerpakete weiter (Store-and-Forward)
- Offline-Szenarien: kein WLAN, kein Yggdrasil nötig — nur Funk

Geplante Inhalte:
- LoRa-Modul als Tier 5 im NetworkTier-System
- Hardware-Targets: Raspberry Pi + LoRaWAN-HAT, ESP32-S3 + SX1276
- Paketformat: Anchor-Pack + Signatur + Hop-Count, max 255 Byte
- Automatische Datenrate-Anpassung (SF7–SF12) je nach Reichweite
- Keine personenbezogenen Daten im Funk — nur Strukturhashes

---

## Phase 10 — Platform Expansion (Vision, 2027)

**Ziel:** Aether auf allen relevanten Plattformen nativ lauffähig — ohne Python-Interpreter-Voraussetzung.

| Plattform | Format | Status |
|-----------|--------|--------|
| Windows | `.exe` via PyInstaller (bestehend) | ✓ Fertig |
| Android | natives APK (Kotlin, API 21+) | ✓ Fertig |
| Linux | `.deb` + `.AppImage` (Rust-Shell + Python-Bundle) | Geplant |
| macOS | `.dmg` (Universal Binary, x86-64 + ARM64) | Geplant |
| iOS | Swift-App (Viewer + Local-Analyse, kein Vault-Write) | Vision |
| Mobile (generisch) | PWA-Wrapper als Fallback für iOS/Android ohne Store | Vision |

Linux-Priorität:
- `daemon_headless.py` läuft bereits auf beliebigem Python 3.6+ ohne native Deps
- Rust-Shell-Binary als `.AppImage` — self-contained, kein sudo required
- `.deb`-Paket für Debian/Ubuntu mit systemd-Unit für Headless-Betrieb

macOS-Priorität:
- Universal Binary (Rosetta-kompatibel + ARM native für M-Chips)
- `.dmg` mit Sign & Notarize für Gatekeeper-Kompatibilität
- Keine Abhängigkeit von Homebrew — Bundle vollständig

---

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

- **Assistant-Erststart-Hinweis (DE/EN)**: Beim allerersten Start erscheint ein klarer Hinweis:
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
  - Assistant-Benachrichtigung bei Relevanz ≥ 70
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

- [x] Erststart-Hinweis (keine Kontowiederherstellung) — Assistant DE/EN
- [x] Domänenübergreifende Muster-Engine (CrossDomainEngine)
- [x] GUI-Tab „DOMÄNEN" mit Disclaimer
- [ ] Automatische Ordnerüberwachung + Anker-Generierung (watchdog-Bibliothek)
- [ ] Live-Session-Keys und widerrufbare Freigaben (PrivacyRegistry-Integration)
- [ ] Tutorial-Modus (einfache Version: Datei-Analyse mit Assistant-Führung)

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

