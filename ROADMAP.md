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

