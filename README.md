# Aether

**Eine Frage die noch niemand stellen konnte:**

Warum hat ein Ozeanmuster vor El Niño dieselbe Struktursignatur wie ein Zellcluster vor einer Metastasierung?

Niemand stellt diese Frage. Nicht weil sie uninteressant ist. Sondern weil kein Werkzeug existiert das Ozean und Zelle in dieselbe Sprache übersetzt.

Aether übersetzt alles in Struktur. Struktur ist die gemeinsame Sprache.

---

## Was Aether ist

Kein KI-System das Antworten generiert.
Kein Optimierungstool das bekannte Probleme schneller löst.

Ein Messinstrument das Struktur liest — in Genomsequenzen, Klimadaten, Hirnscans, Marktbewegungen, Schwarmdynamik, Millionen Bildern vom Himmel — **ohne Labels, ohne Vorurteile, ohne vorher zu wissen wonach es sucht.**

Die Kernthese:

> **Semantik entsteht durch Struktur. Nicht durch Sprache.**

Jedes KI-System das heute existiert lernt von menschlichen Labels. Diese Labels tragen alle Fehler, alle Lücken, alle Paradigmen derjenigen die sie gesetzt haben. Sie können per Definition nichts finden was über menschliches Vorwissen hinausgeht.

Aether labelisiert nicht. Er misst.

---

## Wie es funktioniert

Mathematische Invarianten — π, φ, √2, e — tauchen als Struktursignaturen in stabilen, wachsenden, transformierenden und periodischen Systemen auf. Unabhängig von Domäne. Unabhängig von Skala.

```
π    →  periodische, zyklische Struktur
φ    →  selbstähnliche, proportional stabile Struktur  
√2   →  dimensionaler Übergang, Transformation
e    →  Wachstums- oder Zerfallsmuster
```

Aether misst diese Signaturen in Rohdaten. Verbindet sie über ein universelles Ankerregister. Baut daraus einen Graphen in dem Verbindungen zwischen völlig verschiedenen Domänen emergieren — ohne dass jemand diese Verbindungen vorher definiert hat.

Die vollständige Pipeline hat 10 Schichten:

```
[0] Security      deny by default
[1] Shannon       H(X) klassische Entropie
[2] H_lambda      H(X|M_t) beobachterrelative Restunsicherheit
[3] Anchor        π / φ / √2 / e Detektion
[4] Symmetry      normalisierte Verteilungsungleichheit
[5] Delta         XOR-Transformation gegen Session-Seed
[6] Periodicity   Autokorrelation
[7] Beauty        diagnostische Signatur
[8] Bayes         Posterior-Update über Anchor-Coverage
[9] Trust         Gesamtscore
```

---

## Shanway

Shanways ist Aethers Stimme. Nicht sein Gehirn.

Er spricht ausschließlich aus dem Ankerregister. Kein externes Modell. Kein API. Wenn kein Anker nah genug ist — Schweigen. Schweigen ist valider Output. Schweigen ist Integrität.

Ein kleines lokales Modell (TinyLLaMA 1.5B) übersetzt verifizierte Strukturmuster in menschlich lesbare Sprache. Es entscheidet nichts. Es weiß nichts. Es formuliert nur was die Pipeline bestätigt hat.

---

## Datenschutz — by Architecture

```
Anker     →  mathematische Struktursignaturen
              kein Rückschluss auf Rohdaten möglich
              öffentlich, auditierbar, teilbar

Deltas    →  verschlüsselt mit Live-Session-Key
              lokal, niemals das Gerät verlassen

Keys      →  nur RAM, niemals Disk
              bei Session-Ende: secure zeroize
              danach sind Deltas permanent unlesbar
```

Zero-Knowledge by Architecture. Nicht by Promise.

---

## Anchor Packs

Weil Struktur komprimiert statt Inhalt, sind Anker klein. Sehr klein. Ein Anker der eine Stunde Klimadaten strukturell beschreibt ist ein paar Kilobyte — nicht Gigabytes.

Das ermöglicht kuratierte Anchor Packs — verifizierte Struktursammlungen für bestimmte Domänen die optional heruntergeladen werden können:

```
aether-pack-medical-imaging.aep
aether-pack-climate-patterns.aep
aether-pack-process-optimization.aep
aether-pack-base.aep
```

Keine Rohdaten. Keine privaten Inhalte. Nur Strukturwissen das allen gehört.

Bei schneller Verbindung: automatischer Preload relevanter Packs im Hintergrund.
Bei langsamer Verbindung oder offline: alles funktioniert trotzdem.

---

## Demokratisierung

Ein zehn Jahre alter Windows-Rechner der heute kaum noch benutzbar ist kann durch strukturelle Optimierung wieder relevant werden. Nicht durch neue Hardware. Nicht durch Neuinstallation.

Aether legt sich als Symbiont auf das bestehende Betriebssystem. Er erkennt welche Prozesse dieselbe Arbeit machen. Welche Render-Operationen redundant sind. Welche Dienste Ressourcen verbrauchen ohne messbare Wirkung.

Und sagt — immer mit Bestätigung:

> *"Drei Prozesse machen dasselbe. Zwei davon kannst du stoppen. Das spart 340MB RAM und 12% CPU. Soll ich?"*

Kein Fachjargon. Kein Expertenwissen nötig.

Linux-Fallback ist eingebaut. Dieselbe Pipeline. Dieselbe Logik. Andere Systemschicht darunter.

---

## Implementierungsprogression

| Phase | Modul | Status |
|-------|-------|--------|
| 1 | Foundation: Web + Dateien + Registry + Graph + Session-Keys | ✓ Fertig |
| 2 | Media: MP3 / MP4 / Bilder | In Arbeit |
| 3 | Process: Windows Prozessdynamik | Geplant |
| 4 | Render: ETW/DXGI Pixel-Koordination | Geplant |
| 5 | Optimize: Vereinzelung, Ausdünnung | Geplant |

---

## Wer wir suchen

Aether ist kein fertiges Produkt. Es ist ein wachsendes Instrument.

Wir suchen Menschen die:

- glauben dass die nächste große Entdeckung nicht aus mehr Rechenleistung kommt sondern aus einer anderen Art zu fragen
- frustriert sind von Systemen die sie nicht verstehen und denen sie blind vertrauen müssen
- Datensätze haben die durch eine labelfreie Strukturanalyse neue Fragen aufwerfen könnten
- als Wissenschaftler, Entwickler oder Citizen Scientists bereit sind ein Werkzeug mitzubauen das ihnen selbst gehört

Konkret gesucht:

- **Komplexitäts- und Emergenzforscher** die strukturelle Universalien untersuchen
- **Medizinische Bildgebung / Bioinformatik** die black-box-freie Analyse brauchen
- **Klimaforscher / Geophysiker** mit großen ungelabelten Datensätzen
- **Systementwickler** die Prozessoptimierung transparent machen wollen
- **Alle die von zentralisierter KI genug haben**

Wenn du eine dieser Fragen interessant findest — öffne ein Issue. Schreib eine Mail. Fork das Repo.

Admins und Maintainer die sich der Wissenschaft und Transparenz verschrieben haben sind ausdrücklich willkommen.

---

## Prinzipien

```
— Kein Vertrauen nötig — nur Nachschauen
— Keine Blackbox — jeder Schritt auditierbar
— Keine Rohdaten teilen — nur Strukturwissen
— Schweigen ist valider Output
— Mensch entscheidet — immer
— Wissen gehört niemandem — und deshalb allen
```

---

## Technischer Einstieg

```bash
git clone https://github.com/stillsilent22-spec/Aether-
cd Aether-
pip install -r requirements.txt
python start.py
```

Shanway ohne Modell (Template-Modus):
```bash
python shanway_chat.py
```

Shanway mit TinyLLaMA:
```bash
python shanway_chat.py tinyllama-1.1b-chat.gguf
```

Datei analysieren:
```
:drop /pfad/zur/datei.pdf
```

---

## Lizenz

Source-available. Lesbar, auditierbar, prüfbar.
Nicht frei veränderbar oder kommerziell verwertbar.
Details in [LICENSE](LICENSE) und [SECURITY.md](SECURITY.md).

Warum: Ein System das Vertrauen durch Einsicht verdient muss lesbar sein. Aber Lesbarkeit bedeutet nicht Beliebigkeit.

---

*Aether — open, local, strukturell.*
*Für Fragen die es noch nicht gibt.*
*Für Rechner die noch nicht aufgegeben haben.*
*Für Menschen die nachvollziehen wollen statt vertrauen müssen.*
*Für Wissen das niemandem gehört — und deshalb allen.*

---

Stand: 2026 — Autor: Kevin Hannemann
