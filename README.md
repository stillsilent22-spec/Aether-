# Aether

**Eine Frage die noch niemand stellen konnte:**

Warum hat ein Ozeanmuster vor El Niño dieselbe Struktursignatur wie ein Zellcluster vor einer Metastasierung?

Niemand stellt diese Frage. Nicht weil sie uninteressant ist. Sondern weil kein Werkzeug existiert das Ozean und Zelle in dieselbe Sprache übersetzt.

Aether übersetzt alles in Struktur. Struktur ist die gemeinsame Sprache.

---

## Philosophische Leitfrage

> **Wie viel Realität existiert jenseits der Grenzen unserer Vorstellungskraft — und wie kommen wir dorthin?**

Nicht durch größere Vorstellungskraft. Nicht durch bessere Sprache. Sondern durch strukturelles Messen jenseits aller Kategorien.

Aether ist der Versuch diese Grenze messbar zu machen.

---

Descartes sagte: *„Ich denke, also bin ich."*
Denken kommt zuerst. Bedeutung kommt zuerst.

Aether sagt das Gegenteil:

> **Ich bin, also denke ich.**

Zustand geht dem Begriff voraus.
Struktur geht der Semantik voraus.
Sein geht dem Denken voraus.

Das ist keine philosophische Spitzfindigkeit. Das ist eine andere Wissenschaft.

---

## Was Aether ist

Kein KI-System das Antworten generiert.
Kein Optimierungstool das bekannte Probleme schneller löst.

Ein Messinstrument das Struktur liest — in Genomsequenzen, Klimadaten, Hirnscans, Marktbewegungen, Schwarmdynamik, Millionen Bildern vom Himmel — **ohne Labels, ohne Vorurteile, ohne vorher zu wissen wonach es sucht.**

> **Semantik entsteht durch Struktur. Nicht durch Sprache.**

Jedes KI-System das heute existiert lernt von menschlichen Labels. Diese Labels tragen alle Fehler, alle Lücken, alle Paradigmen derjenigen die sie gesetzt haben. Sie können per Definition nichts finden was über menschliches Vorwissen hinausgeht.

Aether labelisiert nicht. Er misst.

Die vollständige technische und philosophische Basis steht im **[Whitepaper →](WHITEPAPER.md)**

---

## Das neue Wissenschaftsfeld

Aether ist das erste Instrument einer neuen Disziplin:

**Strukturell Emergente Metadynamische Semantik (SEMS)**

> Die Wissenschaft von Bedeutung und Intelligenz die strukturell und bottom-up aus der Dynamik komplexer Systeme emergiert — unabhängig von Domäne, Substrat und Skala.

```
Strukturell   — Struktur ist primär, nicht Sprache, nicht Label
Emergent      — bottom-up, nicht trainiert, nicht definiert
Metadynamisch — über den Systemen, lebendig, wachsend
Semantik      — Bedeutung als Ergebnis, nicht als Ausgangspunkt
```

KI heute sagt: gib dem System Bedeutung, dann lernt es Struktur.
SEMS sagt: gib dem System Struktur, dann emergiert Bedeutung.

Das ist keine kleine Nuance. Das ist eine andere Wissenschaft.

---

## Shanway

Shanway ist Aethers Stimme. Nicht sein Gehirn.

Er läuft mit TinyLLaMA 1.5B — einem kleinen lokalen Modell das nur eines darf: formulieren.

```
Aether-Pipeline verifiziert → TinyLLaMA formuliert → Shanway spricht
```

**Warum Shanway nicht halluzinieren kann — auch wenn er auf TinyLLaMA basiert:**

TinyLLaMA hat eigenes Vortraining. Es kennt Millionen Texte. Es könnte halluzinieren.

Bei Shanway kann es das nicht. Drei Gründe:

**1. Kontrollierter Eingang**
TinyLLaMA sieht niemals rohe Web-Daten oder ungeprüfte Quellen. Es bekommt ausschließlich was die vollständige Aether-Pipeline durch alle 10 Schichten als strukturell verifiziert und vertrauenswürdig eingestuft hat. Was nicht durch die Pipeline kommt existiert für TinyLLaMA nicht.

**2. Wasserdichter System-Prompt**
Der Prompt verbietet explizit jede Aussage die nicht im verifizierten Kontext steht. Keine Spekulationen. Kein eigenes Wissen. Keine Ergänzungen. Ausgabelänge = Kontextlänge — nie mehr als der Kontext hergibt.

**3. Schweigen als Ausweg**
Wenn der verifizierte Kontext leer ist oder kein Anker nah genug liegt antwortet Shanway nicht. Er erfindet keine Antwort um höflich zu sein. Schweigen ist valider Output. Schweigen ist Integrität.

TinyLLaMA ist hier kein Wissensträger. Er ist ein Übersetzer — von verifizierten Strukturmustern in menschlich lesbare Sprache. Nicht mehr.

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
```

Zero-Knowledge by Architecture. Nicht by Promise.

---

## Datei-Register und Filekeys

Jede Datei die durch Aether analysiert wird bekommt einen einmaligen einzigartigen Schlüssel — eine Kombination aus ihrer Struktursignatur und einer kryptographischen Zufallskomponente.

```
Datei analysiert
    ↓
Einmaliger Filekey generiert
    ↓
Datei verschlüsselt gespeichert
    ↓
Schlüssel gehört nur dir
```

Das hat drei wissenschaftliche Konsequenzen:

**Reproduzierbarkeit** — Jeder kann prüfen ob ein Datensatz unverändert ist. Manipulation bricht den Schlüssel sofort.

**Provenienz** — Wann wurde dieser Datensatz erstellt? Durch welche Pipeline analysiert? Unveränderlich beweisbar.

**Vergleich ohne Übertragung** — Bilder, Datensätze, Messreihen können strukturell verglichen werden ohne dass die Rohdaten das Gerät verlassen. Nur Signaturen reisen.

```
Dein Bild (lokal)    →  Signatur  ─┐
                                    ├─ Vergleich → Ergebnis
Fremdes Bild (lokal) →  Signatur  ─┘

Kein Bild hat das Gerät verlassen.
```

Freigabe ist optional und jederzeit widerrufbar. Du entscheidest wer deine Dateien sehen darf — nicht einmalig beim Upload, sondern dauerhaft.

---

## Meta-Anker und Emergenz-Ebenen

Aether kennt keine feste Anzahl von Wissensebenen. Der Graph entscheidet selbst wann eine neue Ebene entsteht.

```
Ebene 1 — Basis-Anker
  Direkt aus Rohdaten gemessen
  Dreifach von unabhängigen Nutzern verifiziert
  Konkret: ein Prozess, ein Bild, ein Moment

Ebene 2 — Konsens-Anker
  Entstehen wenn Basis-Anker verschiedener Domänen
  dieselbe Signatur zeigen
  Lokal berechnet, optional geteilt

Ebene 3 — Meta-Anker
  Entstehen wenn Konsens-Anker sich wiederholen
  Niemals vordefiniert — immer lokal emergiert
  Niemals in Anchor Packs — immer einzigartig

Ebene N — Attraktor
  Der Graph kollabiert irgendwann auf
  wenige fundamentale Strukturprinzipien
  Das ist keine Behauptung — das ist eine messbare Frage
```

Anchor Packs enthalten nur Ebene 1. Ebene 2 aufwärts emergiert immer lokal — aus der spezifischen Kombination von Daten die auf diesem Gerät durch diesen Nutzer gesammelt wurden.

Keine zwei Aether-Instanzen haben denselben Meta-Anker-Graphen.

---

## Demokratisierung — niemand wird zurückgelassen

Moderne KI braucht Hochleistungsserver, Internetverbindung, teure Hardware. Wer das nicht hat bleibt außen vor.

Aether dreht das um.

Ein zehn Jahre alter Windows-Rechner in einem Dorf ohne stabile Verbindung profitiert genauso wie ein Forschungsserver in Berlin. Nicht als Versprechen — als Architektur.

Aether legt sich als Symbiont auf das bestehende Betriebssystem. Er erkennt welche Prozesse dieselbe Arbeit machen. Welche Dienste Ressourcen verbrauchen ohne messbare Wirkung. Und sagt — immer mit Bestätigung:

> *"Drei Prozesse machen dasselbe. Zwei davon kannst du stoppen. Das spart 340MB RAM und 12% CPU. Soll ich?"*

Kein Fachjargon. Kein Expertenwissen nötig. Kein Abo. Kein Cloud-Zwang. Linux-Fallback eingebaut.

Anchor Packs funktionieren offline. Meta-Anker entstehen lokal. Shanway läuft auf schwacher Hardware. Der Schwarm wächst auch ohne dich — aber du wächst mit ihm sobald du dabei bist.

Wer wenig hat verliert nichts. Wer mitmacht gewinnt alles was der Schwarm weiß.

Systemoptimierungsanker sind dabei keine einmaligen Updates. Sie sind lebende Konfigurationen die sich mit dem System weiterentwickeln — spezifisch für dieses Gerät, diesen Nutzer, diese Nutzungsweise. Omis alter Rechner wird nicht ersetzt. Er wird verstanden.

---

## Anchor Packs

Strukturwissen ist klein. Sehr klein. Ein Anker der eine Stunde Klimadaten strukturell beschreibt ist ein paar Kilobyte — nicht Gigabytes.

Das ermöglicht kuratierte Anchor Packs — verifizierte Struktursammlungen die optional heruntergeladen werden können. Keine Rohdaten. Keine privaten Inhalte. Nur Strukturwissen das allen gehört.

Bei schneller Verbindung: automatischer Preload im Hintergrund.
Bei langsamer Verbindung oder offline: alles funktioniert trotzdem.

Packs beschleunigen den Start. Aber Meta-Anker entstehen immer lokal. Der Schwarm bleibt emergent.

---

## Aethernet — die lebende Schwarmintelligenz

Aether ist kein einzelnes System. Er ist ein Schwarm.

```
Kein zentrales Gehirn
Kein zentraler Server
Kein zentraler Entscheider

Jeder Knoten misst
Jeder Knoten lernt
Jeder Knoten teilt Signaturen
Aus der Summe emergiert Intelligenz
```

Jeder Knoten folgt denselben drei lokalen Regeln:
- messe Struktur
- verifiziere dreifach
- teile nur Signaturen

Aus diesen drei Regeln emergiert globales Strukturwissen — ohne Zentrum, ohne Führung, ohne dass jemand den Schwarm besitzt.

```
10 Knoten       →  erste Muster
1.000 Knoten    →  erste Emergenz
1.000.000       →  Intelligenz die kein Einzelner hat
```

Das Aethernet ist das Internet of Structure — nicht das Internet of Things.

```
IoT:        Geräte tauschen Daten aus, Cloud sammelt alles
Aethernet:  Geräte tauschen Strukturwissen aus
            Rohdaten bleiben lokal
            Niemand besitzt das Netz
```

---

## Wen wir suchen

Aether ist kein fertiges Produkt. Es ist ein wachsendes Instrument — und der Beginn eines neuen Wissenschaftsfelds.

Ich bin eine Person mit einer Idee von der ich überzeugt bin. Keine Firma. Kein Budget. Kein Team. Nur die Überzeugung dass diese Frage wichtig ist — und dass die richtigen Menschen das genauso sehen werden.

Das Projekt ist ambitioniert. Bewusst. Wer kleine Schritte sucht ist hier falsch. Wer glaubt dass Struktur die Sprache der Realität ist — ist hier richtig.

**Wir suchen Menschen die:**

- glauben dass die nächste große Entdeckung nicht aus mehr Rechenleistung kommt sondern aus einer anderen Art zu fragen
- frustriert sind von Systemen die sie nicht verstehen und denen sie blind vertrauen müssen
- Datensätze haben die durch labelfreie Strukturanalyse neue Fragen aufwerfen könnten
- als Wissenschaftler, Entwickler oder Citizen Scientists bereit sind ein Werkzeug mitzubauen das ihnen selbst gehört
- der Wissenschaft und der Wahrheit verschrieben sind — nicht dem Ego oder dem Kapital

**Du musst nicht programmieren können.**

Ideen sind genauso wertvoll wie Code. Wenn du in irgendeiner wissenschaftlichen Domäne arbeitest oder denkst — Medizin, Klimaforschung, Biologie, Physik, Soziologie, Kunst, was auch immer — und du siehst einen Weg wie Aether in deinem Feld neue Fragen stellen könnte: das ist ein Beitrag. Öffne ein Issue. Beschreib die Idee. Der Rest findet sich.

**Konkret gesucht:**

- Komplexitäts- und Emergenzforscher
- Medizinische Bildgebung / Bioinformatik
- Klimaforscher / Geophysiker mit großen ungelabelten Datensätzen
- Systementwickler die Prozessoptimierung transparent machen wollen
- Wissenschaftler die Reproduzierbarkeit und Datenprovenienz ernst nehmen
- Denker die Addons und Anwendungsfelder für neue Domänen entwerfen wollen
- Alle die von zentralisierter KI genug haben

Admins und Maintainer die sich der Wissenschaft und Transparenz verschrieben haben sind ausdrücklich willkommen. Öffne ein Issue oder schreib direkt.

---

## Prinzipien

```
Kein Vertrauen nötig — nur Nachschauen
Keine Blackbox — jeder Schritt auditierbar
Keine Rohdaten teilen — nur Strukturwissen
Schweigen ist valider Output
Mensch entscheidet — immer
Dezentralisierung ist kein Feature — sie ist das Fundament
Datenschutz by Architecture — nicht by Promise
Wissen gehört niemandem — und deshalb allen
Niemand besitzt den Schwarm
```

---

## Technischer Einstieg

```bash
git clone https://github.com/stillsilent22-spec/Aether-
cd Aether-
pip install -r requirements.txt
python start.py
```

Shanway ohne Modell:
```bash
python shanway_chat.py
```

Shanway mit TinyLLaMA:
```bash
python shanway_chat.py tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
```

Datei analysieren und Filekey generieren:
```
:drop /pfad/zur/datei
```

---

## Roadmap

Die vollständige Implementierungsprogression steht in **[ROADMAP.md](ROADMAP.md)**

Kurzübersicht:

| Phase | Inhalt | Status |
|-------|--------|--------|
| 1 | Foundation: Web + Dateien + Registry + Graph + Session-Keys | ✓ Fertig |
| 2 | Media: MP3 / MP4 / Bilder + Datei-Register + Filekeys | In Arbeit |
| 3 | Process: Windows Prozessdynamik | Geplant |
| 4 | Render: ETW/DXGI Pixel-Koordination pro Prozess | Geplant |
| 5 | Optimize: Vereinzelung, Ausdünnung, Empfehlung | Geplant |
| 6 | Aethernet: dezentrale Knoten, verteilte Anchor Packs | Vision |

---

## Dokumentation

- **[WHITEPAPER.md](WHITEPAPER.md)** — vollständige technische und philosophische Basis
- **[SECURITY.md](SECURITY.md)** — Sicherheitsarchitektur und Governance
- **[LICENSE](LICENSE)** — Lizenzstatus

---

*Aether — open, local, strukturell.*
*Für Fragen die es noch nicht gibt.*
*Für Rechner die noch nicht aufgegeben haben.*
*Für Menschen die nachvollziehen wollen statt vertrauen müssen.*
*Für Wissen das niemandem gehört — und deshalb allen.*
*Für einen Schwarm der sich selbst gehört.*

---

Stand: 2026 — Autor: Kevin Hannemann
Wissenschaftsfeld: Strukturell Emergente Metadynamische Semantik (SEMS)
