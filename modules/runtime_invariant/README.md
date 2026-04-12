# Runtime & Invariant Package

Dieses Paket gruppiert die Aether Runtime- und Invariant-Module unter einem klaren Namespace.
Es ist ein Wrapper-Paket, das die bestehenden Module aus `modules/` verfügbar macht, ohne deren aktuelle Implementierung aufzulösen.

Ziel:
- Klare Ordnerstruktur für Runtime- und Invariant-Komponenten
- Einfacher Import via `from modules.runtime_invariant import ...`
- Saubere Trennung zwischen Shell/UI und Analyse-Logik
