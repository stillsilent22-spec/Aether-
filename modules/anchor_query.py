from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""
Aether – Anchor Query Adapter für Assistant.

Macht Basis-, Konsens- und Meta-Anker über eine einheitliche API
abfragbar — ohne dass Assistant direkt auf SQLite zugreift.

Privacy-Garantie: Keine Rohdaten, nur strukturelle Metadaten.
"""


import time
from pathlib import Path
from typing import Any

_DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "process_anchors.db"


def _store(db_path: Path | None = None):
    from .process_anchor_store import ProcessAnchorStore
    return ProcessAnchorStore(db_path or _DEFAULT_DB)


class AnchorQuery:
    """
    Assistant-seitige Schnittstelle zum Anker-Store.

    Alle Methoden geben strukturelle Zusammenfassungen zurück —
    kein Prozessinhalt, keine PID-Liste, keine Benutzeridentität.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB

    @property
    def _store(self):
        from .process_anchor_store import ProcessAnchorStore
        return ProcessAnchorStore(self._db_path)

    # ------------------------------------------------------------------
    # Rohe Abfragen (intern)
    # ------------------------------------------------------------------

    def get_meta_anchors(self, limit: int = 20) -> list[dict[str, Any]]:
        """Gibt die neuesten Meta-Anker zurück."""
        return self._store.get_meta_anchors(limit=limit)

    def get_consensus_anchors(self, limit: int = 50) -> list[dict[str, Any]]:
        """Gibt die neuesten Konsens-Anker zurück."""
        return self._store.get_consensus_anchors(limit=limit)

    def get_clusters(
        self,
        eps: float = 12.0,
        min_samples: int = 2,
        window_hours: float = 168.0,
    ) -> list[dict[str, Any]]:
        """Führt DBSCAN-Clustering auf Konsens-Ankern durch."""
        return self._store.cluster_consensus_anchors(
            eps=eps, min_samples=min_samples, window_hours=window_hours
        )

    # ------------------------------------------------------------------
    # Assistant-formatierte Ausgaben (Fließtext)
    # ------------------------------------------------------------------

    def describe_meta_anchors(self, limit: int = 10) -> str:
        """
        Erzeugt eine Assistant-lesbare Zusammenfassung der Meta-Anker.

        Ausgabe enthält ausschließlich strukturelle Beobachtungen —
        keine Interpretationen, keine Kausalaussagen.
        """
        anchors = self.get_meta_anchors(limit=limit)
        if not anchors:
            return "Keine Meta-Anker vorhanden. Noch zu wenig Beobachtungszeit."

        lines = [
            "Strukturelle Beobachtungen (Meta-Ebene, Ebene 3):",
            "",
        ]
        for a in anchors:
            corr = float(a.get("correlation", 0.0))
            direction = "positiv" if corr >= 0 else "negativ"
            lines.append(
                f"• {a['trigger_name']} ↔ {a['effect_name']}: "
                f"{direction} korreliert ({corr:+.2f})"
            )
            obs = a.get("observation", "")
            if obs:
                lines.append(f"  → {obs}")
        lines.append("")
        lines.append(
            "Hinweis: Strukturkorrelation ≠ Kausalität. "
            "Befunde erfordern domänenspezifische Prüfung."
        )
        return "\n".join(lines)

    def describe_clusters(
        self,
        eps: float = 12.0,
        min_samples: int = 2,
        window_hours: float = 168.0,
    ) -> str:
        """
        Zusammenfassung der DBSCAN-Cluster für Assistant.

        Spiegelt Gruppen strukturell ähnlicher Prozesse wider.
        """
        clusters = self.get_clusters(
            eps=eps, min_samples=min_samples, window_hours=window_hours
        )
        if not clusters:
            return "Keine Cluster erkennbar. Datenbasis zu klein oder zu heterogen."

        lines = [
            f"DBSCAN-Cluster (eps={eps}, min_samples={min_samples}, "
            f"Fenster={window_hours:.0f}h):",
            "",
        ]
        for c in clusters:
            cid = c["cluster_id"]
            label = "(Rauschen)" if cid == -1 else f"Cluster {cid}"
            names = ", ".join(sorted(c["process_names"])[:6])
            if len(c["process_names"]) > 6:
                names += f", … ({len(c['process_names'])} gesamt)"
            dom = c.get("dominant_label", "")
            lines.append(
                f"• {label} [{c['size']} Anker]: {names}"
            )
            lines.append(
                f"  CPU: ~{c['centroid_cpu']:.1f}%  "
                f"RAM: ~{c['centroid_memory_mb']:.0f} MB  "
                f"Threads: ~{c['centroid_threads']:.1f}"
                + (f"  Muster: {dom}" if dom else "")
            )
        return "\n".join(lines)

    def describe_snapshot_summary(self) -> str:
        """Kurze Statusmeldung über den aktuellen Anker-Store."""
        count = self._store.count_snapshots()
        consensus = len(self.get_consensus_anchors(limit=1000))
        meta = len(self.get_meta_anchors(limit=1000))
        return (
            f"Anker-Store: {count} Basis-Snapshots, "
            f"{consensus} Konsens-Anker, "
            f"{meta} Meta-Anker."
        )

    def full_report_for_assistant(self) -> str:
        """
        Vollständiger struktureller Bericht — für Assistant-Abfragen.

        Kein roher Prozessinhalt. Nur strukturelle Beobachtungen.
        """
        sections = [
            "=== Aether Prozess-Beobachtungsbericht ===",
            "",
            self.describe_snapshot_summary(),
            "",
            self.describe_clusters(),
            "",
            self.describe_meta_anchors(),
        ]
        return "\n".join(sections)

    # ------------------------------------------------------------------
    # Keyword-basierte Filterabfrage
    # ------------------------------------------------------------------

    def query_meta_anchors(
        self,
        keyword: str = "",
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Filtert Meta-Anker nach Prozessnamen oder Beobachtungstext.

        keyword — Teilstring für Filter (leer = alle)
        """
        anchors = self.get_meta_anchors(limit=limit * 3)
        if not keyword:
            return anchors[:limit]
        kw = keyword.lower()
        return [
            a for a in anchors
            if kw in a.get("trigger_name", "").lower()
            or kw in a.get("effect_name", "").lower()
            or kw in a.get("observation", "").lower()
        ][:limit]


# ---------------------------------------------------------------------------
# Standalone-Modus
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    db_arg = sys.argv[1] if len(sys.argv) > 1 else None
    q = AnchorQuery(db_arg)
    print(q.full_report_for_assistant())
