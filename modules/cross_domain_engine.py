"""
Aether Cross-Domain Pattern Engine
-----------------------------------
Erkennt domaenenuebergreifende Muster durch DBSCAN-Clustering von Ankern aus
verschiedenen Quellen. Alle Berechnungen laufen lokal; keine Rohdaten verlassen
das Geraet.

WICHTIGER HINWEIS: Alle erkannten Muster sind strukturelle Aehnlichkeiten,
keine gesicherten Erkenntnisse. Ob ein Muster eine gemeinsame Ursache oder
Bedeutung hat, muss in der jeweiligen Fachrichtung erforscht werden.

Verwendung:
    engine = CrossDomainEngine("data/cross_domain.db")
    engine.ingest_anchors([
        RawAnchor("id1", "medizin", "EEG-Studie X", [0.1, 0.4, 0.9]),
        RawAnchor("id2", "klima",   "Ozean-Serie Y", [0.13, 0.38, 0.88]),
        ...
    ])
    clusters = engine.cluster(eps=0.35, min_samples=3)
    for c in clusters:
        print(c.cluster_id[:8], c.relevance_score, c.domain_summary())
"""

from __future__ import annotations

import json
import math
import sqlite3
import time
import uuid
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RawAnchor:
    """Minimale Darstellung eines Ankerpunkts fuer das Clustering."""
    anchor_id: str
    domain: str           # z.B. "medizin", "klima", "prozesse"
    source: str           # anonymisierte Quellbeschreibung
    features: list[float] # Merkmalsvektor (wird intern normalisiert)
    timestamp: float = field(default_factory=time.time)


@dataclass
class CrossDomainCluster:
    """Ein domaenenuebergreifendes Cluster."""
    cluster_id: str
    anchors: list[RawAnchor]
    domains: dict[str, int]   # domain -> Anzahl Anker
    centroid: list[float]     # Clustermittelpunkt (normalisierter Raum)
    mean_distance: float      # mittlere Distanz zum Zentrum
    relevance_score: float    # 0 – 100
    first_seen: float         # Unix-Timestamp
    last_updated: float       # Unix-Timestamp

    @property
    def n_anchors(self) -> int:
        return len(self.anchors)

    @property
    def n_domains(self) -> int:
        return len(self.domains)

    def domain_summary(self) -> str:
        """z.B. '12 Medizin, 5 Klima, 3 Astrophysik'"""
        parts = [
            f"{v} {k.capitalize()}"
            for k, v in sorted(self.domains.items(), key=lambda x: -x[1])
        ]
        return ", ".join(parts)


# ---------------------------------------------------------------------------
# Pure-Python DBSCAN  (kein sklearn erforderlich)
# ---------------------------------------------------------------------------

def _euclidean(a: list[float], b: list[float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def _dbscan(points: list[list[float]], eps: float, min_samples: int) -> list[int]:
    """
    Pure-Python DBSCAN — O(n^2).
    Rueckgabe: Labels (int-Liste), -1 = Rauschen, >=0 = Cluster-ID.
    """
    n = len(points)
    labels: list[int] = [-1] * n
    visited: list[bool] = [False] * n
    cluster_id = 0

    def region_query(idx: int) -> list[int]:
        return [j for j in range(n) if _euclidean(points[idx], points[j]) <= eps]

    def expand_cluster(idx: int, neighbors: list[int], cid: int) -> None:
        labels[idx] = cid
        i = 0
        while i < len(neighbors):
            nb = neighbors[i]
            if not visited[nb]:
                visited[nb] = True
                nb_neighbors = region_query(nb)
                if len(nb_neighbors) >= min_samples:
                    neighbors.extend(nb_neighbors)
            if labels[nb] == -1:
                labels[nb] = cid
            i += 1

    for idx in range(n):
        if visited[idx]:
            continue
        visited[idx] = True
        neighbors = region_query(idx)
        if len(neighbors) < min_samples:
            labels[idx] = -1  # Rauschen
        else:
            expand_cluster(idx, neighbors, cluster_id)
            cluster_id += 1

    return labels


# ---------------------------------------------------------------------------
# Relevanzbewertung
# ---------------------------------------------------------------------------

def compute_relevance(
    n_anchors: int,
    n_domains: int,
    growth_rate: float,   # Anteil neuer Anker (letzte 7 Tage)
    mean_distance: float,
    alpha: float = 0.6,
    beta: float = 0.8,
    epsilon: float = 1e-6,
) -> float:
    """
    relevance = (n_anchors^alpha * n_domains^beta * (1 + growth_rate))
                / (mean_distance + epsilon)

    Auf [0, 100] begrenzt.
    """
    raw = (
        (n_anchors ** alpha)
        * (n_domains ** beta)
        * (1.0 + growth_rate)
        / (mean_distance + epsilon)
    )
    return round(min(100.0, raw), 1)


# ---------------------------------------------------------------------------
# CrossDomainEngine
# ---------------------------------------------------------------------------

class CrossDomainEngine:
    """
    Hauptengine fuer domaenenuebergreifende Musteranalyse.

    Alle Ergebnisse sind Hypothesen basierend auf strukturellen Aehnlichkeiten —
    keine gesicherten wissenschaftlichen Erkenntnisse.
    """

    DISCLAIMER_DE = (
        "\u26a0\ufe0f  Strukturelle Auff\u00e4lligkeit \u2013 keine gesicherte Erkenntnis.\n"
        "Dieses Muster basiert ausschlie\u00dflich auf mathematischen \u00c4hnlichkeiten.\n"
        "Ob es eine gemeinsame Ursache oder Bedeutung gibt, muss in der jeweiligen\n"
        "Fachrichtung erforscht werden."
    )

    DISCLAIMER_EN = (
        "\u26a0\ufe0f  Structural anomaly \u2013 no confirmed finding.\n"
        "This pattern is based solely on mathematical similarities.\n"
        "Whether it has a common cause or meaning must be investigated\n"
        "in the respective field of research."
    )

    def __init__(self, db_path: str | Path = "data/cross_domain.db") -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._clusters: list[CrossDomainCluster] = []
        self._init_db()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        con = sqlite3.connect(self._db_path, timeout=10, check_same_thread=False)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def _init_db(self) -> None:
        with self._conn() as con:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS cd_anchors (
                anchor_id   TEXT PRIMARY KEY,
                domain      TEXT NOT NULL,
                source      TEXT NOT NULL,
                features    TEXT NOT NULL,
                timestamp   REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cd_clusters (
                cluster_id      TEXT PRIMARY KEY,
                centroid        TEXT NOT NULL,
                mean_distance   REAL NOT NULL,
                relevance       REAL NOT NULL,
                first_seen      REAL NOT NULL,
                last_updated    REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cd_cluster_members (
                cluster_id  TEXT NOT NULL REFERENCES cd_clusters(cluster_id),
                anchor_id   TEXT NOT NULL REFERENCES cd_anchors(anchor_id),
                PRIMARY KEY (cluster_id, anchor_id)
            );
            """)

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    def ingest_anchors(self, anchors: list[RawAnchor]) -> int:
        """
        Fuegt Anker zur DB hinzu. Gibt Anzahl der neu eingefuegten Anker zurueck.
        Bestehende Anker (gleiche anchor_id) bleiben unveraendert.
        """
        added = 0
        with self._conn() as con:
            for a in anchors:
                cur = con.execute(
                    "INSERT OR IGNORE INTO cd_anchors"
                    "(anchor_id, domain, source, features, timestamp) VALUES (?,?,?,?,?)",
                    (a.anchor_id, a.domain, a.source, json.dumps(a.features), a.timestamp),
                )
                added += cur.rowcount
        return added

    def load_from_db(self) -> list[RawAnchor]:
        """Laedt alle Anker aus der DB."""
        anchors: list[RawAnchor] = []
        with self._conn() as con:
            for row in con.execute(
                "SELECT anchor_id, domain, source, features, timestamp FROM cd_anchors"
            ):
                anchors.append(RawAnchor(
                    anchor_id=row["anchor_id"],
                    domain=row["domain"],
                    source=row["source"],
                    features=json.loads(row["features"]),
                    timestamp=row["timestamp"],
                ))
        return anchors

    def anchor_count(self) -> int:
        with self._conn() as con:
            row = con.execute("SELECT COUNT(*) FROM cd_anchors").fetchone()
            return int(row[0]) if row else 0

    def clear_anchors(self) -> None:
        """Entfernt alle Anker und Cluster (fuer Tests)."""
        with self._conn() as con:
            con.executescript("""
                DELETE FROM cd_cluster_members;
                DELETE FROM cd_clusters;
                DELETE FROM cd_anchors;
            """)
        self._clusters = []

    # ------------------------------------------------------------------
    # Cluster
    # ------------------------------------------------------------------

    def cluster(
        self,
        anchors: Optional[list[RawAnchor]] = None,
        eps: float = 0.35,
        min_samples: int = 3,
        window_days: float = 365.0,
        require_multi_domain: bool = True,
    ) -> list[CrossDomainCluster]:
        """
        Fuehrt DBSCAN-Clustering auf den Ankern durch.

        Args:
            anchors: Zu clusternde Anker. Falls None: aus DB laden.
            eps: Epsilon-Radius fuer DBSCAN (normalisierter [0,1]-Raum).
            min_samples: Mindestanzahl Anker fuer ein Cluster.
            window_days: Nur Anker der letzten N Tage beruecksichtigen.
            require_multi_domain: Cluster muss Anker aus >=2 Domaenen enthalten.

        Returns:
            Liste von CrossDomainCluster, absteigend nach Relevanz sortiert.
        """
        if anchors is None:
            anchors = self.load_from_db()

        cutoff = time.time() - window_days * 86400
        anchors = [a for a in anchors if a.timestamp >= cutoff]

        if not anchors:
            self._clusters = []
            return []

        # Merkmalsraum-Dimensionalitaet
        dim = len(anchors[0].features)
        if dim == 0:
            self._clusters = []
            return []

        # Normalisierung auf [0, 1] pro Dimension
        mins = [min(a.features[d] for a in anchors) for d in range(dim)]
        maxs = [max(a.features[d] for a in anchors) for d in range(dim)]
        ranges = [max(1e-9, maxs[d] - mins[d]) for d in range(dim)]

        def normalize(f: list[float]) -> list[float]:
            return [(f[d] - mins[d]) / ranges[d] for d in range(dim)]

        norm_points = [normalize(a.features) for a in anchors]
        labels = _dbscan(norm_points, eps, min_samples)

        # Gruppen nach Cluster-Label
        groups: dict[int, list[int]] = defaultdict(list)
        for i, lbl in enumerate(labels):
            if lbl >= 0:
                groups[lbl].append(i)

        now = time.time()
        week_ago = now - 7 * 86400
        result: list[CrossDomainCluster] = []

        with self._conn() as con:
            # Alte Cluster-Zuordnungen entfernen
            con.execute("DELETE FROM cd_cluster_members")
            con.execute("DELETE FROM cd_clusters")

            for lbl, indices in groups.items():
                cluster_anchors = [anchors[i] for i in indices]
                norm_pts = [norm_points[i] for i in indices]

                # Domaenenverteilung
                domains: dict[str, int] = defaultdict(int)
                for a in cluster_anchors:
                    domains[a.domain] += 1

                if require_multi_domain and len(domains) < 2:
                    continue

                # Zentroid (im normalisierten Raum)
                centroid = [
                    sum(p[d] for p in norm_pts) / len(norm_pts)
                    for d in range(dim)
                ]

                # Mittlere Distanz zum Zentroid
                mean_dist = sum(
                    _euclidean(p, centroid) for p in norm_pts
                ) / len(norm_pts) if norm_pts else 0.0

                # Wachstumsrate (letzte 7 Tage)
                recent = sum(1 for a in cluster_anchors if a.timestamp >= week_ago)
                growth = recent / max(1, len(cluster_anchors))

                rel = compute_relevance(
                    n_anchors=len(cluster_anchors),
                    n_domains=len(domains),
                    growth_rate=growth,
                    mean_distance=mean_dist,
                )

                first_seen = min(a.timestamp for a in cluster_anchors)
                cid = str(uuid.uuid4())

                cluster = CrossDomainCluster(
                    cluster_id=cid,
                    anchors=cluster_anchors,
                    domains=dict(domains),
                    centroid=centroid,
                    mean_distance=mean_dist,
                    relevance_score=rel,
                    first_seen=first_seen,
                    last_updated=now,
                )
                result.append(cluster)

                # Persistierung
                con.execute(
                    "INSERT INTO cd_clusters"
                    "(cluster_id, centroid, mean_distance, relevance, first_seen, last_updated) "
                    "VALUES (?,?,?,?,?,?)",
                    (cid, json.dumps(centroid), mean_dist, rel, first_seen, now),
                )
                for a in cluster_anchors:
                    con.execute(
                        "INSERT OR IGNORE INTO cd_cluster_members(cluster_id, anchor_id) VALUES (?,?)",
                        (cid, a.anchor_id),
                    )

        result.sort(key=lambda c: c.relevance_score, reverse=True)
        self._clusters = result
        return result

    # ------------------------------------------------------------------
    # Query / Export
    # ------------------------------------------------------------------

    def get_clusters(self) -> list[CrossDomainCluster]:
        """Gibt die zuletzt berechneten Cluster zurueck."""
        return list(self._clusters)

    def export_meta_anchor(self, cluster_id_prefix: str) -> Optional[dict]:
        """
        Exportiert den Meta-Anker (Clusterzentrum) als Dict.
        Enthaelt keine Rohdaten — nur strukturelle Zusammenfassung.
        """
        for c in self._clusters:
            if c.cluster_id == cluster_id_prefix or c.cluster_id.startswith(cluster_id_prefix):
                return {
                    "cluster_id": c.cluster_id,
                    "centroid": c.centroid,
                    "n_anchors": c.n_anchors,
                    "domains": c.domains,
                    "relevance_score": c.relevance_score,
                    "first_seen": c.first_seen,
                    "last_updated": c.last_updated,
                    "disclaimer": self.DISCLAIMER_DE,
                }
        return None

    def summary_text(self, lang: str = "de", top_n: int = 5) -> str:
        """Kurze Zusammenfassung der Top-Cluster fuer Shanway (kein GUI erforderlich)."""
        disclaimer = self.DISCLAIMER_DE if lang == "de" else self.DISCLAIMER_EN

        if not self._clusters:
            no_data = (
                "Noch keine domaenenuebergreifenden Muster gefunden. Mehr Ankerdaten benoetigt."
                if lang == "de"
                else "No cross-domain patterns found yet. More anchor data needed."
            )
            return no_data

        lines: list[str] = []
        for c in self._clusters[:top_n]:
            if lang == "en":
                lines.append(
                    f"Cluster {c.cluster_id[:8]} \u00b7 Relevance {c.relevance_score:.0f}/100 \u00b7 "
                    f"{c.n_anchors} anchors across {c.n_domains} domain(s): {c.domain_summary()}"
                )
            else:
                lines.append(
                    f"Cluster {c.cluster_id[:8]} \u00b7 Relevanz {c.relevance_score:.0f}/100 \u00b7 "
                    f"{c.n_anchors} Anker in {c.n_domains} Dom\u00e4ne(n): {c.domain_summary()}"
                )

        prefix = (
            f"Top-{len(lines)} dom\u00e4nen\u00fcbergreifende Muster:\n"
            if lang == "de"
            else f"Top-{len(lines)} cross-domain patterns:\n"
        )
        return prefix + "\n".join(lines) + "\n\n" + disclaimer

    def shanway_notification(self, lang: str = "de", threshold: float = 70.0) -> Optional[str]:
        """
        Optional: Shanway-Benachrichtigung bei neuem hochrelevantem Cluster (Score >= threshold).
        Gibt None zurueck, wenn kein relevantes Cluster vorhanden.
        """
        high = [c for c in self._clusters if c.relevance_score >= threshold]
        if not high:
            return None
        c = high[0]
        if lang == "en":
            return (
                f"I discovered a new cross-domain pattern in {c.n_domains} independent domain(s) "
                f"({c.domain_summary()}). Relevance: {c.relevance_score:.0f}/100. "
                f"Would you like to view it in the 'Cross-Domain Patterns' tab?"
            )
        return (
            f"Ich habe ein neues dom\u00e4nen\u00fcbergreifendes Muster in {c.n_domains} "
            f"unabh\u00e4ngigen Dom\u00e4ne(n) entdeckt ({c.domain_summary()}). "
            f"Relevanz: {c.relevance_score:.0f}/100. "
            f"M\u00f6chtest du es im Tab \u2018Dom\u00e4nen\u00fcbergreifende Muster\u2019 ansehen?"
        )

    def stats(self) -> dict:
        """Statistische Zusammenfassung (fuer GUI / Reports)."""
        total_anchors = self.anchor_count()
        return {
            "total_anchors_in_db": total_anchors,
            "clusters_last_run": len(self._clusters),
            "top_relevance": self._clusters[0].relevance_score if self._clusters else 0.0,
            "domains_covered": len(
                {d for c in self._clusters for d in c.domains}
            ),
        }
