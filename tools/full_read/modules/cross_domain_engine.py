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
import random
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
    emergence_score: float = 0.0
    p_value: float = 1.0
    stability_score: float = 0.0
    lag_hint: Optional[dict[str, float | str]] = None
    significant: bool = False

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
    # Emergence Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _quantile(values: list[float], q: float) -> float:
        if not values:
            return 0.0
        ranked = sorted(float(v) for v in values)
        idx = int(max(0, min(len(ranked) - 1, round((len(ranked) - 1) * q))))
        return float(ranked[idx])

    @staticmethod
    def _time_window_coverage(cluster_anchors: list[RawAnchor], span_days: float) -> tuple[int, int, float]:
        if not cluster_anchors:
            return 0, 0, 0.0
        span_seconds = max(1.0, float(span_days) * 86400.0)
        timestamps = [float(a.timestamp) for a in cluster_anchors]
        t_min = min(timestamps)
        t_max = max(timestamps)
        total_windows = max(1, int(math.floor((t_max - t_min) / span_seconds)) + 1)
        covered = {
            int(math.floor((float(a.timestamp) - t_min) / span_seconds))
            for a in cluster_anchors
        }
        covered_windows = max(1, len(covered))
        stability = covered_windows / float(total_windows)
        return covered_windows, total_windows, float(max(0.0, min(1.0, stability)))

    @staticmethod
    def _lag_hint(cluster_anchors: list[RawAnchor], span_days: float) -> dict[str, float | str]:
        by_domain: dict[str, list[float]] = defaultdict(list)
        for anchor in cluster_anchors:
            by_domain[str(anchor.domain)].append(float(anchor.timestamp))

        if len(by_domain) < 2:
            return {
                "direction": "undetermined",
                "lag_days": 0.0,
                "consistency": 0.0,
            }

        centers: dict[str, float] = {
            domain: (sum(values) / float(max(1, len(values))))
            for domain, values in by_domain.items()
        }
        ordered = sorted(centers.items(), key=lambda item: item[1])
        earliest_domain, earliest_ts = ordered[0]
        latest_domain, latest_ts = ordered[-1]
        lag_days = max(0.0, (latest_ts - earliest_ts) / 86400.0)
        scale_days = max(1.0, float(span_days))
        consistency = max(0.0, 1.0 - min(1.0, lag_days / scale_days))
        return {
            "direction": f"{earliest_domain}->{latest_domain}",
            "lag_days": round(float(lag_days), 4),
            "consistency": round(float(consistency), 6),
        }

    @staticmethod
    def _permute_points(points: list[list[float]], rng: random.Random) -> list[list[float]]:
        if not points:
            return []
        dim = len(points[0])
        columns: list[list[float]] = [[row[d] for row in points] for d in range(dim)]
        for column in columns:
            rng.shuffle(column)
        return [[columns[d][i] for d in range(dim)] for i in range(len(points))]

    def _null_relevance_distribution(
        self,
        anchors: list[RawAnchor],
        norm_points: list[list[float]],
        eps: float,
        min_samples: int,
        iterations: int,
        random_seed: int,
    ) -> list[float]:
        if not anchors or not norm_points or iterations <= 0:
            return []
        rng = random.Random(int(random_seed))
        now = time.time()
        week_ago = now - 7 * 86400
        distribution: list[float] = []

        for _ in range(int(iterations)):
            permuted = self._permute_points(norm_points, rng)
            labels = _dbscan(permuted, eps, min_samples)
            groups: dict[int, list[int]] = defaultdict(list)
            for idx, lbl in enumerate(labels):
                if lbl >= 0:
                    groups[lbl].append(idx)

            for indices in groups.values():
                if not indices:
                    continue
                cluster_anchors = [anchors[i] for i in indices]
                domains = {a.domain for a in cluster_anchors}
                centroid = [
                    sum(permuted[i][d] for i in indices) / float(len(indices))
                    for d in range(len(permuted[0]))
                ]
                mean_dist = sum(_euclidean(permuted[i], centroid) for i in indices) / float(len(indices))
                recent = sum(1 for a in cluster_anchors if a.timestamp >= week_ago)
                growth = recent / float(max(1, len(cluster_anchors)))
                distribution.append(
                    compute_relevance(
                        n_anchors=len(cluster_anchors),
                        n_domains=len(domains),
                        growth_rate=growth,
                        mean_distance=mean_dist,
                    )
                )
        return distribution

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
        min_persistence_windows: int = 1,
        window_span_days: float = 30.0,
        enable_null_model: bool = False,
        null_iterations: int = 200,
        significance_alpha: float = 0.05,
        random_seed: int = 42,
        min_emergence_score: float = 0.0,
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

        null_distribution: list[float] = []
        null_threshold = 0.0
        if enable_null_model:
            null_distribution = self._null_relevance_distribution(
                anchors=anchors,
                norm_points=norm_points,
                eps=eps,
                min_samples=min_samples,
                iterations=int(max(0, null_iterations)),
                random_seed=int(random_seed),
            )
            null_threshold = self._quantile(null_distribution, 1.0 - float(significance_alpha))

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

                covered_windows, _total_windows, stability = self._time_window_coverage(
                    cluster_anchors,
                    span_days=window_span_days,
                )
                if covered_windows < max(1, int(min_persistence_windows)):
                    continue

                lag_hint = self._lag_hint(cluster_anchors, span_days=window_span_days)
                lag_consistency = float(lag_hint.get("consistency", 0.0) or 0.0)

                total_domains_in_window = max(1, len({a.domain for a in anchors}))
                domain_mix = min(1.0, len(domains) / float(total_domains_in_window))
                density = max(0.0, 1.0 - min(1.0, float(mean_dist)))
                emergence_score = 100.0 * (
                    (0.35 * density)
                    + (0.25 * domain_mix)
                    + (0.20 * stability)
                    + (0.20 * lag_consistency)
                )
                emergence_score = float(max(0.0, min(100.0, emergence_score)))

                if emergence_score < float(min_emergence_score):
                    continue

                p_value = 1.0
                significant = False
                if enable_null_model and null_distribution:
                    ge_count = sum(1 for value in null_distribution if float(value) >= float(rel))
                    p_value = float((ge_count + 1) / float(len(null_distribution) + 1))
                    significant = bool(rel >= null_threshold and p_value <= float(significance_alpha))
                elif enable_null_model:
                    significant = False
                else:
                    significant = True

                if enable_null_model and not significant:
                    continue

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
                    emergence_score=float(round(emergence_score, 6)),
                    p_value=float(round(p_value, 6)),
                    stability_score=float(round(stability, 6)),
                    lag_hint=dict(lag_hint),
                    significant=bool(significant),
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
                    "emergence_score": c.emergence_score,
                    "p_value": c.p_value,
                    "stability_score": c.stability_score,
                    "lag_hint": c.lag_hint,
                    "significant": c.significant,
                    "first_seen": c.first_seen,
                    "last_updated": c.last_updated,
                    "disclaimer": self.DISCLAIMER_DE,
                }
        return None

    def summary_text(self, lang: str = "de", top_n: int = 5) -> str:
        """Kurze Zusammenfassung der Top-Cluster fuer Assistant (kein GUI erforderlich)."""
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
                    f"Emergence {c.emergence_score:.0f}/100 \u00b7 p={c.p_value:.3f} \u00b7 "
                    f"{c.n_anchors} anchors across {c.n_domains} domain(s): {c.domain_summary()}"
                )
            else:
                lines.append(
                    f"Cluster {c.cluster_id[:8]} \u00b7 Relevanz {c.relevance_score:.0f}/100 \u00b7 "
                    f"Emergenz {c.emergence_score:.0f}/100 \u00b7 p={c.p_value:.3f} \u00b7 "
                    f"{c.n_anchors} Anker in {c.n_domains} Dom\u00e4ne(n): {c.domain_summary()}"
                )

        prefix = (
            f"Top-{len(lines)} dom\u00e4nen\u00fcbergreifende Muster:\n"
            if lang == "de"
            else f"Top-{len(lines)} cross-domain patterns:\n"
        )
        return prefix + "\n".join(lines) + "\n\n" + disclaimer

    def assistant_notification(self, lang: str = "de", threshold: float = 70.0) -> Optional[str]:
        """
        Optional: Assistant-Benachrichtigung bei neuem hochrelevantem Cluster (Score >= threshold).
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
            "top_emergence": self._clusters[0].emergence_score if self._clusters else 0.0,
            "significant_clusters": sum(1 for c in self._clusters if c.significant),
            "domains_covered": len(
                {d for c in self._clusters for d in c.domains}
            ),
        }
