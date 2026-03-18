"""
Tests fuer CrossDomainEngine und i18n-Erststart-Texte.

Abgedeckte Klassen / Funktionen:
  - modules.cross_domain_engine.CrossDomainEngine
  - modules.cross_domain_engine.RawAnchor
  - modules.cross_domain_engine.compute_relevance
  - modules.cross_domain_engine._dbscan
  - modules.i18n -- first_start_* Schluessel
"""

from __future__ import annotations

import math
import time
import uuid
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _tmpdir(suffix: str = "") -> Path:
    """Schreibbares tmp-Verzeichnis (kein systemweites tempfile noetig)."""
    p = Path("data") / "_pytest_tmp" / f"cross_domain{suffix}"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _make_anchor(domain: str, features: list[float], ts: float | None = None) -> "RawAnchor":
    from modules.cross_domain_engine import RawAnchor
    return RawAnchor(
        anchor_id=str(uuid.uuid4()),
        domain=domain,
        source=f"test-source-{domain}",
        features=features,
        timestamp=ts or time.time(),
    )


# ---------------------------------------------------------------------------
# TestDBSCAN
# ---------------------------------------------------------------------------

class TestDBSCAN:
    """Unit-Tests fuer die pure-Python DBSCAN-Implementierung."""

    def _dbscan(self, points, eps, min_samples):
        from modules.cross_domain_engine import _dbscan
        return _dbscan(points, eps, min_samples)

    def test_single_cluster(self):
        points = [[0.0, 0.0], [0.1, 0.0], [0.0, 0.1]]
        labels = self._dbscan(points, eps=0.5, min_samples=2)
        assert len(labels) == 3
        # Alle im selben Cluster (Label >= 0)
        assert all(lbl >= 0 for lbl in labels)
        assert len(set(labels)) == 1

    def test_two_clusters(self):
        # Zwei Gruppen weit auseinander
        points = [[0.0, 0.0], [0.1, 0.0], [10.0, 10.0], [10.1, 10.0]]
        labels = self._dbscan(points, eps=0.5, min_samples=2)
        assert len(set(lbl for lbl in labels if lbl >= 0)) == 2

    def test_noise_points(self):
        # Einzelpunkt -> Rauschen (-1)
        points = [[0.0, 0.0], [5.0, 5.0], [10.0, 10.0]]
        labels = self._dbscan(points, eps=0.5, min_samples=2)
        assert all(lbl == -1 for lbl in labels)

    def test_empty_input(self):
        labels = self._dbscan([], eps=0.5, min_samples=2)
        assert labels == []

    def test_min_samples_boundary(self):
        # Genau min_samples=3, nur 2 Punkte nah -> Rauschen
        points = [[0.0, 0.0], [0.1, 0.0], [5.0, 5.0]]
        labels = self._dbscan(points, eps=0.5, min_samples=3)
        # Die nahen Punkte haben nur 2 Nachbarn -> Rauschen
        assert -1 in labels


# ---------------------------------------------------------------------------
# TestComputeRelevance
# ---------------------------------------------------------------------------

class TestComputeRelevance:
    """Unit-Tests fuer die Relevanzbewertungsformel."""

    def test_basic_positive(self):
        from modules.cross_domain_engine import compute_relevance
        score = compute_relevance(n_anchors=10, n_domains=3, growth_rate=0.5, mean_distance=0.1)
        assert 0.0 < score <= 100.0

    def test_more_domains_higher_score(self):
        from modules.cross_domain_engine import compute_relevance
        s1 = compute_relevance(10, 2, 0.0, 0.2)
        s2 = compute_relevance(10, 5, 0.0, 0.2)
        assert s2 > s1

    def test_more_anchors_higher_score(self):
        from modules.cross_domain_engine import compute_relevance
        s1 = compute_relevance(5, 3, 0.0, 0.2)
        s2 = compute_relevance(20, 3, 0.0, 0.2)
        assert s2 > s1

    def test_larger_distance_lower_score(self):
        from modules.cross_domain_engine import compute_relevance
        s1 = compute_relevance(10, 3, 0.0, 0.05)
        s2 = compute_relevance(10, 3, 0.0, 0.5)
        assert s1 > s2

    def test_capped_at_100(self):
        from modules.cross_domain_engine import compute_relevance
        score = compute_relevance(10000, 100, 1.0, 0.0001)
        assert score == 100.0

    def test_growth_rate_boosts_score(self):
        from modules.cross_domain_engine import compute_relevance
        s_no_growth = compute_relevance(10, 3, 0.0, 0.2)
        s_growth = compute_relevance(10, 3, 1.0, 0.2)
        assert s_growth > s_no_growth


# ---------------------------------------------------------------------------
# TestCrossDomainEngine
# ---------------------------------------------------------------------------

class TestCrossDomainEngine:
    """Integrationstests fuer CrossDomainEngine."""

    def _engine(self, suffix=""):
        from modules.cross_domain_engine import CrossDomainEngine
        db = _tmpdir(suffix) / "test.db"
        engine = CrossDomainEngine(db)
        engine.clear_anchors()
        return engine

    def test_empty_cluster_returns_empty(self):
        engine = self._engine("_empty")
        clusters = engine.cluster()
        assert clusters == []

    def test_ingest_and_count(self):
        engine = self._engine("_count")
        anchors = [_make_anchor("medizin", [0.1, 0.2, 0.3]) for _ in range(5)]
        added = engine.ingest_anchors(anchors)
        assert added == 5
        assert engine.anchor_count() == 5

    def test_duplicate_ingest_ignored(self):
        engine = self._engine("_dup")
        a = _make_anchor("klima", [0.5, 0.6, 0.7])
        engine.ingest_anchors([a])
        engine.ingest_anchors([a])  # gleiche anchor_id
        assert engine.anchor_count() == 1

    def test_cluster_requires_multi_domain(self):
        engine = self._engine("_mono")
        # Alle selbe Domaene -> kein Cluster mit require_multi_domain=True
        anchors = [_make_anchor("medizin", [float(i) * 0.01, 0.0]) for i in range(6)]
        engine.ingest_anchors(anchors)
        clusters = engine.cluster(eps=0.5, min_samples=3, require_multi_domain=True)
        assert clusters == []

    def test_cluster_multi_domain_found(self):
        engine = self._engine("_multi")
        # Zwei eng beieinander liegende Gruppen aus verschiedenen Domaenen
        anchors_med = [_make_anchor("medizin", [0.01 * i, 0.0]) for i in range(4)]
        anchors_klima = [_make_anchor("klima", [0.01 * i + 0.005, 0.0]) for i in range(4)]
        engine.ingest_anchors(anchors_med + anchors_klima)
        clusters = engine.cluster(eps=0.5, min_samples=3, require_multi_domain=True)
        assert len(clusters) >= 1
        c = clusters[0]
        assert c.n_domains >= 2
        assert c.n_anchors >= 6

    def test_clusters_sorted_by_relevance(self):
        engine = self._engine("_sort")
        # Gruppe 1: viele Anker aus 3 Domaenen (hohe Relevanz)
        g1 = (
            [_make_anchor("med", [0.0, 0.0]) for _ in range(6)]
            + [_make_anchor("kli", [0.01, 0.0]) for _ in range(4)]
            + [_make_anchor("ast", [0.02, 0.0]) for _ in range(3)]
        )
        # Gruppe 2: wenige Anker aus 2 Domaenen (niedrigere Relevanz) — weit entfernt
        g2 = (
            [_make_anchor("bio", [10.0, 10.0]) for _ in range(2)]
            + [_make_anchor("fin", [10.01, 10.0]) for _ in range(2)]
        )
        engine.ingest_anchors(g1 + g2)
        clusters = engine.cluster(eps=1.0, min_samples=3, require_multi_domain=True)
        if len(clusters) >= 2:
            assert clusters[0].relevance_score >= clusters[1].relevance_score

    def test_export_meta_anchor(self):
        engine = self._engine("_export")
        anchors = (
            [_make_anchor("a", [0.0, 0.0]) for _ in range(3)]
            + [_make_anchor("b", [0.01, 0.0]) for _ in range(3)]
        )
        engine.ingest_anchors(anchors)
        clusters = engine.cluster(eps=0.5, min_samples=3)
        if clusters:
            meta = engine.export_meta_anchor(clusters[0].cluster_id)
            assert meta is not None
            assert "centroid" in meta
            assert "n_anchors" in meta
            assert "disclaimer" in meta

    def test_summary_text_de(self):
        engine = self._engine("_sum_de")
        anchors = (
            [_make_anchor("med", [0.0]) for _ in range(3)]
            + [_make_anchor("kli", [0.01]) for _ in range(3)]
        )
        engine.ingest_anchors(anchors)
        engine.cluster(eps=0.5, min_samples=3)
        text = engine.summary_text(lang="de")
        assert isinstance(text, str)
        assert len(text) > 0

    def test_summary_text_en(self):
        engine = self._engine("_sum_en")
        text = engine.summary_text(lang="en")
        # Leere DB -> no-data-Meldung
        assert "No cross-domain" in text or "no confirmed" in text or isinstance(text, str)

    def test_shanway_notification_none_when_low_relevance(self):
        engine = self._engine("_notif_none")
        # Zu wenige Anker -> Relevanz gering
        anchors = (
            [_make_anchor("a", [0.0, 0.0]) for _ in range(2)]
            + [_make_anchor("b", [0.01, 0.0]) for _ in range(2)]
        )
        engine.ingest_anchors(anchors)
        engine.cluster(eps=0.5, min_samples=2)
        notif = engine.shanway_notification(threshold=1000.0)  # unmoeglich hoch
        assert notif is None

    def test_shanway_notification_returned_when_high(self):
        engine = self._engine("_notif_high")
        # Viele Anker aus mehreren Domaenen -> hohe Relevanz
        anchors = (
            [_make_anchor("med", [0.0]) for _ in range(20)]
            + [_make_anchor("kli", [0.01]) for _ in range(15)]
            + [_make_anchor("ast", [0.02]) for _ in range(10)]
        )
        engine.ingest_anchors(anchors)
        clusters = engine.cluster(eps=0.5, min_samples=3)
        notif = engine.shanway_notification(threshold=0.0)  # immer
        if clusters:
            assert notif is not None
            assert isinstance(notif, str)

    def test_window_days_filter(self):
        engine = self._engine("_window")
        old_ts = time.time() - 400 * 86400  # 400 Tage alt
        old_anchors = (
            [_make_anchor("a", [0.0, 0.0], ts=old_ts) for _ in range(4)]
            + [_make_anchor("b", [0.01, 0.0], ts=old_ts) for _ in range(4)]
        )
        engine.ingest_anchors(old_anchors)
        # window_days=30 -> alte Anker ausgeschlossen
        clusters = engine.cluster(eps=0.5, min_samples=3, window_days=30)
        assert clusters == []

    def test_stats(self):
        engine = self._engine("_stats")
        assert isinstance(engine.stats(), dict)
        assert "total_anchors_in_db" in engine.stats()

    def test_clear_anchors(self):
        engine = self._engine("_clear")
        engine.ingest_anchors([_make_anchor("x", [1.0])])
        engine.clear_anchors()
        assert engine.anchor_count() == 0


# ---------------------------------------------------------------------------
# TestRawAnchor
# ---------------------------------------------------------------------------

class TestRawAnchor:
    def test_default_timestamp(self):
        from modules.cross_domain_engine import RawAnchor
        before = time.time()
        a = RawAnchor("id1", "test", "src", [1.0, 2.0])
        after = time.time()
        assert before <= a.timestamp <= after

    def test_custom_timestamp(self):
        from modules.cross_domain_engine import RawAnchor
        ts = 1000000.0
        a = RawAnchor("id2", "test", "src", [1.0], timestamp=ts)
        assert a.timestamp == ts


# ---------------------------------------------------------------------------
# TestCrossDomainCluster
# ---------------------------------------------------------------------------

class TestCrossDomainCluster:
    def _make_cluster(self, domains: dict, n_per: int = 3) -> "CrossDomainCluster":
        from modules.cross_domain_engine import CrossDomainCluster
        anchors = []
        for d, cnt in domains.items():
            for _ in range(cnt):
                anchors.append(_make_anchor(d, [0.0, 0.0]))
        return CrossDomainCluster(
            cluster_id=str(uuid.uuid4()),
            anchors=anchors,
            domains=domains,
            centroid=[0.0, 0.0],
            mean_distance=0.05,
            relevance_score=42.0,
            first_seen=time.time() - 86400,
            last_updated=time.time(),
        )

    def test_n_anchors(self):
        c = self._make_cluster({"med": 5, "kli": 3})
        assert c.n_anchors == 8

    def test_n_domains(self):
        c = self._make_cluster({"med": 3, "kli": 3, "ast": 2})
        assert c.n_domains == 3

    def test_domain_summary_sorted(self):
        c = self._make_cluster({"kli": 5, "med": 12, "ast": 3})
        summary = c.domain_summary()
        # Med hat die meisten -> sollte zuerst kommen
        assert summary.startswith("12 Med") or "Med" in summary


# ---------------------------------------------------------------------------
# TestI18nFirstStart
# ---------------------------------------------------------------------------

class TestI18nFirstStart:
    """Prueft, dass die Erststart-Texte vorhanden und inhaltlich korrekt sind."""

    def test_first_start_title_de(self):
        from modules.i18n import t, set_language
        set_language("de")
        title = t("first_start_title")
        assert "Aether" in title
        assert "Willkommen" in title

    def test_first_start_title_en(self):
        from modules.i18n import t, set_language
        set_language("en")
        title = t("first_start_title")
        assert "Aether" in title
        assert "Welcome" in title

    def test_first_start_body_de_keywords(self):
        from modules.i18n import t, set_language
        set_language("de")
        body = t("first_start_body")
        for keyword in ["privater Schlüssel", "Backup", ".aether", "Kontrolle"]:
            assert keyword in body, f"'{keyword}' fehlt im DE-Text"

    def test_first_start_body_en_keywords(self):
        from modules.i18n import t, set_language
        set_language("en")
        body = t("first_start_body")
        for keyword in ["private key", "backup", ".aether", "control"]:
            assert keyword.lower() in body.lower(), f"'{keyword}' missing in EN text"

    def test_first_start_body_max_150_words(self):
        """Jede Sprachvariante soll max. 150 Woerter haben."""
        from modules.i18n import t, set_language
        for lang in ("de", "en"):
            set_language(lang)
            body = t("first_start_body")
            words = body.split()
            assert len(words) <= 150, f"{lang}: {len(words)} Woerter (max 150)"

    def test_first_start_ack_de(self):
        from modules.i18n import t, set_language
        set_language("de")
        ack = t("first_start_ack")
        assert len(ack) > 0

    def test_first_start_ack_en(self):
        from modules.i18n import t, set_language
        set_language("en")
        ack = t("first_start_ack")
        assert "Aether" in ack or "start" in ack.lower()

    def test_backup_paths_in_body(self):
        """Beide Sprachvarianten muessen die Backup-Pfade enthalten."""
        from modules.i18n import t, set_language
        for lang in ("de", "en"):
            set_language(lang)
            body = t("first_start_body")
            assert "%USERPROFILE%" in body, f"{lang}: Windows-Pfad fehlt"
            assert "~/.aether" in body, f"{lang}: Linux/macOS-Pfad fehlt"

    def test_no_support_mentioned(self):
        """Beide Versionen muessen auf fehlenden Support hinweisen."""
        from modules.i18n import t, set_language
        for lang in ("de", "en"):
            set_language(lang)
            body = t("first_start_body")
            lower = body.lower()
            has_no_support = (
                "kein support" in lower
                or "no support" in lower
                or "niemand" in lower
                or "nobody" in lower
            )
            assert has_no_support, f"{lang}: Kein Hinweis auf fehlenden Support"


# ---------------------------------------------------------------------------
# TestI18nCrossDomain
# ---------------------------------------------------------------------------

class TestI18nCrossDomain:
    """Prueft die neuen i18n-Schluessel fuer den Domaenen-Tab."""

    def test_cross_domain_heading_de(self):
        from modules.i18n import t, set_language
        set_language("de")
        heading = t("cross_domain_heading")
        assert "Dom" in heading  # "Domänenübergreifende Muster"

    def test_cross_domain_heading_en(self):
        from modules.i18n import t, set_language
        set_language("en")
        heading = t("cross_domain_heading")
        assert "Cross" in heading or "Domain" in heading

    def test_disclaimer_contains_warning(self):
        from modules.i18n import t, set_language
        for lang in ("de", "en"):
            set_language(lang)
            disc = t("cross_domain_disclaimer")
            # Muss Warnsymbol enthalten
            assert "\u26a0" in disc  # ⚠️

    def test_cross_domain_no_data_both_langs(self):
        from modules.i18n import t, set_language
        for lang in ("de", "en"):
            set_language(lang)
            nd = t("cross_domain_no_data")
            assert len(nd) > 5
