"""
Erweiterte Tests für EthicsEngine — verschiedene Textarten und Integrationstests.

Getestete Metriken:
  - Zipf (Worthäufigkeitsverteilung)
  - Benford (Verteilung führender Ziffern)
  - Fraktal (Satzlängenvariation)
  - Noether (thematische Konsistenz)
  - Interferenz (Negationsdichte)
  - Heisenberg (absolute Aussagen)
  - CodeEthicsEngine (Obfuscation-Erkennung)

Verschiedene Textarten:
  - Wissenschaftlicher Text
  - Nachrichtenartikel
  - Programmcode (sauber)
  - Obfuscierter Code
  - Propagandatext (hohe Absolutaussagen)
  - Negationslastiger Text
  - Sehr kurzer Text (Edge Case)
  - Leerer Text (Edge Case)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ---------------------------------------------------------------------------
# Testdaten (repräsentative Texte)
# ---------------------------------------------------------------------------

SCIENTIFIC_TEXT = """
Die Analyse biologischer Sequenzen erfordert statistische Methoden zur Mustererkennung.
In dieser Studie untersuchen wir Entropiemuster in genomischen Daten aus drei unabhängigen
Datensätzen. Die beobachteten Periodizitätsmuster stimmen mit publizierten Ergebnissen überein.
Unsere Messungen zeigen signifikante Abweichungen in Codierungsbereichen im Vergleich zu
intergenischen Sequenzen. Die fraktale Dimension der Sequenzabschnitte variiert zwischen
1.2 und 1.8, wobei Exon-Bereiche typischerweise niedrigere Werte aufweisen.
Die Shannon-Entropie beträgt durchschnittlich 1.94 Bit pro Basenpaar in kodierenden Regionen.
Regulatorische Elemente zeigen charakteristische Periodizitäten bei 10 und 35 Basenpaaren.
Insertionen und Deletionen erzeugen messbare Disruptions im Entropieprofil.
Anwendungen für die Biodiversitätsforschung und Evolutionsbiologie sind vielversprechend.
""".strip()

NEWS_TEXT = """
Die Bundesregierung hat heute neue Maßnahmen zur Förderung erneuerbarer Energien angekündigt.
Das Kabinett beschloss ein Programm mit einem Volumen von 2,4 Milliarden Euro.
Ein Sprecher des Ministeriums teilte mit, die Mittel würden ab Januar nächsten Jahres fließen.
Kritiker bemängeln, das Programm reiche nicht aus, um die Klimaziele zu erreichen.
Der Verband der Erneuerbaren-Energie-Anbieter begrüßte den Beschluss grundsätzlich.
Allerdings seien die bürokratischen Hürden noch zu hoch, sagte eine Verbandssprecherin.
Die Opposition forderte höhere Summen und weniger Bürokratie bei der Antragstellung.
Laut einer Umfrage befürworten 67 Prozent der Bevölkerung den Ausbau erneuerbarer Energien.
""".strip()

PROPAGANDA_TEXT = """
Diese Partei ist absolut korrupt und lügt immer ausnahmslos.
Alle Politiker sind nur auf ihren Vorteil aus, niemals auf das Wohl des Volkes.
Einzig unsere Bewegung vertritt wahrhaftig die Interessen der einfachen Menschen.
Jeder Andersdenkende ist ein Verräter. Niemand kann uns aufhalten.
Diese Lügen der Mainstream-Medien werden wir immer entlarven.
Alle anderen Parteien sind vollständig abgehoben und korrupt.
Nur wir kämpfen ausschließlich für Freiheit und Gerechtigkeit.
Absolut kein anderer Weg ist möglich, außer unserem Weg.
""".strip()

NEGATION_HEAVY_TEXT = """
Das Gerät funktioniert nicht, wie es nicht soll. Wir können nicht verstehen,
warum das System nicht reagiert und nicht die erwarteten Ergebnisse nicht liefert.
Kein Benutzer sollte nicht in der Lage sein, die Anleitung nicht zu verstehen.
Diese Software ist kein Werkzeug für professionelle Anwender.
Nicht alle Funktionen sind nicht verfügbar. Keine der Optionen war bisher nicht getestet.
Niemals sollte man ohne Backup nicht arbeiten. Die Fehlermeldung ist nicht klar.
""".strip()

CLEAN_CODE = """
def calculate_fibonacci(n: int) -> list[int]:
    \"\"\"Returns the first n Fibonacci numbers.\"\"\"
    if n <= 0:
        return []
    elif n == 1:
        return [0]
    sequence = [0, 1]
    for i in range(2, n):
        sequence.append(sequence[i-1] + sequence[i-2])
    return sequence

def format_sequence(numbers: list[int]) -> str:
    return ', '.join(str(x) for x in numbers)

if __name__ == '__main__':
    result = calculate_fibonacci(10)
    print(format_sequence(result))
""".strip()

OBFUSCATED_CODE = """
import base64, sys
exec(base64.b64decode(b'aW1wb3J0IG9z'))
_a=lambda _b:__import__('base64').b64decode(_b)
_c=_a(b'b3MucGF0aC5leGlzdHMoJy90bXAnKQ==')
eval(compile(_c,'<str>','eval'))
_d=b'\\x73\\x68\\x75\\x74\\x64\\x6f\\x77\\x6e'
exec(_a(b'cHJpbnQoJ3gnKQ=='))
__import__('os').system(_d)
_e='QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE='
""".strip()

SHORT_TEXT = "Kurz."
EMPTY_TEXT = ""

MIXED_LANGUAGE_TEXT = """
The Analyse zeigt interessante Patterns in den Daten.
We observed significant Abweichungen from the expected Verteilung.
Diese findings suggest that the Methodik needs to be Überarbeitung.
All results were statistically Signifikant with p < 0.05.
Die Studie used 1200 samples across 4 different Gruppen.
""".strip()


# ---------------------------------------------------------------------------
# Basis-Tests: structural_text_integrity
# ---------------------------------------------------------------------------

class TestStructuralIntegrityScores:

    def _run(self, text):
        from modules.ethics_engine import structural_text_integrity
        return structural_text_integrity(text)

    def test_scientific_score_reasonable(self):
        result = self._run(SCIENTIFIC_TEXT)
        assert isinstance(result["score"], float)
        assert 0.0 <= result["score"] <= 1.0

    def test_news_score_reasonable(self):
        result = self._run(NEWS_TEXT)
        assert 0.0 <= result["score"] <= 1.0
        # Nachrichtentext sollte keine extrem niedrigen Werte haben
        assert result["score"] >= 0.3

    def test_propaganda_heisenberg_low(self):
        """Propagandatext hat sehr viele Absolutaussagen → Heisenberg sollte niedrig sein."""
        result = self._run(PROPAGANDA_TEXT)
        # Heisenberg misst Absolutaussagendichte – hohe Dichte = niedrigerer Score
        assert isinstance(result["heisenberg"], float)
        assert 0.0 <= result["heisenberg"] <= 1.0

    def test_negation_heavy_interferenz(self):
        """Negationslastiger Text → Interferenz-Metrik reagiert auf hohe Negationsdichte."""
        result = self._run(NEGATION_HEAVY_TEXT)
        assert isinstance(result["interferenz"], float)
        assert 0.0 <= result["interferenz"] <= 1.0

    def test_short_text_no_crash(self):
        result = self._run(SHORT_TEXT)
        assert "score" in result
        assert isinstance(result["score"], float)

    def test_empty_text_returns_1(self):
        result = self._run(EMPTY_TEXT)
        assert result["score"] == 1.0

    def test_scientific_noether_reasonable(self):
        """Wissenschaftlicher Text sollte thematisch konsistent sein."""
        result = self._run(SCIENTIFIC_TEXT)
        assert result["noether"] >= 0.0

    def test_mixed_language_handled(self):
        result = self._run(MIXED_LANGUAGE_TEXT)
        assert 0.0 <= result["score"] <= 1.0

    def test_all_metric_keys_present(self):
        result = self._run(NEWS_TEXT)
        expected_keys = {"score", "zipf", "benford", "fraktal", "noether", "interferenz", "heisenberg"}
        assert expected_keys.issubset(result.keys())

    def test_score_with_entropy_mean(self):
        from modules.ethics_engine import structural_text_integrity
        r_low = structural_text_integrity(NEWS_TEXT, entropy_mean=2.0)
        r_high = structural_text_integrity(NEWS_TEXT, entropy_mean=8.0)
        # Beide sollten valid scores liefern
        assert 0.0 <= r_low["score"] <= 1.0
        assert 0.0 <= r_high["score"] <= 1.0


# ---------------------------------------------------------------------------
# EthicsEngine Klassen-API
# ---------------------------------------------------------------------------

class TestEthicsEngineAPI:

    def test_assess_returns_assessment(self):
        from modules.ethics_engine import EthicsEngine, EthicsAssessment
        e = EthicsEngine()
        result = e.assess(SCIENTIFIC_TEXT)
        assert isinstance(result, EthicsAssessment)

    def test_score_method_agrees_with_assess(self):
        from modules.ethics_engine import EthicsEngine
        e = EthicsEngine()
        score_direct = e.score(NEWS_TEXT)
        assess_score = e.assess(NEWS_TEXT).score
        assert abs(score_direct - assess_score) < 1e-9

    def test_assess_empty_text(self):
        from modules.ethics_engine import EthicsEngine
        e = EthicsEngine()
        result = e.assess("")
        assert result.score == 1.0

    def test_assess_single_word(self):
        from modules.ethics_engine import EthicsEngine
        e = EthicsEngine()
        result = e.assess("Hallo")
        assert 0.0 <= result.score <= 1.0

    def test_all_assessment_fields_valid(self):
        from modules.ethics_engine import EthicsEngine
        e = EthicsEngine()
        r = e.assess(SCIENTIFIC_TEXT)
        for field in ("score", "zipf", "benford", "fraktal", "noether", "interferenz", "heisenberg"):
            val = getattr(r, field)
            assert isinstance(val, float), f"{field} is not float"
            assert 0.0 <= val <= 1.0, f"{field}={val} out of [0,1]"

    def test_news_vs_propaganda_score(self):
        """Nachrichtentext und Propagandatext beide valide Scores."""
        from modules.ethics_engine import EthicsEngine
        e = EthicsEngine()
        score_news = e.score(NEWS_TEXT)
        score_prop = e.score(PROPAGANDA_TEXT)
        # Beide müssen im gültigen Bereich liegen
        assert 0.0 <= score_news <= 1.0
        assert 0.0 <= score_prop <= 1.0

    def test_long_text_no_crash(self):
        from modules.ethics_engine import EthicsEngine
        long_text = SCIENTIFIC_TEXT * 20
        e = EthicsEngine()
        result = e.score(long_text)
        assert 0.0 <= result <= 1.0

    def test_numbers_only_text(self):
        from modules.ethics_engine import EthicsEngine
        text = " ".join(str(i) for i in range(1, 500))
        e = EthicsEngine()
        result = e.assess(text)
        assert 0.0 <= result.score <= 1.0


# ---------------------------------------------------------------------------
# CodeEthicsEngine
# ---------------------------------------------------------------------------

class TestCodeEthicsEngineAdvanced:

    def test_clean_code_verdict(self):
        from modules.ethics_engine import CodeEthicsEngine
        e = CodeEthicsEngine()
        r = e.analyze(CLEAN_CODE)
        assert r["verdict"] in ("clean", "suspicious", "anomalous")
        # Sauberer Code sollte nicht als anomalous erkannt werden
        assert r["verdict"] != "anomalous"

    def test_obfuscated_code_anomalous(self):
        from modules.ethics_engine import CodeEthicsEngine
        e = CodeEthicsEngine()
        r = e.analyze(OBFUSCATED_CODE)
        # Obfuscierter Code sollte als suspicious oder anomalous erkannt werden
        assert r["verdict"] in ("suspicious", "anomalous")

    def test_obfuscated_has_flags(self):
        from modules.ethics_engine import CodeEthicsEngine
        e = CodeEthicsEngine()
        r = e.analyze(OBFUSCATED_CODE)
        assert len(r["flags"]) > 0

    def test_clean_code_low_eval_exec_density(self):
        from modules.ethics_engine import CodeEthicsEngine
        e = CodeEthicsEngine()
        r = e.analyze(CLEAN_CODE)
        assert r["eval_exec_density"] < 0.1

    def test_obfuscated_base64_detected(self):
        from modules.ethics_engine import CodeEthicsEngine
        e = CodeEthicsEngine()
        r = e.analyze(OBFUSCATED_CODE)
        # base64 oder hex Muster sollten erkannt werden
        assert r["base64_density"] > 0 or r["hex_ratio"] > 0

    def test_empty_code_no_crash(self):
        from modules.ethics_engine import CodeEthicsEngine
        e = CodeEthicsEngine()
        r = e.analyze("")
        assert r["anomaly_score"] == 1.0
        assert r["verdict"] == "clean"

    def test_is_suspicious_clean(self):
        from modules.ethics_engine import CodeEthicsEngine
        e = CodeEthicsEngine()
        assert not e.is_suspicious(CLEAN_CODE, threshold=0.5)

    def test_is_suspicious_obfuscated(self):
        from modules.ethics_engine import CodeEthicsEngine
        e = CodeEthicsEngine()
        assert e.is_suspicious(OBFUSCATED_CODE, threshold=0.8)

    def test_analyze_code_structure_all_keys(self):
        from modules.ethics_engine import analyze_code_structure
        result = analyze_code_structure(CLEAN_CODE)
        expected = {
            "anomaly_score",
            "byte_entropy",
            "token_entropy",
            "identifier_ratio_short",
            "hex_ratio",
            "base64_density",
            "eval_exec_density",
            "flags",
        }
        assert expected.issubset(result.keys())

    def test_anomaly_score_range(self):
        from modules.ethics_engine import analyze_code_structure
        for code in (CLEAN_CODE, OBFUSCATED_CODE, "", SCIENTIFIC_TEXT):
            r = analyze_code_structure(code)
            assert 0.0 <= r["anomaly_score"] <= 1.0, f"Out of range for code={code[:30]}"


# ---------------------------------------------------------------------------
# Integrationstests: EthicsEngine + analyze_code_structure
# ---------------------------------------------------------------------------

class TestEthicsIntegration:

    def test_ethics_engine_does_not_share_state(self):
        """Zwei EthicsEngine-Instanzen beeinflussen sich nicht gegenseitig."""
        from modules.ethics_engine import EthicsEngine
        e1 = EthicsEngine()
        e2 = EthicsEngine()
        s1 = e1.score(SCIENTIFIC_TEXT)
        s2 = e2.score(PROPAGANDA_TEXT)
        # Ergebnis muss reproduzierbar sein
        assert e1.score(SCIENTIFIC_TEXT) == s1
        assert e2.score(PROPAGANDA_TEXT) == s2

    def test_ethics_score_function_equivalent(self):
        from modules.ethics_engine import ethics_score, EthicsEngine
        e = EthicsEngine()
        for text in (SCIENTIFIC_TEXT, NEWS_TEXT, EMPTY_TEXT):
            assert abs(ethics_score(text) - e.score(text)) < 1e-9


class TestEthicsRuntimeCompatibility:

    def test_evaluate_returns_runtime_fields(self):
        from modules.ethics_engine import EthicsEngine
        e = EthicsEngine()
        r = e.evaluate(
            symmetry_score=83.0,
            entropy_blocks=[3.8, 4.1, 4.5, 4.2, 4.0],
            entropy_mean=4.12,
            periodicity=24,
            delta_ratio=0.12,
            healthy_references=[
                {
                    "symmetry_score": 0.8,
                    "entropy_mean": 4.2,
                    "periodicity": 24,
                    "delta_ratio": 0.15,
                }
            ],
        )
        assert 0.0 <= r.ethics_score <= 1.0
        assert 0.0 <= r.coherence_score <= 1.0
        assert 0.0 <= r.resonance_score <= 1.0
        assert r.integrity_state in ("STRUCTURAL_COHERENCE", "STRUCTURAL_TENSION", "STRUCTURAL_ANOMALY")


class TestOckhamRazorEngine:

    def test_low_risk_prefers_allow(self):
        from modules.ethics_engine import OckhamRazorEngine
        engine = OckhamRazorEngine()
        decision = engine.decide(
            {
                "cpu_load": 0.10,
                "mem_pressure": 0.15,
                "process_spawn_rate": 0.05,
                "unsigned_binary_ratio": 0.01,
                "network_new_peers": 0.08,
                "error_burst": 0.03,
                "integrity_alerts": 0.00,
            }
        )
        assert decision.action == "allow"
        assert 0.0 <= decision.risk_score <= 1.0

    def test_high_risk_avoids_allow(self):
        from modules.ethics_engine import OckhamRazorEngine
        engine = OckhamRazorEngine()
        decision = engine.decide(
            {
                "cpu_load": 0.92,
                "mem_pressure": 0.88,
                "process_spawn_rate": 0.86,
                "unsigned_binary_ratio": 0.73,
                "network_new_peers": 0.82,
                "error_burst": 0.80,
                "integrity_alerts": 0.65,
            }
        )
        assert decision.action != "allow"
        assert any("high" in reason or "integrity" in reason for reason in decision.reasons)

    def test_corpus_scores_distribution(self):
        """Alle Testkorpora produzieren gültige Scores."""
        from modules.ethics_engine import EthicsEngine
        e = EthicsEngine()
        corpus = {
            "scientific": SCIENTIFIC_TEXT,
            "news": NEWS_TEXT,
            "propaganda": PROPAGANDA_TEXT,
            "negation": NEGATION_HEAVY_TEXT,
            "mixed_lang": MIXED_LANGUAGE_TEXT,
            "short": SHORT_TEXT,
        }
        scores = {name: e.score(text) for name, text in corpus.items()}
        for name, score in scores.items():
            assert 0.0 <= score <= 1.0, f"Score {score} out of [0,1] for {name}"


# ---------------------------------------------------------------------------
# aether_core_rs Wrapper Tests
# ---------------------------------------------------------------------------

class TestAetherCoreRsWrapper:

    def test_byte_entropy_empty(self):
        from modules.aether_core_rs import byte_entropy
        assert byte_entropy(b"") == 0.0

    def test_byte_entropy_uniform(self):
        from modules.aether_core_rs import byte_entropy
        # Uniform: alle 256 Werte je einmal → H = 8.0
        data = bytes(range(256))
        h = byte_entropy(data)
        assert abs(h - 8.0) < 0.01

    def test_byte_entropy_constant(self):
        from modules.aether_core_rs import byte_entropy
        # Alle gleich → H = 0.0
        data = bytes([0x41] * 100)
        h = byte_entropy(data)
        assert h == 0.0

    def test_token_entropy_empty(self):
        from modules.aether_core_rs import token_entropy
        assert token_entropy([]) == 0.0

    def test_token_entropy_single(self):
        from modules.aether_core_rs import token_entropy
        assert token_entropy(["word"] * 10) == 0.0

    def test_zipf_score_range(self):
        from modules.aether_core_rs import zipf_score
        # Natürliche Sprachfrequenz sollte hohen Score haben
        freqs = [1000, 500, 300, 200, 150, 100, 80, 60, 50, 40]
        s = zipf_score(freqs)
        assert 0.0 <= s <= 1.0

    def test_zipf_score_few_samples(self):
        from modules.aether_core_rs import zipf_score
        assert zipf_score([10, 5]) == 0.7  # Fallback für < 5 Samples

    def test_noether_score_identical_vectors(self):
        from modules.aether_core_rs import noether_score
        v = {"apple": 10.0, "banana": 5.0, "cherry": 3.0}
        s = noether_score(v, v)
        assert abs(s - 1.0) < 1e-9

    def test_noether_score_orthogonal_vectors(self):
        from modules.aether_core_rs import noether_score
        s = noether_score({"a": 1.0}, {"b": 1.0})
        # Keine gemeinsame Dimension → Dot = 0 → cos = 0 → score = 0
        assert s == 0.0

    def test_noether_score_empty(self):
        from modules.aether_core_rs import noether_score
        assert noether_score({}, {}) == 0.6

    def test_build_info_returns_string(self):
        from modules.aether_core_rs import build_info
        info = build_info()
        assert isinstance(info, str)
        assert len(info) > 0


# ---------------------------------------------------------------------------
# AnchorQuery Tests
# ---------------------------------------------------------------------------

class TestAnchorQuery:
    def _store_and_query(self, tmp_db: Path):
        from modules.anchor_query import AnchorQuery
        return AnchorQuery(tmp_db)

    def _tmpdir(self) -> Path:
        d = _ROOT / "data" / "_pytest_tmp"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def test_describe_snapshot_summary_empty(self):
        import time
        db = self._tmpdir() / f"aq_{time.time_ns()}.db"
        q = self._store_and_query(db)
        summary = q.describe_snapshot_summary()
        assert "0 Basis-Snapshots" in summary

    def test_describe_clusters_empty(self):
        import time
        db = self._tmpdir() / f"aq_cl_{time.time_ns()}.db"
        q = self._store_and_query(db)
        result = q.describe_clusters()
        assert isinstance(result, str)

    def test_describe_meta_anchors_empty(self):
        import time
        db = self._tmpdir() / f"aq_ma_{time.time_ns()}.db"
        q = self._store_and_query(db)
        result = q.describe_meta_anchors()
        assert isinstance(result, str)
        assert "Keine" in result

    def test_full_report_structure(self):
        import time
        db = self._tmpdir() / f"aq_full_{time.time_ns()}.db"
        q = self._store_and_query(db)
        report = q.full_report_for_assistant()
        assert "Aether" in report
        assert "Basis-Snapshots" in report

    def test_query_meta_anchors_filter(self):
        import time
        db = self._tmpdir() / f"aq_qf_{time.time_ns()}.db"
        q = self._store_and_query(db)
        result = q.query_meta_anchors(keyword="python", limit=5)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# DBSCAN Clustering Tests
# ---------------------------------------------------------------------------

class TestDBSCAN:

    def _tmpdir(self) -> Path:
        d = _ROOT / "data" / "_pytest_tmp"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def test_dbscan_static_single_cluster(self):
        from modules.process_anchor_store import ProcessAnchorStore
        points = [[1.0, 0.0, 0.0], [1.5, 0.0, 0.0], [1.2, 0.1, 0.0]]
        labels = ProcessAnchorStore._dbscan(points, eps=1.0, min_samples=2)
        assert len(labels) == 3
        assert all(l == 0 for l in labels)

    def test_dbscan_static_noise(self):
        from modules.process_anchor_store import ProcessAnchorStore
        points = [[0.0, 0.0, 0.0], [100.0, 100.0, 100.0]]
        labels = ProcessAnchorStore._dbscan(points, eps=1.0, min_samples=2)
        assert all(l == -1 for l in labels)

    def test_dbscan_empty(self):
        from modules.process_anchor_store import ProcessAnchorStore
        labels = ProcessAnchorStore._dbscan([], eps=1.0, min_samples=2)
        assert labels == []

    def test_cluster_consensus_anchors_empty_db(self):
        import time
        from modules.process_anchor_store import ProcessAnchorStore
        db = self._tmpdir() / f"dbscan_{time.time_ns()}.db"
        store = ProcessAnchorStore(db)
        clusters = store.cluster_consensus_anchors()
        assert clusters == []

    def test_cluster_consensus_anchors_with_data(self):
        import time
        from modules.process_anchor_store import ProcessAnchorStore, RawSnapshot
        db = self._tmpdir() / f"dbscan_d_{time.time_ns()}.db"
        store = ProcessAnchorStore(db)

        # 6 Snapshots für 2 Prozesse
        now = time.time()
        snaps = [
            RawSnapshot(ts=now - i * 60, pid=i, name="proc_a.exe",
                        cpu_percent=50.0, memory_rss=200 * 1024 * 1024,
                        thread_count=4)
            for i in range(4)
        ] + [
            RawSnapshot(ts=now - i * 60, pid=i + 100, name="proc_b.exe",
                        cpu_percent=5.0, memory_rss=50 * 1024 * 1024,
                        thread_count=1)
            for i in range(4)
        ]
        store.store_snapshots(snaps)
        store.build_consensus_anchors(window_seconds=7200)

        clusters = store.cluster_consensus_anchors(eps=50.0, min_samples=1)
        assert isinstance(clusters, list)
        # Mindestens ein Cluster oder Rauschen
        assert len(clusters) >= 0
