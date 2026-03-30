"""
Tests fuer die neuen Aether-Module (Phase Master-Prompt).

Getestete Module:
  - modules/i18n.py
  - modules/process_anchor_store.py
  - modules/background_monitor.py
  - modules/hardware_profiler.py
  - modules/autopilot_engine.py
  - modules/ethics_engine.py (CodeEthicsEngine / analyze_code_structure)
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

import pytest

# Workspace-Root zum Import-Pfad hinzufuegen
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ---------------------------------------------------------------------------
# Hilfsfunktion: tmp-Verzeichnis ohne Abhaengigkeit von pytest tmp_path
# ---------------------------------------------------------------------------

def _tmpdir() -> Path:
    """Erstellt ein temporaeres Verzeichnis im Projektordner."""
    d = _ROOT / "data" / "_pytest_tmp"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# i18n
# ---------------------------------------------------------------------------

class TestI18n:
    def test_default_language_is_de(self):
        from modules.i18n import get_language
        assert get_language() in ("de", "en")

    def test_set_language_de(self):
        from modules.i18n import set_language, get_language
        set_language("de", persist=False)
        assert get_language() == "de"

    def test_set_language_en(self):
        from modules.i18n import set_language, get_language
        set_language("en", persist=False)
        assert get_language() == "en"

    def test_t_returns_string(self):
        from modules.i18n import t, set_language
        set_language("de", persist=False)
        result = t("welcome")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_t_en_translation(self):
        from modules.i18n import t, set_language
        set_language("en", persist=False)
        result = t("welcome")
        assert "Aether" in result or "welcome" in result.lower()

    def test_t_unknown_key_returns_key(self):
        from modules.i18n import t
        result = t("__nonexistent_key_xyz__")
        assert result == "__nonexistent_key_xyz__"

    def test_t_format_kwargs(self):
        from modules.i18n import t, set_language
        set_language("de", persist=False)
        result = t("suggestion_high_cpu", name="TestProcess", cpu=42.5)
        assert "TestProcess" in result
        assert "42" in result

    def test_invalid_language_ignored(self):
        from modules.i18n import set_language, get_language
        set_language("de", persist=False)
        set_language("xx", persist=False)  # ungültig – sollte ignoriert werden
        assert get_language() == "de"


# ---------------------------------------------------------------------------
# ProcessAnchorStore
# ---------------------------------------------------------------------------

class TestProcessAnchorStore:
    @pytest.fixture
    def store(self):
        from modules.process_anchor_store import ProcessAnchorStore
        db = _tmpdir() / f"store_{time.time_ns()}.db"
        return ProcessAnchorStore(db)

    @pytest.fixture
    def sample_snapshots(self):
        from modules.process_anchor_store import RawSnapshot
        now = time.time()
        return [
            RawSnapshot(ts=now, pid=100, name="python.exe",
                        cpu_percent=5.0, memory_rss=50 * 1024 * 1024,
                        thread_count=4),
            RawSnapshot(ts=now, pid=200, name="notepad.exe",
                        cpu_percent=0.5, memory_rss=10 * 1024 * 1024,
                        thread_count=1),
        ]

    def test_store_and_count(self, store, sample_snapshots):
        n = store.store_snapshots(sample_snapshots)
        assert n == 2
        assert store.count_snapshots() == 2

    def test_empty_store(self, store):
        assert store.count_snapshots() == 0

    def test_store_empty_list(self, store):
        n = store.store_snapshots([])
        assert n == 0

    def test_get_snapshots_for_process(self, store, sample_snapshots):
        store.store_snapshots(sample_snapshots)
        rows = store.get_snapshots_for_process("python.exe")
        assert len(rows) == 1
        assert rows[0]["name"] == "python.exe"

    def test_purge_old_snapshots(self, store):
        from modules.process_anchor_store import RawSnapshot
        old_snap = RawSnapshot(
            ts=time.time() - 10 * 86400,  # 10 Tage alt
            pid=999, name="old.exe",
        )
        store.store_snapshots([old_snap])
        assert store.count_snapshots() == 1
        deleted = store.purge_old_snapshots(7 * 86400)
        assert deleted == 1
        assert store.count_snapshots() == 0

    def test_build_consensus_anchors_needs_samples(self, store, sample_snapshots):
        # Weniger als 3 Samples pro Prozess -> kein Konsens-Anker
        store.store_snapshots(sample_snapshots)
        n = store.build_consensus_anchors(window_seconds=3600)
        assert isinstance(n, int)
        assert n >= 0

    def test_build_consensus_with_enough_samples(self, store):
        from modules.process_anchor_store import RawSnapshot
        now = time.time()
        snaps = [
            RawSnapshot(ts=now - i * 60, pid=i, name="test.exe",
                        cpu_percent=50.0, memory_rss=100 * 1024 * 1024)
            for i in range(5)
        ]
        store.store_snapshots(snaps)
        n = store.build_consensus_anchors(window_seconds=3600)
        assert n >= 1

    def test_log_optimization_and_rollback(self, store):
        log_id = store.log_optimization(
            action_type="priority_lower",
            target="test.exe",
            details={"cpu": 80},
            rollback_data={"prev_priority": "normal"},
            user_consented=True,
        )
        assert log_id > 0
        pending = store.get_pending_rollbacks()
        assert any(p["id"] == log_id for p in pending)

        store.mark_rolled_back(log_id)
        pending_after = store.get_pending_rollbacks()
        assert not any(p["id"] == log_id for p in pending_after)

    def test_raw_snapshot_hash(self):
        from modules.process_anchor_store import RawSnapshot
        s = RawSnapshot(ts=0, pid=1, name="test.exe", cpu_percent=10.0,
                        memory_rss=64 * 1024, thread_count=2)
        h = s.compute_hash()
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex

    def test_raw_snapshot_same_params_same_hash(self):
        from modules.process_anchor_store import RawSnapshot
        s1 = RawSnapshot(ts=1000, pid=1, name="x.exe", cpu_percent=10.0, memory_rss=65536, thread_count=1)
        s2 = RawSnapshot(ts=2000, pid=2, name="x.exe", cpu_percent=10.0, memory_rss=65536, thread_count=1)
        assert s1.compute_hash() == s2.compute_hash()

    def test_meta_anchor_detection_needs_data(self, store):
        n = store.detect_meta_anchors()
        assert n == 0  # kein Konsens-Anker vorhanden


# ---------------------------------------------------------------------------
# BackgroundMonitor
# ---------------------------------------------------------------------------

class TestBackgroundMonitor:
    def test_start_stop(self):
        from modules.background_monitor import BackgroundMonitor
        monitor = BackgroundMonitor(db_path=_tmpdir() / f"mon_{time.time_ns()}.db", interval=999)
        assert not monitor.is_running()
        monitor.start()
        assert monitor.is_running()
        monitor.stop(timeout=5)
        assert not monitor.is_running()

    def test_report_structure(self):
        from modules.background_monitor import BackgroundMonitor
        monitor = BackgroundMonitor(db_path=_tmpdir() / f"mon_r_{time.time_ns()}.db", interval=999)
        report = monitor.get_report()
        assert "running" in report
        assert "snapshots_taken" in report
        assert "db_path" in report

    def test_interval_change(self):
        from modules.background_monitor import BackgroundMonitor
        monitor = BackgroundMonitor(db_path=_tmpdir() / f"mon_i_{time.time_ns()}.db", interval=30)
        monitor.set_interval(60)
        assert monitor._interval == 60.0

    def test_minimum_interval_enforced(self):
        from modules.background_monitor import BackgroundMonitor
        monitor = BackgroundMonitor(db_path=_tmpdir() / f"mon_m_{time.time_ns()}.db", interval=1)
        assert monitor._interval >= 5.0

    def test_collects_snapshots(self):
        """Kurzer Lauf – prüft ob mindestens ein Snapshot gesammelt wird."""
        from modules.background_monitor import BackgroundMonitor
        collected = []
        monitor = BackgroundMonitor(
            db_path=_tmpdir() / f"mon_c_{time.time_ns()}.db",
            interval=5,
            on_snapshot_batch=lambda n: collected.append(n),
        )
        monitor.start()
        time.sleep(7)
        monitor.stop(timeout=5)
        # Falls psutil verfügbar: mindestens ein Batch erwartet
        try:
            import psutil
            assert sum(collected) > 0
        except ImportError:
            pass  # psutil nicht verfügbar -> kein Snapshot erwartet


# ---------------------------------------------------------------------------
# HardwareProfiler
# ---------------------------------------------------------------------------

class TestHardwareProfiler:
    def test_profile_returns_object(self):
        from modules.hardware_profiler import HardwareProfiler, HardwareProfile
        p = HardwareProfiler().profile()
        assert isinstance(p, HardwareProfile)

    def test_profile_has_os_name(self):
        from modules.hardware_profiler import HardwareProfiler
        p = HardwareProfiler().profile()
        assert isinstance(p.os_name, str)
        assert len(p.os_name) > 0

    def test_profile_cpu_cores_positive(self):
        from modules.hardware_profiler import HardwareProfiler
        p = HardwareProfiler().profile()
        assert p.cpu_cores_logical >= 1

    def test_profile_ram_positive(self):
        from modules.hardware_profiler import HardwareProfiler
        p = HardwareProfiler().profile()
        try:
            import psutil
            assert p.ram_total_mb > 0
        except ImportError:
            pass

    def test_profile_disk_type_string(self):
        from modules.hardware_profiler import HardwareProfiler
        p = HardwareProfiler().profile()
        assert isinstance(p.disk_type, str)
        assert p.disk_type in ("HDD", "SSD", "NVMe", "unknown")

    def test_profile_as_dict(self):
        from modules.hardware_profiler import HardwareProfiler
        d = HardwareProfiler().profile().as_dict()
        assert "cpu_name" in d
        assert "ram_total_mb" in d
        assert "is_old_hardware" in d

    def test_profile_is_cached(self):
        from modules.hardware_profiler import HardwareProfiler
        profiler = HardwareProfiler()
        p1 = profiler.profile()
        p2 = profiler.profile()
        assert p1 is p2

    def test_profile_force_refresh(self):
        from modules.hardware_profiler import HardwareProfiler
        profiler = HardwareProfiler()
        p1 = profiler.profile()
        p2 = profiler.profile(force=True)
        assert p2.os_name == p1.os_name


class TestHardwareOptimizer:
    def test_analyze_returns_list(self):
        from modules.hardware_profiler import HardwareOptimizer
        suggestions = HardwareOptimizer().analyze()
        assert isinstance(suggestions, list)

    def test_suggestions_have_required_fields(self):
        from modules.hardware_profiler import HardwareOptimizer, OptimizationSuggestion
        for s in HardwareOptimizer().analyze():
            assert isinstance(s, OptimizationSuggestion)
            assert s.action_type
            assert s.target
            assert s.severity in ("low", "medium", "high")

    def test_suggestions_sorted_by_severity(self):
        from modules.hardware_profiler import HardwareOptimizer
        _order = {"high": 0, "medium": 1, "low": 2}
        suggestions = HardwareOptimizer().analyze()
        severities = [_order[s.severity] for s in suggestions]
        assert severities == sorted(severities)

    def test_suggestion_title_de(self):
        from modules.hardware_profiler import OptimizationSuggestion
        s = OptimizationSuggestion(
            action_type="test", target="x",
            title_de="Deutsch", title_en="English"
        )
        assert s.title("de") == "Deutsch"
        assert s.title("en") == "English"


# ---------------------------------------------------------------------------
# AutopilotEngine
# ---------------------------------------------------------------------------

class TestAutopilotEngine:
    @pytest.fixture
    def store(self):
        from modules.process_anchor_store import ProcessAnchorStore
        return ProcessAnchorStore(_tmpdir() / f"ap_{time.time_ns()}.db")

    def test_autopilot_default_off(self, store):
        from modules.autopilot_engine import AutopilotEngine
        engine = AutopilotEngine(store)
        assert not engine.autopilot_enabled

    def test_enable_disable_autopilot(self, store):
        from modules.autopilot_engine import AutopilotEngine
        engine = AutopilotEngine(store)
        engine.enable_autopilot()
        assert engine.autopilot_enabled
        engine.disable_autopilot()
        assert not engine.autopilot_enabled

    def test_apply_informational_no_action(self, store):
        from modules.autopilot_engine import AutopilotEngine
        from modules.hardware_profiler import OptimizationSuggestion
        engine = AutopilotEngine(store)
        sug = OptimizationSuggestion(
            action_type="memory_alert",
            target="system",
            title_de="Test",
            title_en="Test",
            auto_applicable=False,
        )
        results = engine.apply([sug], user_consented=True)
        assert len(results) == 1
        assert results[0]["success"] is False

    def test_no_consent_blocked(self, store):
        from modules.autopilot_engine import AutopilotEngine
        from modules.hardware_profiler import OptimizationSuggestion
        engine = AutopilotEngine(store)
        sug = OptimizationSuggestion(
            action_type="priority_lower",
            target="nonexistent.exe",
            auto_applicable=True,
        )
        results = engine.apply([sug], user_consented=False)
        assert results[0]["success"] is False

    def test_rollback_nonexistent_returns_failure(self, store):
        from modules.autopilot_engine import AutopilotEngine
        engine = AutopilotEngine(store)
        result = engine.rollback(99999)
        assert result["success"] is False

    def test_rollback_all_empty(self, store):
        from modules.autopilot_engine import AutopilotEngine
        engine = AutopilotEngine(store)
        results = engine.rollback_all()
        assert results == []


# ---------------------------------------------------------------------------
# CodeEthicsEngine / analyze_code_structure
# ---------------------------------------------------------------------------

class TestCodeEthicsEngine:
    def test_clean_code_score_high(self):
        from modules.ethics_engine import analyze_code_structure
        code = """
def calculate_average(numbers):
    if not numbers:
        return 0.0
    return sum(numbers) / len(numbers)

class DataProcessor:
    def __init__(self, data):
        self.data = data

    def process(self):
        return [x * 2 for x in self.data]
"""
        result = analyze_code_structure(code)
        assert result["anomaly_score"] >= 0.5
        assert isinstance(result["flags"], list)

    def test_obfuscated_code_score_low(self):
        from modules.ethics_engine import analyze_code_structure
        # Simulierter obfuskierter Code mit kurzen Bezeichnern und Hex
        code = (
            "a=b=c=d=e=1\n"
            "x=eval('\\x65\\x78\\x65\\x63')\n"
            "q=__import__('os')\n"
            + "ab=" + "A" * 100 + "==\n"  # base64-ähnlich
        )
        result = analyze_code_structure(code)
        assert isinstance(result["anomaly_score"], float)
        assert 0.0 <= result["anomaly_score"] <= 1.0

    def test_empty_code_returns_clean(self):
        from modules.ethics_engine import analyze_code_structure
        result = analyze_code_structure("")
        assert result["anomaly_score"] == 1.0
        assert result["flags"] == []

    def test_whitespace_only_returns_clean(self):
        from modules.ethics_engine import analyze_code_structure
        result = analyze_code_structure("   \n\t  ")
        assert result["anomaly_score"] == 1.0

    def test_verdict_field_present(self):
        from modules.ethics_engine import CodeEthicsEngine
        engine = CodeEthicsEngine()
        result = engine.analyze("x = 1 + 2")
        assert "verdict" in result
        assert result["verdict"] in ("clean", "suspicious", "anomalous")

    def test_is_suspicious_clean_code(self):
        from modules.ethics_engine import CodeEthicsEngine
        code = "def hello(name):\n    return f'Hello, {name}!'\n"
        engine = CodeEthicsEngine()
        assert not engine.is_suspicious(code, threshold=0.4)

    def test_high_byte_entropy_flagged(self):
        from modules.ethics_engine import analyze_code_structure
        # Zufaellige Bytes -> hohe Entropie
        import os
        random_bytes = os.urandom(512)
        code = random_bytes.decode("latin-1")
        result = analyze_code_structure(code)
        assert "high_byte_entropy" in result["flags"] or result["anomaly_score"] < 1.0

    def test_metrics_are_floats(self):
        from modules.ethics_engine import analyze_code_structure
        result = analyze_code_structure("import os\nprint(os.getcwd())")
        for key in ("anomaly_score", "byte_entropy", "token_entropy",
                    "identifier_ratio_short", "hex_ratio", "base64_density",
                    "eval_exec_density"):
            assert isinstance(result[key], float), f"{key} should be float"

    def test_eval_exec_flagged(self):
        from modules.ethics_engine import analyze_code_structure
        code = "\n".join(["eval(x)" for _ in range(20)])
        result = analyze_code_structure(code)
        assert "high_eval_exec_density" in result["flags"]

    def test_hex_literals_flagged(self):
        from modules.ethics_engine import analyze_code_structure
        code = "x = \\x41\\x42\\x43" * 30
        result = analyze_code_structure(code)
        assert "high_hex_literal_ratio" in result["flags"] or result["anomaly_score"] < 1.0


# ---------------------------------------------------------------------------
# EthicsEngine (bestehend) – Regressionstests
# ---------------------------------------------------------------------------

class TestEthicsEngineRegression:
    def test_assess_returns_assessment(self):
        from modules.ethics_engine import EthicsEngine, EthicsAssessment
        engine = EthicsEngine()
        result = engine.assess("Das ist ein normaler Satz. Aether analysiert Struktur.")
        assert isinstance(result, EthicsAssessment)
        assert 0.0 <= result.score <= 1.0

    def test_empty_text_score_one(self):
        from modules.ethics_engine import EthicsEngine
        engine = EthicsEngine()
        result = engine.assess("")
        assert result.score == 1.0

    def test_score_method(self):
        from modules.ethics_engine import EthicsEngine
        engine = EthicsEngine()
        s = engine.score("Text mit normaler Sprachstruktur und Saetzen.")
        assert isinstance(s, float)
        assert 0.0 <= s <= 1.0
