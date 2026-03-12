from modules.privacy_observer import NetworkSignal, ProcessSignal
from modules.telemetry_classifier import (
    TELEMETRY_DOMAIN_ANCHORS,
    TELEMETRY_PROCESS_ANCHORS,
    TelemetryClassifier,
)


def test_classify_process_with_anchor_is_confirmed() -> None:
    classifier = TelemetryClassifier()
    process_name = sorted(TELEMETRY_PROCESS_ANCHORS)[0]
    signal = ProcessSignal(
        pid=1,
        name=process_name,
        cpu_percent=1.0,
        memory_mb=50.0,
        io_read_bytes=0,
        io_write_bytes=0,
        thread_count=2,
        open_connections=4,
        start_time_iso="",
        is_system=False,
        has_window=False,
        snapshot_ts="",
    )
    network = [
        NetworkSignal(
            remote_domain=sorted(TELEMETRY_DOMAIN_ANCHORS)[0],
            remote_port=443,
            local_port=12345,
            protocol="TCP",
            process_name=process_name,
            pid=1,
            packet_size_bucket="tiny",
            connection_count_last_min=6,
            interval_regularity=0.95,
            snapshot_ts="",
        )
    ]
    verdict = classifier.classify_process(signal, network)
    assert verdict.classification == "CONFIRMED"


def test_classify_domain_known_domain_is_confirmed() -> None:
    classifier = TelemetryClassifier()
    signal = NetworkSignal(
        remote_domain=sorted(TELEMETRY_DOMAIN_ANCHORS)[0],
        remote_port=443,
        local_port=12345,
        protocol="TCP",
        process_name="proc",
        pid=1,
        packet_size_bucket="tiny",
        connection_count_last_min=8,
        interval_regularity=0.9,
        snapshot_ts="",
    )
    verdict = classifier.classify_domain(signal)
    assert verdict.classification == "CONFIRMED"


def test_compute_log_weight_grows_with_global_hits() -> None:
    classifier = TelemetryClassifier()
    signal = NetworkSignal(
        remote_domain=sorted(TELEMETRY_DOMAIN_ANCHORS)[0],
        remote_port=443,
        local_port=12345,
        protocol="TCP",
        process_name="proc",
        pid=1,
        packet_size_bucket="tiny",
        connection_count_last_min=8,
        interval_regularity=0.9,
        snapshot_ts="",
    )
    verdict = classifier.classify_domain(signal)
    low = classifier.compute_log_weight(verdict, 1)
    high = classifier.compute_log_weight(verdict, 100)
    assert high >= low
