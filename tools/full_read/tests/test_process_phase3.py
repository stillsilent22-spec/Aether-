import pytest
import os
from modules.process_monitor import ProcessMonitor

def test_monitor_process_self():
    pm = ProcessMonitor()
    pid = os.getpid()
    snap = pm.monitor_windows_process(pid)
    assert snap["cpu_usage"] >= 0
    assert snap["memory"] > 0
    assert "timestamp" in snap
