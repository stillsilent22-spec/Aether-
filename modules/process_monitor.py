import psutil
import time
from typing import Dict, Any

class ProcessMonitor:
    def monitor_windows_process(self, pid: int) -> Dict[str, Any]:
        try:
            p = psutil.Process(pid)
            cpu = p.cpu_percent(interval=0.1)
            mem = p.memory_info().rss
            io = p.io_counters().read_bytes if hasattr(p, "io_counters") else 0
            return {
                "pid": pid,
                "cpu_usage": cpu,
                "memory": mem,
                "io": io,
                "timestamp": time.time()
            }
        except Exception as e:
            raise ValueError(f"Process monitoring failed: {e}")
