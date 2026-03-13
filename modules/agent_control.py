"""Structural control layer for local agent-like background processes."""

from __future__ import annotations

import os
import statistics
import subprocess
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None


ACTION_ORDER = {
    "observe": 0,
    "deprioritize": 1,
    "isolate": 2,
    "network_block": 3,
    "pause": 4,
}
IO_PULSE_BYTES = 32 * 1024 * 1024
FIREWALL_RULE_PREFIX = "AetherAgentControl"


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))


def _signal_value(signal: Any, key: str, default: Any = 0) -> Any:
    if isinstance(signal, dict):
        return signal.get(key, default)
    return getattr(signal, key, default)


def _action_max(left: str, right: str) -> str:
    return left if ACTION_ORDER.get(left, 0) >= ACTION_ORDER.get(right, 0) else right


@dataclass(frozen=True)
class AgentControlThresholds:
    candidate_score: float = 0.45
    drift_deprioritize: float = 0.55
    io_isolate: float = 0.60
    network_block: float = 0.74
    pause_cpu_load: float = 85.0
    pause_memory_load: float = 86.0


@dataclass
class AgentDecision:
    pid: int
    process_name: str
    structural_score: float
    cpu_drift: float
    io_pulse: float
    network_rhythm: float
    activity_score: float
    classification: str
    policy_hits: list[str] = field(default_factory=list)
    recommended_action: str = "observe"
    applied_action: str = "observe"
    control_state: str = "idle"
    note: str = ""


@dataclass
class AgentControlReport:
    ts: str
    agents_enabled: bool
    automatic_policies: bool
    system_pressure: str
    decisions: list[AgentDecision]
    status_line: str


@dataclass
class AppliedControlState:
    pid: int
    process_name: str
    original_priority: Any = None
    original_affinity: list[int] | None = None
    original_ionice: Any = None
    suspended: bool = False
    firewall_rule_names: list[str] = field(default_factory=list)
    exe_path: str = ""
    last_action: str = "observe"


class AgentControlEngine:
    """Detects agent-like background processes by structure and applies reversible controls."""

    def __init__(
        self,
        thresholds: AgentControlThresholds | None = None,
        apply_os_controls: bool = True,
        allow_firewall: bool = True,
    ) -> None:
        self.thresholds = thresholds or AgentControlThresholds()
        self.apply_os_controls = bool(apply_os_controls)
        self.allow_firewall = bool(allow_firewall)
        self._history: dict[int, deque[dict[str, float]]] = defaultdict(lambda: deque(maxlen=8))
        self._controlled: dict[int, AppliedControlState] = {}

    def evaluate_snapshot(
        self,
        snapshot: dict[str, Any],
        *,
        runtime_pressure: Any | None = None,
        agents_enabled: bool = True,
        automatic_policies: bool = True,
    ) -> AgentControlReport:
        process_signals = list(dict(snapshot or {}).get("process_signals", []) or [])
        network_signals = list(dict(snapshot or {}).get("network_signals", []) or [])
        network_by_pid: dict[int, list[Any]] = defaultdict(list)
        for signal in network_signals:
            pid = int(_signal_value(signal, "pid", 0) or 0)
            if pid > 0:
                network_by_pid[pid].append(signal)

        cpu_load = getattr(runtime_pressure, "cpu_load", None)
        memory_load = getattr(runtime_pressure, "memory_load", None)
        system_pause = bool(
            (cpu_load is not None and float(cpu_load) >= self.thresholds.pause_cpu_load)
            or (memory_load is not None and float(memory_load) >= self.thresholds.pause_memory_load)
        )
        if system_pause:
            system_pressure = "high"
        elif (
            (cpu_load is not None and float(cpu_load) >= (self.thresholds.pause_cpu_load - 10.0))
            or (memory_load is not None and float(memory_load) >= (self.thresholds.pause_memory_load - 8.0))
        ):
            system_pressure = "elevated"
        else:
            system_pressure = "steady"

        decisions: list[AgentDecision] = []
        current_pids: set[int] = set()
        ignored_pids = {int(os.getpid()), int(os.getppid())}
        for signal in process_signals:
            pid = int(_signal_value(signal, "pid", 0) or 0)
            if pid <= 0 or pid in ignored_pids:
                continue
            current_pids.add(pid)
            if bool(_signal_value(signal, "is_system", False)):
                continue
            if bool(_signal_value(signal, "has_window", True)):
                continue
            decision = self._build_decision(
                signal,
                network_by_pid.get(pid, []),
                agents_enabled=agents_enabled,
                automatic_policies=automatic_policies,
                system_pause=system_pause,
            )
            if decision is not None:
                decisions.append(decision)

        decisions.sort(
            key=lambda item: (
                -ACTION_ORDER.get(item.applied_action, 0),
                -float(item.structural_score),
                str(item.process_name).lower(),
                int(item.pid),
            )
        )
        candidate_count = sum(
            1 for item in decisions if float(item.structural_score) >= self.thresholds.candidate_score
        )
        applied_count = sum(1 for item in decisions if item.applied_action != "observe")
        if not agents_enabled:
            mode = "manuell deaktiviert"
        elif automatic_policies:
            mode = "auto aktiv"
        else:
            mode = "nur beobachten"
        status_line = (
            f"Agentensteuerung: {mode} | Druck {system_pressure} | "
            f"Kandidaten {candidate_count} | Eingriffe {applied_count}"
        )
        self._trim_history(current_pids)
        return AgentControlReport(
            ts=datetime.now(timezone.utc).isoformat(),
            agents_enabled=bool(agents_enabled),
            automatic_policies=bool(automatic_policies),
            system_pressure=system_pressure,
            decisions=decisions[:24],
            status_line=status_line,
        )

    def enforce_report(self, report: AgentControlReport) -> list[str]:
        target_actions = {
            int(decision.pid): decision
            for decision in report.decisions
            if str(decision.applied_action or "observe") != "observe"
        }
        notes: list[str] = []
        active_pids = {int(decision.pid) for decision in report.decisions}
        for pid, decision in target_actions.items():
            state, note = self._apply_control(decision.pid, decision.process_name, decision.applied_action)
            decision.control_state = state
            decision.note = note
            if note:
                notes.append(note)
        for pid in list(self._controlled):
            if pid not in target_actions:
                note = self._release_control(pid)
                if note:
                    notes.append(note)
        self._trim_history(active_pids)
        return notes

    def release_all(self) -> list[str]:
        notes: list[str] = []
        for pid in list(self._controlled):
            note = self._release_control(pid)
            if note:
                notes.append(note)
        return notes

    def _build_decision(
        self,
        signal: Any,
        network_signals: list[Any],
        *,
        agents_enabled: bool,
        automatic_policies: bool,
        system_pause: bool,
    ) -> AgentDecision | None:
        pid = int(_signal_value(signal, "pid", 0) or 0)
        name = str(_signal_value(signal, "name", "") or "")
        cpu_percent = float(_signal_value(signal, "cpu_percent", 0.0) or 0.0)
        memory_mb = float(_signal_value(signal, "memory_mb", 0.0) or 0.0)
        thread_count = int(_signal_value(signal, "thread_count", 0) or 0)
        open_connections = int(_signal_value(signal, "open_connections", 0) or 0)
        io_total = (
            int(_signal_value(signal, "io_read_bytes", 0) or 0)
            + int(_signal_value(signal, "io_write_bytes", 0) or 0)
        )

        history = self._history[pid]
        prev_cpu = float(history[-1]["cpu"]) if history else float(cpu_percent)
        mean_cpu = statistics.fmean(entry["cpu"] for entry in history) if history else float(cpu_percent)
        prev_io_total = float(history[-1]["io_total"]) if history else float(io_total)
        previous_deltas = [entry["io_delta"] for entry in history if float(entry["io_delta"]) > 0.0]
        avg_io_delta = statistics.fmean(previous_deltas) if previous_deltas else 0.0
        io_delta = max(0.0, float(io_total) - prev_io_total)
        cpu_drift = _clamp(max(abs(cpu_percent - prev_cpu), abs(cpu_percent - mean_cpu)) / 24.0)
        io_pulse = _clamp(io_delta / float(IO_PULSE_BYTES))
        if avg_io_delta > 0.0 and io_delta > (avg_io_delta * 2.5):
            io_pulse = _clamp(io_pulse + 0.15)
        network_rhythm = max(
            (
                float(_signal_value(item, "interval_regularity", 0.0) or 0.0)
                for item in list(network_signals or [])
            ),
            default=0.0,
        )
        activity_score = _clamp(
            (0.42 * _clamp(cpu_percent / 35.0))
            + (0.18 * _clamp(memory_mb / 1024.0))
            + (0.16 * _clamp(thread_count / 16.0))
            + (0.24 * _clamp(open_connections / 6.0))
        )
        structural_score = _clamp(
            0.14
            + (0.18 * _clamp(open_connections / 4.0))
            + (0.15 * _clamp(thread_count / 12.0))
            + (0.17 * cpu_drift)
            + (0.17 * io_pulse)
            + (0.19 * network_rhythm)
        )

        history.append(
            {
                "cpu": float(cpu_percent),
                "io_total": float(io_total),
                "io_delta": float(io_delta),
                "ts": float(time.time()),
            }
        )

        is_candidate = bool(structural_score >= self.thresholds.candidate_score)
        if not agents_enabled and pid in self._controlled:
            is_candidate = True
        if not is_candidate and not agents_enabled:
            is_candidate = bool(
                activity_score >= 0.20
                and (open_connections > 0 or cpu_percent >= 1.0 or io_pulse >= 0.20 or network_rhythm >= 0.40)
            )
        if not is_candidate and activity_score < 0.18:
            return None

        if structural_score >= 0.72:
            classification = "agentisch"
        elif structural_score >= self.thresholds.candidate_score:
            classification = "adaptiv"
        else:
            classification = "ruhig"

        policy_hits: list[str] = []
        recommended_action = "observe"
        if is_candidate:
            if not agents_enabled:
                policy_hits.append("manual_disable")
                recommended_action = "pause"
            else:
                if system_pause:
                    policy_hits.append("system_load_pause")
                    recommended_action = _action_max(recommended_action, "pause")
                if cpu_drift >= self.thresholds.drift_deprioritize:
                    policy_hits.append("cpu_drift")
                    recommended_action = _action_max(recommended_action, "deprioritize")
                if io_pulse >= self.thresholds.io_isolate:
                    policy_hits.append("io_pulse")
                    recommended_action = _action_max(recommended_action, "isolate")
                if network_rhythm >= self.thresholds.network_block and open_connections > 0:
                    policy_hits.append("network_rhythm")
                    recommended_action = _action_max(recommended_action, "network_block")

        should_apply = (not agents_enabled) or bool(automatic_policies)
        applied_action = recommended_action if should_apply else "observe"
        return AgentDecision(
            pid=pid,
            process_name=name or f"pid-{pid}",
            structural_score=round(float(structural_score), 3),
            cpu_drift=round(float(cpu_drift), 3),
            io_pulse=round(float(io_pulse), 3),
            network_rhythm=round(float(network_rhythm), 3),
            activity_score=round(float(activity_score), 3),
            classification=classification,
            policy_hits=policy_hits,
            recommended_action=recommended_action,
            applied_action=applied_action,
        )

    def _apply_control(self, pid: int, process_name: str, action: str) -> tuple[str, str]:
        if action == "observe":
            return "idle", ""
        if not self.apply_os_controls or psutil is None:
            self._controlled[pid] = AppliedControlState(pid=pid, process_name=process_name, last_action=action)
            return "simulated", f"{process_name} ({pid}) -> {action} simuliert"

        state = self._controlled.get(pid)
        if state is not None and state.last_action != action:
            self._release_control(pid)
            state = None

        try:
            process = psutil.Process(pid)
        except Exception:
            self._controlled.pop(pid, None)
            return "gone", f"{process_name} ({pid}) nicht mehr erreichbar"

        if state is None:
            state = AppliedControlState(pid=pid, process_name=process_name)
            try:
                state.original_priority = process.nice()
            except Exception:
                state.original_priority = None
            if hasattr(process, "cpu_affinity"):
                try:
                    state.original_affinity = list(process.cpu_affinity())
                except Exception:
                    state.original_affinity = None
            if hasattr(process, "ionice"):
                try:
                    state.original_ionice = process.ionice()
                except Exception:
                    state.original_ionice = None
            try:
                state.exe_path = str(process.exe() or "")
            except Exception:
                state.exe_path = ""
            self._controlled[pid] = state

        notes: list[str] = []
        self._apply_priority_reduction(process, state, action, notes)
        if action in {"isolate", "network_block", "pause"}:
            self._apply_affinity_limit(process, state, notes)

        if action in {"network_block", "pause"}:
            blocked = self._ensure_network_block(state, notes)
            if action == "pause" or not blocked:
                if not state.suspended:
                    try:
                        process.suspend()
                        state.suspended = True
                        notes.append("pausiert")
                    except Exception as exc:
                        notes.append(f"pause fehlgeschlagen: {exc}")

        state.last_action = action
        state_label = "active" if notes else "noop"
        return state_label, f"{process_name} ({pid}) -> {action}: {', '.join(notes) or 'ohne Aenderung'}"

    def _apply_priority_reduction(
        self,
        process: Any,
        state: AppliedControlState,
        action: str,
        notes: list[str],
    ) -> None:
        if psutil is None:
            return
        priority_target: Any = None
        if os.name == "nt":
            if action in {"network_block", "pause"}:
                priority_target = getattr(psutil, "IDLE_PRIORITY_CLASS", None)
            else:
                priority_target = getattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS", None)
        else:
            priority_target = 15 if action in {"network_block", "pause"} else 10
        if priority_target is not None:
            try:
                process.nice(priority_target)
                notes.append("prioritaet gesenkt")
            except Exception as exc:
                notes.append(f"prioritaet fehlgeschlagen: {exc}")
        if hasattr(process, "ionice"):
            try:
                if os.name == "nt":
                    target = getattr(psutil, "IOPRIO_VERYLOW", getattr(psutil, "IOPRIO_LOW", None))
                    if target is not None:
                        process.ionice(target)
                        notes.append("io niedrig")
                else:
                    target = getattr(psutil, "IOPRIO_CLASS_IDLE", None)
                    if target is not None:
                        process.ionice(target)
                        notes.append("io idle")
            except Exception:
                pass

    def _apply_affinity_limit(
        self,
        process: Any,
        state: AppliedControlState,
        notes: list[str],
    ) -> None:
        if not hasattr(process, "cpu_affinity"):
            return
        affinity = list(state.original_affinity or [])
        if not affinity:
            try:
                affinity = list(process.cpu_affinity())
            except Exception:
                return
        if len(affinity) <= 1:
            return
        target = affinity[: max(1, min(2, len(affinity) // 2))]
        try:
            process.cpu_affinity(target)
            notes.append(f"cpu-limitiert ({len(target)} kern)")
        except Exception as exc:
            notes.append(f"affinity fehlgeschlagen: {exc}")

    def _ensure_network_block(self, state: AppliedControlState, notes: list[str]) -> bool:
        if not self.allow_firewall or os.name != "nt":
            notes.append("netz per firewall nicht verfuegbar")
            return False
        exe_path = str(state.exe_path or "").strip()
        if not exe_path:
            notes.append("netzblock ohne exe-pfad uebersprungen")
            return False
        if state.firewall_rule_names:
            notes.append("netzregel aktiv")
            return True

        rule_names = [
            f"{FIREWALL_RULE_PREFIX}-{state.pid}-out",
            f"{FIREWALL_RULE_PREFIX}-{state.pid}-in",
        ]
        created: list[str] = []
        for rule_name, direction in zip(rule_names, ("out", "in"), strict=False):
            try:
                result = subprocess.run(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name={rule_name}",
                        f"dir={direction}",
                        "action=block",
                        f"program={exe_path}",
                        "enable=yes",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=4.0,
                )
            except Exception as exc:
                notes.append(f"netzregel fehlgeschlagen: {exc}")
                break
            if int(result.returncode) != 0:
                stderr = str(result.stderr or result.stdout or "").strip()
                notes.append(f"netzregel abgelehnt: {stderr or 'unbekannt'}")
                break
            created.append(rule_name)
        if len(created) == len(rule_names):
            state.firewall_rule_names = created
            notes.append("netz geblockt")
            return True
        for rule_name in created:
            self._delete_firewall_rule(rule_name)
        state.firewall_rule_names = []
        return False

    def _release_control(self, pid: int) -> str:
        state = self._controlled.pop(pid, None)
        if state is None:
            return ""
        if not self.apply_os_controls or psutil is None:
            return f"{state.process_name} ({pid}) -> freigegeben"
        try:
            process = psutil.Process(pid)
        except Exception:
            self._remove_firewall_rules(state)
            return f"{state.process_name} ({pid}) -> beendet, Regeln entfernt"

        notes: list[str] = []
        if state.suspended:
            try:
                process.resume()
                notes.append("fortgesetzt")
            except Exception as exc:
                notes.append(f"resume fehlgeschlagen: {exc}")
        if state.original_priority is not None:
            try:
                process.nice(state.original_priority)
                notes.append("prioritaet restauriert")
            except Exception:
                pass
        if state.original_affinity is not None and hasattr(process, "cpu_affinity"):
            try:
                process.cpu_affinity(list(state.original_affinity))
                notes.append("cpu restauriert")
            except Exception:
                pass
        if state.original_ionice is not None and hasattr(process, "ionice"):
            try:
                process.ionice(state.original_ionice)
                notes.append("io restauriert")
            except Exception:
                pass
        if self._remove_firewall_rules(state):
            notes.append("netzregel entfernt")
        return f"{state.process_name} ({pid}) -> freigegeben: {', '.join(notes) or 'keine Aktion'}"

    def _remove_firewall_rules(self, state: AppliedControlState) -> bool:
        removed = False
        for rule_name in list(state.firewall_rule_names):
            removed = self._delete_firewall_rule(rule_name) or removed
        state.firewall_rule_names = []
        return removed

    @staticmethod
    def _delete_firewall_rule(rule_name: str) -> bool:
        try:
            result = subprocess.run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    f"name={rule_name}",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=4.0,
            )
        except Exception:
            return False
        return int(result.returncode) == 0

    def _trim_history(self, active_pids: set[int]) -> None:
        stale = [pid for pid in self._history if pid not in active_pids]
        for pid in stale:
            self._history.pop(pid, None)
