"""Steuernder Agent-Loop fuer sparse Clusterbereiche im Embeddingraum."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import numpy as np


@dataclass
class AgentDirective:
    """Beschreibt die aktuelle Agent-Anweisung fuer die Kameraansicht."""

    instruction: str
    resolved_flash: bool
    resolved_count: int
    target_cluster: int | None
    action: str = ""
    action_payload: dict[str, object] | None = None
    rationale: str = ""
    should_execute: bool = False
    loop_source: str = ""
    loop_iteration: int = 0


class AgentLoopEngine:
    """Leitet Kamera- und Folgeaktionen aus Clustern, Offenheit und Shanway-Befunden ab."""

    def __init__(self) -> None:
        self._last_instruction_update = 0.0
        self._last_resolved_until = 0.0
        self._current_instruction = ""
        self._target_cluster: int | None = None
        self._target_vector = np.zeros(3, dtype=np.float64)
        self.resolved_count = 0
        self._browser_loop_state: dict[str, dict[str, object]] = {}

    def reset(self) -> None:
        """Setzt den Agentenzustand zurueck."""
        self._last_instruction_update = 0.0
        self._last_resolved_until = 0.0
        self._current_instruction = ""
        self._target_cluster = None
        self._target_vector = np.zeros(3, dtype=np.float64)
        self.resolved_count = 0
        self._browser_loop_state = {}

    def reset_browser_loop(self, source_key: str = "") -> None:
        """Setzt Browser-Folgeentscheidungen global oder fuer eine Quelle zurueck."""
        key = str(source_key or "").strip()
        if not key:
            self._browser_loop_state = {}
            return
        self._browser_loop_state.pop(key, None)

    def update(
        self,
        vault_entries: Sequence[dict[str, object]],
        current_embedding: Sequence[float],
        active: bool,
    ) -> AgentDirective:
        """Bestimmt die aktuelle Steueranweisung und prueft Clusterauflosung."""
        if not active:
            return AgentDirective("", False, self.resolved_count, None)

        now = time.time()
        if now - self._last_instruction_update >= 2.0 or not self._current_instruction:
            self._choose_target_cluster(vault_entries)
            self._last_instruction_update = now

        resolved = self._check_resolution(current_embedding)
        if resolved:
            self.resolved_count += 1
            self._last_resolved_until = now + 1.0

        if now <= self._last_resolved_until:
            return AgentDirective("CLUSTER RESOLVED \u2713", True, self.resolved_count, self._target_cluster)
        return AgentDirective(self._current_instruction, False, self.resolved_count, self._target_cluster)

    @staticmethod
    def _query_terms(
        source_label: str,
        file_type: str,
        assessment_payload: dict[str, object],
        current_url: str,
    ) -> list[str]:
        """Leitet robuste Suchterme fuer lokale Browser-Folgeschritte ab."""
        suffix = Path(str(source_label or "")).suffix.lower().strip(".")
        label = suffix or str(file_type or "").strip(". ").lower() or "binary"
        narrative = str(assessment_payload.get("narrative_text", "") or "")
        title_hint = Path(str(current_url or "")).name.replace("-", " ").replace("_", " ")
        terms: list[str] = [label, "file format", "structure"]
        if "pdf" in label or label == "document":
            terms.extend(["layout", "metadata"])
        elif label in {"ttf", "otf", "font"}:
            terms.extend(["glyph metrics", "kerning"])
        elif label in {"mp4", "mkv", "avi", "mov", "webm", "video"}:
            terms.extend(["container", "frame structure"])
        elif label in {"json", "csv", "sqlite", "bin"}:
            terms.extend(["schema", "encoding"])
        else:
            terms.extend(["entropy", "binary layout"])
        if narrative:
            terms.append("observer relative analysis")
        if title_hint:
            terms.extend(str(title_hint).split()[:3])
        deduped: list[str] = []
        for term in terms:
            value = str(term).strip()
            if value and value.lower() not in {item.lower() for item in deduped}:
                deduped.append(value)
        return deduped[:8]

    def plan_browser_followup(
        self,
        *,
        source_key: str,
        source_label: str,
        file_type: str,
        h_lambda: float,
        observer_state: str,
        assessment_payload: dict[str, object] | None = None,
        browser_enabled: bool,
        browser_available: bool,
        current_url: str = "",
        max_iterations: int = 2,
    ) -> AgentDirective:
        """Leitet einen optionalen lokalen Browser-Folgeschritt aus einem offenen Befund ab."""
        payload = dict(assessment_payload or {})
        classification = str(payload.get("classification", "") or "").strip().lower()
        missing_dependencies = [str(item) for item in list(payload.get("missing_dependencies", []) or []) if str(item).strip()]
        missing_data = [str(item) for item in list(payload.get("missing_data", []) or []) if str(item).strip()]
        next_action = str(payload.get("next_action", "") or "").strip()
        vault_gap = str(payload.get("vault_gap", "") or "").strip()
        boundary = str(payload.get("boundary", "") or "").strip().upper()
        key = str(source_key or source_label or "global").strip() or "global"

        if not browser_enabled:
            return AgentDirective("BROWSER-LOOP AUS", False, self.resolved_count, None, rationale="Browser-Liveanalyse ist deaktiviert.", loop_source=key)
        if not browser_available:
            return AgentDirective("BROWSER NICHT VERFUEGBAR", False, self.resolved_count, None, rationale="pywebview fehlt oder Browser ist lokal nicht verfuegbar.", loop_source=key)
        if classification in {"toxic", "sensitive"}:
            return AgentDirective("BROWSER GESPERRT", False, self.resolved_count, None, rationale="Sensible oder toxische Struktur blockiert Folgeaktionen.", loop_source=key)
        if missing_dependencies or missing_data:
            rationale = "Lokale Voraussetzungen fehlen; Browser-Recherche wird nicht als Ersatz missbraucht."
            return AgentDirective("LOKALE VORAUSSETZUNGEN FEHLEN", False, self.resolved_count, None, rationale=rationale, loop_source=key)
        if next_action.startswith("pip install") or "re-baselining" in next_action.lower():
            return AgentDirective("LOKALER NAECHSTER SCHRITT", False, self.resolved_count, None, rationale=next_action, loop_source=key)

        openness = float(h_lambda) >= 4.8 or str(observer_state or "").upper() == "OFFEN" or classification == "uncertain"
        if not openness and not vault_gap and boundary != "STRUCTURAL_HYPOTHESIS":
            return AgentDirective("LOOP STABIL", False, self.resolved_count, None, rationale="Keine externe Kontextsuche noetig.", loop_source=key)

        state = self._browser_loop_state.setdefault(
            key,
            {
                "count": 0,
                "last_query": "",
                "last_url": "",
                "updated_at": 0.0,
            },
        )
        current_count = int(state.get("count", 0) or 0)
        if current_count >= max(1, int(max_iterations)):
            return AgentDirective("LOOPLIMIT ERREICHT", False, self.resolved_count, None, rationale="Maximale Browser-Folgeschritte fuer diese Quelle erreicht.", loop_source=key, loop_iteration=current_count)

        query = " ".join(self._query_terms(source_label, file_type, payload, current_url))
        if query and query == str(state.get("last_query", "")) and current_url:
            return AgentDirective("GLEICHE FOLGEFRAGE", False, self.resolved_count, None, rationale="Die letzte Browser-Frage ist noch identisch; kein weiterer Sprung.", loop_source=key, loop_iteration=current_count)

        iteration = current_count + 1
        state["count"] = int(iteration)
        state["last_query"] = str(query)
        state["updated_at"] = float(time.time())
        reason = (
            f"H_lambda {float(h_lambda):.2f} und Observer {str(observer_state or 'OFFEN')} deuten auf offene Struktur; "
            f"Browser-Kontextlauf {iteration}/{max(1, int(max_iterations))}."
        )
        return AgentDirective(
            instruction=f"SHANWAY LOOP {iteration}: Kontext fuer {file_type or source_label} laden",
            resolved_flash=False,
            resolved_count=self.resolved_count,
            target_cluster=None,
            action="browser_search",
            action_payload={"query": str(query), "scope": "local_browser_context"},
            rationale=reason,
            should_execute=True,
            loop_source=key,
            loop_iteration=int(iteration),
        )

    def note_browser_navigation(self, source_key: str, url: str) -> None:
        """Merkt den zuletzt gestarteten Browser-Sprung fuer eine Quelle."""
        key = str(source_key or "").strip()
        if not key:
            return
        state = self._browser_loop_state.setdefault(key, {"count": 0, "last_query": "", "last_url": "", "updated_at": 0.0})
        state["last_url"] = str(url or "")
        state["updated_at"] = float(time.time())

    def _choose_target_cluster(self, vault_entries: Sequence[dict[str, object]]) -> None:
        """Waehlt den Cluster mit der groessten internen Varianz."""
        clusters: dict[str, list[np.ndarray]] = {}
        for entry in vault_entries:
            label = str(entry.get("cluster_label", "TRANSITIONAL"))
            embedding = entry.get("embedding_vector", [])
            if not embedding:
                continue
            vector = np.array(list(embedding)[:3], dtype=np.float64)
            clusters.setdefault(label, []).append(vector)

        if not clusters:
            self._current_instruction = ""
            self._target_cluster = None
            self._target_vector = np.zeros(3, dtype=np.float64)
            return

        best_label = None
        best_variance = -1.0
        best_vectors: list[np.ndarray] = []
        for label, vectors in clusters.items():
            data = np.vstack(vectors)
            variance = float(np.mean(np.var(data, axis=0)))
            if variance > best_variance:
                best_variance = variance
                best_label = label
                best_vectors = vectors

        assert best_label is not None
        self._target_cluster = {"HARMONIC": 0, "TRANSITIONAL": 1, "CHAOTIC": 2}.get(best_label, 1)
        data = np.vstack(best_vectors)
        centroid = np.mean(data, axis=0)
        spread = np.var(data, axis=0)
        sparse_axis = int(np.argmax(spread))
        direction = 1.0 if float(centroid[sparse_axis]) < 0.0 else -1.0
        self._target_vector = np.array(centroid, copy=True)
        self._target_vector[sparse_axis] += 0.35 * direction
        if sparse_axis == 0:
            self._current_instruction = "ZEIG MIR: Textur"
        elif sparse_axis == 1:
            self._current_instruction = "ZEIG MIR: Flaeche"
        else:
            self._current_instruction = "ZEIG MIR: Kante"

    def _check_resolution(self, current_embedding: Sequence[float]) -> bool:
        """Prueft, ob die aktuelle Beobachtung die Zielregion fuellt."""
        if not self._current_instruction:
            return False
        vector = np.array(list(current_embedding)[:3], dtype=np.float64)
        distance = float(np.linalg.norm(vector - self._target_vector))
        return bool(distance <= 0.18)
