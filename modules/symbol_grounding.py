"""Symbol Grounding Layer mit persistenter Token- und Beziehungsstruktur."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np


class SymbolGroundingLayer:
    """Vergibt Maschinen-Token, Bedeutungen und semantische Beziehungen an Cluster."""

    def __init__(self, state_path: str) -> None:
        self.state_path = Path(state_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state = self._load_state()

    def _load_state(self) -> dict[str, Any]:
        """Liest den gespeicherten Grounding-Zustand."""
        if not self.state_path.is_file():
            return {"tokens": {}, "entry_to_token": {}, "semantic_network": []}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return {"tokens": {}, "entry_to_token": {}, "semantic_network": []}

    def _save_state(self) -> None:
        """Persistiert den aktuellen Grounding-Zustand."""
        self.state_path.write_text(json.dumps(self.state, ensure_ascii=True, indent=2), encoding="utf-8")

    @staticmethod
    def _token_from_centroid(centroid: list[float]) -> str:
        """Erzeugt ein 8-stelliges Maschinen-Token aus dem Clusterzentrum."""
        payload = json.dumps([round(float(value), 6) for value in centroid], ensure_ascii=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8]

    @staticmethod
    def _mean_shape(curves: list[list[float]]) -> str:
        """Leitet eine deutsche Kurvenform aus Entropiekurven ab."""
        if not curves:
            return "flache Entropie"
        slopes = []
        for curve in curves:
            if len(curve) < 2:
                continue
            slopes.append(float(curve[-1]) - float(curve[0]))
        if not slopes:
            return "flache Entropie"
        mean_slope = float(np.mean(slopes))
        if mean_slope > 0.22:
            return "steigende Entropie"
        if mean_slope < -0.22:
            return "fallende Entropie"
        return "flache Entropie"

    @staticmethod
    def _character(mean_d: float) -> str:
        """Leitet eine deutsche Charakteristik aus D ab."""
        if mean_d < 1.25:
            return "harmonisch"
        if mean_d < 1.6:
            return "transitionell"
        return "chaotisch"

    @staticmethod
    def _health(alarm_rate: float) -> str:
        """Leitet eine deutsche Gesundheitsangabe aus der Alarmrate ab."""
        return "sauber" if alarm_rate < 0.25 else "stoerbehaftet"

    def sync_clusters(self, vault_entries: list[dict[str, Any]], cluster_variances: dict[str, float]) -> None:
        """Vergibt Tokens an enge Cluster und aktualisiert Bedeutungen und Beziehungsnetz."""
        grouped: dict[str, list[dict[str, Any]]] = {}
        for entry in vault_entries:
            label = str(entry.get("cluster_label", "TRANSITIONAL"))
            grouped.setdefault(label, []).append(entry)

        dirty = False
        for label, entries in grouped.items():
            variance = float(cluster_variances.get(label, 1.0))
            if variance >= 0.05 or not entries:
                continue
            centroid = np.mean(
                np.array([list(entry.get("embedding_vector", [0.0] * 16)) for entry in entries], dtype=np.float64),
                axis=0,
            ).tolist()
            token = self._token_from_centroid([float(value) for value in centroid])
            token_record = self.state["tokens"].setdefault(
                token,
                {
                    "token": token,
                    "human_name": "",
                    "centroid": [float(value) for value in centroid],
                    "members": [],
                    "meaning": {},
                    "member_updates": 0,
                },
            )
            token_record["centroid"] = [float(value) for value in centroid]
            for entry in entries:
                entry_id = str(entry.get("id"))
                if entry_id not in token_record["members"]:
                    token_record["members"].append(entry_id)
                    token_record["member_updates"] = int(token_record.get("member_updates", 0)) + 1
                    dirty = True
                self.state["entry_to_token"][entry_id] = token

            if int(token_record.get("member_updates", 0)) >= 5:
                curves = [list(item.get("payload_json", {}).get("entropy_curve", [])) for item in entries]
                d_values = [float(item.get("payload_json", {}).get("beauty_d", 1.0)) for item in entries]
                alarm_flags = [1.0 if bool(item.get("payload_json", {}).get("alarm", False)) else 0.0 for item in entries]
                token_record["meaning"] = {
                    "shape": self._mean_shape(curves),
                    "character": self._character(float(np.mean(d_values)) if d_values else 1.0),
                    "health": self._health(float(np.mean(alarm_flags)) if alarm_flags else 0.0),
                }
                token_record["member_updates"] = 0
                dirty = True

        if dirty:
            self._rebuild_semantic_network(vault_entries)
            self._save_state()

    def rename_token(self, token: str, human_name: str) -> None:
        """Speichert einen menschlichen Namen neben der Maschinenidentitaet."""
        if token not in self.state["tokens"]:
            return
        self.state["tokens"][token]["human_name"] = human_name.strip()
        self._save_state()

    def rebuild_network(self, vault_entries: list[dict[str, Any]]) -> None:
        """Berechnet das semantische Netz explizit neu."""
        self._rebuild_semantic_network(vault_entries)
        self._save_state()

    def token_for_entry(self, entry_id: int | str) -> dict[str, Any] | None:
        """Liefert Token-Informationen fuer einen Vault-Eintrag."""
        token = self.state["entry_to_token"].get(str(entry_id))
        if not token:
            return None
        return self.state["tokens"].get(token)

    def named_counts(self) -> tuple[int, int]:
        """Liefert Anzahl benannter Tokens und Gesamtzahl."""
        tokens = list(self.state["tokens"].values())
        total = len(tokens)
        named = sum(1 for token in tokens if str(token.get("human_name", "")).strip())
        return named, total

    def ontology_complete(self) -> bool:
        """Prueft, ob alle Tokens bereits menschliche Namen tragen."""
        named, total = self.named_counts()
        return total > 0 and named == total

    def semantic_lines(self) -> list[str]:
        """Formatiert das semantische Netz fuer die Vault-Anzeige."""
        lines: list[str] = []
        for edge in self.state.get("semantic_network", []):
            left = self._display_name(str(edge.get("source", "")))
            right = self._display_name(str(edge.get("target", "")))
            relation = str(edge.get("relation", "SIMILAR"))
            weight = float(edge.get("weight", 0.0))
            if relation == "OVERLAPS":
                lines.append(f"{left} <-> {right} ({relation} {weight * 100.0:.0f}%)")
            else:
                lines.append(f"{left} <-> {right} ({relation})")
        return lines

    def opposite_pairs(self) -> list[tuple[str, str]]:
        """Liefert bekannte Gegensatz-Paare in Anzeigeform."""
        pairs: list[tuple[str, str]] = []
        for edge in self.state.get("semantic_network", []):
            if str(edge.get("relation", "")) != "OPPOSITE":
                continue
            left = self._display_name(str(edge.get("source", "")))
            right = self._display_name(str(edge.get("target", "")))
            if left and right:
                pairs.append((left, right))
        return pairs

    def related_names(self, token: str) -> list[str]:
        """Liefert menschliche Beziehungsnamen fuer ein Token."""
        names: list[str] = []
        for edge in self.state.get("semantic_network", []):
            if str(edge.get("source", "")) == token:
                names.append(self._display_name(str(edge.get("target", ""))))
            elif str(edge.get("target", "")) == token:
                names.append(self._display_name(str(edge.get("source", ""))))
        return [name for name in names if name]

    def export_state(self) -> dict[str, Any]:
        """Gibt den gesamten Grounding-Zustand fuer Vault-Export zurueck."""
        return json.loads(json.dumps(self.state))

    def _display_name(self, token: str) -> str:
        """Formatiert Hash und optionalen Menschennamen fuer die Anzeige."""
        record = self.state["tokens"].get(token, {})
        human_name = str(record.get("human_name", "")).strip()
        return f"⬡ {token} · {human_name}" if human_name else f"⬡ {token}"

    def _rebuild_semantic_network(self, vault_entries: list[dict[str, Any]]) -> None:
        """Berechnet SIMILAR / OPPOSITE / OVERLAPS zwischen benannten Tokens."""
        del vault_entries
        token_items = list(self.state["tokens"].items())
        edges: list[dict[str, Any]] = []
        for index, (token_a, record_a) in enumerate(token_items):
            name_a = str(record_a.get("human_name", "")).strip()
            if not name_a:
                continue
            centroid_a = np.array(record_a.get("centroid", [0.0] * 16), dtype=np.float64)
            members_a = set(str(item) for item in record_a.get("members", []))
            for token_b, record_b in token_items[index + 1 :]:
                name_b = str(record_b.get("human_name", "")).strip()
                if not name_b:
                    continue
                centroid_b = np.array(record_b.get("centroid", [0.0] * 16), dtype=np.float64)
                members_b = set(str(item) for item in record_b.get("members", []))
                if centroid_a.size == 0 or centroid_b.size == 0:
                    continue
                denom = float(np.linalg.norm(centroid_a) * np.linalg.norm(centroid_b))
                similarity = float(np.dot(centroid_a, centroid_b) / denom) if denom > 1e-9 else 0.0
                if similarity > 0.75:
                    edges.append({"source": token_a, "target": token_b, "relation": "SIMILAR", "weight": similarity})
                inverse_gap = float(np.linalg.norm(centroid_a + centroid_b))
                if inverse_gap < 0.35:
                    edges.append({"source": token_a, "target": token_b, "relation": "OPPOSITE", "weight": inverse_gap})
                overlap = len(members_a & members_b) / max(1, len(members_a | members_b))
                if overlap > 0.4:
                    edges.append({"source": token_a, "target": token_b, "relation": "OVERLAPS", "weight": overlap})
        self.state["semantic_network"] = edges
