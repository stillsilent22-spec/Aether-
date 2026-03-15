"""Evolvierte Systemsprache ohne externes Sprachmodell."""

from __future__ import annotations

import json
import random
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class EvolvedSentence:
    """Eine evolvierte Satzkandidatur."""

    text: str
    score: float
    tree: dict[str, Any]


class EvolvedLanguageEngine:
    """Evolviert deutsche Beschreibungssaetze aus systeminternen Ereignissen."""

    SUBJECTS = ["das system", "die ontologie", "das muster", "der kontrast", "die struktur", "das feld"]
    VERBS = ["ordnet", "verdichtet", "trennt", "verbindet", "stabilisiert", "benennt", "klaert"]
    OBJECTS = [
        "eine ruhige figur",
        "einen neuen gegensatz",
        "die vorhandene spur",
        "eine wachsende beziehung",
        "eine stabile form",
        "eine eigene bedeutung",
    ]
    QUALIFIERS = [
        "im aktuellen feld",
        "zwischen den clustern",
        "aus den letzten beobachtungen",
        "im aetherraum",
        "aus der session-geometrie",
        "ueber die entropische linie",
    ]
    CONNECTORS = ["und", "wobei", "waehrend", "sodass", "wenn"]
    METRIC_WORDS = ["kohaerent", "harmonisch", "chaotisch", "sauber", "gespannt", "vollstaendig"]

    def __init__(self, state_path: str, session_seed: int) -> None:
        self.state_path = Path(state_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.rng = random.Random(int(session_seed) & 0xFFFFFFFF)
        self._lock = threading.Lock()
        self.population_size = 100
        self.generations = 100
        self.state = self._load_state()
        if not self.state.get("population"):
            self.state["population"] = [self._random_tree() for _ in range(self.population_size)]
            self._save_state()

    def _load_state(self) -> dict[str, Any]:
        """Liest persistenten Sprachzustand."""
        if not self.state_path.is_file():
            return {"population": [], "top": [], "events": []}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return {"population": [], "top": [], "events": []}

    def _save_state(self) -> None:
        """Persistiert den Sprachzustand."""
        self.state_path.write_text(json.dumps(self.state, ensure_ascii=True, indent=2), encoding="utf-8")

    def _random_leaf(self) -> dict[str, Any]:
        """Erzeugt ein zufaelliges Terminal."""
        return {
            "kind": self.rng.choice(["subject", "verb", "object", "qualifier", "metric", "event"]),
            "index": self.rng.randrange(0, 6),
        }

    def _random_tree(self, depth: int = 0) -> dict[str, Any]:
        """Erzeugt einen zufaelligen kleinen GP-Baum."""
        if depth >= 2 or self.rng.random() < 0.35:
            return self._random_leaf()
        return {
            "kind": self.rng.choice(["concat", "pair"]),
            "left": self._random_tree(depth + 1),
            "right": self._random_tree(depth + 1),
            "connector": self.rng.randrange(0, len(self.CONNECTORS)),
        }

    def _mutate(self, tree: dict[str, Any], rate: float = 0.18) -> dict[str, Any]:
        """Mutiert einen GP-Baum rekursiv."""
        if self.rng.random() < rate:
            return self._random_tree()
        node = dict(tree)
        if node.get("kind") in {"concat", "pair"}:
            node["left"] = self._mutate(dict(node["left"]), rate)
            node["right"] = self._mutate(dict(node["right"]), rate)
            if self.rng.random() < rate:
                node["connector"] = self.rng.randrange(0, len(self.CONNECTORS))
        elif self.rng.random() < rate:
            node["index"] = self.rng.randrange(0, 6)
        return node

    def _crossover(self, left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
        """Kombiniert zwei GP-Baeume."""
        if left.get("kind") not in {"concat", "pair"} or right.get("kind") not in {"concat", "pair"}:
            return dict(self.rng.choice([left, right]))
        if self.rng.random() < 0.5:
            return {
                "kind": left["kind"],
                "left": dict(left["left"]),
                "right": dict(right["right"]),
                "connector": left["connector"],
            }
        return {
            "kind": right["kind"],
            "left": dict(right["left"]),
            "right": dict(left["right"]),
            "connector": right["connector"],
        }

    def _event_word(self, context: dict[str, Any], index: int) -> str:
        """Leitet Ereigniswoerter aus dem Systemzustand ab."""
        event_type = str(context.get("event_type", "zustand"))
        mapping = {
            0: {
                "pattern_reinforced": "das muster",
                "contrast_discovered": "der gegensatz",
                "ontology_shift": "die ontologie",
                "ontology_complete": "die vollstaendige ontologie",
                "agent_resolved": "die loesung",
                "dialog_turn": "die eingabe",
            },
            1: {
                "pattern_reinforced": "verdichtet sich",
                "contrast_discovered": "wird sichtbar",
                "ontology_shift": "verschiebt sich",
                "ontology_complete": "spricht klar",
                "agent_resolved": "wird geschlossen",
                "dialog_turn": "ordnet sich",
            },
            2: {
                "pattern_reinforced": str(context.get("pattern_label", "eine wiederkehrende form")),
                "contrast_discovered": str(context.get("contrast_label", "zwei gegensaetze")),
                "ontology_shift": str(context.get("ontology_label", "eine neue ordnung")),
                "ontology_complete": str(context.get("ontology_label", "das ganze feld")),
                "agent_resolved": str(context.get("agent_label", "die offene region")),
                "dialog_turn": str(context.get("dialog_label", "eine neue aetherantwort")),
            },
        }
        return mapping.get(index, {}).get(event_type, "das system")

    def _evaluate_tree(self, tree: dict[str, Any], context: dict[str, Any]) -> str:
        """Erzeugt einen Satz aus einem GP-Baum."""
        kind = str(tree.get("kind", "subject"))
        if kind == "subject":
            idx = int(tree.get("index", 0)) % len(self.SUBJECTS)
            return self.SUBJECTS[idx]
        if kind == "verb":
            idx = int(tree.get("index", 0)) % len(self.VERBS)
            return self.VERBS[idx]
        if kind == "object":
            idx = int(tree.get("index", 0)) % len(self.OBJECTS)
            return self.OBJECTS[idx]
        if kind == "qualifier":
            idx = int(tree.get("index", 0)) % len(self.QUALIFIERS)
            return self.QUALIFIERS[idx]
        if kind == "metric":
            idx = int(tree.get("index", 0)) % len(self.METRIC_WORDS)
            return self.METRIC_WORDS[idx]
        if kind == "event":
            idx = int(tree.get("index", 0)) % 3
            return self._event_word(context, idx)
        if kind in {"concat", "pair"}:
            left = self._evaluate_tree(dict(tree.get("left", {})), context)
            right = self._evaluate_tree(dict(tree.get("right", {})), context)
            connector = self.CONNECTORS[int(tree.get("connector", 0)) % len(self.CONNECTORS)]
            if kind == "concat":
                return f"{left} {right}"
            return f"{left} {connector} {right}"
        return "das system beschreibt sich"

    def _cleanup(self, text: str) -> str:
        """Formatiert Satzfragmente zu lesbaren deutschen Saetzen."""
        words = [word for word in str(text).strip().split() if word]
        if not words:
            return "Das System beschreibt seine Struktur."
        sentence = " ".join(words)
        sentence = sentence[:1].upper() + sentence[1:]
        if not sentence.endswith("."):
            sentence += "."
        return sentence

    def _fitness(self, text: str, context: dict[str, Any]) -> float:
        """Bewertet Satzqualitaet aus rein systeminternen Kriterien."""
        lowered = text.lower()
        score = 0.0
        length = len(text)
        if 40 <= length <= 140:
            score += 2.2
        elif 25 <= length <= 180:
            score += 1.3
        unique_ratio = len(set(lowered.split())) / max(1, len(lowered.split()))
        score += unique_ratio * 2.0

        event_type = str(context.get("event_type", ""))
        if event_type == "pattern_reinforced" and ("muster" in lowered or "form" in lowered):
            score += 2.6
        if event_type == "contrast_discovered" and ("gegensatz" in lowered or "kontrast" in lowered):
            score += 2.8
        if event_type == "ontology_shift" and ("ontologie" in lowered or "ordnung" in lowered):
            score += 2.4
        if event_type == "ontology_complete" and ("vollstaendig" in lowered or "ganz" in lowered or "spricht" in lowered):
            score += 3.0
        if event_type == "agent_resolved" and ("region" in lowered or "loesung" in lowered or "geschlossen" in lowered):
            score += 2.2
        if event_type == "dialog_turn" and ("eingabe" in lowered or "antwort" in lowered or "struktur" in lowered):
            score += 2.5

        for value in [context.get("pattern_label", ""), context.get("contrast_label", ""), context.get("ontology_label", ""), context.get("token_name", "")]:
            value_text = str(value).strip().lower()
            if value_text and value_text in lowered:
                score += 1.4
        if context.get("ontology_complete", False):
            score += 1.0
        if "das system" in lowered:
            score += 0.8
        if lowered.count(" ") < 4:
            score -= 1.5
        return score

    def evolve(self, context: dict[str, Any]) -> list[EvolvedSentence]:
        """Fuehrt 100 Generationen mit 100 Baeumen ueber dem Ereigniskontext aus."""
        with self._lock:
            population = [dict(item) for item in self.state.get("population", [])]
            if len(population) < self.population_size:
                population.extend(self._random_tree() for _ in range(self.population_size - len(population)))

            for _ in range(self.generations):
                scored = []
                for tree in population:
                    text = self._cleanup(self._evaluate_tree(tree, context))
                    scored.append((self._fitness(text, context), tree, text))
                scored.sort(key=lambda item: item[0], reverse=True)
                elites = [dict(item[1]) for item in scored[: max(8, self.population_size // 10)]]
                new_population = list(elites)
                while len(new_population) < self.population_size:
                    parent_a = self.rng.choice(elites)
                    parent_b = self.rng.choice(elites)
                    child = self._crossover(parent_a, parent_b)
                    child = self._mutate(child)
                    new_population.append(child)
                population = new_population[: self.population_size]

            final = []
            for tree in population:
                text = self._cleanup(self._evaluate_tree(tree, context))
                final.append(EvolvedSentence(text=text, score=self._fitness(text, context), tree=dict(tree)))
            final.sort(key=lambda item: item.score, reverse=True)
            top = final[:3]
            self.state["population"] = population
            self.state["top"] = [{"text": item.text, "score": item.score, "tree": item.tree} for item in top]
            self.state.setdefault("events", []).append(context)
            self.state["events"] = self.state["events"][-200:]
            self._save_state()
            return top

    def describe(self, context: dict[str, Any], ontology_complete: bool) -> list[EvolvedSentence]:
        """Evolviert neue Saetze und gibt bei Ontologievollstand die Top 3 zurueck."""
        top = self.evolve(context)
        if ontology_complete:
            return top[:3]
        return top[:1]

    def top_sentences(self) -> list[EvolvedSentence]:
        """Liefert die letzten drei fittesten Saetze."""
        with self._lock:
            result = []
            for item in self.state.get("top", [])[:3]:
                result.append(
                    EvolvedSentence(
                        text=str(item.get("text", "")),
                        score=float(item.get("score", 0.0)),
                        tree=dict(item.get("tree", {})),
                    )
                )
            return result
