import networkx as nx
import numpy as np
import hashlib
import logging

class OptimizeEngine:
    def isolate_components(self, graph: nx.Graph) -> list:
        # Vereinzelung: Isoliere Subgraphen (z. B. für Security)
        return [graph.subgraph(c).copy() for c in nx.connected_components(graph)]

    def prune_redundancy(self, features: dict, threshold: float = 0.1) -> dict:
        # Entferne Features mit geringer Varianz (Redundanz)
        pruned = {}
        for k, v in features.items():
            if isinstance(v, (list, np.ndarray)):
                arr = np.array(v)
                if arr.size > 1 and np.std(arr) > threshold:
                    pruned[k] = v
            else:
                pruned[k] = v
        return pruned

    def generate_recommendation(self, optimized: dict) -> str:
        # Empfehlung: z. B. Ressourcen-Reduktion vorschlagen
        drift = optimized.get("drift_variance", 0)
        if drift < 0.05:
            return "System stabil – keine Optimierung nötig."
        elif drift < 0.2:
            return "Empfehlung: Reduziere Ressourcen um 10%."
        else:
            return "Warnung: Hohe Instabilität – weitere Analyse empfohlen."

    def audit_log(self, message: str):
        logging.info(f"[OPTIMIZE] {message}")
