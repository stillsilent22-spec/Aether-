import pytest
import networkx as nx
import numpy as np
from modules.optimize_engine import OptimizeEngine

def test_isolate_components():
    G = nx.Graph()
    G.add_edges_from([(1,2), (3,4)])
    oe = OptimizeEngine()
    isolated = oe.isolate_components(G)
    assert len(isolated) == 2

def test_prune_redundancy():
    features = {"a": [1,1,1,1], "b": [1,2,3,4], "c": 5}
    oe = OptimizeEngine()
    pruned = oe.prune_redundancy(features, threshold=0.5)
    assert "a" not in pruned
    assert "b" in pruned
    assert "c" in pruned

def test_generate_recommendation():
    oe = OptimizeEngine()
    rec1 = oe.generate_recommendation({"drift_variance": 0.01})
    rec2 = oe.generate_recommendation({"drift_variance": 0.1})
    rec3 = oe.generate_recommendation({"drift_variance": 0.5})
    assert "stabil" in rec1
    assert "Reduziere" in rec2
    assert "Warnung" in rec3
