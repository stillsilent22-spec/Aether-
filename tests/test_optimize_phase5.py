from modules.optimize_engine import PreloadOptimizer, EfficiencyMonitor
from modules.reconstruction_engine import ReconstructionEngine, GovernanceContext
def test_preload_optimizer():
    po = PreloadOptimizer()
    features = {"a": [1,2,3], "b": 5}
    loaded = po.preload(features)
    assert po.preloaded
    assert isinstance(loaded["a"], np.ndarray)
    assert loaded["b"] == 5

def test_efficiency_monitor():
    em = EfficiencyMonitor()
    em.record({"drift_variance": 0.05})
    em.record({"drift_variance": 0.10})
    score = em.get_efficiency_score()
    assert 0.8 < score < 1.0

def test_optimize_pipeline():
    engine = ReconstructionEngine(GovernanceContext())
    features = {"a": [1,2,3,4], "b": [2,2,2,2], "c": 5}
    result = engine.optimize_pipeline(features)
    assert "preloaded" in result
    assert "pruned" in result
    assert "efficiency" in result
    assert "recommendation" in result
    assert isinstance(result["monitor_history"], list)
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
