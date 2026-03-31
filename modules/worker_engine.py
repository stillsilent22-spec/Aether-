import logging
logger = logging.getLogger(__name__)
import hashlib, logging, threading, time, json, itertools

_log = logging.getLogger(__name__)
from typing import List, Optional, Dict, Set
from collections import defaultdict

class PermutationNode:
    def __init__(self, path_id, peers, depth=0):
        self.path_id = path_id
        self.peers = peers
        self.depth = depth
        self.invariant_hash = hashlib.sha256(str((path_id, tuple(sorted(peers)))).encode()).hexdigest()
        self.children = []

class SignalObserver:
    def __init__(self, node_id):
        self.node_id = node_id
        self.signal_topology = {}
        self.observation_history = []
    def observe(self, signal_source, connected_peers):
        s = signal_source + ':' + ','.join(sorted(connected_peers))
        h = hashlib.sha256(s.encode()).hexdigest()
        if signal_source not in self.signal_topology:
            self.signal_topology[signal_source] = set()
        self.signal_topology[signal_source].update(connected_peers)
        self.observation_history.append((time.time(), h[:16]))
        return h
    def get_topology_invariant(self):
        d = json.dumps({k: sorted(list(v)) for k,v in self.signal_topology.items()}, sort_keys=True)
        return hashlib.sha256(d.encode()).hexdigest()

class PermutationTree:
    def __init__(self, root_peers, max_depth=3):
        self.root_peers = root_peers
        self.max_depth = max_depth
        self.root = None
        self.all_nodes = []
        self._build_tree()
    def _build_tree(self):
        self.root = PermutationNode('root', self.root_peers, depth=0)
        self.all_nodes.append(self.root)
        q = [self.root]
        while q:
            node = q.pop(0)
            if node.depth >= self.max_depth: continue
            for r in range(1, min(len(node.peers)+1, 4)):
                for perm in itertools.combinations(node.peers, r):
                    pid = node.path_id + '/' + hashlib.sha256(','.join(perm).encode()).hexdigest()[:8]
                    child = PermutationNode(pid, list(perm), node.depth+1)
                    node.children.append(child)
                    self.all_nodes.append(child)
                    q.append(child)
    def invariants_chain(self):
        hashes = sorted([n.invariant_hash for n in self.all_nodes])
        return hashlib.sha256(''.join(hashes).encode()).hexdigest()

class WorkerEngine:
    def __init__(self, node_id):
        self.node_id = node_id
        self.running = False
        self.peer_list = []
        self.permutation_tree = None
        self.signal_observer = SignalObserver(node_id)
        self.invariant_chain_history = []
        self.lock = threading.Lock()
    def set_peers(self, peers):
        with self.lock:
            self.peer_list = peers
            if len(peers) > 0:
                self.permutation_tree = PermutationTree(peers, max_depth=2)
    def compute_invariant_chain(self):
        if not self.permutation_tree:
            return hashlib.sha256(b'empty').hexdigest()
        chain = self.permutation_tree.invariants_chain()
        with self.lock:
            self.invariant_chain_history.append(chain)
        return chain
    def observe_signal(self, signal_source, connected_peers):
        return self.signal_observer.observe(signal_source, connected_peers)
    def get_topology_snapshot(self):
        return {'node_id': self.node_id, 'peer_count': len(self.peer_list), 'perm_nodes': len(self.permutation_tree.all_nodes) if self.permutation_tree else 0, 'topology_inv': self.signal_observer.get_topology_invariant(), 'last_chain': self.invariant_chain_history[-1] if self.invariant_chain_history else None}
    def start_worker_loop(self, interval=10):
        self.running = True
        t = threading.Thread(target=self._daemon_loop, args=(interval,), daemon=True)
        t.start()
    def _daemon_loop(self, interval):
        while self.running:
            try:
                self.compute_invariant_chain()
                if self.peer_list:
                    self.observe_signal(self.node_id, self.peer_list[:min(2, len(self.peer_list))])
            except Exception as exc:
                _log.warning("[WorkerEngine] daemon_loop error: %s", exc)
            time.sleep(interval)

_engine = None
def init_worker_engine(node_id):
    global _engine; _engine = WorkerEngine(node_id); _engine.start_worker_loop(); return _engine
def get_worker_engine(): return _engine
def set_worker_peers(peers):
    if _engine: _engine.set_peers(peers)
def get_invariant_chain():
    if _engine: return _engine.compute_invariant_chain()
    return hashlib.sha256(b'no_engine').hexdigest()
