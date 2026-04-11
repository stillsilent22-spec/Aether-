import py_compile, sys
files = [
    "modules/blindspot_engine.py",
    "modules/gossip_toxicity_filter.py",
    "modules/algo_share.py",
    "modules/swarm_p2p.py",
    "modules/task_broker.py",
]
ok = True
for f in files:
    try:
        py_compile.compile(f, doraise=True)
        print(f"OK  {f}")
    except py_compile.PyCompileError as e:
        print(f"ERR {f}: {e}")
        ok = False
sys.exit(0 if ok else 1)
