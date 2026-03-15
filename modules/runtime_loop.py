from runtime_core import runtime_step, runtime_set_running

def run_loop(runtime: dict, max_ticks: int, delta_provider: callable) -> dict:
    runtime = runtime_set_running(runtime, True)
    for t in range(max_ticks):
        delta = delta_provider(runtime, t)
        if delta is None:
            break
        runtime = runtime_step(runtime, delta)
    runtime = runtime_set_running(runtime, False)
    return runtime

def simple_delta_provider(runtime: dict, t: int) -> dict:
    if t > 100:
        return None
    return {"tick": t}
