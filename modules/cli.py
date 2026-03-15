from runtime_core import init_runtime
from runtime_loop import run_loop, simple_delta_provider
from renderer_visual import render_state_summary, render_timeline
from monitoring_engine import monitor_runtime

def main():
    runtime = init_runtime()
    print("Aether Runtime gestartet")
    runtime = run_loop(runtime, max_ticks=10, delta_provider=simple_delta_provider)
    print(render_state_summary(runtime["state"]))
    print(render_timeline(runtime["history"]))
    print(monitor_runtime(runtime))
    exit(0)

if __name__ == "__main__":
    main()
