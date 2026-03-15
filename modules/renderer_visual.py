from diagnostics import diag_state_summary, diag_delta_summary

def render_state_summary(state: dict) -> str:
    s = diag_state_summary(state)
    return f"STATE SUMMARY\nkeys: {s['keys']}\nversion: {s['version']}\nhash: {s['hash']}"

def render_delta_summary(delta: dict) -> str:
    s = diag_delta_summary(delta)
    return f"DELTA SUMMARY\nkeys_changed: {s['keys_changed']}\nhash: {s['hash']}"

def render_timeline(history: list) -> str:
    lines = [f"[{i}] {h}" for i, h in enumerate(history)]
    return "\n".join(lines)
