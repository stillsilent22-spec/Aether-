def audio_signature_from_state(state: dict) -> dict:
    length = len(state)
    version = state.get("version", 0)
    if length < 3:
        tone = "low"
    elif 3 <= length <= 7:
        tone = "mid"
    else:
        tone = "high"
    return {"length": length, "version": version, "tone": tone}

def render_audio_description(sig: dict) -> str:
    return f"AUDIO: tone={sig['tone']}, length={sig['length']}, version={sig['version']}"
