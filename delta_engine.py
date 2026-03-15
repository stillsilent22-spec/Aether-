from operators import delta_field

def delta_engine(Hλ, Hλ_prev=None):
    if Hλ_prev is None:
        Hλ_prev = 0.0
    delta = delta_field(Hλ, Hλ_prev)
    stability_score = 1.0 if abs(delta) < 0.01 else 0.0
    return {"Δ": delta, "stability_score": stability_score}
