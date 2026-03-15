from operators import entropy_field

def entropy_engine(F, λ_weights=None):
    if λ_weights is None:
        λ_weights = {"λ1": 1.0, "λ2": 1.0, "λ3": 1.0, "λ4": 1.0}
    x = F.get("raw_bytes", None)
    if x is None:
        x = F.get("bytes", b"")
    if not x:
        x = b""
    Hλ = entropy_field(
        x,
        λ_weights["λ1"],
        λ_weights["λ2"],
        λ_weights["λ3"],
        λ_weights["λ4"]
    )
    return {"Hλ": Hλ, "λ_weights": λ_weights}
