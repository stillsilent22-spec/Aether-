from operators import attraktor

def attraktor_engine(Δ):
    result = attraktor(None, None, Δ)
    scale_map = {"delta_variance": result["delta_variance"]}
    return {"A": result, "scale_map": scale_map}
