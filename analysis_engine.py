from operators import gradient, symmetry, frequency, compressibility, local_entropy

def analysis_engine(O):
    x = O.get("bytes", b"")
    features = {
        "gradient": gradient(x),
        "symmetry": symmetry(x),
        "frequency": frequency(x),
        "compressibility": compressibility(x),
        "local_entropy": local_entropy(x)
    }
    justification = {
        "source": "analysis_engine",
        "input_length": O.get("length", None)
    }
    return {"F": features, "justification": justification}
