from operators import beauty_signature

def beauty_engine(A):
    sym = A.get("symmetry", 1.0)
    proportion = 1.0
    gradient_coherence = 1.0
    B = beauty_signature(sym, proportion, gradient_coherence)
    structural_explanation = {"symmetry": sym, "proportion": proportion, "gradient_coherence": gradient_coherence}
    return {"B": B, "structural_explanation": structural_explanation}
