def build_dna(state):
    return {
        ".dna": {
            "O": state.get("O"),
            "F": state.get("F"),
            "Hλ": state.get("Hλ"),
            "Δ": state.get("Δ"),
            "B": state.get("B")
        }
    }

def build_aef(state):
    return {
        ".aef": {
            "A": state.get("A"),
            "governance_trace": state.get("G")
        }
    }
