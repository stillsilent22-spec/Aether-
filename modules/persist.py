def build_dna(state):
    """Erzeugt ein DNA-Objekt aus dem aktuellen State."""
    return {
        ".dna": {
            "O": state.get("O"),
            "F": state.get("F"),
            "Hλ": state.get("Hλ"),
            "Δ": state.get("Δ"),
            "B": state.get("B"),
            "timestamp": state.get("timestamp"),
            "source": state.get("source", "aether")
        }
    }

def build_aef(state):
    """Erzeugt ein AEF-Objekt aus dem aktuellen State."""
    return {
        ".aef": {
            "A": state.get("A"),
            "governance_trace": state.get("G"),
            "timestamp": state.get("timestamp"),
            "source": state.get("source", "aether")
        }
    }