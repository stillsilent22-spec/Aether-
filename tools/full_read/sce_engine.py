from typing import Dict, Any
from operators import sce_signature


def sce_engine(A: Dict[str, Any]) -> Dict[str, Any]:
    """Structural Coherence Engine: Kybernetischer Controller für Aether-Swarm.
    
    Misst Systemkoheränz (symmetry, proportion, gradient_coherence) und generiert
    deterministische Steuersignale für delta_engine, reconstruction_engine und attractor_tuning.
    Prinzip: „Intelligence is in the ecosystem. Aether knows its place."
    """
    
    # === MESSWERTE aus Swarm-Zustand ===
    sym = A.get("symmetry", 1.0)
    proportion = A.get("proportion", 1.0)
    gradient_coherence = A.get("gradient_coherence", 1.0)
    
    # === KOHÄRENZ-BERECHNUNG ===
    # Gewichtetes Mittel mit Nichtlinearität und Abweichungs-Penalty
    w_sym, w_prop, w_grad = 0.4, 0.3, 0.3
    weighted = w_sym * sym + w_prop * proportion + w_grad * gradient_coherence
    
    # Deviation-Penalty: Zu disparäte Messwerte signalisieren Systeminstabilität
    deviation = abs(sym - proportion) + abs(proportion - gradient_coherence)
    penalty = 0.1 * (deviation / 3.0)  # Normalisierung für 3 Dimensionen
    
    # Nichtlinearität (x^1.5): Superlineare Reaktion auf Kohärenz, Homeostase
    coherence_score = max(0.0, min(1.0, (weighted ** 1.5) - penalty))
    
    # Non-invertible Signature (Fingerprint für Anchors – unverändert)
    B = sce_signature(sym, proportion, gradient_coherence)
    
    # === KYBERNETISCHE STEUERSIGNALE ===
    # Negative Rückkopplung: Verstärke Konvergenz wenn Kohärenz sinkt
    delta_adjustment = 1.0 + (0.5 * (1.0 - coherence_score))  # Range [1.0, 1.5]
    
    # Seed-Stabilität: Verstärke "Fixpunkte" wenn System kohärent
    seed_stability_boost = coherence_score ** 1.3  # Asymmetrie bevorzugt stabile Seeds
    
    # Reconstruction-Trigger: Dringlichkeit wenn zu viel Entropie/Deskoheränz
    reconstruction_trigger = 1.0 - coherence_score if coherence_score < 0.6 else 0.0
    
    # Attractor-Tuning: Sanfte Verschiebung (Noether: Symmetrie-Pfad bewahren)
    attractor_tuning = sym - 0.5  # Range [-0.5, 0.5], folgt Symmetrie-Asymmetrien
    
    control_signals = {
        "delta_adjustment": float(delta_adjustment),
        "seed_stability_boost": float(seed_stability_boost),
        "reconstruction_trigger": float(reconstruction_trigger),
        "attractor_tuning": float(attractor_tuning),
    }
    
    return {
        "B": B,
        "coherence_score": float(coherence_score),
        "control_signals": control_signals,
        "structural_explanation": {
            "symmetry": sym,
            "proportion": proportion,
            "gradient_coherence": gradient_coherence,
            "deviation_penalty": float(penalty),
        },
    }
