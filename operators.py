import numpy as np

def gradient(x):
    arr = np.frombuffer(x, dtype=np.uint8)
    grad = np.abs(np.diff(arr))
    return grad

def symmetry(x):
    arr = np.frombuffer(x, dtype=np.uint8)
    if arr.size == 0:
        return 1.0
    half = arr.size // 2
    left = arr[:half]
    right = arr[-half:][::-1]
    if left.size == 0:
        return 1.0
    return 1.0 - np.mean(np.abs(left - right) / 255.0)

def frequency(x):
    arr = np.frombuffer(x, dtype=np.uint8)
    if arr.size == 0:
        return np.array([])
    freq = np.fft.fft(arr)
    return np.abs(freq)

def compressibility(x):
    import zlib
    original = len(x)
    compressed = len(zlib.compress(x))
    return original - compressed

def local_entropy(x):
    arr = np.frombuffer(x, dtype=np.uint8)
    if arr.size == 0:
        return 0.0
    counts = np.bincount(arr, minlength=256)
    probs = counts / arr.size
    entropy = -np.sum([p * np.log2(p) for p in probs if p > 0])
    return entropy

def entropy_field(x, λ1, λ2, λ3, λ4):
    h_local = local_entropy(x)
    sym = symmetry(x)
    comp = compressibility(x)
    grad = gradient(x)
    grad_energy = np.sum(grad) / (len(grad) + 1e-8)
    return λ1 * h_local + λ2 * (1 - sym) + λ3 * comp + λ4 * grad_energy

def delta_field(Hλ_t, Hλ_prev):
    return Hλ_t - Hλ_prev

def attraktor(F, Hλ, Δ):
    if isinstance(Δ, (list, np.ndarray)):
        delta_var = float(np.var(Δ))
    else:
        delta_var = float(np.var([Δ]))
    stable = delta_var < 0.01
    return {"stable": stable, "delta_variance": delta_var}

def beauty_signature(sym, proportion, gradient_coherence):
    norm = lambda v: (v - np.min(v)) / (np.ptp(v) + 1e-8) if isinstance(v, np.ndarray) and v.size > 1 else v
    s = norm(sym)
    p = norm(proportion)
    g = norm(gradient_coherence)
    return float(s + p + g) / 3.0
