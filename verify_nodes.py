"""
Aether Node + Metric Verification Script
Run: python verify_nodes.py
Share ALL output with Gemini to validate Kotlin AetherCascadeEngine.kt
"""
import math
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

def _clamp(v, lo, hi): return max(lo, min(hi, v))

ctx = {'x':0.5,'y':0.3,'z':0.1,'t':0.2,'i':3,'n_val':8,
       'mem':[0.0]*256,'stack':[0.0]*64,'sp':0}
ctx['mem'][0] = 1.5
idx = 5

# N_BRIDGE
a_val, d_val = 12.0, 7.0
ua = int(_clamp(abs(round(a_val)),0,255))
ud = int(_clamp(abs(round(d_val)),0,255))
sa = (ctx['i'] + idx) & 7
sb = (ctx['n_val'] + idx + 3) & 7
mix = ((ua << sa) ^ (ud >> sb) ^ (ua >> ((sb+1)&7)) ^ (ud << ((sa+1)&7))) & 255
bitMix = mix / 255.0
syn = abs(a_val-d_val)*0.06 + abs(bitMix-ctx['y'])*0.32 + abs(ctx['z']-ctx['t'])*0.02
ctx['mem'][252] = ctx['mem'][252]*0.78 + syn*0.22
ctx['mem'][253] = ctx['mem'][253]*0.76 + (ua^mix)/255.0*0.24
ctx['mem'][254] = ctx['mem'][254]*0.76 + (ud^mix)/255.0*0.24
bridge = (a_val*0.22 + d_val*0.18 + bitMix*0.34 + syn
          + ctx['mem'][idx]*0.08 + ctx['mem'][252]*0.08
          + ctx['mem'][253]*0.06 + ctx['mem'][254]*0.04
          + ctx['z']*0.02)
n_val = ctx['n_val']
pos = _clamp(ctx['i']/(n_val-1),0.0,1.0) if n_val > 1 else _clamp(ctx['x'],0.0,1.0)
phA = pos * 2*math.pi
phB = phA + (idx&7)/7.0 * math.pi
bridge += (math.cos(phA)*a_val + math.cos(phB)*d_val) * 0.04
print("N_BRIDGE result: %.15f" % bridge)
print("  ua=%d ud=%d sa=%d sb=%d mix=%d bitMix=%.10f" % (ua,ud,sa,sb,mix,bitMix))
print("  syn=%.10f pos=%.10f phA=%.10f phB=%.10f" % (syn,pos,phA,phB))
print("  cos(phA)=%.10f cos(phB)=%.10f" % (math.cos(phA),math.cos(phB)))
print("  mem252=%.10f mem253=%.10f mem254=%.10f" % (ctx['mem'][252],ctx['mem'][253],ctx['mem'][254]))

# N_INTERFERE (fresh ctx)
sA, sB = 10.0, 6.0
pos2 = _clamp(3/(8-1),0.0,1.0)
ps = (idx & 15) / 15.0 * 2*math.pi
wA = sA * math.cos(pos2 * 2*math.pi)
wB = sB * math.cos(pos2 * 2*math.pi + ps)
ampA, ampB = abs(sA), abs(sB)
result = _clamp((wA+wB+ampA+ampB)*127.5/(ampA+ampB+1e-9)+127.5, 0.0, 255.0)
print("N_INTERFERE result: %.15f" % result)
print("  pos=%.10f ps=%.10f wA=%.10f wB=%.10f" % (pos2,ps,wA,wB))
print("  ampA=%.1f ampB=%.1f numerator=%.10f" % (ampA,ampB,wA+wB+ampA+ampB))

# ── METRIC VERIFICATION ─────────────────────────────────────────────────────
print("\n=== METRIC VERIFICATION (test input: 512 bytes, alternating 0xAB 0x3C) ===")
TEST_DATA = bytes([0xAB, 0x3C] * 256)

# 1. Shannon
counts = [0]*256
for b in TEST_DATA: counts[b] += 1
h_raw = -sum((c/len(TEST_DATA))*math.log2(c/len(TEST_DATA)) for c in counts if c > 0)
shannon = h_raw / 8.0
print("1. Shannon:     %.15f  (raw H=%.15f)" % (shannon, h_raw))

# 2. Boltzmann
s_bolt = -sum((c/len(TEST_DATA))*math.log(c/len(TEST_DATA)) for c in counts if c > 0)
boltzmann = max(0.0, min(1.0, s_bolt / math.log(256)))
print("2. Boltzmann:   %.15f" % boltzmann)

# 3. Zipf (log-log linear regression over byte frequencies)
freqs = sorted([c for c in counts if c > 0], reverse=True)
if len(freqs) >= 2:
    log_ranks = [math.log(i+1) for i in range(len(freqs))]
    log_freqs = [math.log(f) for f in freqs]
    n = len(log_ranks)
    sx = sum(log_ranks); sy = sum(log_freqs)
    sxy = sum(log_ranks[i]*log_freqs[i] for i in range(n))
    sx2 = sum(x*x for x in log_ranks)
    denom = n*sx2 - sx*sx
    zipf_alpha = abs((n*sxy - sx*sy) / denom) if denom != 0 else 0.0
else:
    zipf_alpha = 0.0
print("3. Zipf alpha:  %.15f" % zipf_alpha)

# 4. Benford
benford_expected = [math.log10(1 + 1/d) for d in range(1, 10)]
digit_counts = [0]*10
for i in range(0, len(TEST_DATA)-3, 4):
    val = int.from_bytes(TEST_DATA[i:i+4], 'big')
    s = str(val)
    first = int(s[0]) if s and s[0] != '0' else 0
    if 1 <= first <= 9: digit_counts[first] += 1
total_digits = sum(digit_counts[1:])
if total_digits > 0:
    observed = [digit_counts[d]/total_digits for d in range(1,10)]
    max_dev = sum(benford_expected)
    deviation = sum(abs(observed[d-1] - benford_expected[d-1]) for d in range(1,10))
    benford = max(0.0, min(1.0, 1.0 - deviation/max_dev))
else:
    benford = 0.0
print("4. Benford:     %.15f" % benford)

# 5. Fourier/Periodicity (lag correlation)
n = len(TEST_DATA)
best_lag = 0.0
for lag in range(1, min(65, n//3 + 1)):
    matches = sum(1 for i in range(n-lag) if TEST_DATA[i] == TEST_DATA[i+lag])
    score = matches / (n - lag)
    if score > best_lag: best_lag = score
fourier = max(0.0, min(1.0, best_lag))
print("5. Fourier/Per: %.15f" % fourier)

# 6. Katz Fractal Dimension (over entropy blocks)
block_size = 256
entropy_blocks = []
for bi in range(0, len(TEST_DATA), block_size):
    blk = TEST_DATA[bi:bi+block_size]
    bc = [0]*256
    for b in blk: bc[b] += 1
    eb = -sum((c/len(blk))*math.log2(c/len(blk)) for c in bc if c > 0) if blk else 0.0
    entropy_blocks.append(eb)
if len(entropy_blocks) >= 2:
    curve_len = sum(math.hypot(1.0, entropy_blocks[i]-entropy_blocks[i-1]) for i in range(1, len(entropy_blocks)))
    diameter = max(math.hypot(i, entropy_blocks[i]-entropy_blocks[0]) for i in range(len(entropy_blocks)))
    nn = float(len(entropy_blocks))
    denom_katz = math.log10(max(diameter/curve_len, 1e-9)) + math.log10(max(nn, 1.0))
    katz = max(1.0, min(2.5, math.log10(max(nn,1.0)) / denom_katz)) if abs(denom_katz) > 1e-9 else 1.0
else:
    katz = 1.0
print("6. Katz dim:    %.15f  (blocks=%s)" % (katz, entropy_blocks))

# 7. Permutation Entropy (Bandt & Pompe, order=3, step=1)
order = 3
pattern_counts = {}
signal = list(TEST_DATA)
for i in range(len(signal) - order + 1):
    window = signal[i:i+order]
    perm = tuple(sorted(range(order), key=lambda x: window[x]))
    pattern_counts[perm] = pattern_counts.get(perm, 0) + 1
total_patterns = sum(pattern_counts.values())
if total_patterns > 0:
    max_entropy = math.log(math.factorial(order))
    pe_raw = -sum((c/total_patterns)*math.log(c/total_patterns) for c in pattern_counts.values())
    perm_entropy = max(0.0, min(1.0, pe_raw / max_entropy)) if max_entropy > 0 else 0.0
else:
    perm_entropy = 0.0
print("7. Perm entropy:%.15f  (patterns=%d)" % (perm_entropy, len(pattern_counts)))

# 8. Delta Convergence (no previous frame = 0.0)
delta_convergence = 0.0
print("8. Delta conv:  %.15f  (no prev frame)" % delta_convergence)

# 9. Noether Consistency
periodicity_proxy = _clamp(len(set(TEST_DATA[:512])) / 256.0, 0.0, 1.0)
entropy_delta = abs(entropy_blocks[-1] - entropy_blocks[0]) / 8.0 if len(entropy_blocks) >= 2 else 0.0
delta_penalty = 1.0  # no previous frame
noether = _clamp(0.40*periodicity_proxy + 0.30*(1-entropy_delta) + 0.30*(1-delta_penalty), 0.0, 1.0)
print("9. Noether:     %.15f  (periodicity_proxy=%.6f entropy_delta=%.6f)" % (noether, periodicity_proxy, entropy_delta))

# 10. Trust Score
trust = (shannon + benford + noether + (1.0 - abs(boltzmann - shannon))) / 4.0
trust = max(0.0, min(1.0, trust))
print("10. Trust:      %.15f" % trust)
print("\nrun_id input: SHA256(TEST_DATA + b'4') — compute in Kotlin and compare")
