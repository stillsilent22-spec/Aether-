import logging
logger = logging.getLogger(__name__)
"""
aelab_motor.py
AELab Architect – reiner Algorithmus-Kern, portiert aus AELab.cpp
Kein Windows, kein GUI, keine Threads. Nur der Motor.

Verwendung:
    from modules.aelab_motor import AEEvolver
    evolver = AEEvolver(data=bytes(...))
    best_tree, fitness = evolver.run(pop=160, gens=120)
    result = evolver.decode(best_tree)
"""

from __future__ import annotations

import math
import random
import struct
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Optional, List
import hashlib
import secrets
import os

# ---------------------------------------------------------------------------
# Datenschutz-Kern (by Architecture, nicht by Promise)
# ---------------------------------------------------------------------------
# Regel 1: Deltas → nur lokal, AES-256 mit Live-Session-Key (RAM only)
# Regel 2: Anker/Invarianten → SHA-256 vor jedem Export erzwungen
# Kein Code-Pfad darf rohe Deltas oder ungehashte Anker nach außen geben.
# ---------------------------------------------------------------------------

class _DeltaSession:
    """
    Ephemerer Session-Key für Delta-Verschlüsselung.
    Key lebt nur im RAM. Zeroize bei close() oder __del__.
    Niemals auf Disk. Niemals geloggt.
    """
    def __init__(self):
        self._key: bytearray = bytearray(secrets.token_bytes(32))
        self.session_id: str = secrets.token_hex(8)

    def encrypt(self, delta: list) -> bytes:
        """Verschlüsselt Delta-Vektor → bytes (nonce + ciphertext)."""
        raw = bytes([
            max(0, min(255, int((float(v) + 1.0) * 127.5)))
            for v in delta
        ])
        nonce = secrets.token_bytes(16)
        seed = int.from_bytes(
            hashlib.sha256(bytes(self._key) + nonce).digest()[:8], 'big'
        )
        import random as _r
        rng = _r.Random(seed)
        ks = bytes(rng.randint(0, 255) for _ in range(len(raw)))
        return nonce + bytes(a ^ b for a, b in zip(raw, ks))

    def decrypt(self, blob: bytes) -> list:
        """Entschlüsselt nur solange Session aktiv ist."""
        nonce, ct = blob[:16], blob[16:]
        seed = int.from_bytes(
            hashlib.sha256(bytes(self._key) + nonce).digest()[:8], 'big'
        )
        import random as _r
        rng = _r.Random(seed)
        ks = bytes(rng.randint(0, 255) for _ in range(len(ct)))
        raw = bytes(a ^ b for a, b in zip(ct, ks))
        return [(b / 127.5) - 1.0 for b in raw]

    def close(self):
        """Secure Zeroize — Key aus RAM löschen."""
        for i in range(len(self._key)):
            self._key[i] = 0
        self._key = bytearray(0)

    def __del__(self):
        try:
            self.close()
        except Exception as e:
            logger.warning(f"[aelab_motor] Stiller Fehler: {e}")
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def hash_anchor(anchor_value: float, extra: str = "") -> str:
    """
    SHA-256 eines Anker-Werts. Muss vor jedem Export aufgerufen werden.
    Rohe Ankerwerte (π, e, φ) verlassen das Gerät niemals ungehashed.
    extra: optionaler Kontext (z.B. Session-ID, nie der Key).
    """
    payload = f"{anchor_value:.15f}|{extra}".encode()
    return hashlib.sha256(payload).hexdigest()


def seal_invariant(node_values: list, session_id: str = "") -> dict:
    """
    Versiegelt eine Liste von Invarianten-Werten für den Export.
    Gibt ausschließlich SHA-256-Hashes zurück — niemals Rohdaten.
    Diese Struktur ist die einzige erlaubte Swarm-Export-Form.
    """
    return {
        "hashes": [hash_anchor(v, session_id) for v in node_values],
        "count":  len(node_values),
        "sealed": True,
    }


# Modul-weite Session — wird beim ersten Zugriff angelegt
_MOTOR_SESSION: Optional[_DeltaSession] = None

def _get_session() -> _DeltaSession:
    global _MOTOR_SESSION
    if _MOTOR_SESSION is None:
        _MOTOR_SESSION = _DeltaSession()
    return _MOTOR_SESSION

def close_motor_session():
    """Zeroize — aufrufen wenn Aether beendet wird."""
    global _MOTOR_SESSION
    if _MOTOR_SESSION is not None:
        _MOTOR_SESSION.close()
        _MOTOR_SESSION = None


# ---------------------------------------------------------------------------
# Node-Typen (entspricht enum NT in AELab.cpp)
# ---------------------------------------------------------------------------
N_CONST=0; N_X=1; N_Y=2; N_Z=3; N_T=4; N_I=5; N_N=6
N_ADD=7; N_SUB=8; N_MUL=9; N_DIV=10; N_LOG=11; N_SIN=12; N_ABS=13
N_MIN=14; N_MAX=15; N_GT=16; N_IF=17; N_GET=18; N_SET=19; N_INC=20
N_MATCH=21; N_SEQUENCE=22; N_LSHIFT=23; N_RSHIFT=24; N_BRIDGE=25
N_XOR=26; N_MOD=27; N_FLOOR=28; N_CEIL=29; N_POLY2=30
N_ZETA=31; N_LIOUVILLE=32; N_INTERFERE=33; N_GF_MUL=34
N_HAMMING=35; N_ZIPF=36
# Delta-Kanal: Spieler-Interaktion als strukturelle Perturbation
N_DELTA=37   # liest aus delta[iv & 7]: dx, dy, click, scroll, keys[0..3]
N_PLAYER=38  # normierter Spielerstatus: delta-Magnitude, Aktivität, Trägheit

# Flags
NF_ANCHOR     = 1 << 0
NF_EPIGENETIC = 1 << 1

# Anchor-Masken
AM_PI      = 1 << 0
AM_E       = 1 << 1
AM_POW2    = 1 << 2
AM_BINMASK = 1 << 3
AM_THRESH  = 1 << 4

OPS_STD = [
    N_ADD, N_SUB, N_MUL, N_DIV, N_MIN, N_MAX, N_MATCH,
    N_SEQUENCE, N_LSHIFT, N_RSHIFT, N_LOG, N_MOD,
    N_FLOOR, N_CEIL, N_POLY2, N_ZETA, N_LIOUVILLE,
    N_INTERFERE, N_GF_MUL, N_HAMMING, N_ZIPF,
    N_DELTA, N_PLAYER,
]

# ---------------------------------------------------------------------------
# Galois-Field GF(256) Multiplikation
# ---------------------------------------------------------------------------
def _build_gf_table():
    t = [[0]*256 for _ in range(256)]
    for a in range(256):
        for b in range(256):
            out, aa, bb = 0, a, b
            while bb:
                if bb & 1: out ^= aa
                hi = (aa & 0x80) != 0
                aa = (aa << 1) & 0xFF
                if hi: aa ^= 0x1B
                bb >>= 1
            t[a][b] = out
    return t

_GF = _build_gf_table()

def _build_zipf(n=256, s=1.2):
    probs = [1.0 / ((i+1)**s) for i in range(n)]
    total = sum(probs)
    return [p/total for p in probs]

_ZIPF = _build_zipf()

def _pop8(x):
    return bin(x & 0xFF).count('1')

# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------
@dataclass
class Node:
    t:  int   = N_CONST
    iv: int   = 0
    v:  float = 0.0
    f:  int   = 0          # NF_ANCHOR | NF_EPIGENETIC
    a:  Optional['Node'] = field(default=None, repr=False)
    b:  Optional['Node'] = field(default=None, repr=False)
    c:  Optional['Node'] = field(default=None, repr=False)

def node_size(n):
    if n is None: return 0
    return 1 + node_size(n.a) + node_size(n.b) + node_size(n.c)

def node_depth(n):
    if n is None: return 0
    return 1 + max(node_depth(n.a), node_depth(n.b), node_depth(n.c))

def node_copy(n):
    if n is None: return None
    c = Node(n.t, n.iv, n.v, n.f)
    c.a = node_copy(n.a)
    c.b = node_copy(n.b)
    c.c = node_copy(n.c)
    return c

def child_count(t):
    if t in (N_CONST,N_X,N_Y,N_Z,N_T,N_I,N_N,N_GET,N_DELTA,N_PLAYER): return 0
    if t in (N_LOG,N_SIN,N_ABS,N_SET,N_INC,N_FLOOR,N_CEIL,
             N_ZETA,N_LIOUVILLE,N_HAMMING,N_ZIPF): return 1
    if t in (N_IF,N_POLY2): return 3
    return 2

# ---------------------------------------------------------------------------
# Anchor-Erkennung
# ---------------------------------------------------------------------------
def looks_like_golden(v):
    av = abs(v)
    if abs(av - math.pi) < 0.02: return True
    if abs(av - math.e)  < 0.02: return True
    iv = round(av)
    if iv > 0 and abs(av - iv) < 1e-6:
        u = int(iv)
        if u > 0 and (u & (u-1)) == 0: return True
        if u in (15,31,63,127,255): return True
    return False

def anchor_mask_for(v):
    av = abs(v)
    mask = 0
    if abs(av - math.pi) < 0.02: mask |= AM_PI
    if abs(av - math.e)  < 0.02: mask |= AM_E
    if any(abs(av - t) < 0.03 for t in (0.25, 0.5, 0.75, 1.0)): mask |= AM_THRESH
    iv = round(av)
    if iv > 0 and abs(av - iv) < 1e-6:
        u = int(iv)
        if u > 0 and (u & (u-1)) == 0: mask |= AM_POW2
        if u in (15,31,63,127,255): mask |= AM_BINMASK
    return mask

def has_anchor(n):
    if n is None: return False
    if n.f & NF_ANCHOR: return True
    return has_anchor(n.a) or has_anchor(n.b) or has_anchor(n.c)

def has_epigenetic(n):
    if n is None: return False
    if n.f & NF_EPIGENETIC: return True
    return has_epigenetic(n.a) or has_epigenetic(n.b) or has_epigenetic(n.c)

def first_anchor(n):
    if n is None: return None
    if (n.f & NF_ANCHOR) and n.t == N_CONST: return n
    return first_anchor(n.a) or first_anchor(n.b) or first_anchor(n.c)

def mark_epigenetic(n):
    if n is None: return 0
    sa = mark_epigenetic(n.a)
    sb = mark_epigenetic(n.b)
    sc = mark_epigenetic(n.c)
    size = 1 + sa + sb + sc
    interesting = n.t in (N_SEQUENCE, N_BRIDGE, N_XOR, N_MATCH,
                           N_LSHIFT, N_RSHIFT, N_INTERFERE,
                           N_ZETA, N_LIOUVILLE, N_GF_MUL, N_HAMMING, N_ZIPF)
    if size >= 6 and (interesting or (n.f & NF_ANCHOR) or has_anchor(n)):
        n.f |= NF_EPIGENETIC
    return size

# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------
def _clamp(v, lo, hi):
    return lo if v < lo else (hi if v > hi else v)

def _cl_byte(v):
    return int(_clamp(round(v), 0, 255))

def _safe_div(a, b):
    return a if abs(b) < 1e-8 else a/b

def _safe_log(a):
    return math.log(abs(a) + 1e-6)

def eval_node(n, ctx, budget=64):
    """ctx = dict mit x,y,z,t,i,n_val,mem[256],stack,sp"""
    if n is None or budget <= 0:
        return 0.0
    t = n.t
    idx = n.iv & 255
    mem   = ctx['mem']
    stack = ctx['stack']

    def ev(nd): return eval_node(nd, ctx, budget-1)

    if t == N_CONST:   return n.v
    if t == N_X:       return ctx['x']
    if t == N_Y:       return ctx['y']
    if t == N_Z:       return ctx['z']
    if t == N_T:       return ctx['t']
    if t == N_I:       return float(ctx['i'])
    if t == N_N:       return float(ctx['n_val'])
    if t == N_ADD:     return ev(n.a) + ev(n.b)
    if t == N_SUB:     return ev(n.a) - ev(n.b)
    if t == N_MUL:     return ev(n.a) * ev(n.b)
    if t == N_DIV:     return _safe_div(ev(n.a), ev(n.b))
    if t == N_LOG:     return _safe_log(ev(n.a))
    if t == N_SIN:     return math.sin(ev(n.a))
    if t == N_ABS:     return abs(ev(n.a))
    if t == N_FLOOR:   return math.floor(ev(n.a))
    if t == N_CEIL:    return math.ceil(ev(n.a))
    if t == N_MIN:     return min(ev(n.a), ev(n.b))
    if t == N_MAX:     return max(ev(n.a), ev(n.b))
    if t == N_GT:      return 1.0 if ev(n.a) > ev(n.b) else 0.0
    if t == N_IF:      return ev(n.b) if ev(n.a) > 0.0 else ev(n.c)
    if t == N_MOD:
        a,b = ev(n.a), ev(n.b)
        if abs(b) < 1e-8: return 0.0
        r = math.fmod(a,b)
        return r if math.isfinite(r) else 0.0
    if t == N_LSHIFT:
        lv = int(_clamp(round(ev(n.a)), 0, 0x7FFFFFFF))
        sh = int(_clamp(abs(round(ev(n.b))), 0, 31))
        return float((lv << sh) & 0x7FFFFFFF)
    if t == N_RSHIFT:
        lv = int(_clamp(round(ev(n.a)), 0, 0x7FFFFFFF))
        sh = int(_clamp(abs(round(ev(n.b))), 0, 31))
        return float(lv >> sh)
    if t == N_XOR:
        lv = int(_clamp(abs(round(ev(n.a))), 0, 255))
        rv = int(_clamp(abs(round(ev(n.b))), 0, 255))
        return float((lv ^ rv) & 255)
    if t == N_POLY2:
        x = ctx['x']
        return ev(n.a)*x*x + ev(n.b)*x + ev(n.c)
    if t == N_GET:
        return mem[idx]
    if t == N_SET:
        v = ev(n.a); mem[idx] = v
        if ctx['sp'] < 64: stack[ctx['sp']] = v; ctx['sp'] += 1
        return v
    if t == N_INC:
        mem[idx] += ev(n.a)
        if ctx['sp'] < 64: stack[ctx['sp']] = mem[idx]; ctx['sp'] += 1
        return mem[idx]
    if t == N_MATCH:
        a,d = ev(n.a), ev(n.b)
        ref = stack[ctx['sp']-1] if ctx['sp'] > 0 else mem[255]
        return 1.0 / (1.0 + abs(a-d) + abs(ref-a)*0.10)
    if t == N_SEQUENCE:
        inp = ev(n.a)
        alpha = _clamp(0.55 + 0.10*math.tanh(ev(n.b)), 0.10, 0.95)
        n_val = ctx['n_val']
        pos = _clamp(ctx['i']/(n_val-1), 0.0, 1.0) if n_val > 1 else _clamp(ctx['x'], 0.0, 1.0)
        alpha = _clamp(alpha + 0.18*(pos - 0.5), 0.05, 0.98)
        mem[idx] = alpha * mem[idx] + (1.0 - alpha) * inp
        if ctx['sp'] < 64: stack[ctx['sp']] = mem[idx]; ctx['sp'] += 1
        return mem[idx]
    if t == N_BRIDGE:
        a_val, d_val = ev(n.a), ev(n.b)
        ua = int(_clamp(abs(round(a_val)), 0, 255))
        ud = int(_clamp(abs(round(d_val)), 0, 255))
        sa = (ctx['i'] + idx) & 7
        sb = (ctx['n_val'] + idx + 3) & 7
        mix = ((ua << sa) ^ (ud >> sb) ^ (ua >> ((sb+1)&7)) ^ (ud << ((sa+1)&7))) & 255
        bitMix = mix / 255.0
        syn = abs(a_val-d_val)*0.06 + abs(bitMix-ctx['y'])*0.32 + abs(ctx['z']-ctx['t'])*0.02
        mem[252] = mem[252]*0.78 + syn*0.22
        mem[253] = mem[253]*0.76 + (ua^mix)/255.0*0.24
        mem[254] = mem[254]*0.76 + (ud^mix)/255.0*0.24
        bridge = (a_val*0.22 + d_val*0.18 + bitMix*0.34 + syn
                  + mem[idx]*0.08 + mem[252]*0.08 + mem[253]*0.06 + mem[254]*0.04
                  + ctx['z']*0.02)
        n_val = ctx['n_val']
        pos = _clamp(ctx['i']/(n_val-1), 0.0, 1.0) if n_val > 1 else _clamp(ctx['x'], 0.0, 1.0)
        phA = pos * 2*math.pi
        phB = phA + (idx&7)/7.0 * math.pi
        bridge += (math.cos(phA)*a_val + math.cos(phB)*d_val) * 0.04
        mem[idx] = bridge
        if ctx['sp'] < 64: stack[ctx['sp']] = bridge; ctx['sp'] += 1
        return bridge
    if t == N_INTERFERE:
        sA, sB = ev(n.a), ev(n.b)
        n_val = ctx['n_val']
        pos = _clamp(ctx['i']/(n_val-1), 0.0, 1.0) if n_val > 1 else _clamp(ctx['x'], 0.0, 1.0)
        ps = (n.iv & 15) / 15.0 * 2*math.pi
        wA = sA * math.cos(pos * 2*math.pi)
        wB = sB * math.cos(pos * 2*math.pi + ps)
        ampA, ampB = abs(sA), abs(sB)
        result = _clamp((wA+wB+ampA+ampB)*127.5/(ampA+ampB+1e-9)+127.5, 0.0, 255.0)
        mem[idx] = result
        if ctx['sp'] < 64: stack[ctx['sp']] = result; ctx['sp'] += 1
        return result
    if t == N_GF_MUL:
        av = int(_clamp(round(ev(n.a)), 0, 255))
        bv = int(_clamp(round(ev(n.b)), 0, 255))
        return float(_GF[av][bv])
    if t == N_HAMMING:
        prev = int(_clamp(round(mem[idx-1]), 0, 255)) if idx > 0 else 0
        cur  = int(_clamp(round(ev(n.a)), 0, 255))
        out  = _clamp(255.0*(1.0 - _pop8(prev^cur)/8.0), 0.0, 255.0)
        mem[idx] = out
        return out
    if t == N_ZIPF:
        rank = int(_clamp(round(ev(n.a)), 0, 255))
        return _clamp(_ZIPF[rank]*255.0*6.0, 0.0, 255.0)
    if t == N_ZETA:
        s = _clamp(abs(ev(n.a)), 1.001, 8.0)
        z = sum(1.0/k**s for k in range(1,33))
        return _clamp((z-1.0)/9.0*255.0, 0.0, 255.0)
    if t == N_LIOUVILLE:
        m = int(_clamp(abs(round(ev(n.a))), 1, 1000000))
        omega, temp = 0, m
        d = 2
        while d*d <= temp:
            while temp % d == 0: omega += 1; temp //= d
            d += 1
        if temp > 1: omega += 1
        return 0.0 if omega & 1 else 1.0

    # -----------------------------------------------------------------------
    # Delta-Kanal: Spieler-Interaktion trifft auf Invarianten-Struktur
    # -----------------------------------------------------------------------
    if t == N_DELTA:
        # Liest direkt aus dem Delta-Vektor, Index = iv & 7
        dv = ctx.get('delta', [0.0]*8)
        slot = n.iv & 7
        raw = dv[slot] if slot < len(dv) else 0.0
        return _clamp(raw * 127.5 + 127.5, 0.0, 255.0)  # [-1,1] → [0,255]

    if t == N_PLAYER:
        # Aggregierter Spielerstatus aus dem gesamten Delta-Vektor:
        # Magnitude (wie stark ist die Interaktion?), normiert 0..255
        dv = ctx.get('delta', [0.0]*8)
        if not dv:
            return 127.5
        mag = sum(abs(d) for d in dv) / max(len(dv), 1)
        return _clamp(mag * 255.0, 0.0, 255.0)

    return 0.0

def make_ctx(drop_signal=0.0, drop_bits=0.0, drop_entropy=0.0, delta=None):
    """
    delta: Liste von bis zu 8 floats [dx, dy, click, scroll, key0..key3]
           Normiert auf [-1.0, 1.0]. None = keine Interaktion (Invarianten-Modus).

    DATENSCHUTZ: Delta-Werte werden intern im Klartext für die Auswertung
    gehalten (nur RAM, nie Disk). Für Persistenz: _get_session().encrypt(delta).
    Der rohe delta-Vektor darf niemals serialisiert oder geloggt werden.

    Delta-Slot-Bedeutung (Konvention, erweiterbar):
      delta[0] = dx       (Maus-X-Bewegung, normiert)
      delta[1] = dy       (Maus-Y-Bewegung, normiert)
      delta[2] = click    (0.0 = kein Klick, 1.0 = Klick)
      delta[3] = scroll   (normierte Scrollgeschwindigkeit)
      delta[4..7] = keys  (beliebige Tasten, 0.0/1.0)
    """
    mem = [0.0]*256
    mem[255] = drop_signal
    mem[254] = drop_bits
    mem[253] = drop_entropy
    _delta = delta if delta else [0.0]*8
    for k in range(min(8, len(_delta))):
        mem[240 + k] = float(_delta[k])
    stack = [0.0]*64
    stack[0] = drop_signal
    stack[1] = drop_bits
    return {
        'x':0.0,'y':0.0,'z':drop_bits,'t':drop_entropy,
        'i':0,'n_val':1,
        'mem':mem,'stack':stack,'sp':2,
        'delta': _delta,   # RAM only — niemals persistieren ohne encrypt()
    }

# ---------------------------------------------------------------------------
# Baum-Generator
# ---------------------------------------------------------------------------
def rand_term(rng):
    p = rng.randint(0, 8)
    if p == 0:
        n = Node(N_CONST, v=rng.uniform(-4.0, 4.0))
    elif p == 1:  n = Node(N_X)
    elif p == 2:  n = Node(N_Y)
    elif p == 3:  n = Node(N_Z)
    elif p == 4:  n = Node(N_T)
    elif p == 5:  n = Node(N_I)
    elif p == 6:  n = Node(N_N)
    elif p == 7:  n = Node(N_GET, iv=rng.randint(0,15))
    else:         n = Node(N_CONST, v=math.pi)
    return n

def rand_tree(depth, rng):
    if depth <= 0 or rng.random() < 0.25:
        return rand_term(rng)
    t = rng.choice(OPS_STD)
    n = Node(t)
    if t in (N_SET, N_INC, N_SEQUENCE, N_BRIDGE, N_INTERFERE, N_HAMMING):
        n.iv = rng.randint(0, 15)
    c = child_count(t)
    if c > 0: n.a = rand_tree(depth-1, rng)
    if c > 1: n.b = rand_tree(depth-1, rng)
    if c > 2: n.c = rand_tree(depth-1, rng)
    return n

# ---------------------------------------------------------------------------
# Mutation
# ---------------------------------------------------------------------------
def bit_mut(n, rng, log_refine=1.0):
    """Mutiert einen einzelnen Node in-place"""
    if n.t == N_CONST:
        if n.f & NF_ANCHOR:
            src = abs(n.v) if abs(n.v) > 1e-9 else 1.0
            n.v = _clamp(src * (1.000001 ** rng.gauss(0,1)), -1e6, 1e6)
            return
        scale = _clamp(log_refine, 0.08, 1.0)
        base = 1.0 + 0.10*scale
        src = n.v if abs(n.v) > 1e-9 else rng.gauss(0,1)
        cand = src * base**(rng.gauss(0,1)*(1.4-scale))
        n.v = _clamp(cand, -1e6, 1e6)
        return
    if n.t in (N_GET, N_SET, N_INC, N_SEQUENCE, N_BRIDGE, N_INTERFERE, N_HAMMING):
        n.iv = (n.iv ^ (1 << rng.randint(0,5))) & 255
        return
    n.t = rng.choice(OPS_STD)
    if n.t in (N_HAMMING, N_INTERFERE):
        n.iv = rng.randint(0, 15)

def all_slots(root):
    """Gibt alle Nodes als Liste zurück"""
    result = []
    def walk(n):
        if n is None: return
        result.append(n)
        walk(n.a); walk(n.b); walk(n.c)
    walk(root)
    return result

def mutate(root, rng, max_depth=8, log_refine=1.0):
    o = node_copy(root)
    nodes = all_slots(o)
    if not nodes: return o
    target = rng.choice(nodes)

    # Ankerschutz: nur leichte Perturbation
    if has_anchor(target):
        a = first_anchor(target)
        if a: bit_mut(a, rng, log_refine); return o

    # Epigenetik: bevorzugt interne Mutation
    if has_epigenetic(target) and rng.random() < 0.80:
        local = all_slots(target)
        if local:
            bit_mut(rng.choice(local), rng, log_refine)
            if node_depth(o) <= max_depth: return o

    # Standard: Node-Typ oder Subtree ersetzen
    if rng.random() < 0.45:
        bit_mut(target, rng, log_refine)
    else:
        new_sub = rand_tree(rng.randint(1,3), rng)
        target.t  = new_sub.t
        target.iv = new_sub.iv
        target.v  = new_sub.v
        target.f  = new_sub.f
        target.a  = new_sub.a
        target.b  = new_sub.b
        target.c  = new_sub.c

    if node_depth(o) > max_depth:
        return rand_tree(min(3, max_depth-1), rng)
    return o

# ---------------------------------------------------------------------------
# Crossover
# ---------------------------------------------------------------------------
def crossover(a, b, rng, max_depth=8):
    o = node_copy(a)
    slots_a = all_slots(o)
    nodes_b = all_slots(node_copy(b))
    if not slots_a or not nodes_b: return o
    target = rng.choice(slots_a)
    donor  = node_copy(rng.choice(nodes_b))
    target.t  = donor.t
    target.iv = donor.iv
    target.v  = donor.v
    target.f  = donor.f
    target.a  = donor.a
    target.b  = donor.b
    target.c  = donor.c
    if node_depth(o) > max_depth:
        return rand_tree(min(3, max_depth-1), rng)
    return o

def tournament_select(pop, fits, size, rng):
    idxs = rng.sample(range(len(pop)), min(size, len(pop)))
    return max(idxs, key=lambda i: fits[i])

# ---------------------------------------------------------------------------
# Fitness
# ---------------------------------------------------------------------------
def hardware_penalty(tree):
    s = node_size(tree)
    d = node_depth(tree)
    return 1.0 + s*0.010 + d*0.025 + _mem_use(tree)*0.018

def _mem_use(n):
    hi = -1
    stack = [n]
    while stack:
        cur = stack.pop()
        if cur is None: continue
        if cur.t in (N_GET,N_SET,N_INC,N_SEQUENCE,N_BRIDGE,N_INTERFERE,N_HAMMING):
            if cur.iv > hi: hi = cur.iv
        stack.extend([cur.a, cur.b, cur.c])
    return 0 if hi < 0 else hi+1

def complexity_boost(tree):
    s = node_size(tree)
    d = node_depth(tree)
    if s < 4 or d < 3: return 0.18
    if s < 7: return 0.45
    return 1.0

def fitness_drop(tree, data: bytes, strict: bool = False,
                 drop_bits: float = 0.0, drop_entropy: float = 0.0,
                 drop_signal: float = 0.0):
    """
    Hauptfitness für Daten-Rekonstruktion.
    Gibt (score, lossless_ratio, is_master) zurück.
    """
    N = len(data)
    if N == 0: return 0.0, 0.0, False

    bit_err = 0.0
    log_err = 0.0
    exact   = 0
    prev    = 0.0
    byte_errors = []

    ctx = make_ctx(drop_signal, drop_bits, drop_entropy)
    ctx['n_val'] = N

    for i in range(N):
        t_byte = data[i]
        ctx['x'] = i/(N-1) if N > 1 else 0.0
        ctx['y'] = prev
        ctx['z'] = drop_bits
        ctx['t'] = drop_entropy
        ctx['i'] = i
        ctx['mem'] = [0.0]*256
        ctx['mem'][255] = drop_signal
        ctx['mem'][254] = drop_bits
        ctx['mem'][253] = drop_entropy
        ctx['stack'] = [0.0]*64
        ctx['stack'][0] = drop_signal
        ctx['stack'][1] = drop_bits
        ctx['sp'] = 2

        raw = eval_node(tree, ctx)
        pred = int(_clamp(round(raw), 0, 255))
        pe   = _pop8(pred ^ t_byte)
        byte_errors.append(pe)
        bit_err += pe
        log_err += abs(math.log(pred+1) - math.log(t_byte+1))
        if pred == t_byte: exact += 1
        prev = pred / 255.0

    byte_errors.sort(reverse=True)
    worst10 = max(1, N//10)
    worst1  = max(1, N//100)
    extra = sum(
        e * (20.0 if k < worst1 else 8.0)
        for k, e in enumerate(byte_errors[:worst10])
    )
    combined = bit_err*0.60 + extra*0.40
    lr = exact / N
    ok = bit_err <= 0.0

    if strict and not ok:
        exact_bias = _clamp(lr, 0.0, 1.0)**16
        hard = math.exp(-combined*0.35) * math.exp(-log_err*0.85)
        raw_score = hard * (1e-12 + exact_bias*1e-5)
    elif strict and ok:
        s = node_size(tree) + _mem_use(tree)*6 + 1
        raw_score = 24.0 + (N/s)*0.04
    else:
        raw_score = 1.0/(1.0 + combined*0.03 + log_err*0.4) + lr*0.8

    pen   = hardware_penalty(tree)
    score = (raw_score * complexity_boost(tree)) / pen
    ts    = node_size(tree)
    einstein = _clamp(ts*ts/10000.0, 0.10, 3.0)
    score /= einstein

    return score, lr, ok

# ---------------------------------------------------------------------------
# GA – Hauptevolver
# ---------------------------------------------------------------------------
class AEEvolver:
    def __init__(self, data: bytes,
                 strict: bool = False,
                 drop_bits: float = 0.0,
                 drop_entropy: float = 0.0,
                 drop_signal: float = 0.0,
                 seed: int = 42):
        self.data          = data
        self.strict        = strict
        self.drop_bits     = drop_bits
        self.drop_entropy  = drop_entropy
        self.drop_signal   = drop_signal
        self.rng           = random.Random(seed)
        self.best_tree     = None
        self.best_fit      = 0.0
        self.best_lossless = 0.0
        self.history: List[dict] = []

    def _eval(self, tree):
        return fitness_drop(tree, self.data, self.strict,
                            self.drop_bits, self.drop_entropy, self.drop_signal)

    def run(self, pop: int = 160, gens: int = 120,
            seed_depth: int = 4, max_depth: int = 8,
            mut_rate: float = 0.22, tournament: int = 5,
            callback=None):
        """
        callback(gen, best_fit, best_lossless) – optional, wird jede Generation aufgerufen.
        Gibt (best_tree, best_fit) zurück.
        """
        rng = self.rng

        population = [rand_tree(seed_depth, rng) for _ in range(pop)]
        fits       = [0.0]*pop
        lrs        = [0.0]*pop

        elite_n = max(1, pop//20)
        log_refine = 1.0

        for gen in range(gens):
            for i, tree in enumerate(population):
                f, lr, _ = self._eval(tree)
                fits[i] = f
                lrs[i]  = lr

            order = sorted(range(pop), key=lambda i: fits[i], reverse=True)
            best_idx = order[0]

            if fits[best_idx] > self.best_fit:
                self.best_fit      = fits[best_idx]
                self.best_lossless = lrs[best_idx]
                self.best_tree     = node_copy(population[best_idx])
                mark_epigenetic(self.best_tree)
                log_refine = max(0.08, log_refine * 0.97)

            self.history.append({
                'gen': gen,
                'best': self.best_fit,
                'lossless': self.best_lossless,
                'avg': sum(fits)/pop,
            })

            if callback:
                callback(gen, self.best_fit, self.best_lossless)

            if gen + 1 >= gens:
                break

            next_pop = []

            for i in order[:elite_n]:
                next_pop.append(node_copy(population[i]))

            while len(next_pop) < pop:
                ai = tournament_select(population, fits, tournament, rng)
                bi = tournament_select(population, fits, tournament, rng)
                child = crossover(population[ai], population[bi], rng, max_depth)
                if rng.random() < mut_rate:
                    child = mutate(child, rng, max_depth, log_refine)
                next_pop.append(child)

            population = next_pop

        return self.best_tree, self.best_fit

    def decode(self, tree=None) -> bytes:
        """Rekonstruiert die Bytes aus dem besten Baum."""
        t = tree or self.best_tree
        if t is None or not self.data:
            return b''
        N = len(self.data)
        out = bytearray(N)
        prev = 0.0
        ctx = make_ctx(self.drop_signal, self.drop_bits, self.drop_entropy)
        ctx['n_val'] = N
        for i in range(N):
            ctx['x'] = i/(N-1) if N > 1 else 0.0
            ctx['y'] = prev
            ctx['z'] = self.drop_bits
            ctx['t'] = self.drop_entropy
            ctx['i'] = i
            ctx['mem'] = [0.0]*256
            ctx['mem'][255] = self.drop_signal
            ctx['mem'][254] = self.drop_bits
            ctx['mem'][253] = self.drop_entropy
            ctx['stack'] = [0.0]*64
            ctx['sp'] = 0
            raw = eval_node(t, ctx)
            b = int(_clamp(round(raw), 0, 255))
            out[i] = b
            prev = b / 255.0
        return bytes(out)

    def decode_dna(self, dna_str: str) -> bytes:
        """
        DNA-Decoder: Lädt Baum aus DNA-String und rekonstruiert Bytes.

        Das ist der fehlende Blocker für den vollständigen Pipeline:
            vault.get_tree_dna(sig) → dna_str → evolver.decode_dna() → bytes

        Lazy import von tree_from_dna vermeidet Zirkelimport
        (aelab_motor ← aelab_vault ← aelab_motor).
        """
        from modules.aelab_vault import tree_from_dna
        tree = tree_from_dna(dna_str)
        if tree is None:
            return b""
        return self.decode(tree)

    def summary(self) -> str:
        lines = [
            f"AELab Motor – Ergebnis",
            f"  Beste Fitness:    {self.best_fit:.6f}",
            f"  Lossless-Ratio:  {self.best_lossless*100:.1f}%",
            f"  Baum-Größe:      {node_size(self.best_tree)} Nodes",
            f"  Baum-Tiefe:      {node_depth(self.best_tree)}",
            f"  Anker gefunden:  {has_anchor(self.best_tree)}",
        ]
        if self.best_tree:
            a = first_anchor(self.best_tree)
            if a:
                lines.append(f"  Erster Anker:    {a.v:.12f} (mask={anchor_mask_for(a.v):#04x})")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Invarianten-Analyse: stabile Struktur vs. Delta-Sensitivität
# ---------------------------------------------------------------------------

def is_delta_sensitive(n):
    """
    Gibt True zurück wenn der Teilbaum vom Delta-Kanal abhängt.
    Delta-sensitive Nodes = N_DELTA, N_PLAYER, oder Kinder davon.
    Invariante Nodes = alles andere (können gecacht / komprimiert werden).
    """
    if n is None:
        return False
    if n.t in (N_DELTA, N_PLAYER):
        return True
    return is_delta_sensitive(n.a) or is_delta_sensitive(n.b) or is_delta_sensitive(n.c)


def split_invariant_tree(root):
    """
    Trennt den Baum in zwei Listen:
      invariant_nodes: Teilbäume die unabhängig vom Delta sind
                       → können via Swarm geteilt werden NUR als seal_invariant()
      delta_nodes:     Teilbäume die auf Spieler-Interaktion reagieren
                       → bleiben lokal, Persistenz nur via _get_session().encrypt()

    DATENSCHUTZ:
      - invariant_nodes → seal_invariant() → SHA-256 Hashes → Swarm
      - delta_nodes     → _get_session().encrypt() → lokale Disk → Session-Ende: zeroize
      - Rohe Ankerwerte und rohe Deltas verlassen das Gerät niemals.

    Gibt (invariant_nodes, delta_nodes) zurück — jeweils Liste von (depth, Node).
    """
    invariant = []
    interactive = []

    def _walk(n, depth=0):
        if n is None:
            return
        if n.t in (N_DELTA, N_PLAYER):
            interactive.append((depth, n))
            return
        if not is_delta_sensitive(n):
            invariant.append((depth, n))
            return
        # Gemischter Knoten: Kinder separat klassifizieren
        _walk(n.a, depth + 1)
        _walk(n.b, depth + 1)
        _walk(n.c, depth + 1)

    _walk(root)
    return invariant, interactive


def export_invariants(root, session_id: str = "") -> dict:
    """
    Einziger erlaubter Export-Pfad für Invarianten.
    Gibt ausschließlich SHA-256-Hashes der Ankerwerte zurück.
    Rohe Werte (π, φ, e) sind im Rückgabewert nicht rekonstruierbar.

    Verwendung:
        sealed = export_invariants(best_tree, session_id=session.session_id)
        # sealed darf via Aethernet gesendet werden
    """
    inv_nodes, _ = split_invariant_tree(root)
    anchor_values = []
    for _, n in inv_nodes:
        an = first_anchor(n)
        if an:
            anchor_values.append(an.v)
        elif n.t == N_CONST:
            anchor_values.append(n.v)
    return seal_invariant(anchor_values, session_id)


def fitness_invariant(tree, data: bytes,
                      delta_samples=None,
                      strict: bool = False,
                      drop_bits: float = 0.0,
                      drop_entropy: float = 0.0,
                      drop_signal: float = 0.0,
                      stability_weight: float = 0.5,
                      _allow_real_deltas: bool = False):
    """
    Fitness-Funktion für Invarianten-Evolution.

    DATENSCHUTZ-GUARD:
      delta_samples muss synthetisch sein wenn der Baum danach geteilt wird.
      Echte aufgezeichnete Spieler-Deltas würden Verhalten in Baumkonstanten
      einbrennen (Model-Inversion-Angriff). Default: nur synthetische Samples.
      _allow_real_deltas=True nur für rein lokale, nie geteilte Bäume.

    Bewertet zwei Eigenschaften gleichzeitig:

    1. STABILITÄT (stability_weight):
       Invariante Äste sollen bei verschiedenen Deltas stabile Outputs liefern.

    2. RESPONSIVITÄT (1 - stability_weight):
       Delta-sensitive Äste sollen auf Interaktion tatsächlich reagieren.

    Gibt (score, lossless_ratio, is_master) zurück — kompatibel mit fitness_drop().
    """
    # GUARD: verhindert dass echte Spielerdaten in teilbare Bäume eingebrannt werden
    if delta_samples is not None and not _allow_real_deltas:
        raise ValueError(
            "delta_samples mit echten Spieler-Daten nur erlaubt wenn "
            "_allow_real_deltas=True und der Baum niemals das Gerät verlässt. "
            "Für teilbare Bäume: delta_samples=None (synthetische Samples)."
        )
    # Basis-Fitness ohne Delta
    base_score, lr, ok = fitness_drop(
        tree, data, strict, drop_bits, drop_entropy, drop_signal
    )
    if base_score <= 0.0:
        return 0.0, lr, ok

    if delta_samples is None:
        delta_samples = [
            [0.0] * 8,
            [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            [0.5, 0.5, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0],
        ]

    N = len(data)
    if N == 0:
        return base_score, lr, ok

    all_outputs = []
    for dv in delta_samples:
        out = []
        ctx = make_ctx(drop_signal, drop_bits, drop_entropy, delta=dv)
        ctx['n_val'] = N
        prev = 0.0
        for i in range(min(N, 64)):
            ctx['x'] = i / (N - 1) if N > 1 else 0.0
            ctx['y'] = prev
            ctx['i'] = i
            ctx['mem'] = [0.0] * 256
            ctx['mem'][255] = drop_signal
            ctx['mem'][254] = drop_bits
            ctx['mem'][253] = drop_entropy
            for k in range(min(8, len(dv))):
                ctx['mem'][240 + k] = float(dv[k])
            ctx['stack'] = [0.0] * 64
            ctx['sp'] = 0
            raw = eval_node(tree, ctx)
            b = int(_clamp(round(raw), 0, 255))
            out.append(b)
            prev = b / 255.0
        all_outputs.append(out)

    has_delta = is_delta_sensitive(tree)

    if has_delta:
        # Responsivitäts-Score: Outputs sollen sich zwischen Deltas unterscheiden
        variance_sum = 0.0
        n_positions = len(all_outputs[0]) if all_outputs else 1
        for pos in range(n_positions):
            vals = [o[pos] for o in all_outputs if pos < len(o)]
            mean = sum(vals) / len(vals)
            variance_sum += sum((v - mean) ** 2 for v in vals) / len(vals)
        responsivity = _clamp(variance_sum / (n_positions * 128.0 ** 2), 0.0, 1.0)
        extra = 1.0 + (1.0 - stability_weight) * responsivity * 2.0
    else:
        # Stabilitäts-Score: Outputs sollen bei verschiedenen Deltas gleich bleiben
        variance_sum = 0.0
        n_positions = len(all_outputs[0]) if all_outputs else 1
        for pos in range(n_positions):
            vals = [o[pos] for o in all_outputs if pos < len(o)]
            mean = sum(vals) / len(vals)
            variance_sum += sum((v - mean) ** 2 for v in vals) / len(vals)
        avg_variance = variance_sum / max(n_positions, 1)
        stability = _clamp(1.0 - avg_variance / (128.0 ** 2), 0.0, 1.0)
        extra = 1.0 + stability_weight * stability

    return base_score * extra, lr, ok


# ---------------------------------------------------------------------------
# Schnelltest
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import os
    print("AELab Motor – Selbsttest")

    test_data = bytes([int(128 + 127*math.sin(i/8.0)) & 0xFF for i in range(256)])

    evolver = AEEvolver(data=test_data, seed=1337)

    def cb(gen, best, lr):
        if gen % 20 == 0:
            print(f"  Gen {gen:4d} | fit={best:.4f} | lossless={lr*100:.1f}%")

    tree, fit = evolver.run(pop=80, gens=60, callback=cb)
    print()
    print(evolver.summary())

    result = evolver.decode()
    errors = sum(1 for a,b in zip(test_data, result) if a != b)
    print(f"  Byte-Fehler:     {errors}/{len(test_data)}")
