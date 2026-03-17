import re as _re
import math as _math
from collections import Counter as _Counter
try:
    import numpy as _np
    _NP_OK = True
except Exception:
    _NP_OK = False

_STOP = {"der","die","das","und","in","ist","ein","eine","mit","auf","den",
         "dem","des","von","zu","im","an","für","nicht","als","the","a","an",
         "and","or","in","is","it","of","to","for","that","this","with","are",
         "was","be","at","by","from","on"}
_NEG = {"nicht","kein","keine","keinen","nie","niemals","never","no","not","without","ohne"}
_ABS = {"immer","alle","alles","jeden","jeder","einzig","ausschließlich","always",
        "never","nobody","everyone","everything","only","solely","100%","absolutely"}

def _zipf(words):
    if not _NP_OK or len(words)<10: return 0.7
    try:
        ranked=[f for _,f in _Counter(words).most_common(min(50,len(_Counter(words))))]
        if len(ranked)<5: return 0.7
        c=_np.polyfit(_np.log(range(1,len(ranked)+1)),_np.log([max(1,f) for f in ranked]),1)
        return float(max(0.0,1.0-abs(abs(c[0])-1.0)/0.8))
    except: return 0.7

def _benford(text):
    try:
        nums=_re.findall(r'\b[1-9][0-9]*\b',text)
        if len(nums)<20: return 0.5
        c=_Counter(int(n[0]) for n in nums)
        t=sum(c.values())
        chi2=sum(((c.get(d,0)/t-_math.log10(1+1/d))**2)/_math.log10(1+1/d) for d in range(1,10))
        return float(max(0.0,1.0-chi2/15.0))
    except: return 0.5

def _fraktal(sents):
    try:
        import statistics
        L=[len(s.split()) for s in sents if s.strip()]
        if len(L)<3: return 0.6
        std=statistics.stdev(L)
        if 5<=std<=20: return 1.0
        if std<3: return std/3*0.5
        if std>40: return max(0.0,1.0-(std-40)/40)*0.5
        if std<5: return (std-3)/2*0.5+0.5
        return max(0.0,1.0-(std-20)/20)*0.5+0.5
    except: return 0.6

def _noether(words):
    try:
        f=[w for w in words if w not in _STOP and len(w)>2]
        if len(f)<20: return 0.6
        t=len(f)//3
        a=_Counter(f[:t]); b=_Counter(f[-t:])
        all_w=set(list(a.keys())[:20])|set(list(b.keys())[:20])
        if not all_w: return 0.6
        if _NP_OK:
            va=_np.array([a.get(w,0) for w in all_w],dtype=float)
            vb=_np.array([b.get(w,0) for w in all_w],dtype=float)
            na,nb=float(_np.linalg.norm(va)),float(_np.linalg.norm(vb))
            sim=float(_np.dot(va,vb)/(na*nb)) if na>0 and nb>0 else 0.5
        else:
            ka=set(list(a.keys())[:20]); kb=set(list(b.keys())[:20])
            sim=len(ka&kb)/len(ka|kb) if ka|kb else 0.5
        return float(min(1.0,sim*2.0))
    except: return 0.6

def _interferenz(words):
    try:
        if not words: return 0.6
        d=sum(1 for w in words if w in _NEG)/len(words)
        if d<0.01: return 0.5
        if 0.02<=d<=0.08: return 1.0
        if d>0.15: return 0.2
        if d<0.02: return 0.5+(d-0.01)/0.01*0.5
        return max(0.2,1.0-(d-0.08)/0.07*0.8)
    except: return 0.6

def _heisenberg(sents,words):
    try:
        if not sents: return 0.6
        d=sum(1 for w in words if w in _ABS)/max(1,len(sents))
        if 0.1<=d<=0.8: return 1.0
        if d>1.5: return max(0.0,1.0-(d-0.8)/2.2)
        if d<0.1: return 0.8
        return max(0.0,1.0-(d-0.8)/0.7*0.4)
    except: return 0.6

def structural_text_integrity(text: str, entropy_mean=None) -> dict:
    """Misst strukturelle Integrität — kein Label, kein Keyword-Filter. Nur Struktur."""
    if not text or not text.strip():
        return {"score":1.0,"zipf":1.0,"benford":0.5,"fraktal":1.0,"noether":1.0,"interferenz":1.0,"heisenberg":1.0}
    words=[w.lower().strip(".,!?;:\"'()[]{}") for w in text.split() if w.strip()]
    sents=[s.strip() for s in _re.split(r'[.!?]+',text) if s.strip()]
    z=_zipf(words); b=_benford(text); f=_fraktal(sents)
    n=_noether(words); i=_interferenz(words); h=_heisenberg(sents,words)
    if b==0.5:
        total=z*0.30+f*0.25+n*0.25+i*0.12+h*0.08
    else:
        total=z*0.25+b*0.15+f*0.20+n*0.20+i*0.10+h*0.10
    if entropy_mean is not None:
        if float(entropy_mean)<3.5: total*=0.85
        elif float(entropy_mean)>7.0: total*=0.90
    return {"score":float(max(0.0,min(1.0,total))),"zipf":float(z),"benford":float(b),
            "fraktal":float(f),"noether":float(n),"interferenz":float(i),"heisenberg":float(h)}

def ethics_score(text: str, entropy_mean=None) -> float:
    """Struktureller Integritätsscore — kein Label, nur Struktur."""
    if not text or not text.strip(): return 1.0
    return float(structural_text_integrity(text,entropy_mean=entropy_mean).get("score",1.0))


# ---------------------------------------------------------------------------
# Klassen-API (fuer Import von analysis_engine und theremin_engine)
# ---------------------------------------------------------------------------

try:
    from dataclasses import dataclass as _dataclass, field as _field
    _DC_OK = True
except ImportError:
    _DC_OK = False

if _DC_OK:
    @_dataclass
    class EthicsAssessment:
        """Struktureller Integritaetsbefund fuer einen Text-Payload."""
        score: float = 0.0
        zipf: float = 0.0
        benford: float = 0.0
        fraktal: float = 0.0
        noether: float = 0.0
        interferenz: float = 0.0
        heisenberg: float = 0.0
        notes: list = _field(default_factory=list)
else:
    class EthicsAssessment:  # type: ignore
        def __init__(self, score=0.0, zipf=0.0, benford=0.0, fraktal=0.0,
                     noether=0.0, interferenz=0.0, heisenberg=0.0, notes=None):
            self.score = score; self.zipf = zipf; self.benford = benford
            self.fraktal = fraktal; self.noether = noether
            self.interferenz = interferenz; self.heisenberg = heisenberg
            self.notes = notes or []


class EthicsEngine:
    """
    Strukturelle Integritaetsanalyse auf Basis von Sprachgesetzen.

    Bewertet Text ausschliesslich anhand messbarer Struktureigenschaften
    (Zipf, Benford, fraktale Satzlaengenverteilung, thematische Konsistenz,
    Negationsdichte, Absolute-Aussagen-Rate). Kein Keyword-Matching,
    keine Labels, nur Struktur.
    """

    def assess(self, text: str, entropy_mean=None) -> EthicsAssessment:
        """Vollstaendige Strukturanalyse — gibt EthicsAssessment zurueck."""
        if not text or not text.strip():
            return EthicsAssessment(score=1.0, zipf=1.0, benford=0.5,
                                    fraktal=1.0, noether=1.0,
                                    interferenz=1.0, heisenberg=1.0)
        raw = structural_text_integrity(text, entropy_mean=entropy_mean)
        return EthicsAssessment(
            score=float(raw.get("score", 1.0)),
            zipf=float(raw.get("zipf", 1.0)),
            benford=float(raw.get("benford", 0.5)),
            fraktal=float(raw.get("fraktal", 1.0)),
            noether=float(raw.get("noether", 1.0)),
            interferenz=float(raw.get("interferenz", 1.0)),
            heisenberg=float(raw.get("heisenberg", 1.0)),
            notes=[],
        )

    def score(self, text: str, entropy_mean=None) -> float:
        """Kurzform: gibt nur den Gesamtscore zurueck."""
        return float(self.assess(text, entropy_mean=entropy_mean).score)