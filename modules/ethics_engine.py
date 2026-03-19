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
        symmetry_component: float = 0.0
        coherence_score: float = 0.0
        resonance_score: float = 0.0
        ethics_score: float = 0.0
        integrity_state: str = "STRUCTURAL_TENSION"
        integrity_text: str = "Strukturelle Spannung erkannt"
        notes: list = _field(default_factory=list)
else:
    class EthicsAssessment:  # type: ignore
        def __init__(self, score=0.0, zipf=0.0, benford=0.0, fraktal=0.0,
                     noether=0.0, interferenz=0.0, heisenberg=0.0,
                     symmetry_component=0.0, coherence_score=0.0,
                     resonance_score=0.0, ethics_score=0.0,
                     integrity_state="STRUCTURAL_TENSION",
                     integrity_text="Strukturelle Spannung erkannt", notes=None):
            self.score = score; self.zipf = zipf; self.benford = benford
            self.fraktal = fraktal; self.noether = noether
            self.interferenz = interferenz; self.heisenberg = heisenberg
            self.symmetry_component = symmetry_component
            self.coherence_score = coherence_score
            self.resonance_score = resonance_score
            self.ethics_score = ethics_score
            self.integrity_state = integrity_state
            self.integrity_text = integrity_text
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

    def evaluate(
        self,
        symmetry_score: float,
        entropy_blocks: list,
        entropy_mean: float,
        periodicity: int,
        delta_ratio: float,
        healthy_references=None,
    ) -> EthicsAssessment:
        """Numerische Integritaetsbewertung fuer Analyse-/Runtime-Pipelines."""
        symmetry_component = float(symmetry_score)
        if symmetry_component > 1.0:
            symmetry_component = symmetry_component / 100.0
        symmetry_component = max(0.0, min(1.0, symmetry_component))

        entropy_center = 4.5
        entropy_spread = 2.8
        entropy_health = max(0.0, 1.0 - (abs(float(entropy_mean) - entropy_center) / entropy_spread))

        try:
            if entropy_blocks:
                avg = sum(float(v) for v in entropy_blocks) / float(len(entropy_blocks))
                variance = sum((float(v) - avg) ** 2 for v in entropy_blocks) / float(max(1, len(entropy_blocks)))
                volatility = min(1.0, (variance ** 0.5) / 3.0)
            else:
                volatility = 0.0
        except Exception:
            volatility = 0.0

        periodicity_norm = max(0.0, min(1.0, 1.0 - abs(int(periodicity) - 24) / 48.0))
        delta_health = max(0.0, min(1.0, 1.0 - float(delta_ratio)))

        coherence_score = (
            0.38 * symmetry_component
            + 0.30 * entropy_health
            + 0.18 * periodicity_norm
            + 0.14 * delta_health
        )
        coherence_score *= (1.0 - 0.25 * volatility)
        coherence_score = max(0.0, min(1.0, coherence_score))

        resonance_score = 0.5
        refs = list(healthy_references or [])
        if refs:
            current = [symmetry_component, entropy_health, periodicity_norm, delta_health]
            best_distance = None
            for ref in refs:
                try:
                    ref_vec = [
                        float(ref.get("symmetry_score", symmetry_component)),
                        max(0.0, min(1.0, 1.0 - abs(float(ref.get("entropy_mean", entropy_mean)) - entropy_center) / entropy_spread)),
                        max(0.0, min(1.0, 1.0 - abs(float(ref.get("periodicity", periodicity)) - 24) / 48.0)),
                        max(0.0, min(1.0, 1.0 - float(ref.get("delta_ratio", delta_ratio)))),
                    ]
                    dist = sum((a - b) ** 2 for a, b in zip(current, ref_vec)) ** 0.5
                    best_distance = dist if best_distance is None else min(best_distance, dist)
                except Exception:
                    continue
            if best_distance is not None:
                resonance_score = max(0.0, min(1.0, 1.0 - (best_distance / 2.0)))

        ethics_score = (
            0.50 * coherence_score
            + 0.30 * resonance_score
            + 0.20 * symmetry_component
        )
        ethics_score = max(0.0, min(1.0, ethics_score))

        if ethics_score >= 0.72:
            integrity_state = "STRUCTURAL_COHERENCE"
            integrity_text = "Strukturelle Koharenz stabil"
        elif ethics_score >= 0.46:
            integrity_state = "STRUCTURAL_TENSION"
            integrity_text = "Strukturelle Spannung erkannt"
        else:
            integrity_state = "STRUCTURAL_ANOMALY"
            integrity_text = "Strukturelle Anomalie erkannt"

        return EthicsAssessment(
            score=float(ethics_score),
            zipf=float(coherence_score),
            benford=float(resonance_score),
            fraktal=float(entropy_health),
            noether=float(periodicity_norm),
            interferenz=float(delta_health),
            heisenberg=float(1.0 - volatility),
            symmetry_component=float(symmetry_component),
            coherence_score=float(coherence_score),
            resonance_score=float(resonance_score),
            ethics_score=float(ethics_score),
            integrity_state=integrity_state,
            integrity_text=integrity_text,
            notes=[],
        )


# ---------------------------------------------------------------------------
# Ockham's Razor for OS governance (deterministic, minimal interventions)
# ---------------------------------------------------------------------------

if _DC_OK:
    @_dataclass
    class OckhamDecision:
        action: str = "allow"
        risk_score: float = 0.0
        utility: float = 0.0
        complexity: float = 0.0
        reasons: list = _field(default_factory=list)
        ranked_actions: list = _field(default_factory=list)
else:
    class OckhamDecision:  # type: ignore
        def __init__(self, action="allow", risk_score=0.0, utility=0.0, complexity=0.0, reasons=None, ranked_actions=None):
            self.action = action
            self.risk_score = risk_score
            self.utility = utility
            self.complexity = complexity
            self.reasons = reasons or []
            self.ranked_actions = ranked_actions or []


def _clip01(value) -> float:
    try:
        return float(max(0.0, min(1.0, float(value))))
    except Exception:
        return 0.0


def _risk_from_observation(observation: dict) -> tuple[float, list]:
    cpu_load = _clip01(observation.get("cpu_load", 0.0))
    mem_pressure = _clip01(observation.get("mem_pressure", 0.0))
    spawn_rate = _clip01(observation.get("process_spawn_rate", 0.0))
    unsigned_ratio = _clip01(observation.get("unsigned_binary_ratio", 0.0))
    net_new_peers = _clip01(observation.get("network_new_peers", 0.0))
    error_burst = _clip01(observation.get("error_burst", 0.0))
    integrity_alerts = _clip01(observation.get("integrity_alerts", 0.0))

    risk = (
        0.18 * cpu_load
        + 0.15 * mem_pressure
        + 0.16 * spawn_rate
        + 0.19 * unsigned_ratio
        + 0.12 * net_new_peers
        + 0.08 * error_burst
        + 0.12 * integrity_alerts
    )

    reasons = []
    if cpu_load > 0.82:
        reasons.append("cpu_load_high")
    if mem_pressure > 0.82:
        reasons.append("mem_pressure_high")
    if spawn_rate > 0.72:
        reasons.append("spawn_rate_high")
    if unsigned_ratio > 0.45:
        reasons.append("unsigned_binary_ratio_high")
    if net_new_peers > 0.60:
        reasons.append("network_peer_churn_high")
    if error_burst > 0.70:
        reasons.append("error_burst_high")
    if integrity_alerts > 0.10:
        reasons.append("integrity_alerts_present")

    return (_clip01(risk), reasons)


def _action_table() -> list:
    # complexity: intervention cost; reduction: expected normalized risk reduction
    return [
        {"action": "allow", "complexity": 0.00, "reduction": 0.00},
        {"action": "throttle_background", "complexity": 0.18, "reduction": 0.28},
        {"action": "limit_new_processes", "complexity": 0.26, "reduction": 0.42},
        {"action": "isolate_network", "complexity": 0.33, "reduction": 0.55},
        {"action": "pause_autopilot", "complexity": 0.40, "reduction": 0.66},
        {"action": "require_manual_review", "complexity": 0.52, "reduction": 0.80},
    ]


def ockham_os_razor(observation: dict, complexity_weight: float = 0.35) -> dict:
    """
    Waehlt die einfachste noch wirksame OS-Gegenmassnahme.

    Utility(action) = risk_score * reduction - complexity_weight * complexity
    Der Gewinner maximiert Utility. Bei Gleichstand gewinnt die geringere Komplexitaet.
    """
    risk_score, reasons = _risk_from_observation(dict(observation or {}))

    ranked = []
    for row in _action_table():
        utility = risk_score * float(row["reduction"]) - float(complexity_weight) * float(row["complexity"])
        ranked.append(
            {
                "action": str(row["action"]),
                "utility": float(utility),
                "complexity": float(row["complexity"]),
                "expected_risk_reduction": float(risk_score * float(row["reduction"])),
            }
        )

    ranked.sort(key=lambda item: (-item["utility"], item["complexity"], item["action"]))
    winner = ranked[0] if ranked else {"action": "allow", "utility": 0.0, "complexity": 0.0}

    # Ockham gate: for low risk prefer explicit non-intervention.
    if risk_score < 0.28:
        winner = {"action": "allow", "utility": 0.0, "complexity": 0.0}

    return {
        "action": str(winner["action"]),
        "risk_score": float(risk_score),
        "utility": float(winner["utility"]),
        "complexity": float(winner["complexity"]),
        "reasons": reasons,
        "ranked_actions": ranked,
    }


class OckhamRazorEngine:
    """Deterministisches Minimal-Interventionsmodell fuer OS-Governance."""

    def decide(self, observation: dict, complexity_weight: float = 0.35) -> OckhamDecision:
        raw = ockham_os_razor(observation=observation, complexity_weight=complexity_weight)
        return OckhamDecision(
            action=str(raw.get("action", "allow")),
            risk_score=float(raw.get("risk_score", 0.0)),
            utility=float(raw.get("utility", 0.0)),
            complexity=float(raw.get("complexity", 0.0)),
            reasons=list(raw.get("reasons", [])),
            ranked_actions=list(raw.get("ranked_actions", [])),
        )


# ---------------------------------------------------------------------------
# Code-Obfuscation und strukturelle Anomalie-Erkennung
# ---------------------------------------------------------------------------

def _byte_entropy(data: bytes) -> float:
    """Berechnet Shannon-Entropie ueber alle Bytes (0-8 bit)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * _math.log2(p)
    return entropy


def _token_entropy(tokens: list) -> float:
    """Shannon-Entropie ueber Token-Verteilung."""
    if not tokens:
        return 0.0
    counts = _Counter(tokens)
    n = len(tokens)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            entropy -= p * _math.log2(p)
    return entropy


def _identifier_ratio(code: str) -> float:
    """
    Anteil sehr kurzer Bezeichner (1-2 Zeichen) an allen Bezeichnern.
    Hohes Verhaeltnis deutet auf Obfuscation hin.
    """
    identifiers = _re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code)
    if len(identifiers) < 10:
        return 0.0
    short = sum(1 for i in identifiers if len(i) <= 2)
    return short / len(identifiers)


def _hex_string_ratio(code: str) -> float:
    """Anteil hexadezimaler Literale (typisch fuer Shellcode/Obfuscation)."""
    hex_literals = _re.findall(r'\\x[0-9a-fA-F]{2}|0x[0-9a-fA-F]+', code)
    tokens = code.split()
    if not tokens:
        return 0.0
    return min(1.0, len(hex_literals) / max(1, len(tokens)))


def _base64_density(code: str) -> float:
    """Schätzt den Anteil langer Base64-ähnlicher Zeichenfolgen."""
    b64_blocks = _re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', code)
    total_chars = len(code)
    if not total_chars:
        return 0.0
    b64_chars = sum(len(b) for b in b64_blocks)
    return min(1.0, b64_chars / total_chars)


def _eval_exec_density(code: str) -> float:
    """
    Häufigkeit von eval/exec/compile-ähnlichen Konstrukten.
    Hohe Dichte ist ein Anomalie-Indikator (kein Label, nur Struktur).
    """
    dangerous = _re.findall(
        r'\b(eval|exec|compile|__import__|getattr|setattr|globals|locals)\s*\(',
        code
    )
    lines = [l for l in code.splitlines() if l.strip()]
    if not lines:
        return 0.0
    return min(1.0, len(dangerous) / max(1, len(lines)))


def analyze_code_structure(code: str) -> dict:
    """
    Strukturelle Analyse von Code oder binaerem Text auf Obfuscation-Muster.

    Gibt ein Dict mit Metriken und einem Gesamt-Anomalie-Score zurueck.
    Score nahe 0.0 = stark anomal; Score nahe 1.0 = strukturell normal.

    Kein Keyword-Matching, keine Signaturen — nur Strukturmetriken.
    """
    if not code or not code.strip():
        return {
            "anomaly_score": 1.0,
            "byte_entropy": 0.0,
            "token_entropy": 0.0,
            "identifier_ratio_short": 0.0,
            "hex_ratio": 0.0,
            "base64_density": 0.0,
            "eval_exec_density": 0.0,
            "flags": [],
        }

    byte_ent = _byte_entropy(code.encode("utf-8", errors="replace"))
    tokens = _re.findall(r'[a-zA-Z_]\w*|[0-9]+|[^\w\s]', code)
    tok_ent = _token_entropy(tokens)
    id_ratio = _identifier_ratio(code)
    hex_ratio = _hex_string_ratio(code)
    b64 = _base64_density(code)
    eval_d = _eval_exec_density(code)

    flags = []

    # Hohe Byte-Entropie (>7.0 bit) deutet auf verschlüsselte/gepackte Inhalte hin
    if byte_ent > 7.0:
        flags.append("high_byte_entropy")

    # Sehr kurze Bezeichner (Obfuscation)
    if id_ratio > 0.6:
        flags.append("short_identifier_ratio")

    # Viele Hex-Literale (Shellcode-Muster)
    if hex_ratio > 0.1:
        flags.append("high_hex_literal_ratio")

    # Lange Base64-Blöcke (eingebetteter Payload)
    if b64 > 0.05:
        flags.append("high_base64_density")

    # Häufige eval/exec (dynamische Code-Ausführung)
    if eval_d > 0.05:
        flags.append("high_eval_exec_density")

    # Anomalie-Score: 1.0 = normal, 0.0 = stark verdächtig
    # Jeder Flag zieht Punkte ab (gewichtet)
    score = 1.0
    if "high_byte_entropy" in flags:
        score -= 0.30
    if "short_identifier_ratio" in flags:
        score -= 0.25
    if "high_hex_literal_ratio" in flags:
        score -= 0.20
    if "high_base64_density" in flags:
        score -= 0.15
    if "high_eval_exec_density" in flags:
        score -= 0.15

    # Zipf-Verletzung bei Tokens (Obfuscation stört Zipf)
    if _NP_OK and len(tokens) > 20:
        try:
            ranked = [f for _, f in _Counter(tokens).most_common(min(50, len(tokens)))]
            if len(ranked) >= 5:
                import numpy as _numpy
                c = _numpy.polyfit(
                    _numpy.log(_numpy.arange(1, len(ranked) + 1)),
                    _numpy.log([max(1, f) for f in ranked]),
                    1
                )
                zipf_dev = abs(abs(float(c[0])) - 1.0)
                if zipf_dev > 0.7:
                    flags.append("zipf_violation")
                    score -= 0.10 * min(1.0, zipf_dev)
        except Exception:
            pass

    return {
        "anomaly_score": float(max(0.0, min(1.0, score))),
        "byte_entropy": round(byte_ent, 4),
        "token_entropy": round(tok_ent, 4),
        "identifier_ratio_short": round(id_ratio, 4),
        "hex_ratio": round(hex_ratio, 4),
        "base64_density": round(b64, 4),
        "eval_exec_density": round(eval_d, 4),
        "flags": flags,
    }


class CodeEthicsEngine:
    """
    Strukturelle Integritaetsanalyse fuer Code und binaere Payloads.

    Erkennt Obfuscation, Shellcode-Muster und dynamische Code-Ausfuehrung
    ausschliesslich anhand messbarer Strukturmetriken — kein Keyword-Matching,
    keine Signatur-Datenbank, kein Cloud-Lookup.
    """

    def analyze(self, code: str) -> dict:
        """
        Vollstaendige Code-Strukturanalyse.

        Rueckgabe:
          {
            "anomaly_score": float,   # 0.0 = stark anomal, 1.0 = normal
            "byte_entropy": float,
            "token_entropy": float,
            "identifier_ratio_short": float,
            "hex_ratio": float,
            "base64_density": float,
            "eval_exec_density": float,
            "flags": list[str],       # erkannte Indikator-Flags
            "verdict": str,           # "clean" | "suspicious" | "anomalous"
          }
        """
        result = analyze_code_structure(code)
        score = float(result.get("anomaly_score", 1.0))
        if score >= 0.7:
            verdict = "clean"
        elif score >= 0.4:
            verdict = "suspicious"
        else:
            verdict = "anomalous"
        result["verdict"] = verdict
        return result

    def is_suspicious(self, code: str, threshold: float = 0.5) -> bool:
        """Gibt True zurueck wenn der Anomalie-Score unter *threshold* liegt."""
        return float(analyze_code_structure(code).get("anomaly_score", 1.0)) < threshold