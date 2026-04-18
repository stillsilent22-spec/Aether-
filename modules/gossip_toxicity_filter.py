"""
gossip_toxicity_filter.py
Lokale Giftprüfung für alle eingehenden Gossip-Felder — ohne Quorum.

Erkennung rein lokal, regelbasiert + statistisch:
  1. Strukturprüfung   — Typ, Länge, Wertebereich aller bekannten Felder
  2. Inhaltsanalyse    — Code-Injektions-Pattern in Freitext-Feldern
  3. Statistik-Anomale — Zahlenwerte außerhalb beobachteter Verteilung
  4. Rate-Limiting     — max. Tokens/Hints pro Peer pro Zeitfenster vermeidet Spam
  5. Phishing-Schutz   — Convergence-Fälschung via geklammerte Metriken

Nutzung:
    from modules.gossip_toxicity_filter import GossipToxicityFilter
    clean_msg, warnings = GossipToxicityFilter.instance().validate(msg, peer_id)
    if clean_msg is None:
        return  # Paket komplett verwerfen

clean_msg enthält das bereinigte Paket — Freitext-Injection entfernt,
bei Rate-Limit überschrittenen Peers die betroffenen Felder entfernt.
Felder die strukturell nicht zu retten sind werden entfernt, Rest bleibt.

Privatsphäre: Der Filter logt niemals Inhalte, nur Anomalie-Typen + Peer-Prefix.
"""
from __future__ import annotations

import hashlib
import logging
import math
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Inhalts-Patterns die auf Code-Injection hindeuten
# Denylist für Freitext-Felder (instructions, gap_solutions, intent_sketch)
# ---------------------------------------------------------------------------
_INJECTION_RE = re.compile(
    r"""
    \b(?:exec|eval|compile|__import__|__builtins__)\s*\(
  | \bimport\s+(?:os|subprocess|sys|socket|shutil|ctypes|marshal|pickle|pty)\b
  | os\s*\.\s*(?:system|popen|execv|execve|execvp|spawn|fork)\s*\(
  | subprocess\s*\.\s*(?:run|call|Popen|check_output|check_call|getoutput)\s*\(
  | \bopen\s*\(.*['"]\s*[wa][b]*\s*['"]   # file open for writing
  | \bsocket\s*\.\s*socket\s*\(
  | \bshutil\s*\.
  | [;&|`]\s*(?:rm|del|format|curl|wget|nc|netcat|python|cmd|powershell)\b
  | \.\.[/\\]\.\.[/\\]                    # path traversal
  | (?:&\#x[0-9a-f]+;|%2e%2e|%252e)       # encoded traversal
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Erlaubte Zeichen in source_label (φ-Kandidaten) + domain-Strings
_SAFE_LABEL_RE = re.compile(r"^[A-Za-z0-9_.:\- ]{0,80}$")

# Erlaubte Hex-Fingerprint-Strings
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

def _normalize_token_id_component(value: str, max_len: int = 12) -> str:
    return "".join(
        c if (c.isalnum() or c in "_-.:") else "_"
        for c in str(value)
    )[:max_len] or "x"

# Bekannte metrics_summary Schlüssel + ihre erlaubten Bereiche [min, max]
_METRICS_BOUNDS: Dict[str, Tuple[float, float]] = {
    "delta_ratio":      (0.0,   2.0),
    "entropy":          (0.0,  30.0),
    "shannon_gap_pct":  (0.0, 100.0),
    "anchor_coverage":  (0.0,   1.0),
    "bits_per_joule":   (0.0,   1e9),
    "bpj_slope":        (-1e6,  1e6),
    "h_lambda":         (0.0,  50.0),
    "trust_score":      (0.0,   1.0),
}
_MIN_ALGO_TOKEN_FITNESS = 0.30

# Maximale Anzahl eingehender AlgoTokens pro Peer pro Zeitfenster
_TOKEN_RATE_WINDOW_SEC = 60
_TOKEN_RATE_MAX        = 5   # max. 5 neue Tokens pro Peer pro Minute

# Maximale Anzahl eingehender blindspot_hints + gap_solutions pro Peer pro Fenster
_HINT_RATE_MAX = 20

# Harte Größenlimits
_MAX_FINGERPRINTS      = 50
_MAX_PREFETCH_HINTS    = 8
_MAX_PHI_CANDIDATES    = 10
_MAX_BS_SIGNALS        = 16
_MAX_BS_HINTS          = 10
_MAX_TASK_REQUESTS     = 4
_MAX_TASK_BIDS         = 4
_MAX_TASK_RESULTS      = 4
_MAX_INSTRUCTION_CHARS = 512
_MAX_EDGE_KEY_CHARS    = 80
_MAX_INTENT_CHARS      = 120
_MAX_TOKEN_DICT_KEYS   = 20     # AlgoToken-Dict darf nicht willkürlich groß sein
_MAX_ALGO_TOKEN_BYTES  = 4096   # serialisiert

# Statistik-Fenster für Fitness-Score-Anomalie-Erkennung
_FITNESS_ANOMALY_WINDOW = 50     # erst nach N bekannten Tokens prüfen
_FITNESS_ANOMALY_SIGMA  = 4.0    # Werte > mean + N*std → Anomalie

# ---------------------------------------------------------------------------


class _PeerRateCounter:
    """Zählt Ereignisse pro Peer pro Zeitfenster. Thread-sicher."""

    def __init__(self, window_sec: float, max_count: int) -> None:
        self._window = window_sec
        self._max    = max_count
        self._counts: Dict[str, Tuple[int, float]] = {}  # peer_id → (count, window_start)
        self._lock = threading.Lock()

    def check_and_count(self, peer_id: str) -> bool:
        """True wenn das Ereignis erlaubt ist, False wenn Rate überschritten."""
        now = time.monotonic()
        with self._lock:
            count, start = self._counts.get(peer_id, (0, now))
            if now - start >= self._window:
                # Fenster abgelaufen → zurücksetzen
                count, start = 0, now
            if count >= self._max:
                return False  # gesperrt
            self._counts[peer_id] = (count + 1, start)
            return True

    def cleanup(self) -> None:
        """Alte Einträge entfernen (periodisch aufrufen)."""
        now = time.monotonic()
        with self._lock:
            expired = [p for p, (_, s) in self._counts.items()
                       if now - s >= self._window * 2]
            for p in expired:
                del self._counts[p]


class _FitnessStat:
    """Rolling-Statistik für empfangene fitness_scores (Anomalie-Erkennung)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: List[float] = []

    def add(self, v: float) -> None:
        with self._lock:
            self._values.append(v)
            if len(self._values) > _FITNESS_ANOMALY_WINDOW * 2:
                self._values = self._values[-_FITNESS_ANOMALY_WINDOW:]

    def is_anomalous(self, v: float) -> bool:
        with self._lock:
            if len(self._values) < _FITNESS_ANOMALY_WINDOW:
                return False
            mean = sum(self._values) / len(self._values)
            variance = sum((x - mean) ** 2 for x in self._values) / len(self._values)
            std = math.sqrt(variance) if variance > 0 else 0.0
            if std < 0.01:
                return False  # kaum Streuung → keine Aussage
            return v > mean + _FITNESS_ANOMALY_SIGMA * std


# ---------------------------------------------------------------------------
# Haupt-Filter
# ---------------------------------------------------------------------------

class GossipToxicityFilter:
    """Singleton-Filter für eingehende Gossip-Pakete.

    validate(msg, peer_id) → (bereinigtes msg | None, Liste von Warnungen)
    Gibt (None, warnings) zurück wenn das komplette Paket verworfen werden soll.
    """

    _instance:      Optional["GossipToxicityFilter"] = None
    _instance_lock: threading.Lock = threading.Lock()

    @classmethod
    def instance(cls) -> "GossipToxicityFilter":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self) -> None:
        self._token_rate   = _PeerRateCounter(_TOKEN_RATE_WINDOW_SEC, _TOKEN_RATE_MAX)
        self._hint_rate    = _PeerRateCounter(_TOKEN_RATE_WINDOW_SEC, _HINT_RATE_MAX)
        self._fitness_stat = _FitnessStat()
        self._cleanup_counter = 0

    # ── Public API ────────────────────────────────────────────────────────── #

    def validate(
        self,
        msg: Dict[str, Any],
        peer_id: str = "",
    ) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        """Prüft eingehendes Gossip-Paket und gibt ein bereinigtes Paket zurück.

        Rückgabe: (bereinigtes_msg, warnings)
          bereinigtes_msg = None → komplettes Paket verwerfen
          warnings = Liste von Log-Strings (peer-prefix, kein Inhalt)

        Beibehaltene Felder werden nie verändert außer:
          - Freitext-Felder werden gecleant (Injection-Chars entfernt)
          - Zahlenwerte außerhalb bekannter Bounds werden geclamped, nicht verworfen
          - Rate-überschrittene Felder werden entfernt (Rest des Pakets bleibt)
        """
        if not isinstance(msg, dict):
            return None, ["non-dict message"]

        warnings: List[str] = []
        p = peer_id[:16] or "unknown"

        # Periodisch Rate-Counter aufräumen (~alle 100 Pakete)
        self._cleanup_counter += 1
        if self._cleanup_counter >= 100:
            self._cleanup_counter = 0
            self._token_rate.cleanup()
            self._hint_rate.cleanup()

        msg = dict(msg)  # shallow copy — wir mutieren nicht das Original

        # ── 1. Schema-Check ────────────────────────────────────────────────
        schema = str(msg.get("schema", ""))
        if schema and not schema.startswith("aether."):
            warnings.append(f"[toxicity:{p}] unbekanntes Schema '{schema[:40]}' — verworfen")
            return None, warnings

        # ── 2. Fingerprints ────────────────────────────────────────────────
        fps = msg.get("fingerprints")
        if fps is not None:
            if not isinstance(fps, list):
                warnings.append(f"[toxicity:{p}] fingerprints kein List")
                msg["fingerprints"] = []
            else:
                clean_fps = [fp for fp in fps[:_MAX_FINGERPRINTS]
                             if isinstance(fp, str) and _HEX64_RE.match(fp)]
                if len(clean_fps) < len(fps):
                    warnings.append(
                        f"[toxicity:{p}] {len(fps)-len(clean_fps)} ungültige Fingerprints entfernt"
                    )
                msg["fingerprints"] = clean_fps

        # ── 3. metrics_summary ────────────────────────────────────────────
        ms = msg.get("metrics_summary")
        if isinstance(ms, dict):
            clean_ms: Dict[str, Any] = {}
            for k, v in ms.items():
                k = str(k)
                if k not in _METRICS_BOUNDS:
                    continue  # nur bekannte Keys akzeptieren
                try:
                    fv = float(v)
                    if not math.isfinite(fv):
                        warnings.append(f"[toxicity:{p}] metrics_summary.{k}=non-finite clamped")
                        fv = 0.0
                    lo, hi = _METRICS_BOUNDS[k]
                    if fv < lo or fv > hi:
                        warnings.append(
                            f"[toxicity:{p}] metrics_summary.{k}={fv:.4g} außerhalb [{lo},{hi}] clamped"
                        )
                        fv = max(lo, min(hi, fv))
                    clean_ms[k] = round(fv, 6)
                except (TypeError, ValueError):
                    warnings.append(f"[toxicity:{p}] metrics_summary.{k} kein float — entfernt")
            msg["metrics_summary"] = clean_ms

        # ── 4. AlgoToken ─────────────────────────────────────────────────
        algo_token = msg.get("algo_token")
        if algo_token is not None:
            cleaned_token = self._validate_algo_token(algo_token, p, warnings)
            if cleaned_token is None:
                del msg["algo_token"]
            else:
                # Rate-Limit
                if not self._token_rate.check_and_count(peer_id):
                    warnings.append(
                        f"[toxicity:{p}] AlgoToken-Rate überschritten — Token verworfen"
                    )
                    del msg["algo_token"]
                else:
                    fitness = float(cleaned_token.get("fitness_score", 0.0))
                    if self._fitness_stat.is_anomalous(fitness):
                        warnings.append(
                            f"[toxicity:{p}] AlgoToken fitness={fitness:.4g} Anomalie — verworfen"
                        )
                        del msg["algo_token"]
                    else:
                        self._fitness_stat.add(fitness)
                        msg["algo_token"] = cleaned_token

        algo_tokens = msg.get("algo_tokens")
        if algo_tokens is not None:
            if not isinstance(algo_tokens, list):
                del msg["algo_tokens"]
            else:
                clean_tokens: List[Dict[str, Any]] = []
                for token in algo_tokens[:5]:
                    if not isinstance(token, dict):
                        continue
                    cleaned_token = self._validate_algo_token(token, p, warnings)
                    if cleaned_token is None:
                        continue
                    clean_tokens.append(cleaned_token)
                if clean_tokens:
                    msg["algo_tokens"] = clean_tokens
                else:
                    del msg["algo_tokens"]

        # ── 5. prefetch_hints ─────────────────────────────────────────────
        prefetch = msg.get("prefetch_hints")
        if prefetch is not None:
            if not isinstance(prefetch, list):
                del msg["prefetch_hints"]
            else:
                clean_ph = []
                for h in prefetch[:_MAX_PREFETCH_HINTS]:
                    if not isinstance(h, dict):
                        continue
                    edge_key = str(h.get("edge_key", ""))[:_MAX_EDGE_KEY_CHARS]
                    if not edge_key:
                        continue
                    # edge_key darf kein Injection-Pattern enthalten
                    if _INJECTION_RE.search(edge_key):
                        warnings.append(f"[toxicity:{p}] prefetch edge_key Injection entfernt")
                        continue
                    obs = h.get("observation_count", 1)
                    try:
                        obs = max(1, min(10000, int(obs)))
                    except (TypeError, ValueError):
                        obs = 1
                    preds = h.get("predictions", [])
                    if isinstance(preds, list):
                        preds = [
                            {"fp": str(pr.get("fp", ""))[:64], "count": int(pr.get("count", 1))}
                            for pr in preds[:20]
                            if isinstance(pr, dict) and _HEX64_RE.match(str(pr.get("fp", "")))
                        ]
                    else:
                        preds = []
                    clean_ph.append({
                        "edge_key": edge_key,
                        "observation_count": obs,
                        "predictions": preds,
                    })
                msg["prefetch_hints"] = clean_ph

        # ── 6. φ-Kandidaten ───────────────────────────────────────────────
        phi_cands = msg.get("phi_candidates")
        if phi_cands is not None:
            if not isinstance(phi_cands, list):
                del msg["phi_candidates"]
            else:
                clean_pc = []
                for c in phi_cands[:_MAX_PHI_CANDIDATES]:
                    if not isinstance(c, dict):
                        continue
                    phi = c.get("phi")
                    if not isinstance(phi, list) or len(phi) != 9:
                        continue
                    try:
                        phi_clean = [
                            max(-1e6, min(1e6, float(v))) if math.isfinite(float(v)) else 0.0
                            for v in phi
                        ]
                    except (TypeError, ValueError):
                        continue
                    # source_label: nur sichere Zeichen
                    sl = str(c.get("source_label", ""))
                    if not _SAFE_LABEL_RE.match(sl):
                        sl = ""
                    fp = str(c.get("fingerprint", ""))
                    if fp and not _HEX64_RE.match(fp):
                        fp = ""
                    clean_pc.append({
                        "phi": phi_clean,
                        "fingerprint": fp,
                        "source_label": sl,
                        "remote_node_pubkey": str(c.get("remote_node_pubkey", ""))[:80],
                    })
                msg["phi_candidates"] = clean_pc

        # ── 7. blindspot_signals ──────────────────────────────────────────
        bs_signals = msg.get("blindspot_signals")
        if bs_signals is not None:
            if not isinstance(bs_signals, list):
                del msg["blindspot_signals"]
            else:
                clean_bss = []
                for s in bs_signals[:_MAX_BS_SIGNALS]:
                    if not isinstance(s, dict):
                        continue
                    domain = str(s.get("domain", ""))[:64]
                    if not _SAFE_LABEL_RE.match(domain):
                        domain = domain[:40]
                    desc = self._clean_text(str(s.get("description", "")), 256, p, warnings)
                    priority = s.get("priority", 5)
                    try:
                        priority = max(0, min(10, int(priority)))
                    except (TypeError, ValueError):
                        priority = 5
                    clean_bss.append({
                        k: s[k] for k in ("signal_id", "gap_type", "resolved",
                                          "last_broadcast_ts", "observation_count")
                        if k in s
                    } | {"domain": domain, "description": desc, "priority": priority})
                msg["blindspot_signals"] = clean_bss

        # ── 8. blindspot_hints ────────────────────────────────────────────
        bs_hints = msg.get("blindspot_hints")
        if bs_hints is not None:
            if not isinstance(bs_hints, list):
                del msg["blindspot_hints"]
            else:
                # Rate-Limit für Hints
                hint_allowed = self._hint_rate.check_and_count(peer_id)
                if not hint_allowed:
                    warnings.append(f"[toxicity:{p}] blindspot_hints Rate überschritten — entfernt")
                    del msg["blindspot_hints"]
                else:
                    clean_bsh = []
                    for h in bs_hints[:_MAX_BS_HINTS]:
                        if not isinstance(h, dict):
                            continue
                        instr = self._clean_text(
                            str(h.get("instructions", "")), _MAX_INSTRUCTION_CHARS, p, warnings
                        )
                        if instr is None:
                            warnings.append(f"[toxicity:{p}] blindspot_hint Injection → verworfen")
                            continue
                        domain = str(h.get("domain", ""))[:64]
                        if not _SAFE_LABEL_RE.match(domain):
                            continue
                        clean_bsh.append({
                            k: h[k] for k in ("hint_id", "signal_id", "hint_type",
                                              "payload_hash", "fingerprints", "priority_boost")
                            if k in h
                        } | {"domain": domain, "instructions": instr})
                    msg["blindspot_hints"] = clean_bsh

        # ── 9. task_requests ──────────────────────────────────────────────
        task_reqs = msg.get("task_requests")
        if task_reqs is not None:
            if not isinstance(task_reqs, list):
                del msg["task_requests"]
            else:
                clean_tr = []
                for r in task_reqs[:_MAX_TASK_REQUESTS]:
                    if not isinstance(r, dict):
                        continue
                    r = dict(r)
                    # approach_vector: alle finite Floats
                    av = r.get("approach_vector")
                    if isinstance(av, list):
                        r["approach_vector"] = [
                            max(-1e6, min(1e6, float(v))) if (
                                isinstance(v, (int, float)) and math.isfinite(float(v))
                            ) else 0.0
                            for v in av[:9]
                        ]
                    # intent_sketch: Injection-Check
                    intent = r.get("intent_sketch", "")
                    if intent:
                        cleaned = self._clean_text(str(intent), _MAX_INTENT_CHARS, p, warnings)
                        if cleaned is None:
                            r["intent_sketch"] = ""
                        else:
                            r["intent_sketch"] = cleaned
                    # capability_gap: sichere Strings
                    cg = r.get("capability_gap")
                    if isinstance(cg, list):
                        r["capability_gap"] = [
                            str(cap)[:32] for cap in cg[:16]
                            if isinstance(cap, str) and _SAFE_LABEL_RE.match(str(cap)[:32])
                        ]
                    clean_tr.append(r)
                msg["task_requests"] = clean_tr

        # ── 10. task_bids ─────────────────────────────────────────────────
        bids = msg.get("task_bids")
        if isinstance(bids, list):
            clean_bids = []
            for b in bids[:_MAX_TASK_BIDS]:
                if not isinstance(b, dict):
                    continue
                b = dict(b)
                for float_key in ("capability_score_pct", "eta_seconds"):
                    v = b.get(float_key)
                    if v is not None:
                        try:
                            fv = float(v)
                            b[float_key] = max(0.0, min(1e6, fv)) if math.isfinite(fv) else 0.0
                        except (TypeError, ValueError):
                            b[float_key] = 0.0
                clean_bids.append(b)
            msg["task_bids"] = clean_bids

        # ── 11. task_results ──────────────────────────────────────────────
        results = msg.get("task_results")
        if isinstance(results, list):
            clean_results = []
            for res in results[:_MAX_TASK_RESULTS]:
                if not isinstance(res, dict):
                    continue
                res = dict(res)
                # gap_solutions: Injection-Check für alle Instruction-Strings
                gs = res.get("gap_solutions")
                if isinstance(gs, dict):
                    clean_gs: Dict[str, str] = {}
                    for cap, instr in gs.items():
                        cap = str(cap)[:32]
                        if not _SAFE_LABEL_RE.match(cap):
                            continue
                        cleaned_instr = self._clean_text(
                            str(instr), _MAX_INSTRUCTION_CHARS, p, warnings
                        )
                        if cleaned_instr is not None:
                            clean_gs[cap] = cleaned_instr
                    res["gap_solutions"] = clean_gs
                # simplified_algo_token_data: strukturell validieren
                sat = res.get("simplified_algo_token_data")
                if isinstance(sat, dict):
                    cleaned_sat = self._validate_algo_token(sat, p, warnings)
                    if cleaned_sat is None:
                        res["simplified_algo_token_data"] = {}
                    else:
                        res["simplified_algo_token_data"] = cleaned_sat
                clean_results.append(res)
            msg["task_results"] = clean_results

        return msg, warnings

    # ── Interne Hilfsmethoden ─────────────────────────────────────────────

    def _clean_text(
        self,
        text: str,
        max_len: int,
        peer_prefix: str,
        warnings: List[str],
    ) -> Optional[str]:
        """Bereinigt einen Freitext-String.

        Gibt None zurück wenn ein Injection-Pattern gefunden wurde —
        der gesamte Eintrag soll dann verworfen werden.
        Gibt einen gesäuberten String zurück (max_len, nur druckbare ASCII).
        """
        # Injection-Check zuerst
        if _INJECTION_RE.search(text):
            warnings.append(
                f"[toxicity:{peer_prefix}] Code-Injection-Pattern in Text erkannt — Eintrag verworfen"
            )
            return None
        # Nur druckbare ASCII-Zeichen + deutschsprachige Umlaute + Tilde erlaubt
        cleaned = "".join(
            c for c in text
            if (32 <= ord(c) <= 126) or c in "äöüÄÖÜß€"
        )
        return cleaned[:max_len]

    def _validate_algo_token(
        self,
        token: Any,
        peer_prefix: str,
        warnings: List[str],
    ) -> Optional[Dict[str, Any]]:
        """Prüft ein AlgoToken-Dict strukturell.

        Gibt None zurück wenn das Token invalide ist.
        Gibt ein gesäubertes Dict zurück wenn valide.
        """
        if not isinstance(token, dict):
            return None
        if len(token) > _MAX_TOKEN_DICT_KEYS:
            warnings.append(f"[toxicity:{peer_prefix}] AlgoToken zu viele Keys ({len(token)}) — verworfen")
            return None

        token_id       = str(token.get("token_id", ""))
        tree_sig       = str(token.get("tree_signature", ""))
        domain         = str(token.get("domain_hint", "generic"))
        source_node_id = str(token.get("source_node_id", "")).strip()
        emitted_ts     = float(token.get("emitted_ts", 0.0))

        # Basis-Integrität (gleiche Prüfung wie AutoPropagator.receive_algo_token)
        if not token_id or not tree_sig or len(tree_sig) != 64:
            warnings.append(f"[toxicity:{peer_prefix}] AlgoToken fehlende/falsche Länge tree_sig")
            return None
        if not _HEX64_RE.match(tree_sig):
            warnings.append(f"[toxicity:{peer_prefix}] AlgoToken tree_sig kein Hex")
            return None
        if not source_node_id:
            warnings.append(f"[toxicity:{peer_prefix}] AlgoToken fehlt source_node_id")
            return None
        if len(source_node_id) > 80 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-." for c in source_node_id):
            warnings.append(f"[toxicity:{peer_prefix}] AlgoToken source_node_id invalid")
            return None
        if emitted_ts <= 0.0:
            warnings.append(f"[toxicity:{peer_prefix}] AlgoToken invalid emitted_ts")
            return None

        expected_id = f"{_normalize_token_id_component(source_node_id, 16)}-{tree_sig[:12]}-{_normalize_token_id_component(domain, 10)}"
        if token_id != expected_id:
            warnings.append(f"[toxicity:{peer_prefix}] AlgoToken token_id Integritätsfehler")
            return None

        # fitness_score [0, 1]
        fitness = token.get("fitness_score", 0.0)
        try:
            fitness = float(fitness)
            if not math.isfinite(fitness) or not (0.0 <= fitness <= 1.0):
                warnings.append(f"[toxicity:{peer_prefix}] AlgoToken fitness_score außerhalb [0,1]")
                return None
            if fitness < _MIN_ALGO_TOKEN_FITNESS:
                warnings.append(f"[toxicity:{peer_prefix}] AlgoToken fitness_score zu niedrig ({fitness:.4g}) — verworfen")
                return None
        except (TypeError, ValueError):
            return None

        # node_count + depth: positive Integers
        node_count = token.get("node_count", 0)
        depth      = token.get("depth",      0)
        try:
            node_count = max(0, min(100_000, int(node_count)))
            depth      = max(0, min(10_000,  int(depth)))
        except (TypeError, ValueError):
            node_count, depth = 0, 0

        # domain_hint: Whitelist
        if domain not in {"text", "binary", "audio", "video", "generic",
                          "image", "structured", "sensor", "game"}:
            domain = "generic"

        # invariant_profile: List[str], kurze sichere Strings
        inv_profile = token.get("invariant_profile", [])
        if isinstance(inv_profile, list):
            inv_profile = [
                str(x)[:32] for x in inv_profile[:16]
                if isinstance(x, str) and _SAFE_LABEL_RE.match(str(x)[:32])
            ]
        else:
            inv_profile = []

        return {
            "token_id":         token_id,
            "tree_signature":   tree_sig,
            "invariant_profile": inv_profile,
            "fitness_score":    round(fitness, 4),
            "domain_hint":      domain,
            "cascade_version":  str(token.get("cascade_version", "unknown"))[:32],
            "node_count":       node_count,
            "depth":            depth,
            "source_node_id":   source_node_id,
            "emitted_ts":       round(emitted_ts, 3),
        }

    @staticmethod
    def score_content(msg: Dict[str, Any]) -> float:
        """Bewertet die Inhaltsqualität eines Gossip-Pakets — ohne Peer-Identität.

        Gibt einen Score [0.0–1.0] zurück der ausschließlich auf dem Paket-Inhalt
        basiert — niemals auf wer es gesendet hat.  Dieser Score dient nur zur
        Priorisierung beim Weiterleiten, nie als Gate.

        Kriterien (additiv, je gleichgewichtet):
          +0.25  metrics_summary vorhanden mit trust_score > 0
          +0.25  algo_token vorhanden mit fitness_score >= 0.3
          +0.20  blindspot_signals oder blindspot_hints vorhanden
          +0.15  task_results vorhanden
          +0.10  phi_candidates vorhanden
          Abzug: -0.05 pro verworfenes Feld wenn msg bereits bereinigt wurde
                  (warnings-frei nach validate() → max. 1.0)
        """
        if not isinstance(msg, dict):
            return 0.0

        score = 0.0

        # metrics_summary: trust_score > 0 zeigt aktives Monitoring
        ms = msg.get("metrics_summary")
        if isinstance(ms, dict):
            try:
                ts = float(ms.get("trust_score", 0.0))
                if math.isfinite(ts) and ts > 0.0:
                    score += 0.25
            except (TypeError, ValueError):
                pass

        # algo_token: geteilte Performance-Erkenntnisse
        at = msg.get("algo_token")
        if isinstance(at, dict):
            try:
                fitness = float(at.get("fitness_score", 0.0))
                if math.isfinite(fitness) and fitness >= 0.3:
                    score += 0.25
                elif math.isfinite(fitness) and fitness > 0.0:
                    score += 0.10  # vorhanden aber schwach
            except (TypeError, ValueError):
                pass

        # blindspot_signals / blindspot_hints: kollektive Lücken-Erkennung
        bss = msg.get("blindspot_signals")
        bsh = msg.get("blindspot_hints")
        if (isinstance(bss, list) and len(bss) > 0) or \
           (isinstance(bsh, list) and len(bsh) > 0):
            score += 0.20

        # task_results: abgeschlossene Aufgaben bringen direkt verwertbare Daten
        tr = msg.get("task_results")
        if isinstance(tr, list) and len(tr) > 0:
            score += 0.15

        # phi_candidates: tiefe strukturelle Signaturen
        phi = msg.get("phi_candidates")
        if isinstance(phi, list) and len(phi) > 0:
            score += 0.10

        return round(min(1.0, max(0.0, score)), 3)
