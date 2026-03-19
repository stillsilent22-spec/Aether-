"""Strukturelle YouTube-Analyse fuer Aether.

Keine Semantik.  Keine Interpretation.  Keine Weltmodelle.
Ausschliesslich messbare Strukturmetriken:

  ai_generation_score   — gewichtete Summe aller Struktur-Signale (0..1)
  ai_verdict            — "ai" | "likely_ai" | "human"
  ai_signals            — Liste ausgeloester Signal-IDs
  entropy               — Shannon-Entropie der Seitenstruktur
  upload_rhythm_delta   — Regelmaessigkeit der Upload-Kadenz (0=irregulär, 1=perfekt)
  ockham_penalty        — Strafterm fuer ueberkomplexe Signal-Konfiguration

Schwellwerte (konfigurierbar per Einstellung):
  AI_THRESHOLD_HIGH     0.70  → Verdict "ai"
  AI_THRESHOLD_MID      0.45  → Verdict "likely_ai"

Persistenz:
  Kanal-Profile werden in data/youtube_profiles.json gespeichert.
  Jeder Eintrag ist auditierbar (Timestamp, URL, alle Metriken).
"""
from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Schwellwerte (deterministisch, keine Lernmechanik)
# ---------------------------------------------------------------------------

AI_THRESHOLD_HIGH: float = 0.70   # → "ai"
AI_THRESHOLD_MID: float  = 0.45   # → "likely_ai"
OCKHAM_SIGNAL_MAX: int   = 5      # ab mehr Signalen als nötig gilt Ockham-Strafe
OCKHAM_WEIGHT: float     = 0.04   # Gewicht der Ockham-Strafe pro überschüssigem Signal

_PROFILE_STORE = Path("data") / "youtube_profiles.json"

# ---------------------------------------------------------------------------
# Datenstruktur
# ---------------------------------------------------------------------------

@dataclass
class YouTubeProfile:
    """Strukturelles Profil eines YouTube-Videos oder -Kanals."""

    url: str
    profile_type: str           # "video" | "channel"
    channel_name: str
    title: str
    ai_score: float             # 0..1
    ai_verdict: str             # "ai" | "likely_ai" | "human"
    ai_signals: List[str]       # ausgeloeste Signal-IDs
    entropy: float              # Shannon-Entropie der Seitenstruktur
    upload_rhythm_delta: float  # 0=unregelmässig, 1=perfekt regulär
    ockham_penalty: float       # Strafterm
    scanned_at: float           # Unix-Timestamp
    cluster_id: str = ""        # leer wenn noch nicht geclustert
    metadata: Dict[str, Any] = field(default_factory=dict)

    def verdict_label(self) -> str:
        if self.ai_score >= AI_THRESHOLD_HIGH:
            return "KI-GENERIERT"
        if self.ai_score >= AI_THRESHOLD_MID:
            return "WAHRSCHEINLICH KI"
        return "MENSCHLICH"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Hilffunktionen (keine Semantik)
# ---------------------------------------------------------------------------

def _is_youtube_url(url: str) -> bool:
    return bool(re.search(r"(youtube\.com|youtu\.be)", url, re.IGNORECASE))


def _classify_url_type(url: str) -> str:
    """Unterscheidet Video- von Kanal-URLs rein strukturell."""
    if re.search(r"youtube\.com/(channel/|c/|@|user/)", url, re.IGNORECASE):
        return "channel"
    if re.search(r"(youtube\.com/watch|youtu\.be/)", url, re.IGNORECASE):
        return "video"
    return "unknown"


def upload_rhythm_delta(timestamps: List[float]) -> float:
    """Periodizitaets-Metrik fuer Upload-Kadenz.

    Gibt 0 (vollstaendig irregulär) bis 1 (perfekt regulaer) zurueck.
    Berechnet den normalisierten Variationskoeffizienten der Zeitabstaende.
    Weniger als 2 Timestamps → undefiniert (0.0).
    """
    if len(timestamps) < 2:
        return 0.0
    sorted_ts = sorted(timestamps)
    deltas = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]
    mean = sum(deltas) / len(deltas)
    if mean == 0.0:
        return 1.0
    variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
    std = math.sqrt(variance)
    cv = std / mean          # Variationskoeffizient: 0 = perfekt regulär
    regularity = max(0.0, 1.0 - min(1.0, cv))
    return round(regularity, 4)


def _ockham_penalty(signal_count: int) -> float:
    """Ockham-Strafterm: je mehr Signale als minimal nötig, desto höher die Strafe."""
    excess = max(0, signal_count - OCKHAM_SIGNAL_MAX)
    return min(1.0, round(excess * OCKHAM_WEIGHT, 4))


def _upload_rhythm_from_html(html_text: str) -> float:
    """Schätzt Upload-Rhythmus aus zeitlichen Marker-Mustern im HTML-Text.

    Sucht nach ISO-Zeitstempeln oder Relativangaben und leitet daraus eine
    Periodizitäts-Schätzung ab – ausschliesslich strukturell.
    """
    # Absolute ISO-Zeitstempel (yyyy-mm-dd)
    iso_dates = re.findall(r'"(\d{4}-\d{2}-\d{2})"', html_text)
    timestamps: List[float] = []
    for raw in iso_dates:
        try:
            import datetime as _dt
            ts = _dt.datetime.strptime(raw, "%Y-%m-%d").timestamp()
            timestamps.append(ts)
        except ValueError:
            continue
    if len(timestamps) >= 2:
        return upload_rhythm_delta(timestamps)
    # Relative Angaben (vor X Stunden/Tagen/Monaten/Jahren) — grobkörnig
    relative_hits = re.findall(
        r"vor\s+(\d+)\s+(Stunde[n]?|Tag[en]?|Woche[n]?|Monat[en]?|Jahr[en]?)"
        r"|(\d+)\s+(hour[s]?|day[s]?|week[s]?|month[s]?|year[s]?)\s+ago",
        html_text,
        re.IGNORECASE,
    )
    return round(min(1.0, len(relative_hits) / 20.0), 4) if relative_hits else 0.0


# ---------------------------------------------------------------------------
# Profilspeicher (JSON, auditierbar)
# ---------------------------------------------------------------------------

class ChannelStore:
    """Persistenter Speicher fuer YouTubeProfile-Objekte (JSON, append-only-ähnlich)."""

    def __init__(self, path: Path = _PROFILE_STORE) -> None:
        self._path = Path(path)
        self._profiles: Dict[str, YouTubeProfile] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            for entry in raw if isinstance(raw, list) else []:
                p = YouTubeProfile(**{k: v for k, v in entry.items() if k in YouTubeProfile.__dataclass_fields__})
                self._profiles[p.url] = p
        except Exception:
            pass

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = [p.to_dict() for p in self._profiles.values()]
            self._path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    def store(self, profile: YouTubeProfile) -> None:
        self._profiles[profile.url] = profile
        self.save()

    def all_profiles(self) -> List[YouTubeProfile]:
        return list(self._profiles.values())

    def by_verdict(self, verdict: str) -> List[YouTubeProfile]:
        return [p for p in self._profiles.values() if p.ai_verdict == verdict]

    def recent(self, n: int = 50) -> List[YouTubeProfile]:
        return sorted(self._profiles.values(), key=lambda p: p.scanned_at, reverse=True)[:n]


# ---------------------------------------------------------------------------
# Cluster (strukturelle Ähnlichkeitsgruppen)
# ---------------------------------------------------------------------------

def cluster_profiles(
    profiles: List[YouTubeProfile],
    eps: float = 0.15,
) -> Dict[str, List[YouTubeProfile]]:
    """Einfaches distance-threshold Clustering auf Basis von ai_score + rhythm_delta.

    Kein ML-Stack.  Deterministisch, auditierbar.
    Gibt ein Dict cluster_id -> Liste von Profilen zurück.
    """
    clusters: Dict[str, List[YouTubeProfile]] = {}
    assigned: Dict[str, str] = {}

    def _dist(a: YouTubeProfile, b: YouTubeProfile) -> float:
        return math.sqrt(
            (a.ai_score - b.ai_score) ** 2
            + (a.upload_rhythm_delta - b.upload_rhythm_delta) ** 2
            + (a.entropy / 8.0 - b.entropy / 8.0) ** 2
        )

    cluster_counter = 0
    for profile in profiles:
        if profile.url in assigned:
            continue
        cid = f"c{cluster_counter:04d}"
        cluster_counter += 1
        clusters[cid] = [profile]
        assigned[profile.url] = cid
        profile.cluster_id = cid
        for other in profiles:
            if other.url in assigned:
                continue
            if _dist(profile, other) <= eps:
                clusters[cid].append(other)
                assigned[other.url] = cid
                other.cluster_id = cid
    return clusters


# ---------------------------------------------------------------------------
# Hauptscanner
# ---------------------------------------------------------------------------

class YouTubeScanner:
    """Strukturelle YouTube-Analyse ohne Semantik.

    Verwendet BrowserEngine.inspect_url() und leitet daraus auditierbare
    Entscheidungen ab.  Kein Modell, keine Semantik, keine Weltannahmen.
    """

    def __init__(self, store: Optional[ChannelStore] = None) -> None:
        self._store = store or ChannelStore()

    def scan(self, url: str, timeout: float = 8.0) -> YouTubeProfile:
        """Analysiert ein YouTube-Video oder einen Kanal strukturell.

        Args:
            url:     Beliebige YouTube-URL (Video oder Kanal).
            timeout: HTTP-Timeout in Sekunden.

        Returns:
            YouTubeProfile mit allen gemessenen Metriken.
        """
        from modules.browser_engine import BrowserEngine
        result = BrowserEngine.inspect_url(url, timeout=timeout)

        profile_type = _classify_url_type(url)
        channel_name = str(result.get("metadata", {}).get("channel_name", "") or "")
        if not channel_name:
            # Extrahiere Kanalname aus HTML-Sample falls vorhanden
            html_sample = str(result.get("text_sample", "") or "")
            m = re.search(r'"ownerChannelName"\s*:\s*"([^"]+)"', html_sample)
            channel_name = m.group(1) if m else ""

        title = str(result.get("title", "") or "")
        ai_score = float(result.get("ai_generation_score", 0.0) or 0.0)
        ai_verdict = str(result.get("ai_verdict", "human") or "human")
        ai_signals = list(result.get("ai_signals", []) or [])
        entropy = float(result.get("entropy", 0.0) or 0.0)

        html_text = str(result.get("text_sample", "") or "")
        rhythm = _upload_rhythm_from_html(html_text)
        penalty = _ockham_penalty(len(ai_signals))

        # Ockham-adjustierter Score: höherer Penalty bei überkomplexen Signalmengen
        # hebt Score in Richtung "benötigt manuelle Überprüfung", kein semantischer Eingriff
        adjusted_score = min(1.0, ai_score + penalty * 0.5)

        if adjusted_score >= AI_THRESHOLD_HIGH:
            ai_verdict = "ai"
        elif adjusted_score >= AI_THRESHOLD_MID:
            ai_verdict = "likely_ai"

        profile = YouTubeProfile(
            url=url,
            profile_type=profile_type,
            channel_name=channel_name,
            title=title,
            ai_score=round(adjusted_score, 4),
            ai_verdict=ai_verdict,
            ai_signals=ai_signals,
            entropy=round(entropy, 4),
            upload_rhythm_delta=rhythm,
            ockham_penalty=round(penalty, 4),
            scanned_at=time.time(),
            metadata={
                "risk_score": result.get("risk_score"),
                "backend_summary": result.get("backend_summary", ""),
                "missing_data": result.get("missing_data", []),
            },
        )
        self._store.store(profile)
        return profile

    def scan_channel(self, channel_url: str, timeout: float = 10.0) -> YouTubeProfile:
        """Spezialisierte Kanal-Analyse.  Erzwingt profile_type='channel'."""
        profile = self.scan(channel_url, timeout=timeout)
        profile.profile_type = "channel"
        self._store.store(profile)
        return profile

    def cluster(self, eps: float = 0.15) -> Dict[str, List[YouTubeProfile]]:
        """Cluster alle gespeicherten Profile nach struktureller Ähnlichkeit."""
        return cluster_profiles(self._store.all_profiles(), eps=eps)

    @property
    def store(self) -> ChannelStore:
        return self._store
