"""
swarm_loop_bridge.py — Brücke zwischen Render-Cascade-Ergebnissen und Swarm-Gossip.

Wird von render_coordinator.py aufgerufen wenn ein Frame-Cascade abgeschlossen ist.
Leitet das Ergebnis an den Swarm weiter (via AethernetTransport oder direkt via swarm_p2p).

Privacy:
  - Nur strukturelle Metriken + Fingerprints werden weitergeleitet
  - Keine Pixel-Rohdaten, keine Inhalte
  - Weiterleitung nur wenn Cascade erfolgreich und nicht leer

Design:
  - Fail-silent: Fehler beim Submit werden geloggt aber nie propagiert
  - Kein Return-Wert: Fire-and-forget für den Render-Thread
"""
from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


def submit_cascade_result(
    cascade_result: Dict[str, Any],
    role: str = "observer",
) -> None:
    """Sendet ein Cascade-Ergebnis in die Swarm-Gossip-Pipeline.

    Args:
        cascade_result: Ausgabe von unified_cascade.cascade() —
                        enthält fingerprints, metrics, entropy etc.
        role: "genesis" | "observer" — Genesis-Knoten können Auto-Push auslösen.

    Seiteneffekte:
      - Speichert Fingerprints in AutoPropagator wenn fitness hoch genug
      - Registriert Blindspot-Gap wenn Cascade fehlgeschlagen
      - Meldet an offline_learning für Vorhersage-Training
    """
    if not cascade_result or not isinstance(cascade_result, dict):
        return

    fingerprints = list(cascade_result.get("fingerprints", []))
    if not fingerprints:
        return  # Kein Ergebnis — nichts zu teilen

    # ── OfflineLearner: Vorhersage-Training ──────────────────────────────── #
    try:
        from modules.offline_learning import OfflineLearner
        OfflineLearner.instance().on_task_result(
            fingerprints,
            task_type="render_cascade",
        )
    except Exception as exc:
        logger.debug(f"[swarm_loop_bridge] offline_learning: {exc}")

    # ── AlgoToken: Fitness abrufen + ggf. teilen ─────────────────────────── #
    fitness = float(cascade_result.get("fitness_score", 0.0))
    tree_sig = str(cascade_result.get("tree_signature", ""))
    domain = str(cascade_result.get("domain_hint", "generic"))

    if fitness > 0.0 and tree_sig:
        try:
            from modules.algo_share import AutoPropagator
            # source_node_id aus node.json lesen — ohne ihn werden keine Tokens erzeugt
            _source_node_id = str(cascade_result.get("source_node_id", "") or "").strip()
            if not _source_node_id:
                try:
                    import json as _json
                    from pathlib import Path as _Path
                    _njson = _Path(__file__).resolve().parents[1] / "data" / "swarm" / "node.json"
                    if _njson.is_file():
                        _source_node_id = str(
                            _json.loads(_njson.read_text(encoding="utf-8")).get("node_id", "") or ""
                        ).strip()
                except Exception:
                    pass
            AutoPropagator.instance().emit_if_improved({
                "hit_ratio":         float(cascade_result.get("hit_ratio", fitness)),
                "fitness_score":     fitness,
                "tree_signature":    tree_sig,
                "invariant_profile": list(cascade_result.get("invariant_profile", [])),
                "domain_hint":       domain,
                "node_count":        int(cascade_result.get("node_count", 0)),
                "depth":             int(cascade_result.get("depth", 0)),
                "source_node_id":    _source_node_id,
            })
        except Exception as exc:
            logger.debug(f"[swarm_loop_bridge] algo_share: {exc}")

    # ── BlindspotEngine: Fehler als Gap registrieren ─────────────────────── #
    error = cascade_result.get("error")
    if error:
        try:
            from modules.blindspot_engine import BlindspotEngine, GAP_KNOWLEDGE_GAP
            BlindspotEngine.instance().register_gap(
                domain=domain,
                gap_type=GAP_KNOWLEDGE_GAP,
                description=f"Cascade fehlgeschlagen: {str(error)[:120]}",
                priority=6,
            )
        except Exception as exc:
            logger.debug(f"[swarm_loop_bridge] blindspot_engine: {exc}")

    # ── AethernetTransport: Fingerprints als Anchor-Pack weiterleiten ─────── #
    try:
        from modules.aethernet_transport import AethernetTransport
        transport = AethernetTransport.instance()
        transport.schedule_fingerprint_gossip(fingerprints, domain_hint=domain)
    except Exception as exc:
        logger.debug(f"[swarm_loop_bridge] aethernet_transport: {exc}")
