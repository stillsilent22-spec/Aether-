"""
Aether Delta-Konvergenz Visualisierung.

Erzeugt zwei Ausgaben:
  1. ASCII-Plot im Terminal (immer verfügbar)
  2. HTML-Plot (browser-öffenbar, kein matplotlib nötig)

Aufruf:
  python tools/convergence_plot.py
  python tools/convergence_plot.py --html-only
  python tools/convergence_plot.py --ascii-only
  python tools/convergence_plot.py --signal "hello world"
  python tools/convergence_plot.py --no-open
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from modules.delta_convergence_tracker import DeltaConvergenceTracker, DeltaMeasurement


# ------------------------------------------------------------------
# ASCII Plot
# ------------------------------------------------------------------

def ascii_plot(measurements: list[DeltaMeasurement], title: str = "Delta-Konvergenz") -> str:
    if not measurements:
        return "Keine Messdaten vorhanden."

    width = 60
    height = 20

    node_counts = [m.node_count for m in measurements]
    x_min = min(node_counts)
    x_max = max(node_counts)

    def to_col(n: int) -> int:
        if x_max == x_min:
            return 0
        log_n   = math.log(max(1, n))
        log_min = math.log(max(1, x_min))
        log_max = math.log(max(1, x_max))
        if log_max == log_min:
            return 0
        return int((log_n - log_min) / (log_max - log_min) * (width - 1))

    def to_row(v: float) -> int:
        # y in [0, 1], row 0 = top (y=1.0), row height-1 = bottom (y=0.0)
        return max(0, min(height - 1, int((1.0 - v) * (height - 1))))

    # Build grid
    grid = [[" "] * width for _ in range(height)]

    # Shannon-Limit dots
    for m in measurements:
        col = to_col(m.node_count)
        row = to_row(m.shannon_limit_estimate)
        if 0 <= row < height and 0 <= col < width:
            grid[row][col] = "·"

    # Delta-Ratio bars (overwrite dots if overlap)
    for m in measurements:
        col = to_col(m.node_count)
        row = to_row(m.delta_ratio)
        if 0 <= row < height and 0 <= col < width:
            grid[row][col] = "█"

    lines: list[str] = []
    lines.append(f"\n  {title}")
    lines.append(f"  {'─' * (width + 8)}")

    for i, row in enumerate(grid):
        y_val = 1.0 - (i / max(height - 1, 1))
        prefix = f"  {y_val:.2f} │" if i % 4 == 0 else f"       │"
        lines.append(prefix + "".join(row))

    lines.append(f"       └{'─' * width}")

    # X-axis labels at log positions
    label_ns = [1, 10, 100, 1000]
    label_line = "        "
    last_pos = 0
    for n in label_ns:
        if x_min <= n <= x_max:
            col = to_col(n)
            s = str(n)
            pad = col - last_pos
            if pad >= 0:
                label_line += " " * pad + s
                last_pos = col + len(s)
    lines.append(label_line)
    lines.append("")
    lines.append("  █ = Delta(N)   · = Shannon-Limit")
    lines.append("  X-Achse: Anzahl Knoten N (log-Skala)")
    lines.append("  Y-Achse: Delta-Ratio  (0.0 = lossless, 1.0 = kein Anker)")
    lines.append("")

    # Summary
    first = measurements[0]
    last  = measurements[-1]
    reduction = (
        (1 - last.delta_ratio / first.delta_ratio) * 100
        if first.delta_ratio > 0 else 0
    )
    converging = last.delta_ratio < first.delta_ratio * 0.5
    lines.append(f"  N=1        → Delta={first.delta_ratio:.4f}")
    lines.append(f"  N={last.node_count:<6d} → Delta={last.delta_ratio:.4f}")
    lines.append(f"  Reduktion:      {reduction:.1f}%")
    lines.append(f"  Shannon-Limit:  ~{last.shannon_limit_estimate:.4f}")
    lines.append(f"  H_lambda:       {last.h_lambda:.4f}")
    lines.append(f"  Konvergenz:     {'✓ JA — Delta < 50% des Starts' if converging else '⟳ LÄUFT'}")
    lines.append("")

    return "\n".join(lines)


# ------------------------------------------------------------------
# HTML Plot
# ------------------------------------------------------------------

def html_plot(
    measurements: list[DeltaMeasurement],
    output_path: str = "data/convergence_plot.html",
) -> str:
    """Renders an interactive-style HTML chart and writes it to output_path."""

    node_counts    = [m.node_count for m in measurements]
    delta_ratios   = [m.delta_ratio for m in measurements]
    shannon_limits = [m.shannon_limit_estimate for m in measurements]
    h_lambdas      = [m.h_lambda for m in measurements]

    first = measurements[0]
    last  = measurements[-1]
    reduction  = (1 - last.delta_ratio / first.delta_ratio) * 100 if first.delta_ratio > 0 else 0
    converging = last.delta_ratio < first.delta_ratio * 0.5

    # SVG geometry
    SVG_W, SVG_H = 800, 360
    PAD_L, PAD_R, PAD_T, PAD_B = 65, 20, 45, 50
    plot_w = SVG_W - PAD_L - PAD_R
    plot_h = SVG_H - PAD_T - PAD_B

    log_max = math.log(max(node_counts))
    log_min = math.log(max(1, min(node_counts)))

    def cx(n: int) -> int:
        if log_max == log_min:
            return PAD_L
        return PAD_L + int((math.log(max(1, n)) - log_min) / (log_max - log_min) * plot_w)

    def cy(v: float) -> int:
        return PAD_T + int((1.0 - max(0.0, min(1.0, v))) * plot_h)

    def polyline(values: list[float], color: str, width: float, dash: str = "") -> str:
        pts = " ".join(f"{cx(node_counts[i])},{cy(values[i])}" for i in range(len(values)))
        dash_attr = f'stroke-dasharray="{dash}"' if dash else ""
        return (
            f'<polyline points="{pts}" fill="none" stroke="{color}" '
            f'stroke-width="{width}" {dash_attr} stroke-linejoin="round"/>'
        )

    # Y-axis grid lines + labels
    y_grid = ""
    for tick in [0.0, 0.25, 0.5, 0.75, 1.0]:
        y = cy(tick)
        y_grid += (
            f'<line x1="{PAD_L}" y1="{y}" x2="{SVG_W - PAD_R}" y2="{y}" '
            f'stroke="#1a1a2e" stroke-width="1"/>'
            f'<text x="{PAD_L - 5}" y="{y + 4}" fill="#444" font-size="11" '
            f'text-anchor="end">{tick:.2f}</text>'
        )

    # X-axis labels
    x_labels = ""
    for n in [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000]:
        if min(node_counts) <= n <= max(node_counts):
            x = cx(n)
            x_labels += (
                f'<line x1="{x}" y1="{PAD_T + plot_h}" x2="{x}" '
                f'y2="{PAD_T + plot_h + 5}" stroke="#333" stroke-width="1"/>'
                f'<text x="{x}" y="{PAD_T + plot_h + 18}" fill="#444" '
                f'font-size="11" text-anchor="middle">{n}</text>'
            )

    # Data-point circles
    dots = "".join(
        f'<circle cx="{cx(m.node_count)}" cy="{cy(m.delta_ratio)}" '
        f'r="4" fill="#00d4ff" stroke="#0a0a0f" stroke-width="1.5"/>'
        for m in measurements
    )

    # Table rows
    table_rows = "".join(
        f"<tr>"
        f"<td>{m.node_count}</td>"
        f"<td>{m.anchor_pool_size}</td>"
        f"<td>{m.delta_ratio:.4f}</td>"
        f"<td>{m.h_lambda:.4f}</td>"
        f"<td>{m.shannon_limit_estimate:.4f}</td>"
        f"<td>{m.anchor_hit_rate:.4f}</td>"
        f"</tr>"
        for m in measurements
    )

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    verdict_cls = "converging" if converging else "not-yet"
    verdict_txt = "✓ KONVERGENZ NACHGEWIESEN" if converging else "⟳ KONVERGENZ LÄUFT"

    html = f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<title>Aether — Delta-Konvergenz Beweis</title>
<style>
body {{
  font-family: 'Courier New', monospace;
  background: #0a0a0f;
  color: #e0e0e0;
  margin: 0;
  padding: 24px;
  max-width: 900px;
}}
h1 {{ color: #00d4ff; font-size: 1.4em; margin-bottom: 4px; }}
.subtitle {{ color: #555; font-size: 0.85em; margin-bottom: 24px; }}
.claim {{
  background: #0d1a2e;
  border-left: 3px solid #00d4ff;
  padding: 12px 16px;
  margin: 16px 0 20px;
  font-size: 0.85em;
  color: #a0c4ff;
  line-height: 1.6;
}}
.verdict {{
  font-size: 1.05em;
  padding: 8px 14px;
  border-radius: 4px;
  display: inline-block;
  margin: 0 0 20px;
}}
.converging {{ background: #0a2a0a; color: #00ff88; border: 1px solid #00ff88; }}
.not-yet {{ background: #2a1a0a; color: #ffaa00; border: 1px solid #ffaa00; }}
.stats {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
  margin: 0 0 22px;
}}
.stat {{
  background: #111;
  border: 1px solid #222;
  padding: 12px;
  border-radius: 4px;
  text-align: center;
}}
.stat-val {{ font-size: 1.5em; color: #00d4ff; }}
.stat-label {{ font-size: 0.72em; color: #555; margin-top: 4px; }}
svg {{ display: block; }}
.legend {{
  font-size: 0.78em;
  color: #555;
  margin: 8px 0 24px;
  display: flex;
  gap: 20px;
  flex-wrap: wrap;
}}
.legend span {{ display: flex; align-items: center; gap: 6px; }}
table {{
  border-collapse: collapse;
  width: 100%;
  font-size: 0.8em;
  margin-top: 8px;
}}
th {{
  background: #111;
  color: #555;
  padding: 6px 10px;
  text-align: right;
  border-bottom: 1px solid #222;
  font-weight: normal;
}}
th:first-child {{ text-align: left; }}
td {{
  padding: 5px 10px;
  text-align: right;
  border-bottom: 1px solid #151515;
  color: #aaa;
}}
td:first-child {{ text-align: left; color: #00d4ff; }}
tr:hover td {{ background: #0d1520; }}
.footer {{
  margin-top: 30px;
  font-size: 0.72em;
  color: #2a2a2a;
  border-top: 1px solid #111;
  padding-top: 10px;
}}
</style>
</head>
<body>
<h1>⬡ Aether — Delta-Konvergenz</h1>
<div class="subtitle">Struktureller Beweis · {now_iso}</div>

<div class="claim">
  <strong>These:</strong> Delta(N) schrumpft logarithmisch mit wachsender Knotenzahl N.<br>
  <strong>Formal:</strong> Delta ∝ 1 / log(N) — Shannon-konform, falsifizierbar, reproduzierbar.<br>
  <strong>Claim:</strong> H_lambda(X, t) → H_min(X) mit wachsendem M_t.
  Konvergenz gegen Shannon-Limit nachweisbar.
</div>

<div class="verdict {verdict_cls}">
  {verdict_txt} &mdash; Delta-Reduktion: {reduction:.1f}%
</div>

<div class="stats">
  <div class="stat">
    <div class="stat-val">{first.delta_ratio:.3f}</div>
    <div class="stat-label">Delta bei N=1</div>
  </div>
  <div class="stat">
    <div class="stat-val">{last.delta_ratio:.3f}</div>
    <div class="stat-label">Delta bei N={last.node_count}</div>
  </div>
  <div class="stat">
    <div class="stat-val">{reduction:.1f}%</div>
    <div class="stat-label">Gesamtreduktion</div>
  </div>
  <div class="stat">
    <div class="stat-val">{last.shannon_limit_estimate:.4f}</div>
    <div class="stat-label">Shannon-Limit</div>
  </div>
</div>

<svg width="{SVG_W}" height="{SVG_H}" viewBox="0 0 {SVG_W} {SVG_H}"
     style="background:#080810; border:1px solid #1a1a2e; border-radius:4px;">
  <!-- Y grid + labels -->
  {y_grid}
  <!-- X grid lines (vertical, faint) -->
  {"".join(
    f'<line x1="{cx(n)}" y1="{PAD_T}" x2="{cx(n)}" y2="{PAD_T + plot_h}" stroke="#111" stroke-width="1"/>'
    for n in [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000]
    if min(node_counts) <= n <= max(node_counts)
  )}
  <!-- X-axis ticks + labels -->
  {x_labels}
  <!-- Axes -->
  <line x1="{PAD_L}" y1="{PAD_T}" x2="{PAD_L}" y2="{PAD_T + plot_h}"
        stroke="#333" stroke-width="1"/>
  <line x1="{PAD_L}" y1="{PAD_T + plot_h}" x2="{SVG_W - PAD_R}" y2="{PAD_T + plot_h}"
        stroke="#333" stroke-width="1"/>
  <!-- H-Lambda -->
  {polyline(h_lambdas, "#aa00ff", 1.5, "3,4")}
  <!-- Shannon-Limit -->
  {polyline(shannon_limits, "#ff6600", 1.5, "5,4")}
  <!-- Delta-Ratio (main) -->
  {polyline(delta_ratios, "#00d4ff", 2.5)}
  <!-- Data-point circles -->
  {dots}
  <!-- Axis labels -->
  <text x="{PAD_L + plot_w // 2}" y="{SVG_H - 6}"
        fill="#444" font-size="11" text-anchor="middle">
    Anzahl Knoten N (log-Skala)
  </text>
  <text x="13" y="{PAD_T + plot_h // 2}"
        fill="#444" font-size="11" text-anchor="middle"
        transform="rotate(-90, 13, {PAD_T + plot_h // 2})">
    Delta-Ratio
  </text>
  <!-- Chart title -->
  <text x="{PAD_L + 6}" y="{PAD_T - 10}"
        fill="#555" font-size="11">Delta(N) — Konvergenz-Plot</text>
</svg>

<div class="legend">
  <span>
    <svg width="24" height="4"><line x1="0" y1="2" x2="24" y2="2"
      stroke="#00d4ff" stroke-width="2.5"/></svg>
    Delta(N) — Kernkurve
  </span>
  <span>
    <svg width="24" height="4"><line x1="0" y1="2" x2="24" y2="2"
      stroke="#ff6600" stroke-width="1.5" stroke-dasharray="5,4"/></svg>
    Shannon-Limit
  </span>
  <span>
    <svg width="24" height="4"><line x1="0" y1="2" x2="24" y2="2"
      stroke="#aa00ff" stroke-width="1.5" stroke-dasharray="3,4"/></svg>
    H_lambda (Restunsicherheit)
  </span>
</div>

<h2 style="color:#555; font-size:0.9em; margin-bottom:8px;">Messdaten</h2>
<table>
  <thead>
    <tr>
      <th>N (Knoten)</th>
      <th>Anker-Pool</th>
      <th>Delta-Ratio</th>
      <th>H_lambda</th>
      <th>Shannon-Limit</th>
      <th>Hit-Rate</th>
    </tr>
  </thead>
  <tbody>
    {table_rows}
  </tbody>
</table>

<div class="footer">
  Aether Delta-Konvergenz-Tracker &mdash; generiert {now_iso}<br>
  Kein externer Dienst. Alle Messungen lokal. Nur stdlib + math.
</div>
</body>
</html>"""

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return str(out.resolve())


# ------------------------------------------------------------------
# Proof JSON summary
# ------------------------------------------------------------------

def print_proof_summary(verdict: str, summaries: list[dict]) -> None:
    verdict_color = "\033[92m" if verdict == "CONVERGING" else "\033[93m"
    reset = "\033[0m"
    print(f"\n  Beweis-Verdict: {verdict_color}{verdict}{reset}")
    for s in summaries:
        if s.get("status") in ("no_data", "no_series"):
            continue
        arrow = "✓" if s.get("converging") else "⟳"
        print(
            f"  {arrow} [{s['series_id']}]  "
            f"Delta {s['delta_start']:.3f} → {s['delta_current']:.3f}  "
            f"({s['delta_reduction_pct']:.1f}% Reduktion)  "
            f"slope={s['slope']:.5f}"
        )
    print()


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Aether Delta-Konvergenz — Visualisierung & Beweis"
    )
    parser.add_argument(
        "--signal",
        default="",
        help="Testsignal (Text). Standard: Aether-Whitepaper-Zusammenfassung.",
    )
    parser.add_argument(
        "--ascii-only",
        action="store_true",
        help="Nur ASCII-Plot ausgeben (kein HTML).",
    )
    parser.add_argument(
        "--html-only",
        action="store_true",
        help="Nur HTML generieren (kein ASCII-Plot).",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="HTML nicht automatisch im Browser öffnen.",
    )
    parser.add_argument(
        "--output",
        default="data/convergence_plot.html",
        help="Ausgabepfad für HTML-Plot (Standard: data/convergence_plot.html).",
    )
    parser.add_argument(
        "--vault",
        default="data/aelab_vault",
        help="Pfad zum Anker-Vault (Standard: data/aelab_vault).",
    )
    args = parser.parse_args()

    # Signal vorbereiten
    if args.signal:
        signal_bytes = args.signal.encode("utf-8")
    else:
        # Eingebautes Demo-Signal: Aether-Kernthesen
        signal_bytes = (
            "H_lambda(X,t) → H_min(X) mit wachsendem M_t. "
            "Delta schrumpft logarithmisch. "
            "Konvergenz gegen Shannon-Limit beweisbar. "
            "π φ √2 e — mathematische Anker für strukturelle Redundanz. "
            "Aether ist ein privacy-first Framework für dezentrale Signalanalyse."
        ).encode("utf-8")

    tracker = DeltaConvergenceTracker(vault_path=args.vault)

    print("\n⬡ Aether — Delta-Konvergenz-Tracker")
    print("  Messe Delta(N) für N ∈ {1, 2, 5, 10, 25, 50, 100, 250, 500, 1000} …", flush=True)

    measurements = tracker.measure_node_scaling(signal_bytes)

    # Einzel-Messung für "default"-Serie
    tracker.measure(signal_bytes, series_id="default", node_count=1)

    # Proof-JSON exportieren
    verdict = tracker.export_proof()
    summaries = tracker.get_all_summaries()

    # ASCII
    if not args.html_only:
        print(ascii_plot(measurements, title="Delta(N) — Konvergenz-Plot"))
        print_proof_summary(verdict, summaries)

    # HTML
    if not args.ascii_only:
        html_path = html_plot(measurements, output_path=args.output)
        print(f"  HTML-Plot: {html_path}")
        if not args.no_open:
            try:
                webbrowser.open(f"file:///{html_path.replace(os.sep, '/')}")
                print("  Browser geöffnet.")
            except Exception:
                print("  (Browser konnte nicht automatisch geöffnet werden.)")

    print(f"  Proof-JSON: data/convergence_proof.json")
    print()


if __name__ == "__main__":
    main()
