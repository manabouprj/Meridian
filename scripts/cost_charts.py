"""Charts for the executive review, from docs/cost/cost_model.json (run scripts/cost_model.py first)."""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

D = Path(__file__).resolve().parent.parent / "docs" / "cost"
r = json.loads((D / "cost_model.json").read_text())
INK, INK2, GRID, SURF = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
S1, S2, S3 = "#2a78d6", "#eb6834", "#1baf7a"                 # validated categorical slots 1-3 (light)
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.edgecolor": GRID, "axes.labelcolor": INK2,
                     "xtick.color": INK2, "ytick.color": INK2, "figure.facecolor": SURF, "axes.facecolor": SURF})


def money(v):
    return f"${v/1000:,.1f}k" if v < 100_000 else f"${v/1000:,.0f}k"


# 1. monthly run cost per tier: small multiples (each tier its own scale), 3 bars each
fig, axes = plt.subplots(1, 3, figsize=(10, 3.6))
for ax, tier in zip(axes, ("Small", "Medium", "Large"), strict=True):
    t = r["tiers"][tier]
    vals = [sum(t["sentinel"].values()), sum(t["azure"].values()), sum(t["aws"].values())]
    bars = ax.bar([0, 1, 2], vals, color=[S1, S2, S3], width=0.62, edgecolor=SURF, linewidth=2)
    for b, v in zip(bars, vals, strict=True):
        ax.text(b.get_x() + b.get_width() / 2, v * 1.02, money(v), ha="center", va="bottom", color=INK, fontsize=9)
    ax.set_xticks([0, 1, 2], ["Sentinel\n(today)", "MERIDIAN\nAzure", "MERIDIAN\nAWS"], fontsize=8.5)
    ax.set_title(f"{tier} - {t['gb_day']:,} GB/day", color=INK, fontsize=10.5, loc="left")
    ax.set_ylim(0, max(vals) * 1.18)
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"${v/1000:g}k"))
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
fig.suptitle("Monthly platform cost (cloud + models; excludes people)", x=0.01, ha="left", color=INK, fontsize=12)
fig.tight_layout()
fig.savefig(D / "chart-monthly-cost.png", dpi=200)

# 2. 3-year saving of full replacement vs status quo, by daily volume (hard dollars)
fig, ax = plt.subplots(figsize=(10, 4.2))
for cloud, col in (("Azure", S2), ("AWS", S3)):
    be = r["breakeven"][cloud]
    xs = [b["gb"] for b in be]
    ys = [b["full_saving"] / 1e6 for b in be]
    ax.plot(xs, ys, color=col, linewidth=2, marker="o", markersize=5, markeredgecolor=SURF, markeredgewidth=1.5)
    ax.text(xs[-1] + 25, ys[-1] + (0.09 if cloud == "AWS" else -0.09), f"MERIDIAN on {cloud}", color=INK, va="center",
            fontsize=9)
    for i in range(1, len(xs)):                               # mark the break-even crossing
        if ys[i - 1] < 0 <= ys[i]:
            x0 = xs[i - 1] + (xs[i] - xs[i - 1]) * (-ys[i - 1]) / (ys[i] - ys[i - 1])
            ax.annotate(f"{cloud} break-even ~{round(x0, -1):,.0f} GB/day", (x0, 0),
                        xytext=(40, 1.2 if cloud == "AWS" else 0.85), color=INK, fontsize=9,
                        arrowprops={"arrowstyle": "-", "color": INK2, "lw": 0.8})
ax.axhline(0, color=INK2, linewidth=1)
ax.set_xlabel("Daily telemetry volume (GB/day)")
ax.set_ylabel("3-year saving vs Sentinel ($M)")
ax.set_xlim(0, 1750)
ax.grid(color=GRID, linewidth=0.8)
ax.set_axisbelow(True)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
ax.set_title("Full replacement: 3-year saving incl. build, parallel run and engineering team (hard dollars only)",
             loc="left", color=INK, fontsize=11)
fig.tight_layout()
fig.savefig(D / "chart-breakeven.png", dpi=200)
print("charts written")
