"""Draws the system architecture figure (figures/fig_architecture.png)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

fig, ax = plt.subplots(figsize=(10, 5.4))
ax.set_xlim(0, 100); ax.set_ylim(0, 59); ax.axis("off")
plt.rcParams["font.family"] = "DejaVu Sans"


def box(x, y, w, h, text, fc="#ffffff", ec="#333333", fs=8.5, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3,rounding_size=0.8", fc=fc, ec=ec, lw=1))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, weight="bold" if bold else "normal", wrap=True)


def arrow(x1, y1, x2, y2, text=None, dx=0, dy=1.2, style="-|>", color="#333333", ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=10, color=color, lw=1, linestyle=ls))
    if text:
        ax.text((x1 + x2) / 2 + dx, (y1 + y2) / 2 + dy, text, ha="center", va="bottom", fontsize=7.5, color=color)


def poly(pts, color="#333333", ls="-", text=None, tpos=None):
    for (x1, y1), (x2, y2) in zip(pts[:-2], pts[1:-1]):
        ax.plot([x1, x2], [y1, y2], color=color, lw=1, ls=ls)
    arrow(*pts[-2], *pts[-1], color=color, ls=ls)
    if text:
        ax.text(*tpos, text, fontsize=7.5, color=color, ha="center", va="bottom")


S = 3  # vertical offset of the site panel
ax.add_patch(FancyBboxPatch((1, 30 + S), 98, 24, boxstyle="round,pad=0.3,rounding_size=1", fc="#f4f7fb", ec="#7a8ca5", lw=1, ls="--"))
ax.text(2.5, 52.5 + S, "IDS site i (one of N); raw traffic never leaves the site", fontsize=8.5, color="#4a5a70", va="center")
box(3, 38 + S, 12, 8, "Network flows\n(CICFlowMeter\nfeatures)", fs=7.5)
box(19, 38 + S, 18, 8, "Phase 1: signature match\nkey = protocol, port and\nlog2 bins of 5 counters", fc="#e8f1fb", fs=7.5)
box(42, 38 + S, 21, 8, "Phase 2: ensemble of MLP,\nXGBoost and Random Forest\n(majority vote) on\nGA-selected features", fc="#e8f1fb", fs=7.5)
box(70, 43 + S, 12, 4.5, "Alert", fc="#fdecea", fs=7.5)
box(70, 36.5 + S, 12, 4.5, "Flow passed", fc="#eaf6ea", fs=7.5)
box(41, 31 + S, 23, 4.5, "Signature extraction\n(support of at least 20; self-check)", fc="#fff6e0", fs=7.5)
box(19, 31 + S, 18, 4.5, "Local signature database", fc="#e8f1fb", fs=7.5)
arrow(15, 42 + S, 19, 42 + S)
arrow(37, 42 + S, 42, 42 + S)
ax.text(39.5, 42.4 + S, "no match", fontsize=6.3, ha="center", va="bottom")
poly([(28, 46.3 + S), (28, 50 + S), (76, 50 + S), (76, 47.8 + S)], text="match", tpos=(52, 50.2 + S))
arrow(63, 45.2 + S, 70, 45.2 + S, "attack", dy=0.4)
arrow(63, 38.8 + S, 70, 38.8 + S, "benign", dy=0.4)
arrow(52.5, 38 + S, 52.5, 35.8 + S)
arrow(28, 35.8 + S, 28, 38 + S)

# Ledger
ax.add_patch(FancyBboxPatch((1, 1), 98, 24, boxstyle="round,pad=0.3,rounding_size=1", fc="#fbf8f2", ec="#a58f6a", lw=1, ls="--"))
ax.text(14, 23, "Permissioned signature ledger: n validators (one per site), tolerating f = floor((n - 1) / 3) Byzantine",
        fontsize=8.5, color="#6a5a3a", va="center")
box(3, 10, 15, 9, "1. SUBMIT\nECDSA-signed\nsignature\ntransactions", fc="#fff6e0", fs=7.5)
box(22, 10, 19, 9, "2-3. ENDORSE\neach validator checks\nsignature, membership,\nsupport and benign\nmatch (at most 0.05 %)", fc="#fff6e0", fs=7.5)
box(45, 10, 15, 9, "Keep transactions\nwith at least 2f + 1\nsigned endorsements", fc="#fff6e0", fs=7.5)
box(64, 10, 15, 9, "4-5. PBFT\npre-prepare, prepare\nand commit; endorse-\nments re-checked", fc="#fff6e0", fs=7.5)
box(83, 10, 14, 9, "6. Append block\n(Merkle root,\nprevious hash)", fc="#fff6e0", fs=7.5)
for x1, x2 in ((18, 22), (41, 45), (60, 64), (79, 83)):
    arrow(x1, 14.5, x2, 14.5)
box(21, 2.5, 21, 4.5, "Benign reference of validator j\n(key counts only)", fc="#ffffff", fs=7)
arrow(31.5, 7.3, 31.5, 10)
poly([(52.5, 30.7 + S), (52.5, 28.6), (10.5, 28.6), (10.5, 19.3)], color="#8a6d1f", text="new signatures", tpos=(20, 28.8))
poly([(90, 19.3), (90, 29.8), (33, 29.8), (33, 30.7 + S)], color="#1f5a8a", ls="--",
     text="committed signatures update every site", tpos=(70, 30.0))
fig.savefig("figures/fig_architecture.png", dpi=300, bbox_inches="tight")
print("saved")
