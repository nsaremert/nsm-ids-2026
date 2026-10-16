#!/usr/bin/env python3
"""E1 — dataset description: class distribution, per-session summary, attack timeline."""
import sys, os, glob, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import numpy as np, pandas as pd
import common as C

C.save_seeds()
plt = C.setup_mpl()
df, X, y, sid, feats = C.load_ml(exclude_fragments=False)   # describe the full released dataset
full = pd.read_csv(C.FULL_V12, usecols=["Timestamp", "session_id", "Label", "split_fragment", "parent_label"])
ts = pd.to_datetime(full["Timestamp"], format="%d/%m/%Y %I:%M:%S %p", errors="coerce")
full["epoch"] = (ts - pd.Timestamp("1970-01-01")).dt.total_seconds()
classes = C.classes_sorted(y)
colors = C.class_colors(classes)

# ---------------------------------------------------------------- overall distribution
vc = y.value_counts().reindex(classes)
dist = pd.DataFrame({"flows": vc.astype(int), "percent": (100 * vc / len(y)).round(2)})
dist.index.name = "Label"
dist.to_csv(C.RESULTS / "e1_class_distribution.csv")
C.write_table(dist, "e1_class_distribution", floatfmt="%.2f",
              caption="NSM-IDS-2026 class distribution (177,749 flows).")

fig, ax = plt.subplots(figsize=(6.4, 3.2))
ax.bar(range(len(classes)), vc.values, color=[colors[c] for c in classes])
ax.set_xticks(range(len(classes))); ax.set_xticklabels(classes, rotation=45, ha="right")
ax.set_ylabel("Flows"); ax.set_title("Class distribution")
for i, v in enumerate(vc.values):
    ax.text(i, v, f"{v:,}", ha="center", va="bottom", fontsize=7)
C.savefig(fig, "e1_class_distribution_overall")

# ---------------------------------------------------------------- split-fragment summary
frag = full["split_fragment"] == 1
fr = pd.DataFrame({
    "flows": [int(len(full)), int(frag.sum()), int((~frag).sum())],
    "percent": [100.0, round(100 * frag.mean(), 2), round(100 * (~frag).mean(), 2)],
}, index=["all flows", "split_fragment=1", "split_fragment=0 (kept in main)"])
fr.index.name = "subset"
fr.to_csv(C.RESULTS / "e1_split_fragment_summary.csv")
C.write_table(fr, "e1_split_fragment_summary", floatfmt="%.2f",
              caption="Split-fragment flag (reverse-direction CICFlowMeter continuations, tol=2 s). "
                      "Main experiments exclude split_fragment=1.")
# parent_label distribution of fragments (what the forward half was)
pl = full.loc[frag, "parent_label"].value_counts()
pl_df = pd.DataFrame({"fragments": pl.astype(int),
                      "percent": (100 * pl / frag.sum()).round(2)})
pl_df.index.name = "parent_label"
pl_df.to_csv(C.RESULTS / "e1_fragment_parent_label.csv")
C.write_table(pl_df, "e1_fragment_parent_label", floatfmt="%.2f",
              caption="Forward-half (parent) label of the split-fragment flows.")
frag_attack_parent = int((full.loc[frag, "parent_label"].astype(str) != "BENIGN").sum())

# ---------------------------------------------------------------- per-session summary
rows = []
for s in range(12):
    sub = full[full.session_id == s]
    comp = sub["Label"].value_counts().reindex(classes).fillna(0).astype(int)
    rows.append({"session_id": s, "n_flows": len(sub),
                 "start_utc": pd.Timestamp(sub.epoch.min(), unit="s").strftime("%H:%M:%S"),
                 "end_utc": pd.Timestamp(sub.epoch.max(), unit="s").strftime("%H:%M:%S"),
                 "duration_min": round((sub.epoch.max() - sub.epoch.min()) / 60.0, 1),
                 **{c: int(comp[c]) for c in classes}})
sess = pd.DataFrame(rows).set_index("session_id")
sess.to_csv(C.RESULTS / "e1_session_summary.csv")
# compact table for the paper (counts of all classes would be wide; keep n_flows+dur+a few)
compact = sess[["n_flows", "start_utc", "end_utc", "duration_min"]].copy()
C.write_table(compact, "e1_session_summary", floatfmt="%.1f",
              caption="Per-session flow count and capture span (UTC).")

# ---------------------------------------------------------------- per-session stacked bar
fig, ax = plt.subplots(figsize=(7.2, 3.6))
bottom = np.zeros(12)
for c in classes:
    vals = sess[c].values
    ax.bar(range(12), vals, bottom=bottom, label=c, color=colors[c], width=0.8)
    bottom += vals
ax.set_xticks(range(12)); ax.set_xlabel("session_id"); ax.set_ylabel("Flows")
ax.set_title("Per-session class composition")
ax.legend(ncol=2, bbox_to_anchor=(1.01, 1.0), loc="upper left", frameon=False)
C.savefig(fig, "e1_class_distribution_per_session")

# ---------------------------------------------------------------- attack timeline (Gantt)
gt_files = sorted(glob.glob(str(C.GROUND_TRUTH / "ground_truth_*.csv")))
gts = []
for f in gt_files:
    g = pd.read_csv(f)
    gts.append((g["start_ts"].min(), f, g))
gts.sort(key=lambda t: t[0])                      # chronological -> session index
gt_labels = sorted({lab for _, _, g in gts for lab in g["label"].unique()})
gcolors = {lab: C.TOL_MUTED[i % len(C.TOL_MUTED)] for i, lab in enumerate(gt_labels)}

fig, ax = plt.subplots(figsize=(7.6, 4.2))
for si, (_, f, g) in enumerate(gts):
    t0 = g["start_ts"].min()
    for _, r in g.iterrows():
        start_min = (r["start_ts"] - t0) / 60000.0
        dur_min = max((r["end_ts"] - r["start_ts"]) / 60000.0, 0.15)  # min width for visibility
        ax.barh(si, dur_min, left=start_min, height=0.6,
                color=gcolors[r["label"]], edgecolor="black", linewidth=0.3)
ax.set_yticks(range(len(gts))); ax.set_yticklabels([f"S{i}" for i in range(len(gts))])
ax.set_xlabel("Minutes from session start"); ax.set_ylabel("session")
ax.set_title("Attack timeline across 12 sessions (from ground truth)")
ax.invert_yaxis()
handles = [plt.Rectangle((0, 0), 1, 1, color=gcolors[l]) for l in gt_labels]
ax.legend(handles, gt_labels, ncol=2, bbox_to_anchor=(1.01, 1.0), loc="upper left", frameon=False)
C.savefig(fig, "e1_attack_timeline")

print(json.dumps({
    "total_flows": int(len(y)), "classes": len(classes),
    "split_fragments": int(frag.sum()),
    "split_fragments_pct": round(100 * frag.mean(), 2),
    "split_fragments_attack_parent": frag_attack_parent,
    "kept_in_main_experiments": int((~frag).sum()),
    "sessions": 12, "gt_labels": gt_labels,
    "note": "DoS Hulk appears in ground truth (scheduled) but produced ~0 flows (HULK not installed)."
        if "DoS Hulk" in gt_labels else "",
    "outputs": ["e1_class_distribution.csv", "e1_session_summary.csv",
                "e1_class_distribution_overall.{pdf,png}",
                "e1_class_distribution_per_session.{pdf,png}", "e1_attack_timeline.{pdf,png}"],
}, indent=2))
