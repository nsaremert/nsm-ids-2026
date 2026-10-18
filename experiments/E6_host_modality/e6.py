#!/usr/bin/env python3
"""E6 — technical validity of the host modality (Wazuh).

(a) Per ground-truth attack window: Wazuh alert count, alerts/min, top-5 rules, compared to a
    matched equal-length attack-free (pre-window) interval.
(b) Figure: attack windows + per-minute alert intensity for a few example sessions.
(c) Multi-modal experiment: per-flow host summary in [Timestamp, Timestamp+Flow Duration]
    (count, max rule level, #MITRE tactics); session-based RF network-only / host-only /
    combined macro-F1. Reports unmatched flows and coverage.
"""
import sys, os, glob, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import numpy as np, pandas as pd
import common as C
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

plt = C.setup_mpl()

# ---- align sessions (0..11 chronological) to ground-truth and alert files by TS
gt_files = C.ground_truth_files()   # one GT per session, deduped + chronological (read GT once)
alert_files = sorted(glob.glob(str(C.WAZUH / "alerts_2026*.json")))  # exclude stray alerts.json
# map by TS token in filename
def ts_of(path):
    b = os.path.basename(path)
    return b.replace("ground_truth_", "").replace("alerts_", "").replace(".csv", "").replace(".json", "")
gt_by_ts = {ts_of(f): f for f in gt_files}
al_by_ts = {ts_of(f): f for f in alert_files}
common_ts = sorted(set(gt_by_ts) & set(al_by_ts))        # chronological TS -> session index
assert len(common_ts) == 12, f"beklenen 12 oturum, bulunan {len(common_ts)}"
ts2sess = {ts: i for i, ts in enumerate(common_ts)}


def parse_alerts(path):
    ms, lvl, tactics = [], [], []
    rules = []
    for line in open(path, errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = pd.to_datetime(o.get("timestamp"), utc=True, errors="coerce")
        if pd.isna(t):
            continue
        ms.append(int(t.value // 1_000_000))
        r = o.get("rule", {})
        lvl.append(int(r.get("level", 0)))
        tac = r.get("mitre", {}).get("tactic", []) or []
        tactics.append(frozenset(tac))
        rules.append(r.get("description", ""))
    order = np.argsort(ms, kind="mergesort")
    ms = np.array(ms)[order]
    lvl = np.array(lvl)[order]
    tactics = [tactics[i] for i in order]
    rules = [rules[i] for i in order]
    return ms, lvl, tactics, rules


# ---- (a) attack-window vs matched benign-window alert analysis
rowsA = []
top_rules = {}
for ts in common_ts:
    g = pd.read_csv(gt_by_ts[ts])
    ms, lvl, tactics, rules = parse_alerts(al_by_ts[ts])
    for _, r in g.iterrows():
        lab = r["label"]; s, e = int(r["start_ts"]), int(r["end_ts"])
        L = max(e - s, 1)
        i0, i1 = np.searchsorted(ms, s, "left"), np.searchsorted(ms, e, "right")
        n_att = i1 - i0
        # matched benign window: [s-L, s)
        bi0, bi1 = np.searchsorted(ms, s - L, "left"), np.searchsorted(ms, s, "left")
        n_ben = bi1 - bi0
        rowsA.append({"label": lab, "dur_min": L / 60000.0, "alerts_attack": int(n_att),
                      "alerts_benign_matched": int(n_ben)})
        for d in rules[i0:i1]:
            top_rules.setdefault(lab, {}).setdefault(d, 0)
            top_rules[lab][d] += 1

A = pd.DataFrame(rowsA)
agg = A.groupby("label").agg(windows=("label", "size"), dur_min=("dur_min", "sum"),
                             alerts_attack=("alerts_attack", "sum"),
                             alerts_benign_matched=("alerts_benign_matched", "sum"))
agg["attack_alerts_per_min"] = (agg["alerts_attack"] / agg["dur_min"]).round(1)
agg["benign_alerts_per_min"] = (agg["alerts_benign_matched"] / agg["dur_min"]).round(1)
agg = agg[["windows", "dur_min", "alerts_attack", "alerts_benign_matched",
           "attack_alerts_per_min", "benign_alerts_per_min"]].sort_values("attack_alerts_per_min", ascending=False)
agg["dur_min"] = agg["dur_min"].round(1)
agg.index.name = "Attack"
agg.to_csv(C.RESULTS / "e6_attack_window_alerts.csv")
C.write_table(agg, "e6_attack_window_alerts", floatfmt="%.1f",
              caption="Wazuh host alerts during attack windows vs matched attack-free windows (summed over 12 sessions).")
top5 = {lab: sorted(d.items(), key=lambda x: -x[1])[:5] for lab, d in top_rules.items()}
json.dump(top5, open(C.RESULTS / "e6_top_rules_per_attack.json", "w"), indent=2)

# ---- (b) alert-intensity timeline for example sessions 0, 5, 11
gl_all = sorted(pd.read_csv(gt_by_ts[common_ts[0]])["label"].unique())
gc_all = {l: C.TOL_MUTED[k % len(C.TOL_MUTED)] for k, l in enumerate(gl_all)}
fig, axes = plt.subplots(3, 1, figsize=(7.8, 7.2), sharex=False)
for ax, si in zip(axes, [0, 5, 11]):
    ts = common_ts[si]
    g = pd.read_csv(gt_by_ts[ts]); ms, lvl, tactics, rules = parse_alerts(al_by_ts[ts])
    t0 = g["start_ts"].min()
    mins = (ms - t0) / 60000.0
    bins = np.arange(0, (g["end_ts"].max() - t0) / 60000.0 + 1, 1.0)
    ax.hist(mins, bins=bins, color="#88CCEE", alpha=0.9, label="_alerts/min")
    for _, r in g.iterrows():
        a, b = (r["start_ts"] - t0) / 60000.0, (r["end_ts"] - t0) / 60000.0
        ax.axvspan(a, max(b, a + 0.1), color=gc_all[r["label"]], alpha=0.30)
    ax.set_title(f"Session {si}: Wazuh alerts/min (bars) + attack windows (shaded)")
    ax.set_ylabel("alerts/min")
axes[-1].set_xlabel("minutes from session start")
handles = [plt.Rectangle((0, 0), 1, 1, color=gc_all[l], alpha=0.30) for l in gl_all]
fig.legend(handles, gl_all, loc="lower center", ncol=5, frameon=False, fontsize=7.5,
           bbox_to_anchor=(0.5, -0.02))
fig.tight_layout(rect=[0, 0.05, 1, 1])
C.savefig(fig, "e6_alert_intensity_timeline")

# ---- (c) multi-modal: per-flow host features
# Read full_v1.2 and apply the SAME fragment filter as load_ml() so host features (H),
# built from `full`, stay row-aligned with the network matrix X66.
full = pd.read_csv(C.FULL_V12, usecols=["Timestamp", "session_id", "Flow Duration", "Label", "split_fragment"])
if C.EXCLUDE_FRAGMENTS:
    full = full[full["split_fragment"] == 0].reset_index(drop=True)
tsf = pd.to_datetime(full["Timestamp"], format="%d/%m/%Y %I:%M:%S %p", errors="coerce")
flow_ms = ((tsf - pd.Timestamp("1970-01-01")).dt.total_seconds() * 1000.0).to_numpy()
dur_ms = pd.to_numeric(full["Flow Duration"], errors="coerce").fillna(0).to_numpy() / 1000.0
# per-session alert arrays
sess_alerts = {}
for ts in common_ts:
    sess_alerts[ts2sess[ts]] = parse_alerts(al_by_ts[ts])

h_count = np.zeros(len(full)); h_maxlvl = np.zeros(len(full)); h_ntac = np.zeros(len(full))
sidv = full["session_id"].to_numpy()
for s in range(12):
    ms, lvl, tactics, rules = sess_alerts[s]
    idxs = np.where(sidv == s)[0]
    for i in idxs:
        a, b = flow_ms[i], flow_ms[i] + dur_ms[i]
        i0, i1 = np.searchsorted(ms, a, "left"), np.searchsorted(ms, b, "right")
        if i1 > i0:
            h_count[i] = i1 - i0
            h_maxlvl[i] = lvl[i0:i1].max()
            u = set().union(*tactics[i0:i1]) if i1 - i0 else set()
            h_ntac[i] = len(u)
H = pd.DataFrame({"host_alert_count": h_count, "host_max_level": h_maxlvl, "host_n_tactics": h_ntac})
coverage = float((h_count > 0).mean())
json.dump({"n_flows": int(len(full)), "flows_with_host_alert": int((h_count > 0).sum()),
           "coverage": round(coverage, 4), "flows_without_host_alert": int((h_count == 0).sum())},
          open(C.RESULTS / "e6_coverage.json", "w"), indent=2)

df11, X66, y, sid, feats = C.load_ml_v11()
y = y.values; classes = C.classes_sorted(y)
te = np.isin(sid, C.REF_TEST_SESSIONS); tr = ~te
mm = {}
for tag, cols_df in [("network_only", X66),
                     ("host_only", H),
                     ("combined", pd.concat([X66.reset_index(drop=True), H], axis=1))]:
    Xf = cols_df.reset_index(drop=True)
    rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=0).fit(Xf[tr], y[tr])
    yp = rf.predict(Xf[te])
    mm[tag] = round(float(f1_score(y[te], yp, average="macro")), 4)
    print(f"[E6] {tag:14s} macroF1={mm[tag]:.4f}", flush=True)
mmdf = pd.DataFrame({"macro_F1": mm, "coverage": {"network_only": "-", "host_only": round(coverage,3), "combined": round(coverage,3)}})
mmdf.index.name = "Modality"
mmdf.to_csv(C.RESULTS / "e6_multimodal.csv")
C.write_table(mmdf, "e6_multimodal", floatfmt="%.4f",
              caption=f"Multi-modal RF (session split): macro-F1 by modality. Host coverage {coverage:.1%} of flows have >=1 alert.")

json.dump({"attack_vs_benign_per_min": agg[["attack_alerts_per_min","benign_alerts_per_min"]].to_dict("index"),
           "coverage": coverage, "multimodal_macroF1": mm,
           "outputs": ["e6_attack_window_alerts.{csv,md,tex}", "e6_top_rules_per_attack.json",
                       "e6_alert_intensity_timeline.{pdf,png}", "e6_multimodal.{csv,md,tex}", "e6_coverage.json"]},
          open(C.RESULTS / "e6_meta.json", "w"), indent=2)
print("[E6] DONE  multimodal:", mm, "coverage:", round(coverage, 3))
