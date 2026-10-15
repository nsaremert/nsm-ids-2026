# Technical-validation experiments — NSM-IDS-2026 (Sensors Data Descriptor)

Reproducible experiments backing the **Technical Validation** and **Usage Notes** of the
NSM-IDS-2026 Data Descriptor. Deterministic (fixed seeds `[0,1,2]`, reference test sessions
`[3,7,11]`, 4-fold session CV `[[0,1,2],[3,4,5],[6,7,8],[9,10,11]]`; see `results/seeds.json`).
**No dataset file is modified.** Figures are PDF + 300-dpi PNG (colourblind-safe palette).

```
bash run_all.sh          # runs E1-E6 (E7 skipped unless CICIDS2017 CSVs present)
```

Scripts live in `E*/`; outputs go to `results/` (CSV/JSON), `figures/` (PDF+PNG), `tables/` (MD+TeX).
Shared infrastructure (data loading, folds, models, plotting, table writers): `common.py`.

| Exp | What | Key outputs | Paper section |
|-----|------|-------------|---------------|
| **E1** | Dataset description: class distribution, per-session summary, attack timeline | `e1_class_distribution*`, `e1_session_summary*`, `e1_attack_timeline` | Data Description |
| **E2** | Cross-session CV (4 folds x 3 seeds), RF/XGB/LogReg/MLP, 66 & 62 features; confusion matrix | `e2_cv_summary`, `e2_per_class_f1`, `e2_confusion_matrix_ref`, `e2_cv_raw.jsonl` | Technical Validation |
| **E3** | Evaluation-protocol effect: random vs random-dedup vs session | `e3_protocol_macroF1` | Technical Validation / Usage Notes |
| **E4** | v1.0->v1.1 fix validation: single-feature leakage, Idle corruption by class, v1.0 vs v1.1 | `e4_single_feature_corrupted`, `e4_idle_leak_by_class`, `e4_v10_vs_v11_rf` | Technical Validation |
| **E5** | Feature analysis: permutation importance, lab-topology distributions, 66-vs-62 ablation | `e5_permutation_top20`, `e5_labtopo_boxplots`, `e5_labtopo_single_feature`, `e5_ablation_66_vs_62` | Technical Validation / Usage Notes |
| **E6** | Host modality (Wazuh): per-window alerts, intensity timeline, multi-modal net/host/combined | `e6_attack_window_alerts`, `e6_alert_intensity_timeline`, `e6_multimodal`, `e6_coverage.json` | Technical Validation / Usage Notes |
| **E7** | *(optional, skipped)* CICIDS2017 compatibility + transfer | see `E7_cicids_compat/README.md` | Usage Notes |

Models: RandomForest/XGBoost (200 trees), LogisticRegression & MLP (scaled). Metrics: macro-F1,
accuracy, binary false-alarm rate (BENIGN vs attack), per-class F1.
