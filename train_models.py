#!/usr/bin/env python3
"""Train and evaluate the two detection models.

    python train_models.py

Stage 1  Isolation Forest, trained on normal traffic only: "is this abnormal?"
Stage 2  Random Forest, trained on all labels: "what kind of problem is it?"

Evaluation is honest about time order: samples from one scenario run are
very similar to each other, so a random split would leak. Instead whole
rounds are held out for testing (default: the last 2 of 6), and a
leave-one-round-out cross-validation is reported as a second opinion.

The Isolation Forest is also compared against a simple threshold rule
(loss > 10% or latency > 100 ms), the baseline named in the project plan.

Finally both models are refit on ALL data and saved to models/ for the
decision engine (Week 3).
"""
import argparse
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from config import DATA_DIR, FEATURES, PROJECT_DIR

CLASSES = ["normal", "syn_flood", "port_scan", "link_failure", "congestion"]
RUN_GAP_S = 11      # samples inside one run are ~5 s apart; runs are >15 s apart
SEED = 42


# ---------------------------------------------------------------- data
def load_dataset(path):
    if not os.path.exists(path):
        sys.exit(f"Dataset not found: {path}")
    df = pd.read_csv(path)
    missing = [c for c in ["timestamp", "label"] + FEATURES if c not in df.columns]
    if missing:
        sys.exit(f"{path} is missing columns: {missing}")
    df = df.dropna(subset=FEATURES).reset_index(drop=True)
    unknown = set(df["label"]) - set(CLASSES)
    if unknown:
        sys.exit(f"Unknown labels in {path}: {sorted(unknown)}")
    return df


def assign_rounds(df):
    """Tag each row with the round (0, 1, 2, ...) its scenario run belongs to.

    A new run starts when the label changes or there is a time gap. The n-th
    run of each label is round n, because generate_dataset.py runs every
    scenario once per round.
    """
    ts = pd.to_datetime(df["timestamp"])
    gap = ts.diff().dt.total_seconds() > RUN_GAP_S
    df["run"] = ((df["label"] != df["label"].shift()) | gap).cumsum()
    run_label = df.groupby("run")["label"].first()
    runs_per_label = run_label.groupby(run_label).size()
    if runs_per_label.nunique() == 1:
        df["round"] = df["run"].map(run_label.groupby(run_label).cumcount())
        return df, f"{runs_per_label.iloc[0]} runs per label (clean)"
    # Fallback: split each label's rows into six chronological chunks
    rank = df.groupby("label").cumcount()
    size = df.groupby("label")["label"].transform("size")
    df["round"] = (rank * 6 // size).clip(upper=5)
    return df, ("run boundaries were not clean "
                f"({runs_per_label.to_dict()}); used chronological sixths")


# -------------------------------------------------------------- stage 1
def fit_isolation_forest(X_normal, target_fpr):
    """Fit on normal rows; flag anything scoring below the target_fpr
    quantile of the training scores."""
    model = make_pipeline(StandardScaler(),
                          IsolationForest(n_estimators=200, random_state=SEED))
    model.fit(X_normal)
    scores = model.decision_function(X_normal)
    return model, float(np.quantile(scores, target_fpr))


def threshold_flags(df):
    """Simple rule-based detector used as the comparison baseline."""
    return ((df["loss_pct"] > 10) | (df["latency_ms"] > 100)).to_numpy()


def rate_by_class(labels, flags):
    return {c: float(flags[labels == c].mean())
            for c in CLASSES if (labels == c).any()}


# -------------------------------------------------------------- stage 2
def fit_random_forest(X, y):
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                random_state=SEED)
    return rf.fit(X, y)


def two_stage_predict(iso, threshold, rf, X):
    """Isolation Forest decides if it is abnormal; Random Forest names it.
    If the Random Forest then says 'normal', the result is 'unknown'."""
    flagged = iso.decision_function(X) < threshold
    pred = np.array(["normal"] * len(X), dtype=object)
    if flagged.any():
        named = rf.predict(X[flagged])
        pred[flagged] = np.where(named == "normal", "unknown", named)
    return pred, flagged


# --------------------------------------------------------------- output
def pct(x):
    return f"{100 * x:5.1f}%"


def print_confusion(y_true, y_pred, columns):
    """Rows are the true classes, columns the predicted ones."""
    table = pd.crosstab(pd.Categorical(y_true, categories=CLASSES),
                        pd.Categorical(y_pred, categories=columns),
                        dropna=False)
    table.index.name, table.columns.name = "true \\ predicted", None
    print(table.to_string())


def save_confusion_plot(y_true, y_pred, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("(matplotlib not installed, skipping the confusion-matrix image;"
              " pip install matplotlib to get it)")
        return
    cm = confusion_matrix(y_true, y_pred, labels=CLASSES, normalize="true")
    fig, ax = plt.subplots(figsize=(6.2, 5))
    im = ax.imshow(cm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(CLASSES)), CLASSES, rotation=30, ha="right")
    ax.set_yticks(range(len(CLASSES)), CLASSES)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title("Random Forest on held-out rounds")
    for i in range(len(CLASSES)):
        for j in range(len(CLASSES)):
            ax.text(j, i, f"{cm[i, j]:.2f}", ha="center", va="center",
                    color="white" if cm[i, j] > 0.5 else "black", fontsize=9)
    fig.colorbar(im, ax=ax, fraction=0.046)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    print(f"Saved {path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--data", default=os.path.join(DATA_DIR, "dataset.csv"))
    ap.add_argument("--baseline", default=os.path.join(DATA_DIR, "baseline.csv"),
                    help="extra normal-only data for the Isolation Forest")
    ap.add_argument("--out-dir", default=os.path.join(PROJECT_DIR, "models"))
    ap.add_argument("--test-rounds", type=int, default=2,
                    help="number of final rounds held out for testing")
    ap.add_argument("--fpr", type=float, default=0.02,
                    help="target false-positive rate on training normal data")
    args = ap.parse_args()

    df = load_dataset(args.data)
    df, how = assign_rounds(df)
    n_rounds = int(df["round"].max()) + 1
    if not 1 <= args.test_rounds < n_rounds:
        sys.exit(f"--test-rounds must be between 1 and {n_rounds - 1}")

    extra_normal = pd.DataFrame(columns=FEATURES)
    if os.path.exists(args.baseline):
        b = pd.read_csv(args.baseline)
        extra_normal = b[FEATURES].dropna()

    print(f"Dataset: {len(df)} rows, {n_rounds} rounds ({how})")
    print(df["label"].value_counts().reindex(CLASSES).to_string())
    print(f"Extra normal rows from baseline file: {len(extra_normal)}")

    is_test = df["round"] >= n_rounds - args.test_rounds
    train, test = df[~is_test], df[is_test]
    print(f"\nTrain: rounds 1-{n_rounds - args.test_rounds} ({len(train)} rows)   "
          f"Test: rounds {n_rounds - args.test_rounds + 1}-{n_rounds} ({len(test)} rows)")

    X_train, y_train = train[FEATURES], train["label"].to_numpy()
    X_test, y_test = test[FEATURES], test["label"].to_numpy()
    results = {"rows": len(df), "rounds": n_rounds,
               "train_rows": len(train), "test_rows": len(test)}

    # ---------------------------------------------------- stage 1: anomaly
    normal_fit = pd.concat([train.loc[train["label"] == "normal", FEATURES],
                            extra_normal], ignore_index=True)
    iso, thr = fit_isolation_forest(normal_fit, args.fpr)
    iso_flags = iso.decision_function(X_test) < thr
    iso_rates = rate_by_class(y_test, iso_flags)
    rule_rates = rate_by_class(y_test, threshold_flags(test))
    attack = y_test != "normal"

    print(f"\n=== Stage 1: is it abnormal?  (held-out rounds, {len(normal_fit)} "
          f"normal rows used for training) ===")
    print(f"{'share flagged':<16}{'Isolation Forest':>18}{'Threshold rule':>16}")
    for c in CLASSES:
        if c in iso_rates:
            print(f"{c:<16}{pct(iso_rates[c]):>18}{pct(rule_rates[c]):>16}")
    print(f"{'all attacks':<16}{pct(iso_flags[attack].mean()):>18}"
          f"{pct(threshold_flags(test)[attack].mean()):>16}")
    print("normal row = false-alarm rate (lower is better); attack rows = "
          "detection rate (higher is better).")
    print("Threshold rule = loss > 10% or latency > 100 ms.")
    results["isolation_forest"] = {
        "target_fpr": args.fpr, "by_class": iso_rates,
        "false_positive_rate": iso_rates.get("normal"),
        "attack_detection_rate": float(iso_flags[attack].mean())}
    results["threshold_rule"] = {
        "by_class": rule_rates,
        "false_positive_rate": rule_rates.get("normal"),
        "attack_detection_rate": float(threshold_flags(test)[attack].mean())}

    # --------------------------------------------------- stage 2: classify
    rf = fit_random_forest(X_train, y_train)
    pred = rf.predict(X_test)
    acc = accuracy_score(y_test, pred)
    print(f"\n=== Stage 2: what is it?  Random Forest, held-out rounds ===")
    print(f"Accuracy: {pct(acc)}")
    print(classification_report(y_test, pred, labels=CLASSES, digits=3,
                                zero_division=0))
    print_confusion(y_test, pred, CLASSES)
    results["random_forest"] = {
        "test_accuracy": float(acc),
        "report": classification_report(y_test, pred, labels=CLASSES,
                                        zero_division=0, output_dict=True)}

    # leave-one-round-out cross-validation over all data
    accs = []
    for tr, te in GroupKFold(n_splits=n_rounds).split(df[FEATURES], df["label"],
                                                      df["round"]):
        m = fit_random_forest(df.loc[tr, FEATURES], df.loc[tr, "label"])
        accs.append(accuracy_score(df.loc[te, "label"], m.predict(df.loc[te, FEATURES])))
    print(f"\nLeave-one-round-out CV accuracy: {pct(np.mean(accs))} "
          f"(+/- {100 * np.std(accs):.1f}), per round: "
          + ", ".join(f"{100 * a:.1f}" for a in accs))
    results["random_forest"]["cv_accuracy_mean"] = float(np.mean(accs))
    results["random_forest"]["cv_accuracy_per_round"] = [float(a) for a in accs]

    imp = pd.Series(rf.feature_importances_, index=FEATURES).sort_values(ascending=False)
    print("\nFeature importance:")
    print(imp.round(3).to_string())
    results["random_forest"]["feature_importance"] = imp.round(4).to_dict()

    # --------------------------------------------------- both stages together
    final_pred, _ = two_stage_predict(iso, thr, rf, X_test)
    two_acc = accuracy_score(y_test, final_pred)
    print(f"\n=== Both stages together (Isolation Forest, then Random Forest) ===")
    print(f"Accuracy: {pct(two_acc)}  ('unknown' = flagged as abnormal but the "
          "Random Forest said normal)")
    print_confusion(y_test, final_pred, CLASSES + ["unknown"])
    results["two_stage_accuracy"] = float(two_acc)

    # ------------------------------------------- final models on all the data
    normal_all = pd.concat([df.loc[df["label"] == "normal", FEATURES],
                            extra_normal], ignore_index=True)
    iso_final, thr_final = fit_isolation_forest(normal_all, args.fpr)
    rf_final = fit_random_forest(df[FEATURES], df["label"])
    os.makedirs(args.out_dir, exist_ok=True)
    joblib.dump({"model": iso_final, "threshold": thr_final, "features": FEATURES},
                os.path.join(args.out_dir, "isolation_forest.joblib"))
    joblib.dump({"model": rf_final, "classes": list(rf_final.classes_),
                 "features": FEATURES},
                os.path.join(args.out_dir, "random_forest.joblib"))
    with open(os.path.join(args.out_dir, "metrics.json"), "w") as f:
        json.dump(results, f, indent=1)
    print(f"\nSaved final models (trained on all {len(df)} rows) and metrics.json "
          f"to {args.out_dir}")
    save_confusion_plot(y_test, pred, os.path.join(args.out_dir, "confusion_matrix.png"))


if __name__ == "__main__":
    main()
