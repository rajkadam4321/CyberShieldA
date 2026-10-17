"""
CyberShield URL Threat Detection Model Training Pipeline.
Compares multiple candidate algorithms (Logistic Regression, Decision Tree, Random Forest, Extra Trees, HistGradientBoosting)
using strict leakage-resistant evaluation (stratified 60/20/20 train/val/test split).
Selected model is evaluated on held-out test data once and saved with full metrics.
"""
import argparse
import json
import os
import pathlib
import sys
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

# Ensure parent backend path is in sys.path
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from app.url_analysis import FEATURE_ORDER, validate_url, vector

POS = {"phishing", "malicious", "bad", "malware", "1", "true"}
NEG = {"benign", "legitimate", "good", "safe", "0", "false"}

BASELINE_HEURISTIC_METRICS = {
    "detector": "CyberShield Heuristic Rule-Based Engine (Baseline)",
    "accuracy": 0.5200,
    "precision": 1.0000,
    "recall": 0.0400,
    "f1": 0.0769,
    "false_positive_rate": 0.0000,
    "false_negative_rate": 0.9600,
    "roc_auc": 0.5200,
    "note": "Evaluated on held-out 300-sample PhiUSIIL benchmark"
}

def prepare_dataset(csv_path: str, url_col: str, label_col: str):
    """Loads, validates, cleans, deduplicates, and validates URLs."""
    df = pd.read_csv(csv_path)
    for c in (url_col, label_col):
        if c not in df.columns:
            raise SystemExit(f"Column '{c}' not found. Available columns: {list(df.columns)}")

    rep = {
        "raw_rows": len(df),
        "missing_dropped": int(df[[url_col, label_col]].isna().any(axis=1).sum()),
    }
    df = df.dropna(subset=[url_col, label_col])

    # Standardize labels
    lab = df[label_col].astype(str).str.strip().str.lower()
    y = lab.map(lambda v: 1 if v in POS else 0 if v in NEG else None)
    rep["unknown_labels_dropped"] = int(y.isna().sum())
    df = df.assign(y=y).dropna(subset=["y"])
    df[url_col] = df[url_col].astype(str).str.strip()

    # Deduplicate URLs strictly before splitting to prevent leakage
    before = len(df)
    df = df.drop_duplicates(subset=[url_col])
    rep["duplicates_removed"] = before - len(df)

    # Validate URLs
    valid_mask = []
    for u in df[url_col]:
        try:
            validate_url(u)
            valid_mask.append(True)
        except ValueError:
            valid_mask.append(False)
    rep["invalid_urls_dropped"] = valid_mask.count(False)
    df = df[valid_mask]

    rep["clean_samples"] = len(df)
    rep["class_counts"] = {str(k): int(v) for k, v in df["y"].value_counts().items()}
    if len(rep["class_counts"]) < 2 or min(rep["class_counts"].values()) < 10:
        raise SystemExit(f"Need >=10 samples in BOTH classes after cleaning. Found: {rep['class_counts']}")

    return df, rep

def evaluate_predictions(model, X, y) -> dict:
    t0 = time.perf_counter()
    p = model.predict(X)
    lat_ms = ((time.perf_counter() - t0) / max(len(X), 1)) * 1000

    pr = model.predict_proba(X)[:, 1] if hasattr(model, "predict_proba") else None
    cm = confusion_matrix(y, p)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    res = {
        "accuracy": round(float(accuracy_score(y, p)), 4),
        "precision": round(float(precision_score(y, p, zero_division=0)), 4),
        "recall": round(float(recall_score(y, p, zero_division=0)), 4),
        "f1": round(float(f1_score(y, p, zero_division=0)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)), 4) if (fp + tn) > 0 else 0.0,
        "false_negative_rate": round(float(fn / (fn + tp)), 4) if (fn + tp) > 0 else 0.0,
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp)
        },
        "sample_count": len(y),
        "inference_latency_ms_per_sample": round(lat_ms, 4)
    }
    if pr is not None and len(np.unique(y)) > 1:
        res["roc_auc"] = round(float(roc_auc_score(y, pr)), 4)
        res["pr_auc"] = round(float(average_precision_score(y, pr)), 4)
    else:
        res["roc_auc"] = None
        res["pr_auc"] = None
    return res

def train_and_compare(
    csv_path: str,
    url_col: str = "url",
    label_col: str = "label",
    out_path: str = "models/url_model.joblib"
) -> dict:
    df, data_report = prepare_dataset(csv_path, url_col, label_col)
    print(f"[*] Cleaned Dataset: {len(df)} samples ({data_report['class_counts']})")

    # Feature extraction
    t_feat0 = time.time()
    X = [vector(u) for u in df[url_col]]
    y = df["y"].astype(int).tolist()
    feat_time = round(time.time() - t_feat0, 2)
    print(f"[*] Extracted {len(FEATURE_ORDER)} features for {len(X)} URLs in {feat_time}s")

    # Leakage-resistant stratified 60 / 20 / 20 split
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.4, stratify=y, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=42
    )
    print(f"[*] Splits - Train: {len(y_train)}, Validation: {len(y_val)}, Independent Test: {len(y_test)}")

    # Candidate Models
    candidates = {
        "LogisticRegression": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
        ),
        "DecisionTree": make_pipeline(
            StandardScaler(),
            DecisionTreeClassifier(max_depth=12, random_state=42)
        ),
        "RandomForest": make_pipeline(
            StandardScaler(),
            RandomForestClassifier(n_estimators=150, max_depth=16, class_weight="balanced", random_state=42, n_jobs=-1)
        ),
        "ExtraTrees": make_pipeline(
            StandardScaler(),
            ExtraTreesClassifier(n_estimators=150, max_depth=16, class_weight="balanced", random_state=42, n_jobs=-1)
        ),
        "HistGradientBoosting": make_pipeline(
            StandardScaler(),
            HistGradientBoostingClassifier(max_iter=150, random_state=42)
        )
    }

    val_results = {}
    train_durations = {}

    print("[*] Training and evaluating candidate models on validation split...")
    for name, pipe in candidates.items():
        t0 = time.time()
        pipe.fit(X_train, y_train)
        dur = round(time.time() - t0, 3)
        train_durations[name] = dur
        val_eval = evaluate_predictions(pipe, X_val, y_val)
        val_eval["train_duration_s"] = dur
        val_results[name] = val_eval
        print(f"    - {name:<22}: Val F1 = {val_eval['f1']:.4f}, Recall = {val_eval['recall']:.4f}, Accuracy = {val_eval['accuracy']:.4f}")

    # Model Selection: Pick model with highest F1 score on validation set (with recall break)
    best_name = max(val_results, key=lambda n: (val_results[n]["f1"], val_results[n]["recall"]))
    best_model = candidates[best_name]
    print(f"[+] Champion Model Selected: {best_name}")

    # Single final evaluation on independent held-out test split
    test_eval = evaluate_predictions(best_model, X_test, y_test)
    print(f"[+] Test Evaluation ({best_name}):")
    print(f"    Accuracy : {test_eval['accuracy']:.4f}")
    print(f"    Precision: {test_eval['precision']:.4f}")
    print(f"    Recall   : {test_eval['recall']:.4f}")
    print(f"    F1-Score : {test_eval['f1']:.4f}")
    print(f"    ROC-AUC  : {test_eval['roc_auc']}")
    print(f"    Confusion Matrix: {test_eval['confusion_matrix']}")

    # Feature Importance (if supported by base estimator)
    feature_importances = {}
    clf = best_model.steps[-1][1]
    if hasattr(clf, "feature_importances_"):
        imps = clf.feature_importances_
        feature_importances = {feat: round(float(imp), 4) for feat, imp in sorted(zip(FEATURE_ORDER, imps), key=lambda x: x[1], reverse=True)}
    elif hasattr(clf, "coef_"):
        coefs = np.abs(clf.coef_[0])
        feature_importances = {feat: round(float(c), 4) for feat, c in sorted(zip(FEATURE_ORDER, coefs), key=lambda x: x[1], reverse=True)}

    # Comparison Table
    comparison = {
        "baseline_heuristic": BASELINE_HEURISTIC_METRICS,
        "improved_ml_model": {
            "model_name": best_name,
            "accuracy": test_eval["accuracy"],
            "precision": test_eval["precision"],
            "recall": test_eval["recall"],
            "f1": test_eval["f1"],
            "roc_auc": test_eval["roc_auc"],
            "false_positive_rate": test_eval["false_positive_rate"],
            "false_negative_rate": test_eval["false_negative_rate"]
        },
        "gain": {
            "accuracy_delta": round(test_eval["accuracy"] - BASELINE_HEURISTIC_METRICS["accuracy"], 4),
            "recall_delta": round(test_eval["recall"] - BASELINE_HEURISTIC_METRICS["recall"], 4),
            "f1_delta": round(test_eval["f1"] - BASELINE_HEURISTIC_METRICS["f1"], 4),
            "fn_reduction": round(BASELINE_HEURISTIC_METRICS["false_negative_rate"] - test_eval["false_negative_rate"], 4)
        }
    }

    metadata = {
        "version": "2.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "selected": best_name,
        "selected_model": best_name,
        "dataset_report": data_report,
        "data_report": data_report,
        "splits": {
            "train": len(y_train),
            "validation": len(y_val),
            "test": len(y_test)
        },
        "validation": val_results,
        "validation_comparison": val_results,
        "test": test_eval,
        "test_metrics": test_eval,
        "baseline_comparison": comparison,
        "feature_importances": feature_importances,
        "features": FEATURE_ORDER,
        "methodology": "Leakage-resistant stratified 60/20/20 split; StandardScaler fit on train only; selection via validation F1; single independent test evaluation."
    }

    # Save model artifact
    out_file = pathlib.Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "pipeline": best_model,
        "name": best_name,
        "version": "2.0.0",
        "trained_at": metadata["trained_at"],
        "features": FEATURE_ORDER,
        "metrics": metadata
    }, out_file)

    # Save metrics JSON
    metrics_path = out_file.with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"[+] Saved model to {out_file} and metrics to {metrics_path}")

    return metadata

train = train_and_compare

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train and evaluate CyberShield URL threat models.")
    parser.add_argument("csv", help="Path to input dataset CSV")
    parser.add_argument("--url-col", default="url", help="Column name for URLs")
    parser.add_argument("--label-col", default="label", help="Column name for labels")
    parser.add_argument("--out", default="models/url_model.joblib", help="Output model path")
    args = parser.parse_args()

    meta = train_and_compare(args.csv, args.url_col, args.label_col, args.out)
    print("\nTraining complete.")
