"""Train the URL phishing model from YOUR OWN legally obtained CSV.
Usage: python training/train_model.py data.csv --url-col url --label-col label
Label 1 = phishing/malicious. Accepted labels: phishing, malicious, bad, malware, 1, true | benign, legitimate, good, safe, 0, false.
WARNING: a random split does not prove generalisation to future/unseen attacks. Use time-based or cross-dataset evaluation too."""
import argparse, json, pathlib, sys
import joblib, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from app.url_analysis import FEATURE_ORDER, validate_url, vector

POS = {"phishing", "malicious", "bad", "malware", "1", "true"}
NEG = {"benign", "legitimate", "good", "safe", "0", "false"}

def prepare(csv, ucol, lcol):
    df = pd.read_csv(csv)
    for c in (ucol, lcol):
        if c not in df.columns: raise SystemExit(f"Column '{c}' not found. Columns: {list(df.columns)}")
    rep = {"rows": len(df), "missing": int(df[[ucol, lcol]].isna().any(axis=1).sum())}
    df = df.dropna(subset=[ucol, lcol])
    lab = df[lcol].astype(str).str.strip().str.lower()
    y = lab.map(lambda v: 1 if v in POS else 0 if v in NEG else None)
    rep["unknown_labels"] = int(y.isna().sum())
    df = df.assign(y=y).dropna(subset=["y"]); df[ucol] = df[ucol].astype(str).str.strip()
    before = len(df); df = df.drop_duplicates(subset=[ucol]); rep["duplicates_removed"] = before - len(df)
    ok = []
    for u in df[ucol]:
        try: validate_url(u); ok.append(True)
        except ValueError: ok.append(False)
    rep["invalid_urls_dropped"] = ok.count(False); df = df[ok]
    rep["class_counts"] = {str(k): int(v) for k, v in df["y"].value_counts().items()}
    if len(rep["class_counts"]) < 2 or min(rep["class_counts"].values()) < 10:
        raise SystemExit(f"Need >=10 rows in BOTH classes after cleaning. Got {rep['class_counts']}")
    return df, rep

def metrics(model, X, y):
    p = model.predict(X); pr = model.predict_proba(X)[:, 1]
    return {"accuracy": accuracy_score(y, p), "precision": precision_score(y, p, zero_division=0),
            "recall": recall_score(y, p, zero_division=0), "f1": f1_score(y, p, zero_division=0),
            "roc_auc": roc_auc_score(y, pr), "confusion_matrix": confusion_matrix(y, p).tolist()}

def train(csv, ucol="url", lcol="label", out="models/url_model.joblib"):
    df, rep = prepare(csv, ucol, lcol)
    X = [vector(u) for u in df[ucol]]; y = df["y"].astype(int).tolist()
    Xtr, Xtmp, ytr, ytmp = train_test_split(X, y, test_size=0.4, stratify=y, random_state=42)
    Xva, Xte, yva, yte = train_test_split(Xtmp, ytmp, test_size=0.5, stratify=ytmp, random_state=42)
    cands = {"LogisticRegression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced")),
             "RandomForest": make_pipeline(StandardScaler(), RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42))}
    val = {}
    for n, m in cands.items(): m.fit(Xtr, ytr); val[n] = metrics(m, Xva, yva)
    best = max(val, key=lambda n: val[n]["f1"])          # chosen on VALIDATION only
    test = metrics(cands[best], Xte, yte)                # test set used once, for the final report
    meta = {"selected": best, "data_report": rep, "validation": val, "test": test, "features": FEATURE_ORDER,
            "warning": "Random split only; not proof of generalisation to unseen/future attacks."}
    out = pathlib.Path(out); out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": cands[best], "name": best, "features": FEATURE_ORDER, "metrics": meta}, out)
    out.with_suffix(".metrics.json").write_text(json.dumps(meta, indent=2))
    return meta

if __name__ == "__main__":
    a = argparse.ArgumentParser(); a.add_argument("csv"); a.add_argument("--url-col", default="url")
    a.add_argument("--label-col", default="label"); a.add_argument("--out", default="models/url_model.joblib")
    a = a.parse_args(); print(json.dumps(train(a.csv, a.url_col, a.label_col, a.out), indent=2))
    print("\nWARNING: random split != proof of generalisation. Model saved; restart the backend to use it.")
