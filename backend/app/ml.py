"""
Machine Learning Model Loader and Inference Service.
Loads versioned model pipeline, calculates prediction probabilities, and records inference latency.
Provides clean fallback to heuristic mode if model artifact is unavailable.
"""
import json
import logging
import os
import pathlib
import time
from typing import Any, Dict, Optional

import joblib
from .url_analysis import FEATURE_ORDER, vector

logger = logging.getLogger("cybershield.ml")
_cache: Dict[str, Any] = {}

def model_path() -> pathlib.Path:
    env_p = os.getenv("MODEL_PATH")
    if env_p:
        return pathlib.Path(env_p)
    return pathlib.Path(__file__).resolve().parents[1] / "models" / "url_model.joblib"

def load() -> Optional[Dict[str, Any]]:
    p = model_path()
    if not p.exists():
        return None
    try:
        m = (str(p), p.stat().st_mtime)
        if _cache.get("k") != m:
            art = joblib.load(p)
            _cache.update(k=m, art=art)
        return _cache.get("art")
    except Exception as e:
        logger.error(f"Failed to load ML model artifact from {p}: {e}")
        return None

def predict(url: str) -> Optional[Dict[str, Any]]:
    """Generates prediction using the loaded ML pipeline. Returns None if model is unavailable."""
    art = load()
    if not art or "pipeline" not in art:
        return None

    try:
        t0 = time.perf_counter()
        features = vector(url)
        # Handle pipeline prediction
        pipe = art["pipeline"]
        probs = pipe.predict_proba([features])[0]
        prob_phishing = float(probs[1])
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

        return {
            "prob": prob_phishing,
            "name": art.get("name", "Unknown-Model"),
            "version": art.get("version", "1.0.0"),
            "inference_ms": elapsed_ms,
            "features_used": art.get("features", FEATURE_ORDER)
        }
    except Exception as e:
        logger.error(f"Inference error on URL '{url}': {e}")
        return None

def get_model_info() -> Dict[str, Any]:
    """Returns current model status, metadata, baseline vs improved metrics, and confusion matrix."""
    art = load()
    p = model_path()
    metrics_path = p.with_suffix(".metrics.json")
    
    metrics_data = {}
    if metrics_path.exists():
        try:
            metrics_data = json.loads(metrics_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    if not art:
        return {
            "status": "not_loaded",
            "message": "No trained ML model file found at models/url_model.joblib. Running in rule-based heuristic mode.",
            "baseline_heuristic": {
                "accuracy": 0.52,
                "precision": 1.0,
                "recall": 0.04,
                "f1_score": 0.0769,
                "false_negative_rate": 0.96,
                "note": "Baseline rule-based detector on PhiUSIIL test subset"
            },
            "model_path": str(p),
            "features": FEATURE_ORDER
        }

    return {
        "status": "active",
        "name": art.get("name"),
        "version": art.get("version", "1.0.0"),
        "features": art.get("features", FEATURE_ORDER),
        "trained_at": art.get("trained_at"),
        "metrics": metrics_data or art.get("metrics", {}),
        "model_path": str(p)
    }
