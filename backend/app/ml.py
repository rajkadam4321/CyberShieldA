import os, pathlib, joblib
from .url_analysis import vector
_cache = {}
def model_path():
    return pathlib.Path(os.getenv("MODEL_PATH") or pathlib.Path(__file__).resolve().parents[1] / "models" / "url_model.joblib")
def load():
    p = model_path()
    if not p.exists(): return None
    m = (str(p), p.stat().st_mtime)
    if _cache.get("k") != m: _cache.update(k=m, art=joblib.load(p))
    return _cache["art"]
def predict(url: str):
    art = load()
    if not art: return None
    return {"prob": float(art["pipeline"].predict_proba([vector(url)])[0][1]), "name": art["name"]}
