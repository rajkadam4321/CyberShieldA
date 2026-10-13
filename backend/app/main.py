import csv, io, json, re
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .db import init_db, get_db, User, Scan
from .security import hash_password, verify_password, create_token, current_user
from .url_analysis import validate_url, heuristic_scan
from .ml import predict
from .routes_extra import r as extra

@asynccontextmanager
async def lifespan(app): init_db(); yield

app = FastAPI(title="CyberShield API", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])

class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)
    @field_validator("username")
    @classmethod
    def ok(cls, v):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", v): raise ValueError("Use letters, digits, _ . - only")
        return v

class UrlIn(BaseModel):
    url: str

def scan_out(s: Scan, full=False):
    d = {"id": s.id, "kind": s.kind, "target": s.target, "score": s.score, "category": s.category,
         "mode": s.mode, "created_at": s.created_at.isoformat()}
    if full: d.update(json.loads(s.details_json))
    return d

v1 = "/api/v1"

@app.get(f"{v1}/health")
def health(): return {"status": "ok"}

@app.post(f"{v1}/auth/register", status_code=201)
def register(c: Credentials, db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.username == c.username)):
        raise HTTPException(409, "Username already taken")
    u = User(username=c.username, password_hash=hash_password(c.password)); db.add(u); db.commit()
    return {"id": u.id, "username": u.username}

@app.post(f"{v1}/auth/login")
def login(c: Credentials, db: Session = Depends(get_db)):
    u = db.scalar(select(User).where(User.username == c.username))
    if not u or not verify_password(c.password, u.password_hash): raise HTTPException(401, "Wrong username or password")
    return {"access_token": create_token(u.id), "token_type": "bearer"}

@app.get(f"{v1}/users/me")
def me(u: User = Depends(current_user)): return {"id": u.id, "username": u.username, "created_at": u.created_at.isoformat()}

@app.post(f"{v1}/scans/url", status_code=201)
def scan_url(body: UrlIn, u: User = Depends(current_user), db: Session = Depends(get_db)):
    try: url = validate_url(body.url)
    except ValueError as e: raise HTTPException(422, str(e))
    r = heuristic_scan(url)
    ml = predict(url)
    if ml:
        sc = round(ml["prob"] * 100); r["score"] = sc
        r["category"] = "Low" if sc < 30 else "Suspicious" if sc < 60 else "High"; r["mode"] = f"trained ML model ({ml['name']})"
        r["disclaimer"] = "Score from a trained model; listed indicators are explanatory heuristics. " + r["disclaimer"]
    s = Scan(user_id=u.id, kind="url", target=url, score=r["score"], category=r["category"], mode=r["mode"],
             details_json=json.dumps({k: r[k] for k in ("features", "findings", "recommendations", "disclaimer")}))
    db.add(s); db.commit(); db.refresh(s)
    return scan_out(s, full=True)

@app.get(f"{v1}/scans")
def history(page: int = Query(1, ge=1), size: int = Query(10, ge=1, le=100), category: str | None = None,
            u: User = Depends(current_user), db: Session = Depends(get_db)):
    q = select(Scan).where(Scan.user_id == u.id)
    if category: q = q.where(Scan.category == category)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.order_by(Scan.id.desc()).offset((page - 1) * size).limit(size)).all()
    return {"total": total, "page": page, "items": [scan_out(s) for s in rows]}

@app.get(f"{v1}/scans/export.csv")
def export_csv(u: User = Depends(current_user), db: Session = Depends(get_db)):
    buf = io.StringIO(); w = csv.writer(buf); w.writerow(["id", "kind", "target", "score", "category", "mode", "created_at"])
    for s in db.scalars(select(Scan).where(Scan.user_id == u.id).order_by(Scan.id)):
        w.writerow([s.id, s.kind, s.target.replace("\n", " "), s.score, s.category, s.mode, s.created_at.isoformat()])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=scan_history.csv"})

@app.get(f"{v1}/scans/{{scan_id}}")
def scan_detail(scan_id: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    s = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == u.id))
    if not s: raise HTTPException(404, "Scan not found")
    return scan_out(s, full=True)

@app.get(f"{v1}/dashboard")
def dashboard(u: User = Depends(current_user), db: Session = Depends(get_db)):
    c = dict(db.execute(select(Scan.category, func.count()).where(Scan.user_id == u.id).group_by(Scan.category)).all())
    k = dict(db.execute(select(Scan.kind, func.count()).where(Scan.user_id == u.id).group_by(Scan.kind)).all())
    return {"url": k.get("url", 0), "file": k.get("file", 0), "total": sum(c.values()), "high": c.get("High", 0), "suspicious": c.get("Suspicious", 0), "low": c.get("Low", 0)}

app.include_router(extra)
