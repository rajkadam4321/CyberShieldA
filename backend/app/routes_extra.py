import io, json, os
from xml.sax.saxutils import escape
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import Response
from pydantic import BaseModel
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from sqlalchemy import select
from sqlalchemy.orm import Session
from .db import get_db, User, Scan, QuizAttempt
from .file_analysis import analyze
from .security import current_user

r = APIRouter(prefix="/api/v1")

@r.post("/scans/file", status_code=201)
async def scan_file(file: UploadFile = File(...), u: User = Depends(current_user), db: Session = Depends(get_db)):
    limit = int(os.getenv("MAX_UPLOAD_MB", "5")) * 1024 * 1024
    data = await file.read(limit + 1)
    if len(data) > limit: raise HTTPException(413, "File too large")
    if not data: raise HTTPException(422, "Empty file")
    a = analyze(file.filename or "unnamed", data)
    s = Scan(user_id=u.id, kind="file", target=a["metadata"]["filename"], score=a["score"], category=a["category"],
             mode="static heuristic analysis (not a malware engine)",
             details_json=json.dumps({k: a[k] for k in ("metadata", "findings", "recommendations", "disclaimer")}))
    db.add(s); db.commit(); db.refresh(s)
    return {"id": s.id, "kind": s.kind, "target": s.target, "score": s.score, "category": s.category, "mode": s.mode,
            "created_at": s.created_at.isoformat(), **json.loads(s.details_json)}

def build_pdf(s: Scan, d: dict, username: str) -> bytes:
    st = getSampleStyleSheet(); buf = io.BytesIO()
    P = lambda t, k="BodyText": Paragraph(escape(str(t)), st[k])
    el = [P("CyberShield Security Report", "Title"), P(f"Report ID: CS-{s.id:06d}"), P(f"User: {username}"),
          P(f"Scan date: {s.created_at.isoformat()}"), P(f"Analysis type: {s.kind.upper()}"), P(f"Target: {s.target}"),
          P(f"Detection mode: {s.mode}"), P(f"Risk score: {s.score}/100 ({s.category})")]
    for k, v in (d.get("metadata") or {}).items(): el.append(P(f"{k}: {v}"))
    el += [Spacer(1, 12), P("Findings", "Heading2")]
    el += [P(f"- {f['indicator']}: {f['detail']} (+{f['points']})") for f in d.get("findings", [])] or [P("No indicators found.")]
    el += [P("Recommendations", "Heading2")] + [P(f"- {x}") for x in d.get("recommendations", [])]
    el += [Spacer(1, 12), P("Limitations", "Heading2"), P(d.get("disclaimer", "")), P("Indicators are not proof of maliciousness, and a low score is not a guarantee of safety.")]
    SimpleDocTemplate(buf, pagesize=A4, title=f"CyberShield CS-{s.id:06d}").build(el)
    return buf.getvalue()

@r.get("/scans/{scan_id}/report.pdf")
def report(scan_id: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    s = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == u.id))
    if not s: raise HTTPException(404, "Scan not found")
    return Response(build_pdf(s, json.loads(s.details_json), u.username), media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=cybershield_CS-{s.id:06d}.pdf"})

QUIZ = [
 ("Which is the strongest sign of a phishing email?", ["A greeting with your name", "Urgent threats and a link to a look-alike domain", "A company logo", "A short message"], 1, "Urgency plus mismatched links is the classic pattern."),
 ("What should you do before clicking a link in an unexpected message?", ["Click quickly", "Hover to check the real address, or type the official site yourself", "Forward it to friends", "Reply asking if it is real"], 1, "Check the destination independently."),
 ("Which password practice is best?", ["Reuse one strong password", "Unique passphrases with a password manager and MFA", "Write it on your monitor", "Use your birthday"], 1, "Unique passwords limit damage from breaches; MFA adds a second barrier."),
 ("A file named 'invoice.pdf.exe' is most likely:", ["A normal PDF", "An executable disguised as a document", "An image", "Safe because it has 'pdf' in it"], 1, "Double extensions hide the real executable type."),
 ("Does HTTPS in a URL prove a site is safe?", ["Yes", "No, it only means the connection is encrypted", "Only on weekdays", "Yes if it has a padlock"], 1, "Phishing sites can use HTTPS too."),
]

@r.get("/awareness/quiz")
def quiz(u: User = Depends(current_user)):
    return {"questions": [{"id": i, "question": q, "options": o} for i, (q, o, _, _) in enumerate(QUIZ)]}

class Answers(BaseModel):
    answers: list[int]

@r.post("/awareness/quiz/submit")
def submit(a: Answers, u: User = Depends(current_user), db: Session = Depends(get_db)):
    if len(a.answers) != len(QUIZ): raise HTTPException(422, f"Provide {len(QUIZ)} answers")
    res = [{"id": i, "correct": a.answers[i] == c, "correct_option": c, "explanation": e} for i, (_, _, c, e) in enumerate(QUIZ)]
    score = sum(x["correct"] for x in res)
    db.add(QuizAttempt(user_id=u.id, score=score, total=len(QUIZ))); db.commit()
    return {"score": score, "total": len(QUIZ), "results": res}

@r.get("/awareness/attempts")
def attempts(u: User = Depends(current_user), db: Session = Depends(get_db)):
    return [{"score": x.score, "total": x.total, "created_at": x.created_at.isoformat()}
            for x in db.scalars(select(QuizAttempt).where(QuizAttempt.user_id == u.id).order_by(QuizAttempt.id.desc()).limit(20))]
