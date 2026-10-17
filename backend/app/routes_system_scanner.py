"""
FastAPI Routes for CyberShield System Security and Malware Scanner.
"""
import csv
import io
import json
import threading
from datetime import datetime
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import SessionLocal, SystemScan, SystemScanFinding, User, get_db
from .security import current_user
from .system_scanner import (
    ScanJob,
    active_jobs,
    active_lock,
    execute_scan_worker,
    get_active_job,
    get_defender_status,
    quarantine_finding_file,
    validate_scan_path,
)

sys_router = APIRouter(prefix="/api/v1/system-scans")


class StartScanRequest(BaseModel):
    scan_type: str = Field(pattern="^(quick|full|custom)$")
    target_path: str = ""


class RemediateRequest(BaseModel):
    action: str = Field(pattern="^(quarantine|ignore)$")


@sys_router.get("/engine-status")
def engine_status(u: User = Depends(current_user)):
    """Returns local scanner engine capabilities and Microsoft Defender status."""
    return get_defender_status()


@sys_router.post("/start", status_code=201)
def start_scan(
    req: StartScanRequest,
    u: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Initiates a genuine local Windows system security scan."""
    # Check if a scan is already running
    active = get_active_job()
    if active and active.status in ("running", "paused"):
        raise HTTPException(
            409,
            f"A scan (#{active.scan_id}) is currently {active.status}. Cancel or wait for it to complete.",
        )

    validated_path = ""
    if req.scan_type == "custom":
        try:
            validated_path = validate_scan_path(req.target_path)
        except ValueError as e:
            raise HTTPException(422, str(e))
    elif req.scan_type == "quick":
        validated_path = "Quick Locations (Startup, Downloads, Temp, Registry)"
    elif req.scan_type == "full":
        validated_path = "All Accessible Local System Drives"

    # Create DB entry
    scan_rec = SystemScan(
        user_id=u.id,
        scan_type=req.scan_type,
        status="running",
        target_path=validated_path,
        engine_status=get_defender_status()["engine"],
    )
    db.add(scan_rec)
    db.commit()
    db.refresh(scan_rec)

    # Initialize ScanJob
    job = ScanJob(
        scan_id=scan_rec.id,
        user_id=u.id,
        scan_type=req.scan_type,
        target_path=validated_path,
    )
    with active_lock:
        active_jobs[scan_rec.id] = job

    # Launch background scanning thread
    thread = threading.Thread(
        target=execute_scan_worker,
        args=(job, SessionLocal),
        daemon=True,
    )
    thread.start()

    return {
        "id": scan_rec.id,
        "scan_type": scan_rec.scan_type,
        "status": scan_rec.status,
        "target_path": scan_rec.target_path,
        "message": f"Scan #{scan_rec.id} started successfully.",
    }


@sys_router.get("/active")
def get_active(
    u: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Returns real-time status of the current or most recent system scan."""
    job = get_active_job()
    if job:
        return job.to_dict()

    # Fallback to most recent DB record
    latest = db.scalars(
        select(SystemScan)
        .where(SystemScan.user_id == u.id)
        .order_by(SystemScan.id.desc())
        .limit(1)
    ).first()
    if not latest:
        return {
            "status": "idle",
            "message": "No active or recent scans found.",
        }

    findings = db.scalars(
        select(SystemScanFinding).where(
            SystemScanFinding.scan_id == latest.id
        )
    ).all()
    return {
        "id": latest.id,
        "user_id": latest.user_id,
        "scan_type": latest.scan_type,
        "target_path": latest.target_path,
        "status": latest.status,
        "files_examined": latest.files_examined,
        "files_skipped": latest.files_skipped,
        "errors_count": latest.errors_count,
        "findings_count": latest.findings_count,
        "progress_pct": latest.progress_pct,
        "current_file": latest.current_file,
        "duration_seconds": latest.duration_seconds,
        "findings": [
            {
                "id": f.id,
                "file_path": f.file_path,
                "file_name": f.file_name,
                "file_hash": f.file_hash,
                "finding_type": f.finding_type,
                "detection_source": f.detection_source,
                "severity": f.severity,
                "malware_name": f.malware_name,
                "description": f.description,
                "recommended_action": f.recommended_action,
                "status": f.status,
            }
            for f in findings
        ],
    }


@sys_router.post("/{scan_id}/pause")
def pause_scan(
    scan_id: int,
    u: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    job = get_active_job(scan_id)
    if not job or job.status != "running":
        raise HTTPException(400, "Scan is not currently running.")
    job.pause()
    rec = db.get(SystemScan, scan_id)
    if rec:
        rec.status = "paused"
        db.commit()
    return {"message": f"Scan #{scan_id} paused."}


@sys_router.post("/{scan_id}/resume")
def resume_scan(
    scan_id: int,
    u: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    job = get_active_job(scan_id)
    if not job or job.status != "paused":
        raise HTTPException(400, "Scan is not paused.")
    job.resume()
    rec = db.get(SystemScan, scan_id)
    if rec:
        rec.status = "running"
        db.commit()
    return {"message": f"Scan #{scan_id} resumed."}


@sys_router.post("/{scan_id}/cancel")
def cancel_scan(
    scan_id: int,
    u: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    job = get_active_job(scan_id)
    if not job or job.status not in ("running", "paused"):
        raise HTTPException(400, "Scan is not actively running.")
    job.cancel()
    rec = db.get(SystemScan, scan_id)
    if rec:
        rec.status = "cancelled"
        db.commit()
    return {"message": f"Scan #{scan_id} cancelled."}


@sys_router.get("")
def list_system_scans(
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=100),
    u: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Lists completed and past system scans."""
    q = select(SystemScan).where(SystemScan.user_id == u.id)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(
        q.order_by(SystemScan.id.desc())
        .offset((page - 1) * size)
        .limit(size)
    ).all()
    return {
        "total": total,
        "page": page,
        "items": [
            {
                "id": s.id,
                "scan_type": s.scan_type,
                "status": s.status,
                "target_path": s.target_path,
                "files_examined": s.files_examined,
                "files_skipped": s.files_skipped,
                "errors_count": s.errors_count,
                "findings_count": s.findings_count,
                "progress_pct": s.progress_pct,
                "duration_seconds": s.duration_seconds,
                "started_at": s.started_at.isoformat(),
                "completed_at": (
                    s.completed_at.isoformat() if s.completed_at else None
                ),
                "engine_status": s.engine_status,
            }
            for s in rows
        ],
    }


@sys_router.get("/{scan_id}")
def get_system_scan_details(
    scan_id: int,
    u: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Returns detailed scan information including all individual threat findings."""
    s = db.scalar(
        select(SystemScan).where(
            SystemScan.id == scan_id, SystemScan.user_id == u.id
        )
    )
    if not s:
        raise HTTPException(404, "System scan not found.")

    findings = db.scalars(
        select(SystemScanFinding).where(SystemScanFinding.scan_id == s.id)
    ).all()
    return {
        "id": s.id,
        "scan_type": s.scan_type,
        "status": s.status,
        "target_path": s.target_path,
        "files_examined": s.files_examined,
        "files_skipped": s.files_skipped,
        "errors_count": s.errors_count,
        "findings_count": s.findings_count,
        "progress_pct": s.progress_pct,
        "duration_seconds": s.duration_seconds,
        "started_at": s.started_at.isoformat(),
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "engine_status": s.engine_status,
        "findings": [
            {
                "id": f.id,
                "file_path": f.file_path,
                "file_name": f.file_name,
                "file_hash": f.file_hash,
                "finding_type": f.finding_type,
                "detection_source": f.detection_source,
                "severity": f.severity,
                "malware_name": f.malware_name,
                "description": f.description,
                "recommended_action": f.recommended_action,
                "status": f.status,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ],
    }


@sys_router.post("/findings/{finding_id}/remediate")
def remediate_finding(
    finding_id: int,
    req: RemediateRequest,
    u: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Performs explicit user-authorized remediation or quarantine."""
    f = db.get(SystemScanFinding, finding_id)
    if not f:
        raise HTTPException(404, "Finding record not found.")

    scan = db.get(SystemScan, f.scan_id)
    if not scan or scan.user_id != u.id:
        raise HTTPException(403, "Unauthorized to remediate this finding.")

    if req.action == "ignore":
        f.status = "ignored"
        db.commit()
        return {"status": "ignored", "message": f"Finding #{finding_id} marked as ignored."}

    elif req.action == "quarantine":
        ok, msg = quarantine_finding_file(f.file_path)
        if not ok:
            raise HTTPException(400, msg)
        f.status = "quarantined"
        db.commit()
        return {"status": "quarantined", "message": msg}


@sys_router.get("/{scan_id}/export.csv")
def export_system_scan_csv(
    scan_id: int,
    u: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Exports findings as CSV."""
    s = db.scalar(
        select(SystemScan).where(
            SystemScan.id == scan_id, SystemScan.user_id == u.id
        )
    )
    if not s:
        raise HTTPException(404, "System scan not found.")

    findings = db.scalars(
        select(SystemScanFinding).where(SystemScanFinding.scan_id == s.id)
    ).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "finding_id",
        "severity",
        "malware_name",
        "detection_source",
        "finding_type",
        "file_path",
        "file_hash",
        "description",
        "recommended_action",
        "status",
    ])
    for f in findings:
        w.writerow([
            f.id,
            f.severity,
            f.malware_name,
            f.detection_source,
            f.finding_type,
            f.file_path.replace("\n", " "),
            f.file_hash,
            f.description.replace("\n", " "),
            f.recommended_action.replace("\n", " "),
            f.status,
        ])

    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=system_scan_CS-SYS-{s.id:04d}.csv"
        },
    )


@sys_router.get("/{scan_id}/report.pdf")
def generate_system_scan_pdf(
    scan_id: int,
    u: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Generates an executive PDF report for a local system scan."""
    s = db.scalar(
        select(SystemScan).where(
            SystemScan.id == scan_id, SystemScan.user_id == u.id
        )
    )
    if not s:
        raise HTTPException(404, "System scan not found.")

    findings = db.scalars(
        select(SystemScanFinding).where(SystemScanFinding.scan_id == s.id)
    ).all()

    buf = io.BytesIO()
    st = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "SysTitle",
        parent=st["Title"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0891b2"),
    )
    h2_style = ParagraphStyle(
        "SysH2",
        parent=st["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
    )
    body_style = ParagraphStyle(
        "SysBody",
        parent=st["BodyText"],
        fontSize=9,
        leading=12,
    )
    bold_style = ParagraphStyle(
        "SysBold",
        parent=st["BodyText"],
        fontSize=9,
        leading=12,
        fontName="Helvetica-Bold",
    )

    P = lambda t, s=body_style: Paragraph(escape(str(t)), s)

    elements = [
        Paragraph("CyberShield System Security & Malware Assessment Report", title_style),
        Spacer(1, 10),
        P(f"Report ID: CS-SYS-{s.id:04d}", bold_style),
        P(f"User / Operator: {u.username}"),
        P(f"Scan Mode: {s.scan_type.capitalize()} Scan"),
        P(f"Target Scope: {s.target_path}"),
        P(f"Detection Engine: {s.engine_status}"),
        P(f"Scan Duration: {s.duration_seconds}s | Status: {s.status.capitalize()}"),
        P(f"Timestamp: {s.started_at.isoformat()}"),
        Spacer(1, 12),
        Paragraph("Execution Summary", h2_style),
        Spacer(1, 6),
    ]

    summary_data = [
        ["Files Examined", "Files Skipped", "Errors", "Confirmed Threats / Anomalies"],
        [str(s.files_examined), str(s.files_skipped), str(s.errors_count), str(len(findings))],
    ]
    t_sum = Table(summary_data, colWidths=[120, 120, 100, 160])
    t_sum.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    elements.append(t_sum)
    elements.append(Spacer(1, 14))

    elements.append(Paragraph("Identified Threat Findings & Security Advisories", h2_style))
    elements.append(Spacer(1, 6))

    if not findings:
        elements.append(P("No malicious artifacts, persistence anomalies, or active infections were detected during this scan."))
    else:
        table_rows = [["Severity", "Threat / Indicator", "Source", "Action"]]
        for f in findings:
            table_rows.append([
                f.severity,
                f"{f.malware_name}\n({f.file_name})",
                f.detection_source,
                f.recommended_action[:60] + "..." if len(f.recommended_action) > 60 else f.recommended_action,
            ])
        t_find = Table(table_rows, colWidths=[70, 160, 130, 140])
        t_find.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0891b2")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_find)

    elements.append(Spacer(1, 14))
    elements.append(Paragraph("Security Recommendations & Limitations", h2_style))
    elements.append(P("1. Maintain Microsoft Defender and real-time protection definitions up-to-date."))
    elements.append(P("2. Never execute unrecognized files from downloads or temporary storage locations."))
    elements.append(P("3. Periodically review Windows Startup & autorun persistence entries."))
    elements.append(P("4. Disclaimer: Local scanning checks known signatures, heuristics, and Windows Defender output. Static inspection does not guarantee total eradication of advanced zero-day threats."))

    SimpleDocTemplate(buf, pagesize=A4, title=f"CyberShield-Report-CS-SYS-{s.id:04d}").build(elements)

    return Response(
        buf.getvalue(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=cybershield_sys_CS-{s.id:04d}.pdf"
        },
    )
