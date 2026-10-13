from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..serializers import finding_out
from ..services import recount

router = APIRouter(prefix="/api/findings", tags=["findings"])


class TriageRequest(BaseModel):
    status: Literal["open", "false_positive", "accepted", "fixed"]
    reason: str | None = None


@router.get("/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    f = db.get(models.Finding, finding_id)
    if f is None:
        raise HTTPException(404, "achado não encontrado")
    data = finding_out(f)
    history = db.execute(
        select(models.Scan.id, models.Scan.created_at, models.Finding.status)
        .join(models.Finding, models.Finding.scan_id == models.Scan.id)
        .where(models.Finding.fingerprint == f.fingerprint, models.Scan.project_id == f.scan.project_id)
        .order_by(models.Scan.created_at)
    ).all()
    data["history"] = [{"scan_id": h[0], "date": h[1].isoformat(), "status": h[2]} for h in history]
    return data


@router.patch("/{finding_id}")
def triage_finding(finding_id: int, req: TriageRequest, db: Session = Depends(get_db)):
    """Triagem humana. A decisão e persistida por fingerprint e reaplicada nos próximos scans."""
    f = db.get(models.Finding, finding_id)
    if f is None:
        raise HTTPException(404, "achado não encontrado")
    f.status = req.status
    project_id = f.scan.project_id
    decision = db.scalar(select(models.TriageDecision).where(
        models.TriageDecision.project_id == project_id, models.TriageDecision.fingerprint == f.fingerprint))
    if decision is None:
        decision = models.TriageDecision(project_id=project_id, fingerprint=f.fingerprint, status=req.status)
        db.add(decision)
    decision.status, decision.reason = req.status, req.reason
    f.scan.counts = recount(list(f.scan.findings))
    db.commit()
    return finding_out(f)
