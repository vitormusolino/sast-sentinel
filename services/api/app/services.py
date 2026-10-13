"""Regras de negocio: persistência de resultados, novos/corrigidos, triagem."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .models import utcnow

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def get_or_create_project(db: Session, name: str, repo_url: str | None = None) -> models.Project:
    project = db.scalar(select(models.Project).where(models.Project.name == name))
    if project is None:
        project = models.Project(name=name, repo_url=repo_url)
        db.add(project)
        db.flush()
    elif repo_url and not project.repo_url:
        project.repo_url = repo_url
    return project


def triage_map(db: Session, project_id: int) -> dict[str, str]:
    rows = db.scalars(select(models.TriageDecision).where(models.TriageDecision.project_id == project_id))
    return {r.fingerprint: r.status for r in rows if r.status != "open"}


def previous_fingerprints(db: Session, scan: models.Scan) -> set[str] | None:
    prev = db.scalar(
        select(models.Scan)
        .where(models.Scan.project_id == scan.project_id, models.Scan.status == "completed",
               models.Scan.id != scan.id, models.Scan.created_at <= scan.created_at)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.desc())
        .limit(1)
    )
    if prev is None:
        return None
    return set(db.scalars(select(models.Finding.fingerprint).where(models.Finding.scan_id == prev.id)))


def recount(findings: list[models.Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f.status == "open":
            counts[f.effective_severity] = counts.get(f.effective_severity, 0) + 1
    return counts


def persist_result(db: Session, scan: models.Scan, result: dict[str, Any], gate: dict[str, Any] | None,
                   ai_summary: dict[str, Any] | None = None) -> models.Scan:
    decisions = triage_map(db, scan.project_id)
    prev = previous_fingerprints(db, scan)
    current: set[str] = set()
    rows: list[models.Finding] = []
    for f in result.get("findings", []):
        fp = f.get("fingerprint", "")
        current.add(fp)
        status = decisions.get(fp, f.get("status", "open"))
        rows.append(models.Finding(
            scan_id=scan.id,
            fingerprint=fp,
            rule_id=f["rule_id"],
            title=f.get("title", f["rule_id"])[:300],
            message=f.get("message", ""),
            severity=f.get("severity", "MEDIUM"),
            effective_severity=f.get("effective_severity", f.get("severity", "MEDIUM")),
            confidence=f.get("confidence", "MEDIUM"),
            cwe=f.get("cwe", ""),
            owasp=f.get("owasp"),
            file=f.get("file", "")[:500],
            line=int(f.get("line", 0)),
            column=int(f.get("column", 0) or 0),
            end_line=f.get("end_line"),
            snippet=f.get("snippet"),
            engine=f.get("engine", "ast"),
            trace=f.get("trace") or [],
            remediation=f.get("remediation"),
            confirmed_by=f.get("confirmed_by") or [],
            ai=f.get("ai"),
            status=status,
            is_new=prev is None or fp not in prev,
        ))
    db.add_all(rows)
    scan.files_scanned = int(result.get("files_scanned", 0))
    scan.lines_of_code = int(result.get("lines_of_code", 0))
    scan.duration_seconds = float(result.get("duration_seconds", 0.0))
    scan.engines = result.get("engines", [])
    scan.errors = result.get("errors", [])[:50]
    scan.ai_stats = result.get("ai_stats")
    scan.ai_summary = ai_summary
    scan.counts = recount(rows)
    scan.new_count = sum(1 for r in rows if r.is_new) if prev is not None else len(rows)
    scan.fixed_count = len(prev - current) if prev is not None else 0
    if gate is not None:
        scan.gate = gate
        scan.gate_passed = bool(gate.get("passed")) if gate.get("analyzed", True) else None
    scan.status = "completed"
    scan.progress = 1.0
    scan.message = "concluído"
    scan.finished_at = utcnow()
    db.commit()
    return scan
