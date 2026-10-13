"""Metricas agregadas para o dashboard executivo."""

from __future__ import annotations

from collections import Counter, defaultdict

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .. import models
from ..db import get_db
from ..services import SEVERITIES

router = APIRouter(prefix="/api/metrics", tags=["metrics"])

RISK_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _completed(db: Session, project_id: int | None, limit: int = 500) -> list[models.Scan]:
    stmt = (select(models.Scan).options(selectinload(models.Scan.project))
            .where(models.Scan.status == "completed").order_by(models.Scan.created_at, models.Scan.id))
    if project_id:
        stmt = stmt.where(models.Scan.project_id == project_id)
    return list(db.scalars(stmt))[-limit:]


@router.get("/overview")
def overview(project_id: int | None = None, days: int = Query(90, le=365), db: Session = Depends(get_db)):
    scans = _completed(db, project_id)
    latest: dict[int, models.Scan] = {}
    for s in scans:
        latest[s.project_id] = s
    latest_ids = [s.id for s in latest.values()]

    open_findings = list(db.scalars(select(models.Finding).where(
        models.Finding.scan_id.in_(latest_ids or [-1]), models.Finding.status == "open"))) if latest_ids else []
    all_latest = list(db.scalars(select(models.Finding).where(models.Finding.scan_id.in_(latest_ids or [-1]))))

    severity = {s: 0 for s in SEVERITIES}
    for f in open_findings:
        severity[f.effective_severity] = severity.get(f.effective_severity, 0) + 1

    # ---- top arquivos críticos (ponderado por severidade)
    per_file: dict[str, Counter] = defaultdict(Counter)
    for f in open_findings:
        per_file[f"{latest[f.scan.project_id].project.name}:{f.file}" if not project_id else f.file][f.effective_severity] += 1
    top_files = sorted(
        ({"file": name, "total": sum(c.values()), "risk": sum(RISK_WEIGHT[k] * v for k, v in c.items()),
          **{k: c.get(k, 0) for k in SEVERITIES}} for name, c in per_file.items()),
        key=lambda x: (-x["risk"], -x["total"]))[:5]

    # ---- tendência: snapshot diario do último scan de cada projeto
    trend: list[dict] = []
    current: dict[int, models.Scan] = {}
    by_day: dict[str, list[models.Scan]] = defaultdict(list)
    for s in scans:
        by_day[s.created_at.date().isoformat()].append(s)
    for day in sorted(by_day)[-days:]:
        new = fixed = 0
        for s in by_day[day]:
            current[s.project_id] = s
            new += s.new_count
            fixed += s.fixed_count
        point = {"date": day, "new": new, "fixed": fixed}
        for sev in SEVERITIES:
            point[sev] = sum((sc.counts or {}).get(sev, 0) for sc in current.values())
        point["total"] = sum(point[s] for s in SEVERITIES)
        trend.append(point)

    cwe_counter = Counter(f.cwe for f in open_findings)
    cwe_titles = {f.cwe: f.title for f in open_findings}
    owasp_counter = Counter((f.owasp or "Sem categoria") for f in open_findings)
    engine_counter: Counter = Counter()
    for f in open_findings:
        engine_counter[f.engine] += 1
        for e in f.confirmed_by or []:
            engine_counter[e] += 1

    recent = sorted(scans, key=lambda s: s.created_at)[-30:]
    gated = [s for s in recent if s.gate_passed is not None]
    ai_reviewed = [f for f in all_latest if f.ai]
    critical_list = sorted(
        (f for f in open_findings if f.effective_severity in {"CRITICAL", "HIGH"}),
        key=lambda f: (SEVERITIES.index(f.effective_severity), -f.scan_id))[:6]

    return {
        "kpis": {
            "open_findings": len(open_findings),
            "critical": severity["CRITICAL"],
            "high": severity["HIGH"],
            "projects": len(latest),
            "scans": len(scans),
            "files_scanned": sum(s.files_scanned for s in latest.values()),
            "lines_of_code": sum(s.lines_of_code for s in latest.values()),
            "gate_pass_rate": round(sum(1 for s in gated if s.gate_passed) / len(gated), 3) if gated else None,
            "avg_scan_seconds": round(sum(s.duration_seconds for s in recent) / len(recent), 2) if recent else 0,
            "new_last_scan": sum(s.new_count for s in latest.values()),
            "fixed_last_scan": sum(s.fixed_count for s in latest.values()),
            "ai_reviewed": len(ai_reviewed),
            "ai_llm_reviewed": sum(1 for f in ai_reviewed if (f.ai or {}).get("mode") == "llm"),
            "ai_fixes_verified": sum(1 for f in ai_reviewed if (f.ai or {}).get("fix_verified")),
            "likely_false_positives": sum(1 for f in all_latest if f.status == "likely_false_positive"),
            "false_positives": sum(1 for f in all_latest if f.status == "false_positive"),
            "risk_score": sum(RISK_WEIGHT[k] * v for k, v in severity.items()),
        },
        "severity": severity,
        "trend": trend,
        "top_files": top_files,
        "top_cwes": [{"cwe": c, "title": cwe_titles[c], "count": n} for c, n in cwe_counter.most_common(8)],
        "owasp": [{"category": c, "count": n} for c, n in owasp_counter.most_common()],
        "engines": dict(engine_counter),
        "critical_findings": [{"id": f.id, "scan_id": f.scan_id, "title": f.title, "cwe": f.cwe, "file": f.file,
                               "line": f.line, "severity": f.effective_severity, "message": f.message}
                              for f in critical_list],
        "latest_scans": [{"id": s.id, "project": s.project.name, "created_at": s.created_at.isoformat(),
                          "gate_passed": s.gate_passed, "counts": s.counts} for s in reversed(recent[-8:])],
    }
