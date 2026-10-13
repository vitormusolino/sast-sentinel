from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db

router = APIRouter(tags=["misc"])


@router.get("/api/health")
def health(db: Session = Depends(get_db)):
    from sast_engine.ai import OllamaClient
    from sast_engine.integrations import tool_available
    from sast_engine.parsers.js_parser import TREE_SITTER_AVAILABLE

    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:  # noqa: BLE001
        db_ok = False
    client = OllamaClient(timeout=3)
    return {
        "status": "ok" if db_ok else "degraded",
        "database": db_ok,
        "llm": {"available": client.available(), "model": client.model, "url": client.base_url},
        "tools": {"bandit": tool_available("bandit"), "semgrep": tool_available("semgrep"),
                  "tree_sitter": TREE_SITTER_AVAILABLE},
    }


@router.get("/api/projects")
def list_projects(db: Session = Depends(get_db)):
    rows = db.execute(
        select(models.Project, func.count(models.Scan.id), func.max(models.Scan.created_at))
        .outerjoin(models.Scan).group_by(models.Project.id).order_by(models.Project.name)
    ).all()
    return [{"id": p.id, "name": p.name, "repo_url": p.repo_url, "scans": n,
             "last_scan": last.isoformat() if last else None} for p, n, last in rows]


@router.get("/api/rules")
def list_rules():
    from sast_engine.rules import RULES

    return [{"id": r.id, "title": r.title, "cwe": r.cwe, "owasp": r.owasp, "severity": r.severity.name,
             "language": r.language, "engine": r.engine, "description": r.description,
             "remediation": r.remediation} for r in RULES.values()]
