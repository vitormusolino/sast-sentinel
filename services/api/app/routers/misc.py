from __future__ import annotations

import time

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .. import models
from ..auth import current_user
from ..db import get_db

router = APIRouter(tags=["misc"])

# o health check da plataforma de deploy bate aqui a cada poucos segundos: o status do LLM
# fica em cache para não gastar a cota da API de IA (nem esperar timeout do Ollama) toda vez
_LLM_TTL = 60.0
_llm_cache: dict[str, object] = {"at": -_LLM_TTL, "value": None}


def _llm_status() -> dict:
    from sast_engine.ai import make_client

    now = time.monotonic()
    if now - float(_llm_cache["at"]) >= _LLM_TTL:
        client = make_client(timeout=3)
        _llm_cache["value"] = {"available": client.available(), "model": client.model, "url": client.base_url}
        _llm_cache["at"] = now
    return dict(_llm_cache["value"])  # type: ignore[arg-type]


@router.get("/api/health")
def health(db: Session = Depends(get_db)):
    from sast_engine.integrations import tool_available
    from sast_engine.parsers.js_parser import TREE_SITTER_AVAILABLE

    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:  # noqa: BLE001
        db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "database": db_ok,
        "llm": _llm_status(),
        "tools": {"bandit": tool_available("bandit"), "semgrep": tool_available("semgrep"),
                  "tree_sitter": TREE_SITTER_AVAILABLE},
    }


@router.get("/api/projects", dependencies=[Depends(current_user)])
def list_projects(db: Session = Depends(get_db)):
    rows = db.execute(
        select(models.Project, func.count(models.Scan.id), func.max(models.Scan.created_at))
        .outerjoin(models.Scan).group_by(models.Project.id).order_by(models.Project.name)
    ).all()
    return [{"id": p.id, "name": p.name, "repo_url": p.repo_url, "scans": n,
             "last_scan": last.isoformat() if last else None} for p, n, last in rows]


@router.get("/api/rules", dependencies=[Depends(current_user)])
def list_rules():
    from sast_engine.rules import RULES

    return [{"id": r.id, "title": r.title, "cwe": r.cwe, "owasp": r.owasp, "severity": r.severity.name,
             "language": r.language, "engine": r.engine, "description": r.description,
             "remediation": r.remediation} for r in RULES.values()]
