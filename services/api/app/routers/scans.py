from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .. import models
from ..config import settings
from ..db import get_db
from ..serializers import finding_out, scan_out
from ..services import get_or_create_project, persist_result
from ..worker import dispatch_scan
from ..workspace import WorkspaceError, cleanup, extract_zip, new_workspace, validate_git_url

router = APIRouter(prefix="/api/scans", tags=["scans"])

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class ScanOptions(BaseModel):
    ai: bool = settings.ai_default
    bandit: bool = True
    semgrep: bool = False
    fail_on: str = settings.default_fail_on
    exclude: list[str] = Field(default_factory=list)


class GitScanRequest(ScanOptions):
    project: str | None = None
    repo_url: str
    branch: str | None = None


class ImportRequest(BaseModel):
    project: str
    repo_url: str | None = None
    branch: str | None = None
    commit: str | None = None
    triggered_by: str = "ci"
    result: dict[str, Any]
    gate: dict[str, Any] | None = None


def require_api_key(x_api_key: str = Header(default="")) -> None:
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="API key inválida")


def _get_scan(db: Session, scan_id: int) -> models.Scan:
    scan = db.get(models.Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "scan não encontrado")
    return scan


@router.post("/upload", status_code=202)
async def create_upload_scan(
    file: UploadFile = File(..., description="Arquivo .zip com o código-fonte"),
    project: str = Form(...),
    ai: bool = Form(settings.ai_default),
    bandit: bool = Form(True),
    semgrep: bool = Form(False),
    fail_on: str = Form(settings.default_fail_on),
    db: Session = Depends(get_db),
):
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "envie um arquivo .zip")
    ws = new_workspace("upload-")
    zip_path = ws.parent / f"{ws.name}.zip"
    limit = settings.max_upload_mb * 1024 * 1024
    size = 0
    with open(zip_path, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                out.close()
                zip_path.unlink(missing_ok=True)
                cleanup(ws)
                raise HTTPException(413, f"upload maior que {settings.max_upload_mb}MB")
            out.write(chunk)
    try:
        extract_zip(zip_path, ws)
    except WorkspaceError as exc:
        cleanup(ws)
        raise HTTPException(400, str(exc)) from exc
    finally:
        zip_path.unlink(missing_ok=True)

    proj = get_or_create_project(db, project.strip()[:200])
    scan = models.Scan(project_id=proj.id, source_type="upload", source_ref=file.filename, triggered_by="ui",
                       options={"ai": ai, "bandit": bandit, "semgrep": semgrep, "fail_on": fail_on})
    db.add(scan)
    db.commit()
    dispatch_scan(scan.id, str(ws))
    db.refresh(scan)
    return scan_out(scan)


@router.post("/git", status_code=202)
def create_git_scan(req: GitScanRequest, db: Session = Depends(get_db)):
    try:
        url = validate_git_url(req.repo_url)
    except WorkspaceError as exc:
        raise HTTPException(400, str(exc)) from exc
    name = req.project or url.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]
    proj = get_or_create_project(db, name, url)
    scan = models.Scan(project_id=proj.id, source_type="git", source_ref=url, branch=req.branch, triggered_by="ui",
                       options=req.model_dump(include={"ai", "bandit", "semgrep", "fail_on", "exclude"}))
    db.add(scan)
    db.commit()
    dispatch_scan(scan.id)
    db.refresh(scan)
    return scan_out(scan)


@router.post("/import", status_code=201, dependencies=[Depends(require_api_key)])
def import_scan(req: ImportRequest, db: Session = Depends(get_db)):
    """Recebe o resultado de um scan executado no pipeline CI/CD (CLI `sast scan --upload`)."""
    proj = get_or_create_project(db, req.project[:200], req.repo_url)
    scan = models.Scan(project_id=proj.id, source_type="ci", source_ref=req.repo_url, branch=req.branch,
                       commit_sha=req.commit, triggered_by=req.triggered_by[:20], status="running")
    db.add(scan)
    db.flush()
    persist_result(db, scan, req.result, req.gate)
    db.refresh(scan)
    return scan_out(scan)


@router.get("")
def list_scans(project_id: int | None = None, limit: int = Query(50, le=500), db: Session = Depends(get_db)):
    stmt = select(models.Scan).options(selectinload(models.Scan.project)).order_by(models.Scan.created_at.desc(),
                                                                                   models.Scan.id.desc())
    if project_id:
        stmt = stmt.where(models.Scan.project_id == project_id)
    return [scan_out(s) for s in db.scalars(stmt.limit(limit))]


@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    return scan_out(_get_scan(db, scan_id))


@router.get("/{scan_id}/findings")
def list_findings(
    scan_id: int,
    severity: str | None = None,
    status: str | None = None,
    engine: str | None = None,
    file: str | None = None,
    q: str | None = None,
    only_new: bool = False,
    db: Session = Depends(get_db),
):
    _get_scan(db, scan_id)
    stmt = select(models.Finding).where(models.Finding.scan_id == scan_id)
    if severity:
        stmt = stmt.where(models.Finding.effective_severity.in_([s.upper() for s in severity.split(",")]))
    if status:
        stmt = stmt.where(models.Finding.status.in_(status.split(",")))
    if engine:
        stmt = stmt.where(models.Finding.engine == engine)
    if file:
        stmt = stmt.where(models.Finding.file == file)
    if only_new:
        stmt = stmt.where(models.Finding.is_new.is_(True))
    rows = list(db.scalars(stmt))
    if q:
        needle = q.lower()
        rows = [f for f in rows if needle in f"{f.title} {f.file} {f.rule_id} {f.cwe} {f.message}".lower()]
    rows.sort(key=lambda f: (SEV_ORDER.get(f.effective_severity, 9), f.file, f.line))
    return [finding_out(f, full=False) for f in rows]


@router.get("/{scan_id}/sarif")
def scan_sarif(scan_id: int, db: Session = Depends(get_db)):
    from sast_engine.models import Finding as EngineFinding
    from sast_engine.models import ScanResult
    from sast_engine.reporting import to_sarif

    scan = _get_scan(db, scan_id)
    findings = [EngineFinding.from_dict(finding_out(f)) for f in scan.findings]
    return to_sarif(ScanResult(target=scan.source_ref or "", findings=findings))


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    db.delete(_get_scan(db, scan_id))
    db.commit()

