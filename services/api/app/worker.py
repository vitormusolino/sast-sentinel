"""Processamento assincrono com Celery + Redis.

A API apenas registra o scan e pública uma mensagem na fila; workers
independentes (escalaveis horizontalmente: `docker compose up --scale worker=4`)
fazem o trabalho pesado de clonar, analisar e consultar o LLM.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from celery import Celery

from .config import settings
from .db import SessionLocal, init_db
from .models import Scan, utcnow
from .services import persist_result, triage_map
from .workspace import WorkspaceError, cleanup, clone_repo

logger = logging.getLogger("sast.worker")

celery_app = Celery("sast", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    task_always_eager=settings.celery_eager,
    task_eager_propagates=False,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=60 * 30,
    task_soft_time_limit=60 * 28,
    task_default_queue="scans",
    broker_connection_retry_on_startup=True,
)


@celery_app.on_after_configure.connect
def _setup(**_kwargs) -> None:  # pragma: no cover - so no worker real
    init_db()


@celery_app.task(name="sast.run_scan", bind=True, max_retries=1)
def run_scan(self, scan_id: int, workspace: str | None = None) -> dict:
    from sast_engine import ScanConfig, Scanner
    from sast_engine.ai import AIAnalyzer
    from sast_engine.gate import GatePolicy, evaluate
    from sast_engine.models import Severity

    db = SessionLocal()
    scan = db.get(Scan, scan_id)
    if scan is None:
        db.close()
        return {"error": "scan inexistente"}
    ws = Path(workspace) if workspace else None
    last_commit = [0.0]

    def progress(msg: str, pct: float) -> None:
        # limita escritas no banco a ~2 por segundo
        now = time.monotonic()
        if now - last_commit[0] > 0.5 or pct >= 1.0:
            scan.progress, scan.message = round(0.1 + pct * 0.8, 3), msg
            db.commit()
            last_commit[0] = now

    try:
        scan.status, scan.started_at = "running", utcnow()
        scan.message = "preparando código-fonte"
        db.commit()
        if scan.source_type == "git":
            ws = ws or Path(_workspace_for(scan_id))
            scan.commit_sha = clone_repo(scan.source_ref or "", ws, scan.branch)
            db.commit()
        if ws is None or not ws.exists():
            raise WorkspaceError("workspace não encontrado")

        opts = scan.options or {}
        config = ScanConfig(
            use_bandit=bool(opts.get("bandit", True)),
            use_semgrep=bool(opts.get("semgrep", False)),
            use_ai=bool(opts.get("ai", settings.ai_default)),
            ai_max_findings=int(opts.get("ai_max_findings", settings.ai_max_findings)),
            excludes=list(opts.get("exclude", [])),
        )
        result = Scanner(config, progress).scan_path(ws)

        decisions = triage_map(db, scan.project_id)
        for f in result.findings:
            if f.fingerprint in decisions:
                f.status = decisions[f.fingerprint]
        policy = GatePolicy(fail_on=Severity.parse(opts.get("fail_on", settings.default_fail_on)))
        gate = evaluate(result, policy, baseline=set())

        summary = None
        if result.findings:
            open_f = [f for f in result.findings if f.status == "open"]
            summary = AIAnalyzer().executive_summary(
                result.counts(),
                Counter(f.file for f in open_f).most_common(5),
                Counter(f.cwe for f in open_f).most_common(5),
            ) if config.use_ai else None
        persist_result(db, scan, result.to_dict(), gate.to_dict(), summary)
        return {"scan_id": scan_id, "findings": len(result.findings), "gate": gate.passed}
    except WorkspaceError as exc:
        _fail(db, scan, str(exc))
        return {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - registra qualquer falha no scan
        logger.exception("scan %s falhou", scan_id)
        _fail(db, scan, f"erro interno: {type(exc).__name__}: {exc}")
        return {"error": str(exc)}
    finally:
        cleanup(ws)
        db.close()


_executor = None
_executor_lock = threading.Lock()


def dispatch_scan(scan_id: int, workspace: str | None = None) -> None:
    """Envia o scan para execução.

    * `SCAN_RUNNER=celery` (padrão, docker compose): publica na fila Redis para os workers.
    * `SCAN_RUNNER=thread` (deploy em contêiner único): roda em segundo plano no próprio
      processo da API, sem Redis. A requisição responde na hora e o dashboard acompanha
      o progresso normalmente.
    """
    global _executor
    if settings.scan_runner == "thread" and not settings.celery_eager:
        with _executor_lock:
            if _executor is None:
                _executor = ThreadPoolExecutor(max_workers=max(1, settings.scan_threads),
                                               thread_name_prefix="scan")
        _executor.submit(run_scan, scan_id, workspace)
    else:
        run_scan.delay(scan_id, workspace)


def fail_interrupted_scans() -> int:
    """No modo thread, scans que estavam na fila/rodando quando o processo reiniciou nunca terminarão."""
    db = SessionLocal()
    try:
        stuck = db.query(Scan).filter(Scan.status.in_(["queued", "running"]), Scan.source_type != "ci").all()
        for scan in stuck:
            scan.status, scan.message, scan.finished_at = "failed", "interrompido por reinício do servidor", utcnow()
        db.commit()
        return len(stuck)
    finally:
        db.close()


def _workspace_for(scan_id: int) -> str:
    from .workspace import new_workspace

    return str(new_workspace(f"scan{scan_id}-"))


def _fail(db, scan: Scan, message: str) -> None:
    db.rollback()
    scan.status, scan.message, scan.finished_at = "failed", message[:1000], utcnow()
    db.commit()
