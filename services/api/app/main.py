"""API REST da plataforma SAST Sentinel (FastAPI).

Documentação interativa: http://localhost:8000/docs
"""

from __future__ import annotations

import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .config import settings
from .db import init_db
from .routers import findings, metrics, misc, scans

logger = logging.getLogger("sast.api")

# mesma política do nginx.conf do dashboard (usada quando a API serve o frontend)
FRONTEND_CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                "connect-src 'self'")


def _seed_if_empty() -> None:
    from sqlalchemy import func, select

    from . import models
    from .db import SessionLocal
    from .seed import find_samples, seed

    db = SessionLocal()
    try:
        empty = db.scalar(select(func.count(models.Project.id))) == 0
    finally:
        db.close()
    if not empty:
        return
    try:
        seed(find_samples(), days=10)
    except Exception:  # noqa: BLE001 - a demo é opcional; a API sobe mesmo assim
        logger.exception("falha ao popular o histórico de demonstração")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    if settings.scan_runner == "thread":
        from .worker import fail_interrupted_scans

        fail_interrupted_scans()
    if settings.seed_on_startup:
        # em segundo plano: a porta abre na hora (as plataformas de deploy checam isso)
        threading.Thread(target=_seed_if_empty, name="seed", daemon=True).start()
    yield


app = FastAPI(
    title="SAST Sentinel API",
    version="1.0.0",
    description="Plataforma SAST com taint analysis, triagem por LLM local e Security Gates para CI/CD.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "X-API-Key"],
)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(metrics.router)
app.include_router(misc.router)


# --- Dashboard servido pela própria API (deploy em contêiner único) -------------------------
_static = Path(settings.static_dir).resolve() if settings.static_dir else None
if _static and (_static / "index.html").is_file():
    # allowlist fechada com os arquivos do build: a URL nunca vira caminho no disco (sem path traversal)
    STATIC_FILES = {p.relative_to(_static).as_posix(): p for p in _static.rglob("*") if p.is_file()}
    INDEX_HTML = _static / "index.html"

    @app.get("/{path:path}", include_in_schema=False)
    def frontend(path: str):
        if path.startswith("api/"):
            raise HTTPException(404, "rota inexistente")
        if path not in STATIC_FILES:
            # qualquer rota que não é arquivo do build pertence ao React (SPA) -> index.html
            response = FileResponse(INDEX_HTML, headers={"Cache-Control": "no-cache"})
        else:
            response = FileResponse(STATIC_FILES[path])
            if path.startswith("assets/"):  # nomes com hash do Vite: cache longo é seguro
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        response.headers["Content-Security-Policy"] = FRONTEND_CSP
        return response
