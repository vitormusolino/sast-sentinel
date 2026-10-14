"""Configuração via variáveis de ambiente (12-factor)."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _list(name: str, default: str) -> list[str]:
    return [v.strip() for v in os.getenv(name, default).split(",") if v.strip()]


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./sast.db")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    celery_eager: bool = _bool("CELERY_EAGER", False)
    api_key: str = os.getenv("API_KEY", "")
    workspace_dir: str = os.getenv("WORKSPACE_DIR", os.path.join(tempfile.gettempdir(), "sast-workspaces"))
    max_upload_mb: int = int(os.getenv("MAX_UPLOAD_MB", "50"))
    max_zip_files: int = int(os.getenv("MAX_ZIP_FILES", "5000"))
    allowed_git_hosts: list[str] = field(default_factory=lambda: _list(
        "ALLOWED_GIT_HOSTS", "github.com,gitlab.com,bitbucket.org"))
    cors_origins: list[str] = field(default_factory=lambda: _list(
        "CORS_ORIGINS", "http://localhost:5173,http://localhost:8080"))
    default_fail_on: str = os.getenv("GATE_FAIL_ON", "HIGH")
    ai_default: bool = _bool("AI_ENABLED_DEFAULT", True)
    ai_max_findings: int = int(os.getenv("AI_MAX_FINDINGS", "10"))
    # Modo "contêiner único" (deploy em Render/Railway/etc.): sem Redis nem workers separados.
    #   celery = fila Redis + workers (docker compose) | thread = scans em segundo plano no próprio processo
    scan_runner: str = os.getenv("SCAN_RUNNER", "celery").strip().lower()
    scan_threads: int = int(os.getenv("SCAN_THREADS", "1"))
    # pasta com o build do dashboard (vite build); se definida, a API também serve o frontend
    static_dir: str = os.getenv("STATIC_DIR", "")
    # popula o histórico de demonstração na subida se o banco estiver vazio (bom para disco efêmero)
    seed_on_startup: bool = _bool("SEED_ON_STARTUP", False)


settings = Settings()
