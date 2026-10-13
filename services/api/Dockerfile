# Imagem unica para API (uvicorn) e worker (celery) - contexto de build: raiz do repositorio
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/api/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# Semgrep em venv isolado (evita conflito de dependencias com a API)
RUN python -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install semgrep==1.179.0 \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

COPY engine /opt/engine
RUN pip install /opt/engine

COPY services/api/app /app/app

# usuario sem privilegios (principio do menor privilegio)
RUN useradd --create-home --uid 10001 sast \
    && mkdir -p /workspaces \
    && chown -R sast:sast /workspaces /app
USER sast

ENV WORKSPACE_DIR=/workspaces
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
