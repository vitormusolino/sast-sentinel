"""Preparacao segura do código a ser analisado.

A própria plataforma de segurança e um alvo: aceitar zips e URLs arbitrarias
abre espaco para Zip Slip, zip bombs, SSRF e injeção de argumentos no git.
Por isso:
  * zip: limite de tamanho descompactado e de arquivos, rejeita caminhos
    absolutos/`..` e links simbolicos;
  * git: apenas https:// para hosts em allowlist, `--` antes da URL, clone raso,
    sem prompt de credencial e com timeout.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from .config import settings

BRANCH_RE = re.compile(r"^[A-Za-z0-9._/\-]{1,200}$")


class WorkspaceError(ValueError):
    pass


def new_workspace(prefix: str) -> Path:
    base = Path(settings.workspace_dir)
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base))


def cleanup(path: Path | str | None) -> None:
    if path:
        shutil.rmtree(path, ignore_errors=True)


def extract_zip(zip_path: Path, dest: Path) -> int:
    max_bytes = settings.max_upload_mb * 1024 * 1024 * 4  # descompactado até 4x o upload
    total = 0
    count = 0
    dest_resolved = dest.resolve()
    try:
        archive = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise WorkspaceError("arquivo enviado não e um zip válido") from exc
    with archive:
        for info in archive.infolist():
            name = info.filename
            if info.is_dir():
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                continue  # ignora symlinks
            parts = PurePosixPath(name.replace("\\", "/")).parts
            if name.startswith(("/", "\\")) or ".." in parts or (parts and ":" in parts[0]):
                raise WorkspaceError(f"caminho inseguro no zip: {name}")
            target = (dest / Path(*parts)).resolve()
            if not str(target).startswith(str(dest_resolved) + os.sep):
                raise WorkspaceError(f"caminho inseguro no zip: {name}")
            count += 1
            total += info.file_size
            if count > settings.max_zip_files:
                raise WorkspaceError(f"zip com mais de {settings.max_zip_files} arquivos")
            if total > max_bytes:
                raise WorkspaceError("conteúdo descompactado excede o limite (possível zip bomb)")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, length=1024 * 64)
    return count


def validate_git_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme != "https":
        raise WorkspaceError("apenas URLs https:// são aceitas")
    host = (parsed.hostname or "").lower()
    if host not in settings.allowed_git_hosts:
        raise WorkspaceError(f"host '{host}' fora da allowlist ({', '.join(settings.allowed_git_hosts)})")
    if parsed.username or parsed.password:
        raise WorkspaceError("não envie credenciais na URL")
    return parsed.geturl()


def clone_repo(url: str, dest: Path, branch: str | None = None, timeout: int = 180) -> str | None:
    url = validate_git_url(url)
    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--no-tags"]
    if branch:
        if not BRANCH_RE.match(branch) or branch.startswith("-"):
            raise WorkspaceError("nome de branch inválido")
        cmd += ["--branch", branch]
    cmd += ["--", url, str(dest)]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)  # nosec - lista fixa, URL validada
    except subprocess.TimeoutExpired as exc:
        raise WorkspaceError("tempo limite excedido ao clonar o repositório") from exc
    if proc.returncode != 0:
        raise WorkspaceError(f"falha no git clone: {proc.stderr.strip()[:300]}")
    head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True,  # nosec
                          timeout=10, check=False)
    return head.stdout.strip() or None
