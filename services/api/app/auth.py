"""Autenticação: senhas com scrypt, sessões por cookie HttpOnly e proteção contra força bruta.

Decisões de segurança (OWASP A07 - Identification and Authentication Failures):
* **scrypt** (stdlib) com salt aleatório por usuário: custo de memória alto torna ataques
  com GPU/ASIC caros; comparação em tempo constante (hmac.compare_digest).
* **Token de sessão** aleatório de 256 bits entregue em cookie `HttpOnly` (JavaScript não lê:
  mitiga roubo por XSS) e `SameSite=Strict` (navegador não envia em requisições de outros
  sites: mitiga CSRF). No banco fica só o **SHA-256 do token**.
* **Bloqueio após N falhas** por usuário+IP e mensagem/tempo de resposta idênticos para
  usuário inexistente (evita enumeração de usuários).
* **Sem senha padrão**: o admin inicial vem de ADMIN_PASSWORD ou recebe uma senha aleatória
  exibida uma única vez no log.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import models
from .config import settings
from .db import SessionLocal, get_db
from .models import utcnow

logger = logging.getLogger("sast.auth")

COOKIE_NAME = "sast_session"
MIN_PASSWORD_LENGTH = 10
_SCRYPT = {"n": 2**14, "r": 8, "p": 1}


# ------------------------------------------------------------------ senhas
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **_SCRYPT)
    b64 = base64.b64encode
    return f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}${b64(salt).decode()}${b64(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        expected = base64.b64decode(hash_b64)
        digest = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64), dklen=len(expected),
                                n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(digest, expected)
    except (ValueError, TypeError):
        return False


# hash fixo para gastar o mesmo tempo quando o usuário não existe (anti-enumeração)
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def validate_new_password(password: str, username: str = "") -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(400, f"a senha deve ter pelo menos {MIN_PASSWORD_LENGTH} caracteres")
    if username and username.lower() in password.lower():
        raise HTTPException(400, "a senha não pode conter o nome de usuário")


# ------------------------------------------------------------------ força bruta
class LoginThrottle:
    """Contador em memória de falhas por (usuário, IP). Suficiente para uma instância da API."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures: dict[tuple[str, str], tuple[int, float]] = {}

    def locked_for(self, key: tuple[str, str]) -> int:
        with self._lock:
            count, until = self._failures.get(key, (0, 0.0))
            remaining = until - time.monotonic()
            return int(remaining) + 1 if count >= settings.login_max_attempts and remaining > 0 else 0

    def fail(self, key: tuple[str, str]) -> None:
        """Conta a falha numa janela de LOGIN_LOCK_MINUTES; ao atingir o limite, a janela vira bloqueio."""
        with self._lock:
            count, until = self._failures.get(key, (0, 0.0))
            now = time.monotonic()
            if until and now > until:
                count = 0  # janela/bloqueio anterior expirou
            self._failures[key] = (count + 1, now + settings.login_lock_minutes * 60)

    def reset(self, key: tuple[str, str]) -> None:
        with self._lock:
            self._failures.pop(key, None)


throttle = LoginThrottle()


# ------------------------------------------------------------------ sessões
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)  # SQLite devolve datetime sem fuso


def authenticate(db: Session, username: str, password: str) -> models.User | None:
    user = db.scalar(select(models.User).where(func.lower(models.User.username) == username.strip().lower()))
    if user is None or not user.active:
        verify_password(password, _DUMMY_HASH)  # mesmo custo de tempo
        return None
    return user if verify_password(password, user.password_hash) else None


def create_session(db: Session, user: models.User) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    expires = utcnow() + timedelta(hours=settings.session_hours)
    db.add(models.UserSession(token_hash=_hash_token(token), user_id=user.id, expires_at=expires))
    db.execute(delete(models.UserSession).where(models.UserSession.expires_at < utcnow()))  # limpeza
    user.last_login_at = utcnow()
    db.commit()
    return token, expires


def destroy_session(db: Session, token: str | None) -> None:
    if token:
        db.execute(delete(models.UserSession).where(models.UserSession.token_hash == _hash_token(token)))
        db.commit()


def current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    """Dependência do FastAPI: exige sessão válida (401 caso contrário)."""
    token = request.cookies.get(COOKIE_NAME)
    if token:
        session = db.scalar(select(models.UserSession).where(models.UserSession.token_hash == _hash_token(token)))
        if session is not None and _aware(session.expires_at) > utcnow() and session.user.active:
            return session.user
    raise HTTPException(401, "autenticação necessária")


def require_admin(user: models.User = Depends(current_user)) -> models.User:
    if user.role != "admin":
        raise HTTPException(403, "apenas administradores")
    return user


# ------------------------------------------------------------------ bootstrap
def ensure_admin() -> None:
    """Cria o admin inicial se ainda não houver nenhum usuário."""
    db = SessionLocal()
    try:
        if db.scalar(select(func.count(models.User.id))):
            return
        password = settings.admin_password
        generated = not password
        if generated:
            password = secrets.token_urlsafe(12)
        db.add(models.User(username=settings.admin_username, password_hash=hash_password(password), role="admin"))
        db.commit()
        if generated:
            logger.warning("=" * 60)
            logger.warning("Usuário admin criado: %s", settings.admin_username)
            logger.warning("Senha gerada (exibida só agora): %s", password)
            logger.warning("Defina ADMIN_PASSWORD no .env para escolher a senha.")
            logger.warning("=" * 60)
        else:
            logger.info("usuário admin '%s' criado a partir de ADMIN_PASSWORD", settings.admin_username)
    finally:
        db.close()
