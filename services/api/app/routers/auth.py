from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .. import models
from ..auth import (
    COOKIE_NAME,
    _hash_token,
    authenticate,
    create_session,
    current_user,
    destroy_session,
    hash_password,
    require_admin,
    throttle,
    validate_new_password,
    verify_password,
)
from ..config import settings
from ..db import get_db

router = APIRouter(tags=["auth"])
audit = logging.getLogger("sast.audit")


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class NewUser(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(max_length=256)
    role: Literal["admin", "analyst"] = "analyst"


def user_out(user: models.User) -> dict:
    return {"id": user.id, "username": user.username, "role": user.role, "active": user.active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None}


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


@router.post("/api/auth/login")
def login(req: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    key = (req.username.strip().lower(), _client_ip(request))
    wait = throttle.locked_for(key)
    if wait:
        audit.warning("login bloqueado usuario=%s ip=%s", key[0], key[1])
        raise HTTPException(429, f"muitas tentativas; tente novamente em {wait} s")
    user = authenticate(db, req.username, req.password)
    if user is None:
        throttle.fail(key)
        audit.warning("login falhou usuario=%s ip=%s", key[0], key[1])
        raise HTTPException(401, "usuário ou senha inválidos")
    throttle.reset(key)
    token, expires = create_session(db, user)
    response.set_cookie(COOKIE_NAME, token, max_age=settings.session_hours * 3600, httponly=True,
                        samesite="strict", secure=settings.cookie_secure, path="/")
    audit.info("login ok usuario=%s ip=%s", user.username, key[1])
    return user_out(user)


@router.post("/api/auth/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    destroy_session(db, request.cookies.get(COOKIE_NAME))
    response.delete_cookie(COOKIE_NAME, path="/")


@router.get("/api/auth/me")
def me(user: models.User = Depends(current_user)):
    return user_out(user)


@router.post("/api/auth/password", status_code=204)
def change_password(req: PasswordChange, request: Request, user: models.User = Depends(current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(req.current_password, user.password_hash):
        raise HTTPException(400, "senha atual incorreta")
    validate_new_password(req.new_password, user.username)
    user.password_hash = hash_password(req.new_password)
    # encerra as outras sessões do usuário (ex.: um login esquecido em outra máquina); a atual continua
    current_hash = _hash_token(request.cookies.get(COOKIE_NAME, ""))
    db.execute(delete(models.UserSession).where(models.UserSession.user_id == user.id,
                                                models.UserSession.token_hash != current_hash))
    db.commit()
    audit.info("senha alterada usuario=%s", user.username)


# ------------------------------------------------------------------ gestão de usuários (admin)
@router.get("/api/users")
def list_users(_: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    return [user_out(u) for u in db.scalars(select(models.User).order_by(models.User.username))]


@router.post("/api/users", status_code=201)
def create_user(req: NewUser, admin: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.scalar(select(models.User).where(func.lower(models.User.username) == req.username.lower())):
        raise HTTPException(409, "usuário já existe")
    validate_new_password(req.password, req.username)
    user = models.User(username=req.username, password_hash=hash_password(req.password), role=req.role)
    db.add(user)
    db.commit()
    audit.info("usuario criado %s (%s) por %s", user.username, user.role, admin.username)
    return user_out(user)


@router.delete("/api/users/{user_id}", status_code=204)
def delete_user(user_id: int, admin: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.get(models.User, user_id)
    if user is None:
        raise HTTPException(404, "usuário não encontrado")
    if user.id == admin.id:
        raise HTTPException(400, "você não pode remover o próprio usuário")
    db.delete(user)
    db.commit()
    audit.info("usuario removido %s por %s", user.username, admin.username)
