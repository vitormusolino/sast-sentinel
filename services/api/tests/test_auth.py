"""Testes de segurança da autenticação (sessões, força bruta, autorização)."""

import tests.test_api  # noqa: F401 - garante as variáveis de ambiente de teste antes de importar o app
from app.auth import hash_password, verify_password
from app.main import app
from fastapi.testclient import TestClient

ADMIN = {"username": "admin", "password": "Senha-de-Teste-123"}


def new_client() -> TestClient:
    return TestClient(app)


def test_protected_routes_require_login():
    with new_client() as c:
        for path in ["/api/scans", "/api/metrics/overview", "/api/projects", "/api/rules", "/api/users"]:
            assert c.get(path).status_code == 401, path
        assert c.get("/api/health").status_code == 200  # público (healthcheck)


def test_login_sets_httponly_strict_cookie_and_logout_revokes():
    with new_client() as c:
        r = c.post("/api/auth/login", json=ADMIN)
        assert r.status_code == 200 and r.json()["role"] == "admin"
        cookie = r.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie
        assert c.get("/api/auth/me").json()["username"] == "admin"
        token = c.cookies.get("sast_session")
        assert c.post("/api/auth/logout").status_code == 204
        # o token antigo não vale mais, mesmo se alguém o tiver copiado
        c.cookies.set("sast_session", token)
        assert c.get("/api/auth/me").status_code == 401


def test_wrong_password_same_message_as_unknown_user_and_lockout():
    with new_client() as c:
        a = c.post("/api/auth/login", json={"username": "admin", "password": "errada"})
        b = c.post("/api/auth/login", json={"username": "nao-existe", "password": "errada"})
        assert a.status_code == b.status_code == 401
        assert a.json()["detail"] == b.json()["detail"]  # não revela se o usuário existe
        for _ in range(3):
            c.post("/api/auth/login", json={"username": "vitima", "password": "x"})
        r = c.post("/api/auth/login", json={"username": "vitima", "password": "x"})
        assert r.status_code == 429  # bloqueado após LOGIN_MAX_ATTEMPTS


def test_ci_import_uses_api_key_not_session():
    with new_client() as c:
        payload = {"project": "ci-auth", "result": {"findings": []}, "gate": {"passed": True}}
        assert c.post("/api/scans/import", json=payload).status_code == 401
        assert c.post("/api/scans/import", json=payload, headers={"X-API-Key": "ci-test-key"}).status_code == 201


def test_user_management_and_roles():
    with new_client() as admin:
        admin.post("/api/auth/login", json=ADMIN)
        assert admin.post("/api/users", json={"username": "ana", "password": "curta"}).status_code == 400
        assert admin.post("/api/users", json={"username": "ana", "password": "ana-senha-123"}).status_code == 400
        r = admin.post("/api/users", json={"username": "ana", "password": "Seguranca#2026", "role": "analyst"})
        assert r.status_code == 201
        ana_id = r.json()["id"]
        assert admin.post("/api/users", json={"username": "ANA", "password": "Seguranca#2026"}).status_code == 409

        with new_client() as ana:
            assert ana.post("/api/auth/login", json={"username": "ana", "password": "Seguranca#2026"}).status_code == 200
            assert ana.get("/api/scans").status_code == 200       # analista vê scans
            assert ana.get("/api/users").status_code == 403       # mas não gerencia usuários
            assert ana.post("/api/auth/password",
                            json={"current_password": "Seguranca#2026", "new_password": "Nova-Senha-2026"}).status_code == 204

        assert admin.delete(f"/api/users/{ana_id}").status_code == 204
        me = admin.get("/api/auth/me").json()
        assert admin.delete(f"/api/users/{me['id']}").status_code == 400  # não remove a si mesmo


def test_password_hash_is_salted_scrypt():
    h1, h2 = hash_password("mesma-senha-123"), hash_password("mesma-senha-123")
    assert h1 != h2 and h1.startswith("scrypt$")
    assert verify_password("mesma-senha-123", h1) and not verify_password("outra", h1)
