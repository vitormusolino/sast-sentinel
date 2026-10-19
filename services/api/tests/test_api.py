import io
import os
import tempfile
import zipfile
from pathlib import Path

_tmp = tempfile.mkdtemp()
os.environ.update({
    "DATABASE_URL": f"sqlite:///{_tmp}/test.db",
    "CELERY_EAGER": "1",
    "WORKSPACE_DIR": f"{_tmp}/ws",
    "AI_ENABLED_DEFAULT": "0",
    "API_KEY": "ci-test-key",
    "OLLAMA_URL": "http://127.0.0.1:9",  # porta fechada -> modo heuristico
    "ADMIN_USERNAME": "admin",
    "ADMIN_PASSWORD": "Senha-de-Teste-123",
    "LOGIN_MAX_ATTEMPTS": "3",
})
ADMIN = {"username": "admin", "password": "Senha-de-Teste-123"}

import pytest  # noqa: E402
from app.main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[3] / "samples"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        assert c.post("/api/auth/login", json=ADMIN).status_code == 200
        yield c


def make_zip(folder: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for p in folder.rglob("*"):
            if p.is_file() and "__pycache__" not in p.parts:
                z.write(p, p.relative_to(folder).as_posix())
    return buf.getvalue()


def upload(client, folder: Path, project: str):
    return client.post("/api/scans/upload",
                       files={"file": ("code.zip", make_zip(folder), "application/zip")},
                       data={"project": project, "ai": "false", "bandit": "false"})


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["database"] is True
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_upload_scan_flow(client):
    r = upload(client, SAMPLES / "vulnerable_app", "demo")
    assert r.status_code == 202, r.text
    scan_id = r.json()["id"]
    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "completed", scan["message"]
    assert scan["gate_passed"] is False
    assert scan["counts"]["CRITICAL"] >= 5

    findings = client.get(f"/api/scans/{scan_id}/findings", params={"severity": "CRITICAL"}).json()
    assert findings and all(f["effective_severity"] == "CRITICAL" for f in findings)

    detail = client.get(f"/api/findings/{findings[0]['id']}").json()
    assert detail["trace"] and detail["remediation"]

    sarif = client.get(f"/api/scans/{scan_id}/sarif").json()
    assert sarif["version"] == "2.1.0"


def test_triage_persists_to_next_scan(client):
    first = upload(client, SAMPLES / "vulnerable_app", "triage").json()["id"]
    target = client.get(f"/api/scans/{first}/findings").json()[0]
    r = client.patch(f"/api/findings/{target['id']}", json={"status": "false_positive", "reason": "teste"})
    assert r.json()["status"] == "false_positive"

    second = upload(client, SAMPLES / "vulnerable_app", "triage").json()["id"]
    again = [f for f in client.get(f"/api/scans/{second}/findings").json() if f["fingerprint"] == target["fingerprint"]]
    assert again[0]["status"] == "false_positive"
    scan2 = client.get(f"/api/scans/{second}").json()
    assert scan2["new_count"] == 0 and scan2["fixed_count"] == 0


def test_fixed_findings_are_counted(client):
    upload(client, SAMPLES / "vulnerable_app", "evolucao")
    second = upload(client, SAMPLES / "safe_app", "evolucao").json()
    assert second["fixed_count"] > 0


def test_import_requires_api_key(client):
    payload = {"project": "ci-proj", "branch": "main", "commit": "abc123", "result": {"findings": []},
               "gate": {"passed": True}}
    assert client.post("/api/scans/import", json=payload).status_code == 401
    r = client.post("/api/scans/import", json=payload, headers={"X-API-Key": "ci-test-key"})
    assert r.status_code == 201 and r.json()["gate_passed"] is True


def test_metrics_overview(client):
    data = client.get("/api/metrics/overview").json()
    assert data["kpis"]["projects"] >= 1
    assert set(data["severity"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    assert data["trend"] and data["top_files"]
    assert data["top_files"][0]["risk"] >= data["top_files"][-1]["risk"]


def test_zip_slip_rejected(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../evil.py", "print('x')")
    r = client.post("/api/scans/upload", files={"file": ("x.zip", buf.getvalue(), "application/zip")},
                    data={"project": "evil"})
    assert r.status_code == 400 and "inseguro" in r.json()["detail"]


@pytest.mark.parametrize("url", ["http://github.com/a/b", "https://evil.internal/a/b", "file:///etc/passwd",
                                 "https://user:pass@github.com/a/b"])
def test_git_url_validation(client, url):
    assert client.post("/api/scans/git", json={"repo_url": url}).status_code == 400


def test_rules_and_projects(client):
    assert any(r["id"] == "TAINT-SQLI" for r in client.get("/api/rules").json())
    assert any(p["name"] == "demo" for p in client.get("/api/projects").json())
