import json
from pathlib import Path

import pytest
from sast_engine.ai.analyzer import AIAnalyzer, AIConfig, enclosing_block, verify_python_fix
from sast_engine.ai.llm import parse_json_loose
from sast_engine.benchmark import load_ground_truth, score
from sast_engine.cli import main
from sast_engine.gate import GatePolicy, evaluate
from sast_engine.models import Finding, Severity
from sast_engine.reporting import to_markdown, to_sarif
from sast_engine.scanner import ScanConfig, Scanner, deduplicate

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


@pytest.fixture(scope="module")
def vuln_result():
    return Scanner(ScanConfig()).scan_path(SAMPLES / "vulnerable_app")


def test_scan_vulnerable_app(vuln_result):
    assert vuln_result.files_scanned >= 4
    rules = {f.rule_id for f in vuln_result.findings}
    assert {"TAINT-SQLI", "TAINT-CMDI", "PY001", "PY005"} <= rules
    assert vuln_result.counts()["CRITICAL"] >= 5


def test_safe_app_has_no_python_findings():
    result = Scanner(ScanConfig()).scan_path(SAMPLES / "safe_app")
    assert [f for f in result.findings if f.file.endswith(".py")] == []


def test_benchmark_precision_floor():
    result = Scanner(ScanConfig()).scan_path(SAMPLES)
    total, _ = score(result.findings, load_ground_truth(SAMPLES))
    assert total.precision >= 0.9
    assert total.recall >= 0.9


def test_dedupe_merges_engines_within_tolerance():
    a = Finding("TAINT-SQLI", "t", "m", Severity.CRITICAL, "CWE-89", "a.py", 10, engine="taint")
    b = Finding("PY006", "t", "m", Severity.HIGH, "CWE-89", "a.py", 10, engine="ast")
    c = Finding("BANDIT-B608", "t", "m", Severity.MEDIUM, "CWE-89", "a.py", 9, engine="bandit")
    merged = deduplicate([a, b, c])
    assert len(merged) == 1
    assert merged[0].engine == "taint"
    assert merged[0].confirmed_by == ["ast", "bandit"]
    assert merged[0].confidence == "HIGH"


def test_gate_policy_and_baseline(vuln_result):
    gate = evaluate(vuln_result, GatePolicy(fail_on=Severity.HIGH), baseline=set())
    assert not gate.passed
    baseline = {f.fingerprint for f in vuln_result.findings}
    gate2 = evaluate(vuln_result, GatePolicy(fail_on=Severity.HIGH), baseline=baseline)
    assert gate2.passed and gate2.baseline_matched == len(vuln_result.findings)
    gate3 = evaluate(vuln_result, GatePolicy(fail_on=None, max_counts={"MEDIUM": 100}), baseline=set())
    assert gate3.passed


def test_gate_respects_ai_false_positive(vuln_result):
    f = vuln_result.findings[0]
    single = type(vuln_result)(target="x", findings=[f])
    f_status = f.status
    f.status = "likely_false_positive"
    try:
        assert evaluate(single, GatePolicy(), baseline=set()).passed
    finally:
        f.status = f_status


def test_sarif_structure(vuln_result):
    sarif = to_sarif(vuln_result)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert len(run["results"]) == len(vuln_result.findings)
    flows = [r for r in run["results"] if "codeFlows" in r]
    assert flows, "achados de taint devem exportar codeFlows"
    assert all("security-severity" in r["properties"] for r in run["tool"]["driver"]["rules"])


def test_markdown_summary(vuln_result):
    gate = evaluate(vuln_result, GatePolicy(), baseline=set())
    md = to_markdown(vuln_result, gate)
    assert "BLOQUEADO" in md and "CRITICAL" in md


def test_cli_exit_codes(tmp_path):
    out = tmp_path / "r.json"
    assert main(["scan", str(SAMPLES / "vulnerable_app"), "--format", "json", "--json", str(out), "--no-ai"]) == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["gate"]["status"] == "FAILED"
    assert main(["scan", str(SAMPLES / "safe_app"), "--format", "markdown", "--no-ai"]) == 0
    assert main(["scan", str(SAMPLES / "vulnerable_app"), "--no-fail", "--format", "markdown"]) == 0


# ------------------------------------------------------------------ IA
class FakeClient:
    model = "fake-llm"

    def __init__(self, response):
        self.response = response
        self.prompts = []

    def available(self):
        return True

    def generate_json(self, prompt, system=""):
        self.prompts.append(prompt)
        return self.response


VULN_SRC = '''import os
from flask import request

def view():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "ok"
'''
FIXED_BLOCK = '''def view():
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host], check=True)
    return "ok"'''


def _finding():
    return Finding("TAINT-CMDI", "Command Injection", "m", Severity.CRITICAL, "CWE-78", "app.py", 6, engine="taint")


def test_enclosing_block():
    assert enclosing_block(VULN_SRC, 6) == (4, 7)


def test_fix_verification_accepts_real_fix_and_rejects_fake():
    ok = verify_python_fix(VULN_SRC, _finding(), 4, 7, FIXED_BLOCK)
    assert ok["fix_verified"] is True
    bad = verify_python_fix(VULN_SRC, _finding(), 4, 7, FIXED_BLOCK.replace(
        'subprocess.run(["ping", "-c", "1", host], check=True)', 'os.system("ping " + host)'))
    assert bad["fix_verified"] is False
    broken = verify_python_fix(VULN_SRC, _finding(), 4, 7, "def view(:\n  pass")
    assert "SyntaxError" in broken["fix_check"]


def test_llm_guardrails_limit_severity_and_fp():
    client = FakeClient({"is_false_positive": True, "confidence": 0.85, "severity": "INFO",
                         "explanation": "x", "fixed_code": FIXED_BLOCK})
    finding = _finding()
    stats = AIAnalyzer(client, AIConfig()).enrich([finding], {"app.py": VULN_SRC})
    # taint comprovado nao e rebaixado; taint exige confianca >= 0.9 para virar FP
    assert finding.ai["severity"] == "CRITICAL"
    assert finding.status == "open"
    assert finding.ai["fix_verified"] is True
    assert stats["mode"] == "llm" and stats["fixes_verified"] == 1
    assert "linha 6" in client.prompts[0] or ">>   6" in client.prompts[0]


def test_heuristic_mode_when_llm_unavailable():
    class Down(FakeClient):
        def available(self):
            return False
    finding = _finding()
    finding.file = "tests/test_app.py"
    AIAnalyzer(Down(None), AIConfig()).enrich([finding], {})
    assert finding.ai["mode"] == "heuristic"
    assert finding.ai["severity"] == "HIGH"  # arquivo de teste reduz 1 nivel
    assert finding.ai["fixed_code"]


def test_parse_json_loose():
    assert parse_json_loose('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json_loose('Claro! Aqui esta: {"a": 2} espero ter ajudado') == {"a": 2}
    assert parse_json_loose("nada") is None


# ------------------------------------------------------------------ integracoes
def test_bandit_integration_normalizes_cwe():
    from sast_engine.integrations import BANDIT_IGNORED, run_bandit, tool_available

    if not tool_available("bandit"):
        pytest.skip("bandit nao instalado")
    findings, err = run_bandit(SAMPLES / "vulnerable_app", [])
    assert err is None and findings
    assert all(f.rule_id.split("-")[1] not in BANDIT_IGNORED for f in findings)
    assert any(f.cwe == "CWE-798" for f in findings)  # B105 normalizado de CWE-259


def test_scanner_with_bandit_builds_consensus():
    result = Scanner(ScanConfig(use_bandit=True)).scan_path(SAMPLES / "vulnerable_app")
    if "bandit" not in result.engines:
        pytest.skip("bandit nao instalado")
    assert any("bandit" in f.confirmed_by for f in result.findings)


def test_ollama_client_offline_and_mocked(monkeypatch, tmp_path):
    import httpx
    from sast_engine.ai.llm import OllamaClient

    offline = OllamaClient(base_url="http://127.0.0.1:9", timeout=1)
    assert offline.available() is False
    assert offline.generate_json("x") is None

    class Resp:
        status_code = 200

        def __init__(self, data):
            self._data = data

        def json(self):
            return self._data

        def raise_for_status(self):
            return None

    calls = []
    monkeypatch.setattr(httpx, "get", lambda *a, **k: Resp({"models": [{"name": "llama3.2:3b"}]}))

    def fake_post(url, json, timeout):
        calls.append(json)
        return Resp({"response": '{"is_false_positive": false, "severity": "HIGH"}'})

    monkeypatch.setattr(httpx, "post", fake_post)
    client = OllamaClient(model="llama3.2:3b", cache_dir=str(tmp_path))
    assert client.available()
    assert client.generate_json("prompt")["severity"] == "HIGH"
    assert client.generate_json("prompt")["severity"] == "HIGH"  # segunda vez vem do cache
    assert len(calls) == 1 and calls[0]["format"] == "json"


def test_baseline_cli_roundtrip(tmp_path):
    baseline = tmp_path / "baseline.json"
    assert main(["baseline", str(SAMPLES / "vulnerable_app"), "-o", str(baseline)]) == 0
    assert main(["scan", str(SAMPLES / "vulnerable_app"), "--baseline", str(baseline), "--format", "markdown"]) == 0


def test_rules_command(capsys):
    assert main(["rules"]) == 0
    assert "TAINT-SQLI" in capsys.readouterr().out


def test_severity_change_limited_to_one_level_for_rules():
    client = FakeClient({"is_false_positive": False, "confidence": 0.9, "severity": "INFO", "fixed_code": ""})
    finding = Finding("PY001", "t", "m", Severity.HIGH, "CWE-798", "app.py", 1, engine="ast")
    AIAnalyzer(client, AIConfig()).enrich([finding], {"app.py": "PASSWORD = 'x1y2z3w4'\n"})
    assert finding.ai["severity"] == "MEDIUM"


def test_clean_llm_text():
    from sast_engine.ai.analyzer import clean_llm_text

    assert clean_llm_text('```json\n{"resumo": "Texto final."}\n```') == "Texto final."
    assert clean_llm_text("Texto simples.") == "Texto simples."


def test_file_with_utf8_bom_is_analyzed(tmp_path):
    # editores do Windows (Bloco de Notas, PowerShell) salvam com BOM; antes o arquivo era ignorado
    (tmp_path / "app.py").write_bytes(b"\xef\xbb\xbfimport os\nos.system(input())\n")
    result = Scanner(ScanConfig()).scan_path(tmp_path)
    assert not result.errors
    assert any(f.cwe == "CWE-78" for f in result.findings)


def test_unsupported_language_is_not_approved(tmp_path):
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n")
    result = Scanner(ScanConfig(semgrep_fallback=False)).scan_path(tmp_path)
    assert any("Go" in e["error"] for e in result.errors)
    gate = evaluate(result, GatePolicy(), baseline=set())
    assert not gate.passed and gate.to_dict()["status"] == "NOT_ANALYZED"


def test_openai_compat_client_and_selection(monkeypatch, tmp_path):
    import httpx
    from sast_engine.ai.llm import OllamaClient, OpenAICompatClient, make_client

    monkeypatch.delenv("LLM_API_KEY", raising=False)
    assert isinstance(make_client(), OllamaClient)
    monkeypatch.setenv("LLM_API_KEY", "chave-de-teste")
    client = make_client()
    assert isinstance(client, OpenAICompatClient) and client.model == "llama-3.1-8b-instant"

    class Resp:
        def __init__(self, status, data):
            self.status_code, self._data = status, data

        def json(self):
            return self._data

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError("erro", request=None, response=None)

    calls = []
    monkeypatch.setattr(httpx, "get", lambda url, headers, timeout: Resp(200, {"data": []}))

    def fake_post(url, json, headers, timeout):
        calls.append(json)
        if "response_format" in json:  # simula provedor sem modo JSON
            return Resp(400, {})
        return Resp(200, {"choices": [{"message": {"content": '```json\n{"severity": "HIGH"}\n```'}}]})

    monkeypatch.setattr(httpx, "post", fake_post)
    client = OpenAICompatClient("https://exemplo/v1", "k", "m", cache_dir=str(tmp_path))
    assert client.available()
    assert client.generate_json("prompt")["severity"] == "HIGH"
    assert client.generate_json("prompt")["severity"] == "HIGH"  # cache
    assert len(calls) == 2 and "response_format" not in calls[1]
    assert OpenAICompatClient("https://exemplo/v1", "", "m").available() is False
