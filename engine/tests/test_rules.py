import textwrap

import pytest
from sast_engine.models import Severity
from sast_engine.parsers.python_parser import parse_python
from sast_engine.rules.python_rules import run_python_rules


def scan(code: str):
    module = parse_python("t.py", textwrap.dedent(code))
    findings, suppressed = run_python_rules(module)
    return findings, suppressed


def rule_ids(code: str) -> list[str]:
    return [f.rule_id for f in scan(code)[0]]


@pytest.mark.parametrize("code", [
    'DB_PASSWORD = "Sup3rS3nh@2024"',
    'config["api_key"] = "abcd1234efgh"',
    'connect(host="db", password="hunter22")',
    'def login(user, password="admin123"): pass',
    'creds = {"secret": "x9f8g7h6"}',
    'if pwd == "admin123": pass',
    'url = "postgres://app:S3nh4Forte@db:5432/prod"',
    'k = "AKIAIOSFODNN7EXAMPLE1"',
    'SENHA_BANCO = "minhaSenha123"',
    'chave_api = "a8f5f167f44f4964e6c998dee827110c"',
    'conectar(usuario="app", senha="Pr0ducao!")',
])
def test_hardcoded_secret_detected(code):
    assert "PY001" in rule_ids(code)


@pytest.mark.parametrize("code", [
    'PASSWORD_FIELD = "password"',
    'TOKEN_URL = "https://auth.example.com/token"',
    'password = os.environ["DB_PASSWORD"]',
    'api_key = ""',
    'API_KEY = "your-api-key-here"',
    'password_prompt = "Digite sua senha"',
    'passwordLabel = "Senha"',
    'token_type = "bearer"',
    'campo_senha = "senha"',
    'chave_primaria = "id_cliente"',
])
def test_hardcoded_secret_false_positive_traps(code):
    assert "PY001" not in rule_ids(code)


def test_eval_dynamic_vs_literal():
    findings, _ = scan("eval(user_input)\neval('1+1')")
    sev = {f.line: f.severity for f in findings if f.rule_id == "PY002"}
    assert sev[1] == Severity.HIGH
    assert sev[2] == Severity.LOW


def test_import_alias_resolution():
    code = """
    from os import system as run_cmd
    import subprocess as sp
    run_cmd(cmd)
    sp.Popen(cmd, shell=True)
    sp.run(["ls"], shell=False)
    """
    ids = [(f.rule_id, f.line) for f in scan(code)[0]]
    assert ("PY003", 4) in ids
    assert ("PY003", 5) in ids
    assert all(line != 6 for _, line in ids)


def test_deserialization():
    code = """
    import pickle, yaml
    pickle.loads(data)
    yaml.load(data)
    yaml.load(data, Loader=yaml.SafeLoader)
    yaml.safe_load(data)
    """
    lines = [f.line for f in scan(code)[0] if f.rule_id == "PY004"]
    assert lines == [3, 4]


def test_weak_hash_respects_usedforsecurity():
    code = """
    import hashlib
    hashlib.md5(x)
    hashlib.md5(x, usedforsecurity=False)
    hashlib.new("sha1")
    hashlib.sha256(x)
    """
    lines = [f.line for f in scan(code)[0] if f.rule_id == "PY005"]
    assert lines == [3, 5]


def test_dynamic_sql_and_tracked_variable():
    code = """
    def f(cur, name):
        cur.execute(f"SELECT * FROM u WHERE n = '{name}'")
        q = "SELECT * FROM u WHERE n = '" + name + "'"
        cur.execute(q)
        cur.execute("SELECT * FROM u WHERE n = ?", (name,))
        cur.execute(QUERY % TABLE)
    """
    lines = [f.line for f in scan(code)[0] if f.rule_id == "PY006"]
    assert lines == [3, 5]


def test_misc_rules():
    code = """
    import requests, tempfile, ssl
    app.run(host="0.0.0.0", debug=True)
    requests.get(url, verify=False, timeout=3)
    requests.get(url)
    tempfile.mktemp()
    try:
        x()
    except Exception:
        pass
    """
    ids = set(rule_ids(code))
    assert {"PY007", "PY011", "PY008", "PY016", "PY009", "PY015"} <= ids


def test_random_for_token():
    code = """
    import random
    reset_token = random.randint(100000, 999999)
    dice = random.randint(1, 6)
    """
    lines = [f.line for f in scan(code)[0] if f.rule_id == "PY010"]
    assert lines == [3]


def test_suppression_comment():
    findings, suppressed = scan('eval(x)  # nosec - revisado pela equipe')
    assert findings == [] and suppressed == 1


def test_weak_cipher():
    code = """
    from Crypto.Cipher import DES, AES
    DES.new(k, DES.MODE_ECB)
    AES.new(k, AES.MODE_ECB)
    AES.new(k, AES.MODE_GCM)
    """
    lines = [f.line for f in scan(code)[0] if f.rule_id == "PY014"]
    assert lines == [3, 4]


def test_fingerprint_stable_when_line_shifts():
    a, _ = scan('eval(x)')
    b, _ = scan('\n\n\neval(x)')
    assert a[0].fingerprint == b[0].fingerprint
    assert a[0].line != b[0].line
