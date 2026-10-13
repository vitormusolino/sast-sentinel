import pytest
from sast_engine.parsers.js_parser import TREE_SITTER_AVAILABLE, analyze_javascript

pytestmark = pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter nao instalado")


def ids(code: str) -> list[tuple[str, int]]:
    findings, _ = analyze_javascript("a.js", code)
    return [(f.rule_id, f.line) for f in findings]


def test_js_rules():
    code = """const API_KEY = "sk_live_abcdefghijklmnopqrstuv";
el.innerHTML = userInput;
el.innerHTML = "<b>fixo</b>";
eval(code);
new Function(body);
exec(`rm ${file}`);
execFile("ls", ["-la"]);
db.query("SELECT * FROM u WHERE id = " + id);
db.query("SELECT * FROM u WHERE id = ?", [id]);
"""
    found = ids(code)
    assert ("JS004", 1) in found
    assert ("JS002", 2) in found and ("JS002", 3) not in found
    assert ("JS001", 4) in found and ("JS001", 5) in found
    assert ("JS003", 6) in found and all(ln != 7 for _, ln in found)
    assert ("JS005", 8) in found and all(ln != 9 for _, ln in found)


def test_js_suppression():
    findings, suppressed = analyze_javascript("a.js", "eval(x); // nosec\n")
    assert findings == [] and suppressed == 1
