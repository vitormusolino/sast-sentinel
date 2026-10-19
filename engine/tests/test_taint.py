import textwrap

from sast_engine.parsers.python_parser import parse_python
from sast_engine.taint.python_taint import analyze_project


def taint(*sources: tuple[str, str]):
    modules = [parse_python(name, textwrap.dedent(code)) for name, code in sources]
    return analyze_project(modules)


def hits(code: str) -> list[tuple[str, int]]:
    return [(f.rule_id, f.line) for f in taint(("app.py", code))]


FLASK = "from flask import Flask, request, redirect, render_template_string\nimport os, subprocess, requests, shlex\n"


def test_direct_sqli():
    code = FLASK + """
def view():
    name = request.args.get("name")
    cur.execute("SELECT * FROM t WHERE n = '%s'" % name)
"""
    assert ("TAINT-SQLI", 6) in hits(code)


def test_parameterized_query_is_safe():
    code = FLASK + """
def view():
    name = request.args.get("name")
    cur.execute("SELECT * FROM t WHERE n = ?", (name,))
"""
    assert hits(code) == []


def test_reassignment_kills_taint():
    code = FLASK + """
def view():
    x = request.args.get("x")
    x = "constante"
    os.system("echo " + x)
"""
    assert hits(code) == []


def test_int_sanitizer_and_category_specific_sanitizer():
    code = FLASK + """
def view():
    a = int(request.args.get("a"))
    os.system(f"echo {a}")
    b = shlex.quote(request.args.get("b"))
    os.system("echo " + b)
    cur.execute(f"SELECT {b}")
"""
    result = hits(code)
    assert result == [("TAINT-SQLI", 9)]


def test_subprocess_requires_shell_true():
    code = FLASK + """
def view():
    h = request.args.get("h")
    subprocess.run(["ping", h])
    subprocess.run("ping " + h, shell=True)
"""
    assert hits(code) == [("TAINT-CMDI", 7)]


def test_route_parameter_is_source_and_int_converter_is_not():
    code = FLASK + """
app = Flask(__name__)
@app.route("/u/<name>")
def a(name):
    return render_template_string("<b>" + name + "</b>")
@app.route("/i/<int:item>")
def b(item):
    return render_template_string("<b>%s</b>" % item)
"""
    assert hits(code) == [("TAINT-XSS", 7)]


def test_reflected_xss_on_return_and_escape():
    code = FLASK + """from markupsafe import escape
app = Flask(__name__)
@app.route("/a")
def a():
    return f"<p>{request.args.get('q')}</p>"
@app.route("/b")
def b():
    return f"<p>{escape(request.args.get('q'))}</p>"
"""
    assert hits(code) == [("TAINT-XSS", 7)]


def test_interprocedural_cross_file_with_trace():
    findings = taint(
        ("app.py", FLASK + """from repo import find
def view():
    q = request.args.get("q")
    return find(q)
"""),
        ("repo.py", """
def find(term):
    sql = "SELECT * FROM t WHERE x = '" + term + "'"
    return db.execute(sql)
"""),
    )
    assert len(findings) == 1
    f = findings[0]
    assert (f.rule_id, f.file, f.line) == ("TAINT-SQLI", "app.py", 6)
    files = [step.file for step in f.trace]
    assert files[0] == "app.py" and files[-1] == "repo.py"
    assert "Sink" in f.trace[-1].description


def test_interprocedural_sanitizing_helper():
    code = FLASK + """
def clean(v):
    return int(v)
def view():
    x = clean(request.args.get("x"))
    os.system(f"echo {x}")
"""
    assert hits(code) == []


def test_return_propagation_through_helper():
    code = FLASK + """
def build(v):
    return "echo " + v
def view():
    os.system(build(request.args.get("x")))
"""
    assert ("TAINT-CMDI", 7) in hits(code)


def test_container_mutation():
    code = FLASK + """
def view():
    parts = []
    for p in request.args.getlist("p"):
        parts.append(p)
    os.system(" ".join(parts))
"""
    assert ("TAINT-CMDI", 8) in hits(code)


def test_allowlist_guard():
    code = FLASK + """
from flask import abort
ALLOWED = {"/a"}
def view():
    t = request.args.get("t")
    if t not in ALLOWED:
        abort(400)
    return redirect(t)
def view2():
    t = request.args.get("t")
    if t in ALLOWED:
        return redirect(t)
    return redirect(t)
"""
    assert hits(code) == [("TAINT-REDIRECT", 15)]


def test_ssrf_and_deserialization():
    code = FLASK + """import pickle
def view():
    requests.get(request.args["url"], timeout=3)
    pickle.loads(request.data)
"""
    assert set(hits(code)) == {("TAINT-SSRF", 5), ("TAINT-DESER", 6)}


def test_cli_sources_have_lower_severity():
    findings = taint(("cli.py", "import sys, os\nos.system('ls ' + sys.argv[1])\n"))
    assert findings and findings[0].severity.name == "HIGH" and findings[0].confidence == "MEDIUM"


def test_dict_get_not_confused_with_project_function():
    code = FLASK + """
def get(x):
    os.system(x)
def view():
    d = {}
    d.get(request.args.get("k"))
"""
    assert hits(code) == []


def test_implicit_shell_via_sh_c_list():
    code = FLASK + """
def view():
    s = request.args.get("s")
    subprocess.run(["sh", "-c", s], check=True)
    subprocess.run(["ls", s], check=True)
"""
    assert hits(code) == [("TAINT-CMDI", 6)]


def test_dynamic_dispatch_with_getattr():
    code = FLASK + """
def view():
    cmd = request.args.get("cmd")
    runner = getattr(os, "system")
    runner(cmd)
    getattr(os, "popen")(cmd)
    safe = getattr(os, "getcwd")
    safe()
"""
    assert set(hits(code)) == {("TAINT-CMDI", 7), ("TAINT-CMDI", 8)}
