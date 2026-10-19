"""Casos DIFICEIS para o SAST (corpus de estresse).

Mistura vulnerabilidades sutis (anotadas com EXPECT) e codigo seguro que
"parece" vulneravel (armadilhas de falso positivo). Alguns casos documentam
LIMITACOES CONHECIDAS do motor e sao discutidos em docs/BENCHMARK.md.
"""

import os
import shlex
import sqlite3
import subprocess
from urllib.parse import urlparse

from flask import Flask, abort, redirect, request

app = Flask(__name__)
ALLOWED_REDIRECTS = {"/home", "/profile"}
ALLOWED_REPORTS = {"daily", "weekly"}
USERS_TABLE = "users"
QUERY_BY_ID = "SELECT * FROM %s WHERE id = ?"
API_KEY = "your-api-key-here"


def get_db():
    return sqlite3.connect("app.db")


def to_int(value):
    return int(value)


class UserRepository:
    def __init__(self, conn):
        self.conn = conn

    def by_email(self, email):
        return self.conn.execute("SELECT * FROM users WHERE email = '%s'" % email)  # EXPECT: CWE-89


# --- 1. taint atraves de container (lista montada em loop)
@app.route("/cleanup")
def cleanup():
    parts = []
    for name in request.args.getlist("f"):
        parts.append(name)
    os.system("rm -f " + " ".join(parts))  # EXPECT: CWE-78
    return {"ok": True}


# --- 2. sanitizador da categoria ERRADA: shlex.quote nao protege SQL
@app.route("/report")
def report():
    kind = shlex.quote(request.args.get("kind", ""))
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM reports WHERE kind = {kind}")  # EXPECT: CWE-89
    return {"rows": cur.fetchall()}


# --- 3. sanitizacao interprocedural: to_int() devolve inteiro -> SEGURO
@app.route("/order")
def order():
    order_id = to_int(request.args.get("id"))
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM orders WHERE id = {order_id}")
    return {"rows": cur.fetchall()}


# --- 4. allowlist que encerra o fluxo -> SEGURO
@app.route("/next")
def next_page():
    target = request.args.get("to", "/")
    if target not in ALLOWED_REDIRECTS:
        abort(400)
    return redirect(target)


# --- 5. allowlist positiva -> SEGURO dentro do if
@app.route("/run-report")
def run_report():
    name = request.args.get("name", "")
    if name in ALLOWED_REPORTS:
        subprocess.run(["/opt/reports/run.sh", name], check=True)
    return {"ok": True}


# --- 6. SQL com constantes de modulo (nao ha entrada externa) -> SEGURO
def user_by_id(user_id):
    return get_db().execute(QUERY_BY_ID % USERS_TABLE, (user_id,))


# --- 7. metodo de classe com SQL concatenado
@app.route("/by-email")
def by_email():
    repo = UserRepository(get_db())
    return {"rows": repo.by_email(request.args["email"]).fetchall()}


# --- 8. LIMITACAO: validacao por urlparse (o motor nao entende a semantica)
@app.route("/out")
def outbound():
    target = request.args.get("url", "/")
    if urlparse(target).netloc:
        target = "/"
    return redirect(target)


# --- 9. despacho dinamico via getattr (era limitacao; resolvido para nome constante)
@app.route("/dyn")
def dynamic_dispatch():
    cmd = request.args.get("cmd")
    runner = getattr(os, "system")
    runner(cmd)  # EXPECT: CWE-78
    return {"ok": True}


# --- 10. shell implicito via "sh -c" com lista (era limitacao; resolvido)
@app.route("/sh")
def via_sh():
    script = request.args.get("script")
    subprocess.run(["sh", "-c", script], check=True)  # EXPECT: CWE-78
    return {"ok": True}
