"""Aplicacao Flask PROPOSITALMENTE VULNERAVEL.

Usada exclusivamente como corpus de teste do SAST (codigo proprio do grupo,
sem propriedade intelectual de terceiros). NAO EXECUTE EM PRODUCAO.
Cada linha vulneravel esta anotada com `# EXPECT: <CWE>` (gabarito do benchmark).
"""

import hashlib
import os
import pickle
import sqlite3

import requests
import yaml
from flask import Flask, redirect, render_template_string, request, send_file

from db import find_user_by_name
from utils import run_backup

app = Flask(__name__)
app.config["SECRET_KEY"] = "s3cr3t-k3y-n0t-s0-s3cr3t"  # EXPECT: CWE-798

DB_PASSWORD = "Sup3rS3nh@2024"  # EXPECT: CWE-798
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # EXPECT: CWE-798


@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")  # EXPECT: CWE-89
    return {"rows": cur.fetchall()}


@app.route("/search")
def search():
    term = request.args.get("q", "")
    return find_user_by_name(term)  # EXPECT: CWE-89


@app.route("/ping")
def ping():
    host = request.args.get("host")
    output = os.popen("ping -c 1 " + host).read()  # EXPECT: CWE-78
    return {"output": output}


@app.route("/backup", methods=["POST"])
def backup():
    target = request.form.get("dir")
    run_backup(target)  # EXPECT: CWE-78
    return {"status": "ok"}


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    result = eval(expr)  # EXPECT: CWE-95
    return {"result": result}


@app.route("/hello/<name>")
def hello(name):
    return render_template_string(f"<h1>Ola {name}</h1>")  # EXPECT: CWE-79


@app.route("/greet")
def greet():
    who = request.args.get("who", "visitante")
    return f"<p>Bem-vindo, {who}</p>"  # EXPECT: CWE-79


@app.route("/download")
def download():
    filename = request.args.get("file")
    path = os.path.join("/var/data", filename)
    return send_file(path)  # EXPECT: CWE-22


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    resp = requests.get(url)  # EXPECT: CWE-918, CWE-400
    return {"status": resp.status_code}


@app.route("/load", methods=["POST"])
def load():
    data = pickle.loads(request.data)  # EXPECT: CWE-502
    return {"ok": bool(data)}


@app.route("/config", methods=["POST"])
def config():
    cfg = yaml.load(request.data)  # EXPECT: CWE-502
    return {"keys": list(cfg)}


@app.route("/go")
def go():
    nxt = request.args.get("next")
    return redirect(nxt)  # EXPECT: CWE-601


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # EXPECT: CWE-327


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user")
    pwd = request.form.get("password")
    if user == "admin" and pwd == "admin123":  # EXPECT: CWE-798
        app.logger.info(f"login de {user}")  # EXPECT: CWE-117
        return {"token": hash_password(pwd)}
    return {"error": "credenciais invalidas"}, 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # EXPECT: CWE-489, CWE-605
