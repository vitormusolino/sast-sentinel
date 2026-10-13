"""Aplicacao Flask SEGURA com padroes parecidos com os vulneraveis.

Serve para medir falsos positivos: nenhum achado deveria aparecer aqui.
"""

import ast
import hashlib
import logging
import os
import secrets
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, render_template, request, url_for
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
logger = logging.getLogger(__name__)

PASSWORD_FIELD = "password"
TOKEN_URL = "https://auth.example.com/token"
API_KEY_ENV = "PAYMENTS_API_KEY"
DEFAULT_PASSWORD_LENGTH = 12
UPLOAD_DIR = "/var/data"


@app.route("/user")
def get_user():
    name = request.args.get("name")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return {"rows": cur.fetchall()}


@app.route("/item/<int:item_id>")
def item(item_id):
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM items WHERE id = ?", (item_id,))
    return {"item": cur.fetchone()}


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, check=False)
    return {"rc": result.returncode}


@app.route("/page")
def page():
    number = int(request.args.get("n", 1))
    return {"page": number, "next": number + 1}


@app.route("/greet")
def greet():
    who = request.args.get("who", "")
    return f"<p>Ola {escape(who)}</p>"


@app.route("/profile")
def profile():
    return render_template("profile.html", name=request.args.get("name"))


@app.route("/download")
def download():
    filename = secure_filename(request.args.get("file", ""))
    with open(os.path.join(UPLOAD_DIR, filename), "rb") as fh:
        return fh.read()


@app.route("/home")
def home():
    return redirect(url_for("profile"))


@app.route("/count")
def count():
    term = request.args.get("q", "")
    logger.info("busca com %d caracteres", len(term))
    return {"size": len(term)}


def hash_file(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cache_key(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def load_config(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def new_reset_token() -> str:
    return secrets.token_urlsafe(32)


def list_files():
    subprocess.run(["ls", "-la"], check=True)


def parse_literal(text):
    return ast.literal_eval(text)


def fetch_status():
    return requests.get("https://status.example.com/health", timeout=5)


def parse_port(value):
    try:
        return int(value)
    except ValueError:
        logger.warning("porta invalida: %r", value)
        return 8080


def connect():
    return sqlite3.connect(os.getenv("DB_PATH", "app.db"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.getenv("FLASK_DEBUG") == "1")
