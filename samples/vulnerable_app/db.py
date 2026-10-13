"""Camada de dados vulneravel (fluxo interprocedural entre arquivos)."""

import sqlite3


def get_connection():
    return sqlite3.connect("app.db")


def find_user_by_name(name):
    conn = get_connection()
    query = "SELECT id, name FROM users WHERE name LIKE '%" + name + "%'"
    rows = conn.execute(query).fetchall()  # EXPECT: CWE-89
    return {"rows": rows}
