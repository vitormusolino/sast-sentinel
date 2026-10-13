// API Node PROPOSITALMENTE vulneravel (corpus de teste do SAST).
const express = require("express");
const { exec } = require("child_process");
const db = require("./db");

const app = express();

app.get("/ping", (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, out) => res.send(out)); // EXPECT: CWE-78
});

app.get("/user", (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id, (err, rows) => res.json(rows)); // EXPECT: CWE-89
});

app.listen(3000);
