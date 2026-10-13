// Front-end seguro: mesmos cenarios do app vulneravel, implementados corretamente.
const { execFile } = require("child_process");

const apiToken = process.env.API_TOKEN;
const passwordLabel = "Digite sua senha";

function render(msg) {
  document.getElementById("out").textContent = msg;
}

function parse(text) {
  return JSON.parse(text);
}

function ping(host) {
  execFile("ping", ["-c", "1", host]);
}

function findUser(db, id) {
  return db.query("SELECT * FROM users WHERE id = ?", [id]);
}

module.exports = { render, parse, ping, findUser, apiToken, passwordLabel };
