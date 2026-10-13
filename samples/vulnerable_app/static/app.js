// Front-end PROPOSITALMENTE vulneravel (corpus de teste do SAST).
const API_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"; // EXPECT: CWE-798

function render(msg) {
  document.getElementById("out").innerHTML = msg; // EXPECT: CWE-79
}

function calc(expr) {
  return eval(expr); // EXPECT: CWE-95
}

fetch("/api/data", { headers: { Authorization: `Bearer ${API_TOKEN}` } })
  .then((r) => r.text())
  .then(render);
