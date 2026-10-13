import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Card, Empty, Sev } from "../components/ui.jsx";

export default function Rules() {
  const [rules, setRules] = useState(null);
  const [filter, setFilter] = useState("");
  useEffect(() => {
    api.rules().then(setRules);
  }, []);
  if (!rules) return <Empty>Carregando...</Empty>;
  const needle = filter.toLowerCase();
  const rows = rules.filter((r) => `${r.id} ${r.title} ${r.cwe} ${r.owasp}`.toLowerCase().includes(needle));
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Catálogo de regras</h1>
          <p>{rules.length} regras próprias (AST, taint e Tree-sitter) mapeadas para CWE e OWASP Top 10, além de Bandit e Semgrep.</p>
        </div>
        <input type="text" placeholder="Filtrar..." value={filter} onChange={(e) => setFilter(e.target.value)} />
      </div>
      <Card title="Regras">
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr><th>ID</th><th>Severidade</th><th>Regra</th><th>CWE</th><th>OWASP</th><th>Motor</th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td><code>{r.id}</code></td>
                  <td><Sev level={r.severity} /></td>
                  <td>
                    <b>{r.title}</b>
                    <div className="secondary" style={{ fontSize: 12 }}>{r.description}</div>
                  </td>
                  <td>
                    <a href={`https://cwe.mitre.org/data/definitions/${r.cwe.split("-")[1]}.html`} target="_blank" rel="noreferrer noopener">{r.cwe}</a>
                  </td>
                  <td className="secondary" style={{ fontSize: 12 }}>{r.owasp}</td>
                  <td><span className="badge">{r.engine} · {r.language}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
