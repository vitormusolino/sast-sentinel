import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Card, Empty, Gate, fmtDate } from "../components/ui.jsx";

function NewScan({ onCreated }) {
  const [mode, setMode] = useState("git");
  const [repo, setRepo] = useState("");
  const [branch, setBranch] = useState("");
  const [project, setProject] = useState("");
  const [file, setFile] = useState(null);
  const [opts, setOpts] = useState({ ai: true, bandit: true, semgrep: false, fail_on: "HIGH" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      let scan;
      if (mode === "git") {
        scan = await api.scanGit({ repo_url: repo, branch: branch || null, project: project || null, ...opts });
      } else {
        const form = new FormData();
        form.append("file", file);
        form.append("project", project || file.name.replace(/\.zip$/i, ""));
        Object.entries(opts).forEach(([k, v]) => form.append(k, String(v)));
        scan = await api.scanUpload(form);
      }
      onCreated(scan);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Nova varredura" sub="Análise apenas código próprio ou de repositórios open source autorizados.">
      <form onSubmit={submit}>
        <div className="seg" style={{ marginBottom: 14 }}>
          <button type="button" className={mode === "git" ? "on" : ""} onClick={() => setMode("git")}>Repositório Git</button>
          <button type="button" className={mode === "zip" ? "on" : ""} onClick={() => setMode("zip")}>Upload .zip</button>
        </div>
        {mode === "git" ? (
          <>
            <label className="field">
              <span>URL HTTPS do repositório</span>
              <input type="url" required placeholder="https://github.com/org/projeto" value={repo} onChange={(e) => setRepo(e.target.value)} />
            </label>
            <label className="field">
              <span>Branch (opcional)</span>
              <input type="text" placeholder="main" value={branch} onChange={(e) => setBranch(e.target.value)} />
            </label>
          </>
        ) : (
          <label className="field">
            <span>Arquivo .zip (max. 50MB)</span>
            <input type="file" accept=".zip" required onChange={(e) => setFile(e.target.files[0])} />
          </label>
        )}
        <label className="field">
          <span>Nome do projeto (opcional)</span>
          <input type="text" value={project} onChange={(e) => setProject(e.target.value)} />
        </label>
        <div className="toolbar">
          <label className="check"><input type="checkbox" checked={opts.ai} onChange={(e) => setOpts({ ...opts, ai: e.target.checked })} /> Triagem com IA (Ollama)</label>
          <label className="check"><input type="checkbox" checked={opts.bandit} onChange={(e) => setOpts({ ...opts, bandit: e.target.checked })} /> Bandit</label>
          <label className="check"><input type="checkbox" checked={opts.semgrep} onChange={(e) => setOpts({ ...opts, semgrep: e.target.checked })} /> Semgrep</label>
        </div>
        <div className="toolbar">
          <span className="secondary">Gate reprova a partir de</span>
          <select value={opts.fail_on} onChange={(e) => setOpts({ ...opts, fail_on: e.target.value })}>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
        {error && <p className="error">{error}</p>}
        <button className="btn primary" disabled={busy}>{busy ? "Enviando..." : "Iniciar varredura"}</button>
      </form>
    </Card>
  );
}

export default function Scans({ projectId, navigate }) {
  const [scans, setScans] = useState(null);

  useEffect(() => {
    let alive = true;
    const load = () => api.scans(projectId).then((s) => alive && setScans(s));
    load();
    const t = setInterval(load, 4000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [projectId]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Varreduras</h1>
          <p>Scans da interface, da API e do pipeline CI/CD (GitHub Actions).</p>
        </div>
      </div>
      <div className="grid two">
        <Card title="Histórico">
          {!scans ? (
            <Empty>Carregando...</Empty>
          ) : !scans.length ? (
            <Empty>Nenhum scan ainda.</Empty>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table>
                <thead>
                  <tr><th>#</th><th>Projeto</th><th>Origem</th><th>Status</th><th>Gate</th><th className="num">Achados</th><th>Data</th></tr>
                </thead>
                <tbody>
                  {scans.map((s) => {
                    const total = Object.values(s.counts || {}).reduce((a, b) => a + b, 0);
                    return (
                      <tr key={s.id} className="clickable" onClick={() => navigate(`/scans/${s.id}`)}>
                        <td>{s.id}</td>
                        <td>
                          <b>{s.project}</b>
                          {s.branch && <div className="muted mono">{s.branch}{s.commit_sha ? ` @ ${s.commit_sha.slice(0, 7)}` : ""}</div>}
                        </td>
                        <td><span className="badge">{s.triggered_by === "ci" ? "CI/CD" : s.source_type}</span></td>
                        <td style={{ minWidth: 120 }}>
                          {s.status === "running" || s.status === "queued" ? (
                            <>
                              <div className="progress"><span style={{ width: `${Math.round(s.progress * 100)}%` }} /></div>
                              <div className="muted" style={{ fontSize: 11 }}>{s.message || s.status}</div>
                            </>
                          ) : s.status === "failed" ? (
                            <span className="error" title={s.message}>falhou</span>
                          ) : (
                            <span className="secondary">concluído</span>
                          )}
                        </td>
                        <td>{s.status === "completed" && <Gate passed={s.gate_passed} />}</td>
                        <td className="num">{s.status === "completed" ? total : "-"}</td>
                        <td className="secondary">{fmtDate(s.created_at)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <NewScan onCreated={(scan) => navigate(`/scans/${scan.id}`)} />
      </div>
    </>
  );
}
