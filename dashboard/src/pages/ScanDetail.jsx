import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { Card, Empty, Gate, Kpi, SEVERITIES, SEV_LABEL, STATUS_LABEL, Sev, fmtDate, fmtNum } from "../components/ui.jsx";

function FindingDrawer({ id, onClose, onChanged }) {
  const [f, setF] = useState(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setF(null);
    api.finding(id).then(setF);
  }, [id]);

  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const triage = async (status) => {
    setBusy(true);
    const updated = await api.triage(id, status, reason || null);
    setF({ ...f, ...updated });
    setBusy(false);
    onChanged();
  };

  const ai = f?.ai;
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Detalhe do achado">
        {!f ? (
          <Empty>Carregando...</Empty>
        ) : (
          <>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
              <div>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                  <Sev level={f.effective_severity} />
                  {f.effective_severity !== f.severity && <span className="badge">regra: {f.severity}</span>}
                  <span className="badge">{f.rule_id}</span>
                  <span className="badge">{f.cwe}</span>
                  <span className="badge">confianca {f.confidence}</span>
                </div>
                <h2 style={{ margin: "10px 0 4px", fontSize: 18 }}>{f.title}</h2>
                <code className="secondary">{f.file}:{f.line}</code>
              </div>
              <button className="btn" onClick={onClose} aria-label="Fechar">✕</button>
            </div>
            <p className="secondary">{f.message}</p>
            <div className="muted" style={{ fontSize: 12 }}>
              Motor: <b>{f.engine}</b>
              {f.confirmed_by?.length > 0 && <> · confirmado por <b>{f.confirmed_by.join(", ")}</b></>}
              {f.owasp && <> · {f.owasp}</>}
            </div>

            <h3>Código</h3>
            <pre className="code">{f.snippet}</pre>

            {f.trace?.length > 0 && (
              <>
                <h3>Fluxo de dados (taint)</h3>
                <ol className="trace">
                  {f.trace.map((t, i) => (
                    <li key={i} className={i === 0 ? "source" : i === f.trace.length - 1 ? "sink" : ""}>
                      <code className="muted">{t.file}:{t.line}</code>
                      <div>{t.description}</div>
                    </li>
                  ))}
                </ol>
              </>
            )}

            {ai && (
              <>
                <h3>Análise da IA {ai.mode === "llm" ? `(${ai.model})` : "(modo heurístico)"}</h3>
                <div className="ai-box">
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
                    <span className={`gate ${ai.verdict === "likely_false_positive" ? "pass" : "fail"}`}>
                      {ai.verdict === "likely_false_positive" ? "Provavel falso positivo" : "Verdadeiro positivo"}
                    </span>
                    <span className="badge">confianca {Math.round((ai.confidence || 0) * 100)}%</span>
                    {ai.severity_changed && <span className="badge">severidade ajustada para {ai.severity}</span>}
                  </div>
                  <p style={{ margin: "6px 0" }}>{ai.explanation}</p>
                  {ai.exploit_scenario && <p className="secondary" style={{ margin: "6px 0" }}><b>Cenário de exploração:</b> {ai.exploit_scenario}</p>}
                </div>
              </>
            )}

            <h3>Remediação</h3>
            <p>{f.remediation}</p>
            {ai?.fixed_code && (
              <>
                <div style={{ display: "flex", gap: 8, alignItems: "center", margin: "8px 0" }}>
                  <b>Código corrigido sugerido</b>
                  {ai.fix_verified ? (
                    <span className="gate pass" title={ai.fix_check}>✓ verificado pelo motor</span>
                  ) : (
                    <span className="badge" title={ai.fix_check}>{ai.fix_check}</span>
                  )}
                </div>
                <pre className="code diff-add">{ai.fixed_code}</pre>
              </>
            )}
            {ai?.references?.length > 0 && (
              <p style={{ fontSize: 12 }}>
                {ai.references.map((r) => <a key={r} href={r} target="_blank" rel="noreferrer noopener" style={{ marginRight: 12 }}>{r}</a>)}
              </p>
            )}

            <h3>Triagem</h3>
            <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
              Status atual: <b>{STATUS_LABEL[f.status] || f.status}</b>. A decisão vale para os próximos scans deste projeto.
            </p>
            <textarea rows={2} style={{ width: "100%", marginBottom: 8 }} placeholder="Justificativa (opcional)"
                      value={reason} onChange={(e) => setReason(e.target.value)} />
            <div className="toolbar">
              <button className="btn" disabled={busy} onClick={() => triage("false_positive")}>Marcar falso positivo</button>
              <button className="btn" disabled={busy} onClick={() => triage("accepted")}>Aceitar risco</button>
              <button className="btn" disabled={busy} onClick={() => triage("open")}>Reabrir</button>
            </div>

            {f.history?.length > 1 && (
              <>
                <h3>Histórico</h3>
                <p className="secondary" style={{ fontSize: 12 }}>
                  Presente em {f.history.length} scans: {f.history.map((h) => `#${h.scan_id}`).join(", ")}
                </p>
              </>
            )}
          </>
        )}
      </aside>
    </>
  );
}

export default function ScanDetail({ scanId, query, navigate }) {
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState(null);
  const [sev, setSev] = useState([]);
  const [status, setStatus] = useState("open,likely_false_positive");
  const [q, setQ] = useState("");
  const [onlyNew, setOnlyNew] = useState(false);
  const selected = query.get("finding");

  const loadFindings = useCallback(() => {
    api.findings(scanId, { severity: sev.join(","), status, only_new: onlyNew }).then(setFindings);
  }, [scanId, sev, status, onlyNew]);

  useEffect(() => {
    let alive = true;
    let timer;
    const load = async () => {
      const s = await api.scan(scanId);
      if (!alive) return;
      setScan(s);
      if (s.status === "queued" || s.status === "running") timer = setTimeout(load, 1500);
      else loadFindings();
    };
    load();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [scanId, loadFindings]);

  const visible = useMemo(() => {
    if (!findings) return [];
    const needle = q.toLowerCase();
    return needle ? findings.filter((f) => `${f.title} ${f.file} ${f.rule_id} ${f.cwe}`.toLowerCase().includes(needle)) : findings;
  }, [findings, q]);

  if (!scan) return <Empty>Carregando...</Empty>;
  const running = scan.status === "queued" || scan.status === "running";
  const toggleSev = (s) => setSev(sev.includes(s) ? sev.filter((x) => x !== s) : [...sev, s]);
  const open = (id) => navigate(`/scans/${scanId}?finding=${id}`);

  return (
    <>
      <div className="page-head">
        <div>
          <a href="#/scans" className="muted">← Varreduras</a>
          <h1>Scan #{scan.id} · {scan.project}</h1>
          <p>
            {scan.source_ref} {scan.branch && <>· <code>{scan.branch}</code></>}
            {scan.commit_sha && <> · <code>{scan.commit_sha.slice(0, 7)}</code></>} · {fmtDate(scan.created_at)}
          </p>
        </div>
        <div className="toolbar" style={{ margin: 0 }}>
          {scan.status === "completed" && <a className="btn" href={api.sarifUrl(scan.id)} download={`scan-${scan.id}.sarif`}>Baixar SARIF</a>}
          {scan.status === "completed" && <Gate passed={scan.gate_passed} />}
        </div>
      </div>

      {running && (
        <Card title="Análise em andamento" sub={scan.message || "na fila"}>
          <div className="progress"><span style={{ width: `${Math.round(scan.progress * 100)}%` }} /></div>
        </Card>
      )}
      {scan.status === "failed" && <Card title="Falha na varredura"><p className="error">{scan.message}</p></Card>}
      {scan.status === "completed" && scan.errors?.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <Card title="Avisos da análise" sub={scan.files_scanned === 0 ? "Nada foi analisado: o gate não aprova código que não leu." : "Itens que não puderam ser analisados."}>
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {scan.errors.slice(0, 10).map((e, i) => (
                <li key={i} className="secondary">{e.file !== "*" && <code>{e.file}: </code>}{e.error}</li>
              ))}
            </ul>
          </Card>
        </div>
      )}

      {scan.status === "completed" && (
        <>
          <div className="grid kpis">
            {SEVERITIES.slice(0, 4).map((s) => (
              <Kpi key={s} label={SEV_LABEL[s]} value={fmtNum(scan.counts?.[s])} />
            ))}
            <Kpi label="Novos / corrigidos" value={`${scan.new_count} / ${scan.fixed_count}`} hint="vs. scan anterior" />
            <Kpi label="Arquivos · linhas" value={fmtNum(scan.files_scanned)} hint={`${fmtNum(scan.lines_of_code)} linhas · ${scan.duration_seconds.toFixed(1)}s`} />
          </div>

          {(scan.ai_summary || scan.gate) && (
            <div className="grid half" style={{ marginBottom: 16 }}>
              {scan.ai_summary && (
                <Card title="Resumo executivo" sub={scan.ai_summary.mode === "llm" ? "gerado pelo LLM local" : "gerado por heurística"}>
                  <p style={{ margin: 0 }}>{scan.ai_summary.text}</p>
                </Card>
              )}
              {scan.gate && (
                <Card title="Security Gate" sub={`Motores: ${scan.engines.join(", ")}`}>
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {scan.gate.reasons?.map((r) => <li key={r}>{r}</li>)}
                  </ul>
                  {scan.ai_stats && (
                    <p className="muted" style={{ fontSize: 12 }}>
                      IA: {scan.ai_stats.llm_reviewed} achados revisados pelo LLM, {scan.ai_stats.likely_false_positives} provaveis FP,{" "}
                      {scan.ai_stats.fixes_verified} correções verificadas.
                    </p>
                  )}
                </Card>
              )}
            </div>
          )}

          <Card title="Achados" sub={`${visible.length} exibidos`}>
            <div className="toolbar">
              {SEVERITIES.map((s) => (
                <button key={s} className={`chip ${sev.includes(s) ? "on" : ""}`} onClick={() => toggleSev(s)}>
                  <span className={`sev sev-${s}`} style={{ padding: 0, background: "none" }}>{SEV_LABEL[s]}</span>
                </button>
              ))}
              <select value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="open,likely_false_positive">Abertos</option>
                <option value="">Todos</option>
                <option value="likely_false_positive">Provavel FP (IA)</option>
                <option value="false_positive,accepted">Triados</option>
              </select>
              <label className="check"><input type="checkbox" checked={onlyNew} onChange={(e) => setOnlyNew(e.target.checked)} /> so novos</label>
              <input type="text" placeholder="Buscar arquivo, regra, CWE..." value={q} onChange={(e) => setQ(e.target.value)} style={{ flex: 1, minWidth: 180 }} />
            </div>
            {!findings ? (
              <Empty>Carregando...</Empty>
            ) : !visible.length ? (
              <Empty>Nenhum achado para os filtros selecionados.</Empty>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table>
                  <thead>
                    <tr><th>Severidade</th><th>Vulnerabilidade</th><th>Local</th><th>Motor</th><th>IA</th></tr>
                  </thead>
                  <tbody>
                    {visible.map((f) => (
                      <tr key={f.id} className="clickable" onClick={() => open(f.id)}>
                        <td><Sev level={f.effective_severity} /></td>
                        <td>
                          <b>{f.title}</b> {f.is_new && <span className="badge">novo</span>}
                          <div className="muted" style={{ fontSize: 12 }}>{f.rule_id} · {f.cwe}</div>
                        </td>
                        <td><code>{f.file}:{f.line}</code></td>
                        <td className="secondary">{f.engine}{f.confirmed_by.length > 0 && <span className="muted"> +{f.confirmed_by.length}</span>}</td>
                        <td>
                          {f.status === "likely_false_positive" && <span className="badge">provavel FP</span>}
                          {f.status === "false_positive" && <span className="badge">FP</span>}
                          {f.status === "accepted" && <span className="badge">aceito</span>}
                          {f.fix_verified && <span className="badge" title="correção verificada pelo motor">✓ fix</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
      {selected && <FindingDrawer id={selected} onClose={() => navigate(`/scans/${scanId}`)} onChanged={loadFindings} />}
    </>
  );
}
