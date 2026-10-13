import { useEffect, useState } from "react";
import { api } from "../api.js";
import { CweBars, NewFixedChart, SeverityDonut, TopFiles, TrendChart } from "../components/charts.jsx";
import { Card, Empty, Gate, Kpi, Sev, fmtDate, fmtNum, fmtPct } from "../components/ui.jsx";

export default function Overview({ projectId, navigate }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let alive = true;
    const load = () =>
      api.overview(projectId).then((d) => alive && setData(d)).catch((e) => alive && setError(e.message));
    load();
    const t = setInterval(load, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [projectId]);

  if (error) return <Empty>Erro ao carregar métricas: {error}</Empty>;
  if (!data) return <Empty>Carregando...</Empty>;
  const k = data.kpis;
  if (!k.scans)
    return (
      <Empty>
        Nenhum scan concluído ainda. <a href="#/scans">Inicie a primeira varredura</a>.
      </Empty>
    );

  const latestSummary = data.latest_scans?.[0];
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Visão executiva de segurança</h1>
          <p>Postura atual com base no último scan de {k.projects === 1 ? "1 projeto" : `${k.projects} projetos`}.</p>
        </div>
        {latestSummary && <Gate passed={latestSummary.gate_passed} />}
      </div>

      <div className="grid kpis">
        <Kpi label="Achados abertos" value={fmtNum(k.open_findings)}
             hint={`+${k.new_last_scan} novos · -${k.fixed_last_scan} corrigidos`} />
        <Kpi label="Críticos + altos" value={fmtNum(k.critical + k.high)} hint={`${k.critical} críticos`}
             hintClass={k.critical ? "delta-up" : ""} />
        <Kpi label="Índice de risco" value={fmtNum(k.risk_score)} hint="10·C + 5·A + 2·M + 1·B" />
        <Kpi label="Taxa de aprovação do gate" value={fmtPct(k.gate_pass_rate)} hint="últimos 30 scans" />
        <Kpi label="Correções verificadas pela IA" value={fmtNum(k.ai_fixes_verified)}
             hint={`${k.ai_llm_reviewed} revisados por LLM · ${k.likely_false_positives} provaveis FP`} />
        <Kpi label="Código analisado" value={fmtNum(k.lines_of_code)}
             hint={`${fmtNum(k.files_scanned)} arquivos · ${k.avg_scan_seconds}s/scan`} />
      </div>

      <div className="grid two" style={{ marginBottom: 16 }}>
        <Card title="Tendência de falhas" sub="Achados abertos por severidade ao longo do tempo">
          <TrendChart data={data.trend} />
        </Card>
        <Card title="Severidade" sub="Distribuição dos achados abertos">
          <SeverityDonut data={data.severity} />
        </Card>
      </div>

      <div className="grid half" style={{ marginBottom: 16 }}>
        <Card title="Top 5 arquivos críticos" sub="Ordenados por risco ponderado pela severidade">
          <TopFiles rows={data.top_files} />
        </Card>
        <Card title="Categorias mais frequentes (CWE)" sub="Onde concentrar treinamento e correções">
          <CweBars rows={data.top_cwes} />
        </Card>
      </div>

      <div className="grid two" style={{ marginBottom: 16 }}>
        <Card title="Falhas críticas detectadas" sub="Achados CRITICAL/HIGH abertos - clique para detalhes">
          {data.critical_findings.length ? (
            data.critical_findings.map((f) => (
              <div className="list-item" key={f.id}>
                <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <Sev level={f.severity} />
                  <a href={`#/scans/${f.scan_id}?finding=${f.id}`}><b>{f.cwe} - {f.title}</b></a>
                </div>
                <div className="secondary" style={{ marginTop: 4 }}>{f.message}</div>
                <code className="muted">{f.file}:{f.line}</code>
              </div>
            ))
          ) : (
            <Empty>Nenhuma falha crítica aberta</Empty>
          )}
        </Card>
        <Card title="Novos x corrigidos" sub="Fluxo de entrada e saída de vulnerabilidades">
          <NewFixedChart data={data.trend} />
          <h2 style={{ marginTop: 18 }}>OWASP Top 10</h2>
          <table>
            <tbody>
              {data.owasp.slice(0, 6).map((o) => (
                <tr key={o.category}>
                  <td className="truncate secondary" style={{ padding: "5px 4px", maxWidth: 260 }}>{o.category}</td>
                  <td className="num" style={{ padding: "5px 4px" }}>{o.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>

      <Card title="Últimos scans">
        <table>
          <thead>
            <tr><th>#</th><th>Projeto</th><th>Data</th><th>Gate</th><th className="num">Crit.</th><th className="num">Alta</th><th className="num">Média</th></tr>
          </thead>
          <tbody>
            {data.latest_scans.map((s) => (
              <tr key={s.id} className="clickable" onClick={() => navigate(`/scans/${s.id}`)}>
                <td>{s.id}</td>
                <td>{s.project}</td>
                <td className="secondary">{fmtDate(s.created_at)}</td>
                <td><Gate passed={s.gate_passed} /></td>
                <td className="num">{s.counts?.CRITICAL ?? 0}</td>
                <td className="num">{s.counts?.HIGH ?? 0}</td>
                <td className="num">{s.counts?.MEDIUM ?? 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </>
  );
}
