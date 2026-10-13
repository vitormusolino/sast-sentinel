import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartTooltip, Empty, SEVERITIES, SEV_LABEL, SEV_VAR, fmtDay, fmtNum } from "./ui.jsx";

const axis = { stroke: "var(--text-muted)", fontSize: 11, tickLine: false, axisLine: false };

export function SeverityDonut({ data }) {
  const rows = SEVERITIES.map((s) => ({ name: s, value: data?.[s] || 0 })).filter((r) => r.value > 0);
  const total = rows.reduce((a, r) => a + r.value, 0);
  if (!total) return <Empty>Nenhum achado aberto 🎉</Empty>;
  return (
    <div className="donut-wrap">
      <div style={{ height: 170, position: "relative" }}>
        <ResponsiveContainer>
          <PieChart>
            <Pie data={rows} dataKey="value" nameKey="name" innerRadius={52} outerRadius={80} paddingAngle={2}
                 stroke="var(--surface-1)" strokeWidth={2} isAnimationActive={false}>
              {rows.map((r) => <Cell key={r.name} fill={SEV_VAR[r.name]} />)}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", pointerEvents: "none" }}>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: 24, fontWeight: 700 }}>{fmtNum(total)}</div>
            <div className="muted" style={{ fontSize: 11 }}>abertos</div>
          </div>
        </div>
      </div>
      <table>
        <tbody>
          {SEVERITIES.map((s) => {
            const v = data?.[s] || 0;
            return (
              <tr key={s}>
                <td style={{ padding: "6px 4px" }}><span className={`sev sev-${s}`}>{SEV_LABEL[s]}</span></td>
                <td className="num" style={{ padding: "6px 4px" }}>{fmtNum(v)}</td>
                <td className="num muted" style={{ padding: "6px 4px", width: 48 }}>{total ? Math.round((v / total) * 100) : 0}%</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function TrendChart({ data }) {
  if (!data?.length) return <Empty>Sem histórico ainda. Rode mais de um scan para ver a tendência.</Empty>;
  const series = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  return (
    <>
      <div style={{ height: 240 }}>
        <ResponsiveContainer>
          <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
            <CartesianGrid stroke="var(--grid)" vertical={false} />
            <XAxis dataKey="date" tickFormatter={fmtDay} {...axis} />
            <YAxis allowDecimals={false} {...axis} />
            <Tooltip content={<ChartTooltip labelFormatter={fmtDay} />} cursor={{ stroke: "var(--text-muted)", strokeDasharray: "3 3" }} />
            {series.map((s) => (
              <Area key={s} type="monotone" dataKey={s} name={SEV_LABEL[s]} stackId="1" stroke={SEV_VAR[s]}
                    strokeWidth={2} fill={SEV_VAR[s]} fillOpacity={0.35} isAnimationActive={false}
                    dot={data.length < 3 ? { r: 4 } : false} />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="legend">
        {series.map((s) => <span key={s}><i style={{ background: SEV_VAR[s] }} />{SEV_LABEL[s]}</span>)}
      </div>
    </>
  );
}

export function NewFixedChart({ data }) {
  if (!data?.length) return <Empty>Sem dados</Empty>;
  return (
    <>
      <div style={{ height: 200 }}>
        <ResponsiveContainer>
          <BarChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }} barGap={2}>
            <CartesianGrid stroke="var(--grid)" vertical={false} />
            <XAxis dataKey="date" tickFormatter={fmtDay} {...axis} />
            <YAxis allowDecimals={false} {...axis} />
            <Tooltip content={<ChartTooltip labelFormatter={fmtDay} />} cursor={{ fill: "var(--surface-2)" }} />
            <Bar dataKey="new" name="Novos" fill="var(--series-2)" radius={[4, 4, 0, 0]} maxBarSize={18} isAnimationActive={false} />
            <Bar dataKey="fixed" name="Corrigidos" fill="var(--series-1)" radius={[4, 4, 0, 0]} maxBarSize={18} isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="legend">
        <span><i style={{ background: "var(--series-2)" }} />Novos</span>
        <span><i style={{ background: "var(--series-1)" }} />Corrigidos</span>
      </div>
    </>
  );
}

export function TopFiles({ rows, onSelect }) {
  if (!rows?.length) return <Empty>Nenhum arquivo com achados abertos</Empty>;
  const max = Math.max(...rows.map((r) => r.total));
  return (
    <div>
      {rows.map((r) => (
        <div className="filebar" key={r.file} title={`Risco ponderado: ${r.risk}`}>
          <code className="truncate" style={{ cursor: onSelect ? "pointer" : "default" }} onClick={() => onSelect?.(r.file)}>
            {r.file}
          </code>
          <b className="num">{r.total} falhas</b>
          <div className="stack" style={{ width: `${(r.total / max) * 100}%` }}>
            {SEVERITIES.filter((s) => r[s]).map((s) => (
              <span key={s} title={`${SEV_LABEL[s]}: ${r[s]}`} style={{ flex: r[s], background: SEV_VAR[s] }} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

export function CweBars({ rows }) {
  if (!rows?.length) return <Empty>Sem dados</Empty>;
  const data = rows.map((r) => ({ ...r, label: r.cwe }));
  return (
    <div style={{ height: Math.max(160, data.length * 30) }}>
      <ResponsiveContainer>
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 24, left: 8, bottom: 0 }}>
          <XAxis type="number" hide allowDecimals={false} />
          <YAxis type="category" dataKey="label" width={70} {...axis} />
          <Tooltip
            cursor={{ fill: "var(--surface-2)" }}
            content={({ active, payload }) =>
              active && payload?.length ? (
                <div className="chart-tooltip">
                  <div className="t">{payload[0].payload.cwe}</div>
                  <div className="secondary">{payload[0].payload.title}</div>
                  <b>{payload[0].value} achados</b>
                </div>
              ) : null
            }
          />
          <Bar dataKey="count" fill="var(--series-1)" radius={[0, 4, 4, 0]} maxBarSize={16} isAnimationActive={false}
               label={{ position: "right", fill: "var(--text-secondary)", fontSize: 11 }} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
