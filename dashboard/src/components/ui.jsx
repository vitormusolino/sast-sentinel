export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const SEV_LABEL = { CRITICAL: "Crítica", HIGH: "Alta", MEDIUM: "Média", LOW: "Baixa", INFO: "Info" };
export const SEV_VAR = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
  INFO: "var(--sev-info)",
};
export const STATUS_LABEL = {
  open: "Aberto",
  likely_false_positive: "Provavel FP (IA)",
  false_positive: "Falso positivo",
  accepted: "Risco aceito",
  fixed: "Corrigido",
};

export const fmtNum = (n) => (n ?? 0).toLocaleString("pt-BR");
export const fmtPct = (n) => (n == null ? "-" : `${Math.round(n * 100)}%`);
export const fmtDate = (iso) =>
  iso ? new Date(iso).toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }) : "-";
export const fmtDay = (iso) => {
  const [, m, d] = iso.split("-");
  return `${d}/${m}`;
};

export function Sev({ level }) {
  return <span className={`sev sev-${level}`}>{level}</span>;
}

export function Gate({ passed }) {
  if (passed === null || passed === undefined) return <span className="badge" title="nenhum código de linguagem suportada">⚠ sem análise</span>;
  return <span className={`gate ${passed ? "pass" : "fail"}`}>{passed ? "✓ Gate aprovado" : "✕ Gate bloqueado"}</span>;
}

export function Kpi({ label, value, hint, hintClass }) {
  return (
    <div className="card kpi">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {hint && <div className={`hint ${hintClass || ""}`}>{hint}</div>}
    </div>
  );
}

export function Card({ title, sub, children, action }) {
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>{title}</h2>
          {sub && <p className="sub">{sub}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

export function Empty({ children }) {
  return <div className="empty">{children}</div>;
}

export function ChartTooltip({ active, payload, label, labelFormatter }) {
  if (!active || !payload || !payload.length) return null;
  return (
    <div className="chart-tooltip">
      <div className="t">{labelFormatter ? labelFormatter(label) : label}</div>
      {payload
        .filter((p) => p.value !== undefined)
        .map((p) => (
          <div className="row" key={p.dataKey}>
            <span>
              <i className="sw" style={{ background: p.color || p.payload?.fill }} /> {p.name}
            </span>
            <b>{fmtNum(p.value)}</b>
          </div>
        ))}
    </div>
  );
}
