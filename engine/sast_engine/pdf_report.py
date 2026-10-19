"""Relatório em PDF para leitura humana (resumo executivo + detalhes técnicos).

O SARIF é para ferramentas; este PDF é para pessoas: gestores, professores, auditores.
Recebe dicionários simples (o mesmo formato de `ScanResult.to_dict()` / API), então é usado
pela CLI (`sast scan --pdf`), pela API (`/api/scans/{id}/report.pdf`) e pelo CI.

Requer o extra `pdf` (reportlab): `pip install "sast-engine[pdf]"`.
"""

from __future__ import annotations

import io
import textwrap
from collections import Counter
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_LABEL = {"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Média", "LOW": "Baixa", "INFO": "Informativa"}
SEV_COLOR = {"CRITICAL": "#C62F2F", "HIGH": "#E06A35", "MEDIUM": "#E9A500", "LOW": "#4C8DF6", "INFO": "#8A8F98"}
SEV_TEXT = {"CRITICAL": "#FFFFFF", "HIGH": "#FFFFFF", "MEDIUM": "#1A1A1A", "LOW": "#FFFFFF", "INFO": "#FFFFFF"}
STATUS_LABEL = {"open": "Aberto", "likely_false_positive": "Provável FP (IA)", "false_positive": "Falso positivo",
                "accepted": "Risco aceito", "fixed": "Corrigido"}
SOURCE_LABEL = {"upload": "Upload (.zip)", "git": "Repositório Git", "ci": "Pipeline CI/CD", "cli": "Linha de comando"}

INK = "#1B2234"
MUTED = "#5B6475"
LINE = "#D9DCE3"
PANEL = "#F3F4F7"
ACCENT = "#E06A35"

# fontes padrão do PDF usam WinAnsi (cp1252): troca símbolos fora dele por equivalentes legíveis
_REPLACE = {"→": "->", "←": "<-", "≥": ">=", "≤": "<=", "✓": "OK", "✔": "OK", "✕": "x", "⛔": "", "⚠": "!",
            "🛡": "", "️": "", "±": "+/-", "×": "x", "≈": "~", "∞": "inf"}


def _clean(text: Any) -> str:
    s = "" if text is None else str(text)
    for a, b in _REPLACE.items():
        s = s.replace(a, b)
    return s.encode("cp1252", errors="replace").decode("cp1252")


def _p(text: Any) -> str:
    """Texto seguro para Paragraph (mini-HTML do ReportLab)."""
    return escape(_clean(text))


def _code(text: str, width: int = 92, max_lines: int = 18) -> str:
    lines: list[str] = []
    for raw in _clean(text).replace("\t", "    ").splitlines():
        lines.extend(textwrap.wrap(raw, width, replace_whitespace=False, drop_whitespace=False,
                                   subsequent_indent="    ") or [""])
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ["    (...)"]
    return "\n".join(lines)


def _sev(finding: dict) -> str:
    sev = str(finding.get("effective_severity") or finding.get("severity") or "MEDIUM").upper()
    return sev if sev in SEVERITIES else "MEDIUM"


def _executive_text(counts: dict, findings: list[dict], gate: dict | None) -> str:
    total = sum(counts.get(s, 0) for s in SEVERITIES)
    if not total:
        return ("Nenhum achado aberto foi encontrado nesta análise. O código está aprovado pela política "
                "de segurança configurada.")
    crit = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    files = Counter(f.get("file") for f in findings if f.get("status", "open") == "open").most_common(1)
    cwes = Counter(f.get("cwe") for f in findings if f.get("status", "open") == "open").most_common(1)
    parts = [f"A análise encontrou {total} achado(s) em aberto, dos quais {crit} de severidade crítica ou alta."]
    if files:
        parts.append(f"O arquivo que concentra mais problemas é {files[0][0]} ({files[0][1]} achado(s)).")
    if cwes:
        parts.append(f"A categoria mais frequente é {cwes[0][0]}.")
    if gate and gate.get("analyzed", True) and not gate.get("passed"):
        parts.append("O Security Gate BLOQUEOU este código: os itens críticos e altos devem ser corrigidos "
                     "antes de seguir para produção.")
    return " ".join(parts)


def build_pdf(meta: dict[str, Any], findings: list[dict[str, Any]], gate: dict[str, Any] | None = None,
              summary: str | None = None, errors: list[dict[str, Any]] | None = None, max_details: int = 40) -> bytes:
    """Gera o PDF e devolve os bytes.

    meta: project, scan_id, date, source, source_ref, branch, commit, files_scanned, lines_of_code,
          duration_seconds, engines, counts, new_count, fixed_count, ai_stats (todos opcionais)
    findings: dicionários no formato de Finding.to_dict() / API
    """
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        CondPageBreak,
        KeepTogether,
        PageBreak,
        Paragraph,
        Preformatted,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    c = colors.HexColor
    base = ParagraphStyle("base", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=c(INK),
                          alignment=TA_LEFT)
    st = {
        "title": ParagraphStyle("title", parent=base, fontName="Helvetica-Bold", fontSize=24, leading=28),
        "subtitle": ParagraphStyle("subtitle", parent=base, fontSize=13, leading=17, textColor=c(MUTED)),
        "h1": ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=15, leading=19,
                             spaceBefore=6, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=11.5, leading=15,
                             spaceBefore=4, spaceAfter=3),
        "label": ParagraphStyle("label", parent=base, fontName="Helvetica-Bold", fontSize=8.5, leading=11,
                                textColor=c(MUTED)),
        "body": base,
        "small": ParagraphStyle("small", parent=base, fontSize=8.5, leading=11.5, textColor=c(MUTED)),
        "cell": ParagraphStyle("cell", parent=base, fontSize=8.5, leading=11),
        "cellb": ParagraphStyle("cellb", parent=base, fontName="Helvetica-Bold", fontSize=8.5, leading=11),
        "code": ParagraphStyle("code", parent=base, fontName="Courier", fontSize=7.6, leading=9.6,
                               textColor=c("#22283A")),
    }

    counts = meta.get("counts") or {s: 0 for s in SEVERITIES}
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings = sorted(findings, key=lambda f: (order[_sev(f)], str(f.get("file")), int(f.get("line") or 0)))
    open_findings = [f for f in findings if f.get("status", "open") == "open"]
    project = _clean(meta.get("project") or "Projeto")
    generated = datetime.now().strftime("%d/%m/%Y %H:%M")
    story: list = []

    def sev_chip(sev: str, label: str | None = None) -> Table:
        t = Table([[Paragraph(f"<b>{_p(label or SEV_LABEL[sev])}</b>",
                              ParagraphStyle("chip", parent=st["cell"], textColor=c(SEV_TEXT[sev]),
                                             alignment=1))]], colWidths=[22 * mm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), c(SEV_COLOR[sev])),
                               ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                               ("ROUNDEDCORNERS", [3, 3, 3, 3])]))
        return t

    # ------------------------------------------------------------------ capa / resumo
    story += [Paragraph("Relatório de Segurança", st["title"]), Spacer(1, 3),
              Paragraph(_p(project), st["subtitle"]), Spacer(1, 12)]

    date_raw = meta.get("date")
    try:
        date_txt = datetime.fromisoformat(str(date_raw)).strftime("%d/%m/%Y %H:%M") if date_raw else generated
    except ValueError:
        date_txt = str(date_raw)
    meta_rows = [
        ("Análise", f"#{meta['scan_id']}" if meta.get("scan_id") else "linha de comando"),
        ("Data", date_txt),
        ("Origem", SOURCE_LABEL.get(str(meta.get("source")), meta.get("source") or "-")),
        ("Código analisado", meta.get("source_ref") or "-"),
        ("Branch / commit", " / ".join(x for x in [meta.get("branch"), (meta.get("commit") or "")[:10]] if x) or "-"),
        ("Arquivos / linhas", f"{meta.get('files_scanned', 0)} arquivos, {meta.get('lines_of_code', 0)} linhas"),
        ("Motores", ", ".join(meta.get("engines") or []) or "-"),
    ]
    mt = Table([[Paragraph(_p(k), st["label"]), Paragraph(_p(v), st["cell"])] for k, v in meta_rows],
               colWidths=[38 * mm, 136 * mm])
    mt.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, c(LINE)), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story += [mt, Spacer(1, 14)]

    # resultado do gate
    if gate is not None:
        analyzed = gate.get("analyzed", True)
        passed = bool(gate.get("passed"))
        if not analyzed:
            color, verdict = "#8A8F98", "SEM ANÁLISE"
        elif passed:
            color, verdict = "#1F8A3B", "APROVADO"
        else:
            color, verdict = "#C62F2F", "BLOQUEADO"
        reasons = "; ".join(gate.get("reasons") or [])
        gt = Table([[Paragraph(f"<font size=8 color='#FFFFFF'>SECURITY GATE</font><br/>"
                               f"<font size=17 color='#FFFFFF'><b>{verdict}</b></font>", st["body"]),
                     Paragraph(_p(reasons or "-"), ParagraphStyle("gr", parent=st["body"],
                                                                   textColor=c("#FFFFFF")))]],
                   colWidths=[50 * mm, 124 * mm])
        gt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), c(color)), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                                ("LEFTPADDING", (0, 0), (-1, -1), 10), ("ROUNDEDCORNERS", [4, 4, 4, 4])]))
        story += [gt, Spacer(1, 14)]

    # contagem por severidade
    story.append(Paragraph("Achados em aberto por severidade", st["h2"]))
    total = sum(counts.get(s, 0) for s in SEVERITIES)
    head = [Paragraph(f"<b>{SEV_LABEL[s]}</b>", ParagraphStyle("sh", parent=st["cell"],
                                                             textColor=c(SEV_TEXT[s]), alignment=1))
            for s in SEVERITIES] + [Paragraph("<b>Total</b>", ParagraphStyle("st", parent=st["cell"], alignment=1,
                                                                           textColor=c("#FFFFFF")))]
    nums = [Paragraph(f"<font size=16><b>{counts.get(s, 0)}</b></font>",
                      ParagraphStyle("sn", parent=st["cell"], alignment=1, leading=20)) for s in SEVERITIES] + \
           [Paragraph(f"<font size=16><b>{total}</b></font>", ParagraphStyle("tn", parent=st["cell"], alignment=1,
                                                                            leading=20))]
    sevt = Table([head, nums], colWidths=[29 * mm] * 6)
    style = [("BOX", (0, 0), (-1, -1), 0.5, c(LINE)), ("INNERGRID", (0, 0), (-1, -1), 0.5, c(LINE)),
             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
             ("BACKGROUND", (5, 0), (5, 0), c(INK))]
    style += [("BACKGROUND", (i, 0), (i, 0), c(SEV_COLOR[s])) for i, s in enumerate(SEVERITIES)]
    sevt.setStyle(TableStyle(style))
    story += [sevt, Spacer(1, 6)]
    extra = []
    if meta.get("new_count") is not None:
        extra.append(f"{meta.get('new_count', 0)} novo(s) e {meta.get('fixed_count', 0)} corrigido(s) em relação à análise anterior.")
    ai = meta.get("ai_stats") or {}
    if ai:
        extra.append(f"IA ({_clean(ai.get('model') or 'heurística')}): {ai.get('llm_reviewed', 0)} achado(s) revisado(s), "
                     f"{ai.get('fixes_verified', 0)} correção(ões) verificada(s) pelo motor.")
    if extra:
        story.append(Paragraph(_p(" ".join(extra)), st["small"]))
    story.append(Spacer(1, 12))

    # resumo executivo
    story.append(Paragraph("Resumo executivo", st["h2"]))
    story.append(Paragraph(_p(summary or _executive_text(counts, findings, gate)), st["body"]))
    story.append(Spacer(1, 12))

    # top arquivos / categorias
    top_files = Counter(f.get("file") for f in open_findings).most_common(5)
    top_cwes = Counter((f.get("cwe"), f.get("title")) for f in open_findings).most_common(5)
    if top_files:
        left = [[Paragraph("<b>Arquivos mais críticos</b>", st["cell"]), Paragraph("<b>Qtde</b>", st["cell"])]] + \
               [[Paragraph(_p(name), st["cell"]), Paragraph(str(n), st["cell"])] for name, n in top_files]
        right = [[Paragraph("<b>Categorias mais frequentes</b>", st["cell"]), Paragraph("<b>Qtde</b>", st["cell"])]] + \
                [[Paragraph(f"<b>{_p(cwe)}</b> {_p(title)}", st["cell"]), Paragraph(str(n), st["cell"])]
                 for (cwe, title), n in top_cwes]
        tables = []
        for data in (left, right):
            t = Table(data, colWidths=[70 * mm, 13 * mm])
            t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, c(LINE)),
                                   ("BACKGROUND", (0, 0), (-1, 0), c(PANEL)), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                   ("ALIGN", (1, 0), (1, -1), "RIGHT")]))
            tables.append(t)
        two = Table([tables], colWidths=[87 * mm, 87 * mm])
        two.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        story.append(two)

    if errors:
        story += [Spacer(1, 10), Paragraph("Avisos da análise", st["h2"])]
        for e in errors[:10]:
            prefix = "" if e.get("file") in (None, "*") else f"{e.get('file')}: "
            story.append(Paragraph(_p(f"- {prefix}{e.get('error')}"), st["small"]))

    # ------------------------------------------------------------------ tabela de achados
    story += [PageBreak(), Paragraph(f"Achados ({len(findings)})", st["h1"])]
    if not findings:
        story.append(Paragraph("Nenhum achado.", st["body"]))
    else:
        rows = [[Paragraph(f"<b>{h}</b>", st["cell"]) for h in ("#", "Severidade", "Vulnerabilidade", "Local", "Status")]]
        for i, f in enumerate(findings, 1):
            sev = _sev(f)
            rows.append([
                Paragraph(str(i), st["cell"]),
                sev_chip(sev),
                Paragraph(f"<b>{_p(f.get('title'))}</b><br/><font color='{MUTED}'>{_p(f.get('rule_id'))} · "
                          f"{_p(f.get('cwe'))}</font>", st["cell"]),
                Paragraph(f"{_p(f.get('file'))}:{_p(f.get('line'))}", st["cell"]),
                Paragraph(_p(STATUS_LABEL.get(f.get("status", "open"), f.get("status"))), st["cell"]),
            ])
        ft = Table(rows, colWidths=[8 * mm, 25 * mm, 70 * mm, 49 * mm, 22 * mm], repeatRows=1)
        ft.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), c(PANEL)), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                ("LINEBELOW", (0, 0), (-1, -1), 0.4, c(LINE)), ("TOPPADDING", (0, 0), (-1, -1), 3),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
        story.append(ft)

    # ------------------------------------------------------------------ detalhes
    detailed = [f for f in open_findings if _sev(f) in ("CRITICAL", "HIGH")][:max_details]
    if detailed:
        story += [PageBreak(), Paragraph("Detalhes dos achados críticos e altos", st["h1"]),
                  Paragraph("Para cada achado: onde está, por que é perigoso, o caminho do dado (quando rastreado) e "
                            "como corrigir.", st["small"]), Spacer(1, 8)]
    for i, f in enumerate(detailed, 1):
        sev = _sev(f)
        block: list = []
        title = Table([[sev_chip(sev), Paragraph(f"<b>{i}. {_p(f.get('title'))}</b>", st["h2"])]],
                      colWidths=[25 * mm, 149 * mm])
        title.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        block.append(title)
        info = (f"<b>Local:</b> {_p(f.get('file'))}, linha {_p(f.get('line'))} &nbsp;·&nbsp; <b>{_p(f.get('cwe'))}</b>"
                + (f" &nbsp;·&nbsp; {_p(f.get('owasp'))}" if f.get("owasp") else "")
                + f" &nbsp;·&nbsp; motor: {_p(f.get('engine'))}"
                + (f" (confirmado por {_p(', '.join(f.get('confirmed_by')))})" if f.get("confirmed_by") else ""))
        block += [Paragraph(info, st["small"]), Spacer(1, 3), Paragraph(_p(f.get("message")), st["body"])]
        if f.get("snippet"):
            block += [Spacer(1, 4), _code_box(Preformatted(_code(f["snippet"]), st["code"]), c, mm)]
        story.append(KeepTogether(block))
        trace = f.get("trace") or []
        if trace:
            steps = "<br/>".join(f"{n}. {_p(t.get('file'))}:{_p(t.get('line'))} - {_p(t.get('description'))}"
                                 for n, t in enumerate(trace, 1))
            story += [Spacer(1, 4), Paragraph("Caminho do dado (taint analysis)", st["label"]),
                      Paragraph(steps, st["cell"])]
        if f.get("remediation"):
            story += [Spacer(1, 5), Paragraph("Como corrigir", st["label"]), Paragraph(_p(f["remediation"]), st["body"])]
        ai_f = f.get("ai") or {}
        if ai_f:
            mode = "LLM local" if ai_f.get("mode") == "llm" else "heurística"
            story += [Spacer(1, 5), Paragraph(f"Análise da IA ({_p(ai_f.get('model') or mode)})", st["label"])]
            if ai_f.get("explanation"):
                story.append(Paragraph(_p(ai_f["explanation"]), st["body"]))
            if ai_f.get("exploit_scenario"):
                story.append(Paragraph(f"<b>Cenário de exploração:</b> {_p(ai_f['exploit_scenario'])}", st["body"]))
            if ai_f.get("fixed_code"):
                verified = ai_f.get("fix_verified")
                badge = ("<font color='#1F8A3B'><b>Correção verificada pelo motor</b></font>" if verified
                         else f"<font color='{MUTED}'>Correção sugerida ({_p(ai_f.get('fix_check') or 'não verificada')})</font>")
                story += [Spacer(1, 3), Paragraph(badge, st["small"]),
                          _code_box(Preformatted(_code(ai_f["fixed_code"], max_lines=24), st["code"]), c, mm,
                                    background="#EEF7F0")]
        story += [Spacer(1, 6), _rule(c), Spacer(1, 6), CondPageBreak(60 * mm)]
    rest = [f for f in open_findings if _sev(f) in ("CRITICAL", "HIGH")][max_details:]
    if rest:
        story.append(Paragraph(_p(f"... e mais {len(rest)} achado(s) crítico(s)/alto(s), listados na tabela acima."),
                               st["small"]))

    # ------------------------------------------------------------------ como ler
    story += [PageBreak(), Paragraph("Como ler este relatório", st["h1"])]
    glossary = [
        ("Severidade", "Crítica e Alta: exploráveis com impacto relevante; corrigir antes de ir para produção. "
                       "Média: corrigir no ciclo atual. Baixa e Informativa: boas práticas."),
        ("Security Gate", "Política automática que bloqueia o código (por exemplo, um Pull Request) quando há "
                          "achados acima do limite configurado (padrão: Alta ou superior)."),
        ("SAST", "Análise estática de segurança: o código é lido, nunca executado."),
        ("Taint analysis", "Rastreamento do dado que vem do usuário (fonte) até uma função perigosa (sink), como uma "
                           "consulta SQL. Quando existe esse caminho sem sanitização, a falha é explorável."),
        ("CWE / OWASP", "Classificações padrão de fraquezas (CWE, do MITRE) e dos riscos mais comuns em aplicações "
                        "web (OWASP Top 10)."),
        ("Correção verificada", "A correção sugerida pela IA foi aplicada em memória e o motor reanalisou o código: "
                                "a vulnerabilidade não é mais detectada."),
        ("Provável falso positivo", "Achado que a IA, com alta confiança, considera não explorável. Ele não é "
                                    "apagado: cabe a uma pessoa confirmar."),
    ]
    gt2 = Table([[Paragraph(f"<b>{_p(k)}</b>", st["cell"]), Paragraph(_p(v), st["cell"])] for k, v in glossary],
                colWidths=[38 * mm, 136 * mm])
    gt2.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, c(LINE)), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    story.append(gt2)
    story += [Spacer(1, 10), Paragraph("Relatório gerado automaticamente pelo SAST Sentinel. Os dados técnicos completos "
                                       "estão no arquivo SARIF da mesma análise.", st["small"])]

    # ------------------------------------------------------------------ montagem
    def decorate(canvas, doc) -> None:
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(c(INK))
        canvas.rect(0, h - 11 * mm, w, 11 * mm, fill=1, stroke=0)
        canvas.setFillColor(c(ACCENT))
        canvas.rect(0, h - 11 * mm - 1.2, w, 1.2, fill=1, stroke=0)
        canvas.setFillColor(c("#FFFFFF"))
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(18 * mm, h - 7 * mm, "SAST Sentinel")
        canvas.setFont("Helvetica", 9)
        canvas.drawRightString(w - 18 * mm, h - 7 * mm, _clean(f"Relatório de segurança - {project}")[:80])
        canvas.setFillColor(c(MUTED))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(18 * mm, 10 * mm, _clean(f"Gerado em {generated}"))
        canvas.drawRightString(w - 18 * mm, 10 * mm, f"Página {doc.page}")
        canvas.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm,
                            bottomMargin=18 * mm, title=_clean(f"Relatório de segurança - {project}"),
                            author="SAST Sentinel", subject="Análise estática de segurança (SAST)")
    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return buf.getvalue()


def _code_box(flowable, c, mm, background: str = PANEL):
    from reportlab.platypus import Table, TableStyle

    t = Table([[flowable]], colWidths=[174 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), c(background)), ("BOX", (0, 0), (-1, -1), 0.4, c(LINE)),
                           ("LEFTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    return t


def _rule(c):
    from reportlab.platypus import HRFlowable

    return HRFlowable(width="100%", thickness=0.5, color=c(LINE))
