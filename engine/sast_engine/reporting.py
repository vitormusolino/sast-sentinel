"""Exportadores: JSON, SARIF 2.1.0 (GitHub Code Scanning), Markdown e tabela de terminal."""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .gate import GateResult
from .models import ScanResult, Severity
from .rules.catalog import RULES
from .scanner import top_cwes, top_files

SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
               Severity.LOW: "note", Severity.INFO: "note"}
SECURITY_SCORE = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                  Severity.LOW: "3.0", Severity.INFO: "1.0"}
EMOJI = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "INFO": "⬜"}


def to_json(result: ScanResult, gate: GateResult | None = None) -> str:
    data = result.to_dict()
    if gate is not None:
        data["gate"] = gate.to_dict()
    return json.dumps(data, indent=2, ensure_ascii=False)


def to_sarif(result: ScanResult) -> dict[str, Any]:
    rules_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for f in result.findings:
        if f.rule_id not in rules_index:
            meta = RULES.get(f.rule_id)
            rules_index[f.rule_id] = len(rules)
            rules.append({
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": meta.description if meta else f.message},
                "help": {"text": f.remediation or (meta.remediation if meta else ""),
                         "markdown": f"**Correção:** {f.remediation}"},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[-1]}.html",
                "properties": {
                    "tags": ["security", f.cwe, f.owasp] if f.owasp else ["security", f.cwe],
                    "security-severity": SECURITY_SCORE[f.severity],
                    "precision": {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(f.confidence, "medium"),
                },
            })
        sev = f.effective_severity
        entry: dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": rules_index[f.rule_id],
            "level": SARIF_LEVEL[sev],
            "message": {"text": f"[{sev.name}] {f.message}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": f.line, "startColumn": f.column + 1,
                           **({"endLine": f.end_line} if f.end_line else {})},
            }}],
            "partialFingerprints": {"sastFingerprint/v1": f.fingerprint},
            "properties": {"engine": f.engine, "confidence": f.confidence, "cwe": f.cwe,
                           "status": f.status, "confirmed_by": f.confirmed_by},
        }
        if f.trace:
            entry["codeFlows"] = [{"threadFlows": [{"locations": [
                {"location": {"physicalLocation": {"artifactLocation": {"uri": t.file},
                                                   "region": {"startLine": max(1, t.line)}},
                              "message": {"text": t.description}}}
                for t in f.trace]}]}]
        if f.status == "likely_false_positive":
            entry["suppressions"] = [{"kind": "external", "justification": "Triagem por IA: provavel falso positivo"}]
        results.append(entry)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SAST Sentinel", "version": __version__,
                                "informationUri": "https://github.com/", "rules": rules}},
            "results": results,
        }],
    }


def to_markdown(result: ScanResult, gate: GateResult | None = None, limit: int = 25) -> str:
    counts = result.counts()
    lines = ["## 🛡️ SAST Sentinel - Relatório de Segurança", ""]
    if gate is not None:
        icon = "⚠️" if not gate.analyzed else ("✅" if gate.passed else "⛔")
        label = "SEM ANÁLISE" if not gate.analyzed else ("APROVADO" if gate.passed else "BLOQUEADO")
        lines += [f"**Security Gate:** {icon} **{label}** - "
                  + "; ".join(gate.reasons), ""]
        if gate.baseline_matched:
            lines += [f"_{gate.baseline_matched} achado(s) já conhecidos (baseline) não bloqueiam o merge._", ""]
    lines += ["| Severidade | Qtde |", "|---|---:|"]
    lines += [f"| {EMOJI[k]} {k} | {v} |" for k, v in counts.items()]
    lines += ["", f"Arquivos analisados: **{result.files_scanned}** | Linhas: **{result.lines_of_code}** | "
                  f"Motores: `{', '.join(result.engines)}` | Tempo: {result.duration_seconds:.1f}s", ""]
    tf = top_files(result.findings)
    if tf:
        lines += ["**Top arquivos críticos:** " + ", ".join(f"`{f}` ({n})" for f, n in tf), ""]
    tc = top_cwes(result.findings)
    if tc:
        lines += ["**CWEs mais frequentes:** " + ", ".join(f"{c} ({n})" for c, n in tc), ""]
    open_findings = [f for f in result.findings if f.status == "open"]
    if open_findings:
        lines += [f"<details><summary>Achados (até {limit})</summary>", "",
                  "| Sev | Regra | Arquivo | Descrição |", "|---|---|---|---|"]
        for f in open_findings[:limit]:
            msg = f.message.replace("|", "\\|")
            lines.append(f"| {EMOJI[f.effective_severity.name]} {f.effective_severity.name} | {f.rule_id} ({f.cwe}) "
                         f"| `{f.file}:{f.line}` | {msg} |")
        lines += ["", "</details>"]
    return "\n".join(lines)


ANSI = {"CRITICAL": "\033[1;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[1;33m", "LOW": "\033[1;36m",
        "INFO": "\033[2m", "RESET": "\033[0m", "BOLD": "\033[1m", "DIM": "\033[2m", "GREEN": "\033[1;32m"}


def to_terminal(result: ScanResult, gate: GateResult | None = None, color: bool = True, verbose: bool = False) -> str:
    c = ANSI if color else {k: "" for k in ANSI}
    out = [f"{c['BOLD']}SAST Sentinel {__version__}{c['RESET']}  alvo: {result.target}", ""]
    for f in result.findings:
        sev = f.effective_severity.name
        tag = f"{c[sev]}{sev:<8}{c['RESET']}"
        status = f" {c['DIM']}[{f.status}]{c['RESET']}" if f.status != "open" else ""
        confirmed = f" {c['DIM']}+{','.join(f.confirmed_by)}{c['RESET']}" if f.confirmed_by else ""
        out.append(f"{tag} {f.rule_id:<14} {f.file}:{f.line}  {f.title} ({f.cwe}){confirmed}{status}")
        out.append(f"         {c['DIM']}{f.message}{c['RESET']}")
        if verbose:
            for line in f.snippet.splitlines()[:3]:
                out.append(f"         {c['DIM']}| {line}{c['RESET']}")
            for t in f.trace:
                out.append(f"         {c['DIM']}-> L{t.line}: {t.description}{c['RESET']}")
            if f.ai and f.ai.get("fix_check"):
                out.append(f"         {c['DIM']}IA: {f.ai.get('fix_check')}{c['RESET']}")
    counts = result.counts()
    out += ["", "Resumo: " + "  ".join(f"{c[k]}{k}{c['RESET']}={v}" for k, v in counts.items()),
            f"{result.files_scanned} arquivos, {result.lines_of_code} linhas, {result.duration_seconds:.2f}s, "
            f"motores: {', '.join(result.engines)}, suprimidos: {result.suppressed}"]
    for e in result.errors[:10]:
        out.append(f"{c['DIM']}aviso: {e['file']}: {e['error']}{c['RESET']}")
    if gate is not None:
        color_gate = c["GREEN"] if gate.passed else c["CRITICAL"]
        label = "NOT ANALYZED" if not gate.analyzed else ("PASSED" if gate.passed else "FAILED")
        out.append(f"\nSecurity Gate: {color_gate} {label} {c['RESET']} - "
                   + "; ".join(gate.reasons))
    return "\n".join(out)
