"""Módulo de IA: triagem semântica, classificacao de severidade e remediação.

Fluxo por achado
----------------
1. Monta o contexto: trecho da função envolvente com números de linha,
   regra, CWE e o caminho do taint (source -> sink).
2. Pede ao LLM local (Ollama) um JSON estruturado com veredito
   (verdadeiro/falso positivo), severidade, explicacao, cenário de exploração
   e o trecho corrigido.
3. **Guardrails**: a IA pode ajustar a severidade em no máximo 1 nível; so marca
   "provavel falso positivo" com confianca alta (>= 0.8; >= 0.9 para fluxos de
   taint comprovados). A IA nunca apaga achados: ela os triageia.
4. **Remediação auto-verificada**: o patch sugerido e aplicado em memória no
   arquivo original, re-parseado e reanalisado pelo próprio motor (regras +
   taint). So recebe `fix_verified=True` se o código compila e a mesma
   vulnerabilidade desaparece.
5. Sem LLM disponível, cai para o modo heurístico (remediação do catálogo),
   garantindo que o pipeline nunca quebre por falta de GPU/modelo.
"""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass
from typing import Any

from ..models import Finding, Severity
from ..rules.catalog import get_rule
from .llm import OllamaClient, OpenAICompatClient, make_client

SYSTEM_PROMPT = (
    "Você e um engenheiro de segurança de aplicacoes (AppSec) especialista em revisão de código e SAST. "
    "Análise achados de ferramentas de análise estática, decida se são exploráveis de verdade e proponha "
    "correções minimas e seguras. Responda SEMPRE em JSON válido e em portugues do Brasil."
)

PROMPT_TEMPLATE = """Achado da ferramenta SAST:
- Regra: {rule_id} - {title}
- CWE: {cwe} | OWASP: {owasp}
- Severidade atribuída pela regra: {severity}
- Mensagem: {message}
- Arquivo: {file}, linha {line}
{trace_block}{context_block}
Trecho de código (linhas {start}-{end}; a linha marcada com >> e a do achado):
```{lang}
{numbered}
```

Tarefas:
1. Decida se e um verdadeiro positivo considerando o contexto (dados realmente externos? existe validação? e código de teste?).
2. Classifique a severidade real: CRITICAL, HIGH, MEDIUM, LOW ou INFO. Se não houver um motivo concreto no código para mudar, repita a severidade atribuída pela regra ({severity}).
3. Explique o risco em até 3 frases e descreva um cenário de exploração concreto.
4. Reescreva o trecho COMPLETO das linhas {start}-{end} já corrigido, mantendo a mesma indentacao e o mesmo comportamento funcional, sem números de linha.

Responda apenas com este JSON:
{{"is_false_positive": <true|false>, "confidence": <número entre 0 e 1>, "severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>", "explanation": "<texto>", "exploit_scenario": "<texto>", "fixed_code": "<código corrigido>", "references": ["<url>"]}}
"""

SEVERITY_NAMES = {s.name for s in Severity}
# CWEs de injeção/fluxo: para estes, a ausência de fluxo no taint é evidência relevante para o LLM
INJECTION_CWES = {"CWE-89", "CWE-78", "CWE-95", "CWE-22", "CWE-918", "CWE-79", "CWE-601", "CWE-502", "CWE-117"}
TEST_PATH_HINTS = ("/tests/", "/test/", "test_", "_test.py", "/fixtures/", "conftest.py", "/spec/", ".spec.js", ".test.js")


@dataclass
class AIConfig:
    enabled: bool = True
    max_llm_findings: int = 10
    fp_threshold: float = 0.8
    fp_threshold_taint: float = 0.9
    verify_fixes: bool = True


class AIAnalyzer:
    def __init__(self, client: OllamaClient | OpenAICompatClient | None = None, config: AIConfig | None = None):
        self.client = client or make_client()
        self.config = config or AIConfig()
        self._taint_lines: set[tuple[str, int]] = set()

    @property
    def llm_available(self) -> bool:
        return self.config.enabled and self.client.available()

    # ------------------------------------------------------------------ API
    def enrich(self, findings: list[Finding], sources: dict[str, str]) -> dict[str, Any]:
        """Enriquece os achados in-place. Retorna estatisticas da triagem."""
        use_llm = self.llm_available
        # linhas onde o taint comprovou um fluxo (usado como evidência no prompt)
        self._taint_lines = {(f.file, f.line) for f in findings if f.engine == "taint" or "taint" in f.confirmed_by}
        ordered = sorted(findings, key=lambda f: (-int(f.severity), f.engine != "taint"))
        stats = {"mode": "llm" if use_llm else "heuristic", "model": self.client.model if use_llm else None,
                 "llm_reviewed": 0, "likely_false_positives": 0, "fixes_verified": 0, "severity_changed": 0}
        for i, finding in enumerate(ordered):
            source = sources.get(finding.file, "")
            result = None
            if use_llm and i < self.config.max_llm_findings and source:
                result = self._llm_review(finding, source)
                if result:
                    stats["llm_reviewed"] += 1
            if result is None:
                result = self._heuristic_review(finding, source)
            finding.ai = result
            if result.get("severity_changed"):
                stats["severity_changed"] += 1
            if result.get("verdict") == "likely_false_positive":
                finding.status = "likely_false_positive"
                stats["likely_false_positives"] += 1
            if result.get("fix_verified"):
                stats["fixes_verified"] += 1
        return stats

    def executive_summary(self, counts: dict[str, int], top_files: list[tuple[str, int]], top_cwes: list[tuple[str, int]]
                          ) -> dict[str, str]:
        facts = (f"Total de achados abertos: {sum(counts.values())}. Contagem por severidade: {counts}. Arquivos mais críticos: {top_files[:5]}. "
                 f"CWEs mais frequentes: {top_cwes[:5]}.")
        if self.llm_available:
            text = self.client.generate_text(
                "Escreva um resumo executivo (máximo 5 frases, portugues do Brasil, sem markdown) para gestores "
                f"sobre o resultado desta varredura SAST, priorizando ações. Dados: {facts}", SYSTEM_PROMPT)
            if text:
                return {"mode": "llm", "text": clean_llm_text(text)}
        total = sum(counts.values())
        crit = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
        parts = [f"A varredura encontrou {total} achados abertos, sendo {crit} de severidade alta ou crítica."]
        if top_files:
            parts.append(f"O arquivo mais crítico e {top_files[0][0]} ({top_files[0][1]} achados).")
        if top_cwes:
            parts.append(f"A categoria predominante e {top_cwes[0][0]}; priorize correções desse tipo.")
        parts.append("Recomenda-se corrigir os itens CRITICAL/HIGH antes do próximo merge, pois o Security Gate os bloqueia.")
        return {"mode": "heuristic", "text": " ".join(parts)}

    # ------------------------------------------------------------------ LLM
    def _extra_context(self, finding: Finding, source: str, start: int, end: int) -> str:
        """Engenharia de contexto: o que o LLM não vê no trecho, mas o motor determinístico sabe.

        1. Evidência do taint analysis: se a regra é de injeção e o taint (que entende int(),
           escape, allowlists...) NÃO encontrou fluxo de dado externo até a linha, isso é dito.
        2. Definição das funções do mesmo arquivo chamadas no trecho (ex.: um helper `to_int()`
           que sanitiza o valor e fica fora da função analisada).
        """
        parts: list[str] = []
        if finding.engine != "taint" and finding.cwe in INJECTION_CWES and finding.file.endswith(".py") \
                and (finding.file, finding.line) not in self._taint_lines:
            parts.append("- Evidência do motor de taint analysis: NENHUM fluxo de dado externo não sanitizado "
                         "(request, input, argv...) alcança esta linha. Os valores interpolados vêm de constantes "
                         "ou foram convertidos/sanitizados. Considere isso ao decidir se é explorável.")
        helpers = called_helpers(source, start, end) if finding.file.endswith(".py") else []
        if helpers:
            parts.append("- Funções auxiliares do mesmo arquivo usadas no trecho:\n```python\n"
                         + "\n\n".join(helpers) + "\n```")
        return ("\n".join(parts) + "\n") if parts else ""

    def _llm_review(self, finding: Finding, source: str) -> dict[str, Any] | None:
        lines = source.splitlines()
        start, end = enclosing_block(source, finding.line)
        numbered = "\n".join(
            f"{'>>' if n == finding.line else '  '}{n:4d}| {lines[n - 1]}" for n in range(start, end + 1))
        trace_block = ""
        if finding.trace:
            steps = "\n".join(f"  {i + 1}. linha {t.line}: {t.description}" for i, t in enumerate(finding.trace))
            trace_block = f"- Fluxo de dados detectado (taint):\n{steps}\n"
        prompt = PROMPT_TEMPLATE.format(
            rule_id=finding.rule_id, title=finding.title, cwe=finding.cwe, owasp=finding.owasp or "-",
            severity=finding.severity.name, message=finding.message, file=finding.file, line=finding.line,
            trace_block=trace_block, context_block=self._extra_context(finding, source, start, end),
            start=start, end=end, numbered=numbered,
            lang="javascript" if finding.file.endswith((".js", ".jsx", ".mjs")) else "python",
        )
        data = self.client.generate_json(prompt, SYSTEM_PROMPT)
        if not data:
            return None

        # ---- guardrails
        try:
            confidence = float(data.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))
        proposed = str(data.get("severity", finding.severity.name)).upper()
        proposed_sev = Severity[proposed] if proposed in SEVERITY_NAMES else finding.severity
        delta = max(-1, min(1, int(proposed_sev) - int(finding.severity)))
        if finding.engine == "taint" and delta < 0:
            delta = 0  # fluxo source->sink comprovado pelo motor: a IA não rebaixa
        final_sev = Severity(int(finding.severity) + delta)
        is_fp = bool(data.get("is_false_positive"))
        threshold = self.config.fp_threshold_taint if finding.engine == "taint" else self.config.fp_threshold
        verdict = "likely_false_positive" if is_fp and confidence >= threshold else "true_positive"

        fixed_code = str(data.get("fixed_code") or "").strip("\n")
        verification = {"fix_verified": False, "fix_check": "não verificado"}
        if fixed_code and self.config.verify_fixes and finding.file.endswith(".py"):
            verification = verify_python_fix(source, finding, start, end, fixed_code)

        return {
            "mode": "llm",
            "model": self.client.model,
            "verdict": verdict,
            "confidence": round(confidence, 2),
            "severity": final_sev.name,
            "severity_changed": final_sev != finding.severity,
            "llm_raw_severity": proposed,
            "explanation": str(data.get("explanation", ""))[:1500],
            "exploit_scenario": str(data.get("exploit_scenario", ""))[:1000],
            "fixed_code": fixed_code[:4000],
            "fix_range": [start, end],
            "references": [str(r) for r in (data.get("references") or [])][:5],
            **verification,
        }

    # ------------------------------------------------------------------ heurística
    def _heuristic_review(self, finding: Finding, source: str) -> dict[str, Any]:
        rule = get_rule(finding.rule_id)
        severity = finding.severity
        notes = []
        path = "/" + finding.file.replace("\\", "/").lower()
        if any(h in path for h in TEST_PATH_HINTS):
            severity = Severity(max(Severity.INFO, severity - 1))
            notes.append("arquivo de teste: severidade reduzida em 1 nível")
        if len(finding.confirmed_by) >= 1:
            notes.append(f"confirmado por {len(finding.confirmed_by) + 1} motores")
        explanation = (rule.description if rule else finding.message)
        if notes:
            explanation += " (" + "; ".join(notes) + ")"
        return {
            "mode": "heuristic",
            "model": None,
            "verdict": "true_positive",
            "confidence": 0.9 if finding.confirmed_by or finding.engine == "taint" else 0.7,
            "severity": severity.name,
            "severity_changed": severity != finding.severity,
            "explanation": explanation,
            "exploit_scenario": "",
            "fixed_code": rule.example_fix if rule else "",
            "fix_range": None,
            "references": [f"https://cwe.mitre.org/data/definitions/{finding.cwe.split('-')[-1]}.html"],
            "fix_verified": False,
            "fix_check": "exemplo do catálogo (modo heurístico)",
        }


# ---------------------------------------------------------------------- utilitarios
def clean_llm_text(text: str) -> str:
    """Remove cercas de markdown e desembrulha JSON que modelos pequenos às vezes devolvem."""
    import json
    import re

    stripped = re.sub(r"^```\w*\s*|\s*```$", "", text.strip())
    try:
        data = json.loads(stripped)
    except ValueError:
        return stripped
    if isinstance(data, dict):
        values = [v for v in data.values() if isinstance(v, str)]
        return " ".join(values) if values else stripped
    return stripped if not isinstance(data, str) else data


def called_helpers(source: str, start: int, end: int, max_helpers: int = 3, max_lines: int = 20) -> list[str]:
    """Código-fonte das funções do mesmo arquivo chamadas entre as linhas start..end."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    defs = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    lines = source.splitlines()
    called: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and start <= getattr(node, "lineno", 0) <= end:
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
            if name in defs and name not in called and not (start <= defs[name].lineno <= end):
                called.append(name)
    out = []
    for name in called[:max_helpers]:
        fn = defs[name]
        body = lines[fn.lineno - 1:(fn.end_lineno or fn.lineno)]
        if len(body) <= max_lines:
            out.append("\n".join(body))
    return out


def enclosing_block(source: str, line: int, max_lines: int = 40, radius: int = 8) -> tuple[int, int]:
    """Linhas da função que contém `line` (ou uma janela ao redor se for grande)."""
    total = len(source.splitlines())
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return max(1, line - radius), min(total, line + radius)
    best: tuple[int, int] | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            end = node.end_lineno or node.lineno
            if start <= line <= end and (best is None or end - start < best[1] - best[0]):
                best = (node.lineno, end)
    if best and best[1] - best[0] + 1 <= max_lines:
        return best
    return max(1, line - radius), min(total, line + radius)


def _reindent(code: str, reference_line: str) -> str:
    indent = reference_line[: len(reference_line) - len(reference_line.lstrip())]
    dedented = textwrap.dedent(code)
    return "\n".join((indent + ln) if ln.strip() else ln for ln in dedented.splitlines())


def verify_python_fix(source: str, finding: Finding, start: int, end: int, fixed_code: str) -> dict[str, Any]:
    """Aplica o patch em memória e roda o motor de novo sobre o arquivo corrigido."""
    from ..parsers.python_parser import parse_python
    from ..rules.python_rules import run_python_rules
    from ..taint.python_taint import analyze_project

    lines = source.splitlines()
    candidates = [fixed_code, _reindent(fixed_code, lines[start - 1] if start - 1 < len(lines) else "")]
    for candidate in candidates:
        patched = "\n".join(lines[: start - 1] + candidate.splitlines() + lines[end:])
        try:
            module = parse_python(finding.file, patched)
        except SyntaxError:
            continue
        new_len = len(candidate.splitlines())
        region = range(start, start + new_len + 1)
        rule_findings, _ = run_python_rules(module)
        taint_findings = analyze_project([module])
        still = [f for f in rule_findings + taint_findings
                 if f.line in region and (f.rule_id == finding.rule_id or f.cwe == finding.cwe)]
        if still:
            return {"fix_verified": False,
                    "fix_check": f"o motor ainda detecta {still[0].rule_id} no código corrigido (linha {still[0].line})"}
        return {"fix_verified": True, "fix_check": "patch compila e a vulnerabilidade não e mais detectada"}
    return {"fix_verified": False, "fix_check": "código sugerido não compila (SyntaxError)"}
