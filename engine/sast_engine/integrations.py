"""Integração com ferramentas SAST externas (Bandit e Semgrep).

As ferramentas rodam como subprocessos e seus resultados são normalizados para
`Finding`. O scanner cruza esses achados com os do motor próprio: quando dois
motores concordam (mesmo arquivo, linha e CWE), o achado ganha confianca HIGH
("consenso entre motores"), o que reduz falsos positivos na triagem.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .models import Finding, Severity
from .rules.catalog import A01, A02, A03, A05, A07, A08, CWE_REMEDIATION

SEMGREP_RULES_DIR = Path(__file__).parent / "semgrep_rules"

CWE_TO_OWASP = {
    "CWE-89": A03, "CWE-78": A03, "CWE-79": A03, "CWE-94": A03, "CWE-95": A03,
    "CWE-22": A01, "CWE-601": A01, "CWE-377": A01,
    "CWE-327": A02, "CWE-328": A02, "CWE-295": A02, "CWE-330": A02,
    "CWE-798": A07, "CWE-259": A07,
    "CWE-502": A08, "CWE-611": A05, "CWE-605": A05, "CWE-489": A05, "CWE-703": "A09:2021-Security Logging and Monitoring Failures",
}


# Normalizacao: o Bandit usa CWEs diferentes da nossa taxonomia para o mesmo problema
BANDIT_CWE_OVERRIDE = {
    "B105": "CWE-798", "B106": "CWE-798", "B107": "CWE-798",  # hardcoded password (Bandit: CWE-259)
    "B307": "CWE-95",  # eval (Bandit: CWE-78)
    "B102": "CWE-95",  # exec
    "B506": "CWE-502",  # yaml.load (Bandit: CWE-20)
    "B201": "CWE-489",  # flask debug (Bandit: CWE-94)
    **{f"B3{n}": "CWE-611" for n in range(13, 21)},  # xml.* (Bandit: CWE-20)
}
# Testes que apenas sinalizam IMPORT de módulo (ruido) ou o padrão seguro (subprocess sem shell)
BANDIT_IGNORED = {"B403", "B404", "B405", "B406", "B407", "B408", "B409", "B410", "B411", "B412", "B413",
                  "B603", "B607"}


def tool_available(name: str) -> bool:
    if name == "bandit":
        try:
            import bandit  # noqa: F401
            return True
        except ImportError:
            return shutil.which("bandit") is not None
    return shutil.which(name) is not None


def _relative(path: str, root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def run_bandit(root: Path, excludes: list[str], timeout: int = 600) -> tuple[list[Finding], str | None]:
    if not tool_available("bandit"):
        return [], "bandit não instalado"
    cmd = [sys.executable, "-m", "bandit", "-r", str(root), "-f", "json", "-q"]
    if excludes:
        cmd += ["-x", ",".join(str(root / e) for e in excludes)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)  # nosec - comando fixo
    except subprocess.TimeoutExpired:
        return [], "bandit excedeu o tempo limite"
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [], f"saída inválida do bandit: {proc.stderr[:200]}"
    findings = []
    sev_map = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH}
    for r in data.get("results", []):
        test_id = r.get("test_id", "")
        if test_id in BANDIT_IGNORED:
            continue
        cwe_id = (r.get("issue_cwe") or {}).get("id")
        cwe = BANDIT_CWE_OVERRIDE.get(test_id) or (f"CWE-{cwe_id}" if cwe_id else "CWE-710")
        findings.append(Finding(
            rule_id=f"BANDIT-{r.get('test_id')}",
            title=r.get("test_name", "bandit").replace("_", " "),
            message=r.get("issue_text", ""),
            severity=sev_map.get(r.get("issue_severity", "MEDIUM"), Severity.MEDIUM),
            cwe=cwe,
            owasp=CWE_TO_OWASP.get(cwe, ""),
            file=_relative(r.get("filename", ""), root),
            line=int(r.get("line_number", 1)),
            column=int(r.get("col_offset", 0) or 0),
            snippet="\n".join(ln.split(" ", 1)[-1] for ln in (r.get("code") or "").strip().splitlines()[:3]),
            confidence=r.get("issue_confidence", "MEDIUM"),
            engine="bandit",
            remediation=CWE_REMEDIATION.get(cwe, "Consulte a documentação do Bandit para este teste."),
        ))
    return findings, None


def run_semgrep(root: Path, excludes: list[str], use_registry: bool = False, timeout: int = 900,
                rulesets: list[str] | None = None, includes: list[str] | None = None
                ) -> tuple[list[Finding], str | None]:
    """Executa o Semgrep. Com `rulesets`, usa só esses pacotes do registry (ex.: p/golang) e
    `includes` restringe os arquivos (ex.: *.go) - é o fallback para linguagens sem motor próprio."""
    if not tool_available("semgrep"):
        return [], "semgrep não instalado"
    if rulesets:
        configs = [arg for r in rulesets for arg in ("--config", r)]
    else:
        configs = ["--config", str(SEMGREP_RULES_DIR)]
        if use_registry:
            configs += ["--config", "p/python", "--config", "p/javascript"]
    cmd = ["semgrep", "scan", *configs, "--json", "--quiet", "--metrics=off", "--timeout", "30", str(root)]
    for e in excludes:
        cmd += ["--exclude", e]
    for pattern in includes or []:
        cmd += ["--include", pattern]
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off"}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False, env=env)  # nosec
    except subprocess.TimeoutExpired:
        return [], "semgrep excedeu o tempo limite"
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [], f"saída inválida do semgrep: {proc.stderr[:200]}"
    sev_map = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwe_raw = meta.get("cwe", ["CWE-710"])
        cwe_raw = cwe_raw[0] if isinstance(cwe_raw, list) else cwe_raw
        cwe = str(cwe_raw).split(":")[0].strip()
        sev = meta.get("sast_severity")
        findings.append(Finding(
            rule_id=f"SEMGREP-{r.get('check_id', '').rsplit('.', 1)[-1]}",
            title=meta.get("title") or r.get("check_id", "semgrep"),
            message=extra.get("message", ""),
            severity=Severity.parse(sev) if sev else sev_map.get(extra.get("severity", "WARNING"), Severity.MEDIUM),
            cwe=cwe,
            owasp=CWE_TO_OWASP.get(cwe, ""),
            file=_relative(r.get("path", ""), root),
            line=int(r.get("start", {}).get("line", 1)),
            column=int(r.get("start", {}).get("col", 0)),
            end_line=int(r.get("end", {}).get("line", 1)),
            snippet=(extra.get("lines") or "").strip()[:500],
            confidence=meta.get("confidence", "MEDIUM"),
            engine="semgrep",
            remediation=meta.get("fix_hint") or CWE_REMEDIATION.get(cwe, ""),
        ))
    return findings, None
