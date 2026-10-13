"""Benchmark de precisão/recall usando código anotado com o gabarito.

Cada linha vulnerável do corpus de teste recebe um comentário `# EXPECT: CWE-89`
(ou `// EXPECT: CWE-79` em JS). Qualquer achado fora do gabarito conta como
falso positivo; qualquer linha anotada sem achado e um falso negativo.
O corpus `samples/safe_app` não tem anotacoes: tudo que aparecer la e FP.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding
from .scanner import ScanConfig, Scanner

EXPECT_RE = re.compile(r"(?:#|//)\s*EXPECT:\s*([A-Z0-9\-, ]+)")


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    fp_items: list[str] = field(default_factory=list)
    fn_items: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


def load_ground_truth(root: Path) -> set[tuple[str, int, str]]:
    truth: set[tuple[str, int, str]] = set()
    for path in sorted(root.rglob("*")):
        if path.suffix not in {".py", ".js", ".java"} or "__pycache__" in path.parts:
            continue
        rel = path.relative_to(root).as_posix()
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = EXPECT_RE.search(line)
            if m:
                for cwe in m.group(1).split(","):
                    if cwe.strip():
                        truth.add((rel, n, cwe.strip()))
    return truth


def score(findings: list[Finding], truth: set[tuple[str, int, str]]) -> tuple[Metrics, dict[str, Metrics]]:
    total = Metrics()
    per_cwe: dict[str, Metrics] = defaultdict(Metrics)
    reported = {(f.file, f.line, f.cwe) for f in findings if f.status == "open"}
    # tolerancia: CWEs equivalentes (hash fraco 327/328, eval 94/95, segredo 798/259)
    equiv = {"CWE-328": "CWE-327", "CWE-94": "CWE-95", "CWE-259": "CWE-798", "CWE-916": "CWE-327"}
    reported = {(f, ln, equiv.get(c, c)) for f, ln, c in reported}
    for item in reported:
        if item in truth:
            total.tp += 1
            per_cwe[item[2]].tp += 1
        else:
            total.fp += 1
            per_cwe[item[2]].fp += 1
            total.fp_items.append(f"{item[0]}:{item[1]} {item[2]}")
    for item in truth - reported:
        total.fn += 1
        per_cwe[item[2]].fn += 1
        total.fn_items.append(f"{item[0]}:{item[1]} {item[2]}")
    return total, dict(per_cwe)


def run_benchmark(root: str | Path, compare_bandit: bool = True) -> str:
    root = Path(root).resolve()
    truth = load_ground_truth(root)
    rows: list[tuple[str, Metrics, dict[str, Metrics]]] = []

    ours = Scanner(ScanConfig()).scan_path(root)
    total, per = score(ours.findings, truth)
    rows.append(("SAST Sentinel (AST + taint)", total, per))

    if compare_bandit:
        from .integrations import run_bandit, tool_available
        if tool_available("bandit"):
            bandit_findings, _ = run_bandit(root, [])
            b_total, b_per = score(bandit_findings, truth)
            rows.append(("Bandit (sozinho)", b_total, b_per))
            combo = Scanner(ScanConfig(use_bandit=True)).scan_path(root)
            c_total, c_per = score(combo.findings, truth)
            rows.append(("SAST Sentinel + Bandit (consenso)", c_total, c_per))

    out = ["# Benchmark de Precisão SAST", "",
           f"Corpus: `{root.name}`, {len(truth)} vulnerabilidades anotadas (gabarito `# EXPECT:`).", "",
           "| Ferramenta | TP | FP | FN | Precisão | Recall | F1 |", "|---|---:|---:|---:|---:|---:|---:|"]
    for name, m, _ in rows:
        out.append(f"| {name} | {m.tp} | {m.fp} | {m.fn} | {m.precision:.1%} | {m.recall:.1%} | {m.f1:.2f} |")
    out += ["", "## Por CWE (SAST Sentinel)", "", "| CWE | TP | FP | FN | Precisão | Recall |", "|---|---:|---:|---:|---:|---:|"]
    for cwe, m in sorted(rows[0][2].items()):
        out.append(f"| {cwe} | {m.tp} | {m.fp} | {m.fn} | {m.precision:.0%} | {m.recall:.0%} |")
    if rows[0][1].fp_items:
        out += ["", "### Falsos positivos", ""] + [f"- `{i}`" for i in sorted(rows[0][1].fp_items)]
    if rows[0][1].fn_items:
        out += ["", "### Falsos negativos", ""] + [f"- `{i}`" for i in sorted(rows[0][1].fn_items)]
    return "\n".join(out) + "\n"
