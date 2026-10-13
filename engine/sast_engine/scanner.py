"""Orquestrador: descobre arquivos, executa os motores e consolida os achados.

Pipeline:  descoberta -> parsing -> regras AST -> taint (projeto inteiro)
           -> Tree-sitter (JS) -> Bandit/Semgrep (opcional) -> dedupe/consenso
           -> triagem por IA (opcional)
"""

from __future__ import annotations

import fnmatch
import os
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .integrations import run_bandit, run_semgrep
from .models import Finding, ScanResult, Severity
from .parsers.java_parser import JAVA_AVAILABLE, JAVA_EXTENSIONS, analyze_java
from .parsers.js_parser import JS_EXTENSIONS, TREE_SITTER_AVAILABLE, analyze_javascript
from .parsers.python_parser import ParsedModule, parse_python
from .rules.python_rules import run_python_rules
from .taint.python_taint import analyze_project

DEFAULT_EXCLUDES = [
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build",
    ".tox", ".mypy_cache", ".pytest_cache", "site-packages", "*.min.js", ".sast_cache",
]
MAX_FILE_BYTES = 1_000_000

# linguagens sem motor próprio: analisadas pelo Semgrep (regras da comunidade) se disponível;
# caso contrário, o scan avisa em vez de "aprovar" em silêncio
UNSUPPORTED_EXTENSIONS = {".kt": "Kotlin", ".go": "Go", ".php": "PHP", ".rb": "Ruby",
                          ".cs": "C#", ".ts": "TypeScript", ".tsx": "TypeScript", ".c": "C", ".cpp": "C++",
                          ".rs": "Rust", ".swift": "Swift", ".scala": "Scala"}
SEMGREP_RULESETS = {"Kotlin": "p/kotlin", "Go": "p/golang", "PHP": "p/php", "Ruby": "p/ruby", "C#": "p/csharp",
                    "TypeScript": "p/typescript", "C": "p/c", "C++": "p/c", "Rust": "p/rust", "Swift": "p/swift",
                    "Scala": "p/scala"}

# prioridade quando dois motores reportam o mesmo problema: fica o achado mais rico
ENGINE_PRIORITY = {"taint": 0, "ast": 1, "treesitter": 2, "semgrep": 3, "bandit": 4}


@dataclass
class ScanConfig:
    excludes: list[str] = field(default_factory=list)
    use_bandit: bool = False
    use_semgrep: bool = False
    semgrep_registry: bool = False
    use_ai: bool = False
    ai_max_findings: int = 10
    min_severity: Severity = Severity.INFO
    languages: tuple[str, ...] = ("python", "javascript", "java")
    semgrep_fallback: bool = True  # outras linguagens via Semgrep registry (requer semgrep + internet)

    @classmethod
    def from_file(cls, path: str | Path) -> tuple[ScanConfig, dict[str, Any]]:
        """Le `.sast.yml`. Retorna (config do scanner, política do gate)."""
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        scan = data.get("scan", {})
        cfg = cls(
            excludes=list(scan.get("exclude", [])),
            use_bandit=bool(scan.get("bandit", False)),
            use_semgrep=bool(scan.get("semgrep", False)),
            semgrep_registry=bool(scan.get("semgrep_registry", False)),
            use_ai=bool(data.get("ai", {}).get("enabled", False)),
            ai_max_findings=int(data.get("ai", {}).get("max_findings", 10)),
            min_severity=Severity.parse(scan.get("min_severity", "INFO")),
        )
        return cfg, data.get("gate", {})


class Scanner:
    def __init__(self, config: ScanConfig | None = None, progress: Callable[[str, float], None] | None = None):
        self.config = config or ScanConfig()
        self.progress = progress or (lambda msg, pct: None)

    # ------------------------------------------------------------------ descoberta
    def _excluded(self, rel: str) -> bool:
        parts = rel.replace("\\", "/").split("/")
        for pattern in DEFAULT_EXCLUDES + self.config.excludes:
            pattern = pattern.rstrip("/")
            if any(fnmatch.fnmatch(p, pattern) for p in parts):
                return True
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, pattern + "/*") or rel.startswith(pattern + "/"):
                return True
        return False

    def discover(self, root: Path) -> list[Path]:
        if root.is_file():
            return [root]
        files = []
        self.unsupported: Counter[str] = Counter()
        self.unsupported_files: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            rel_dir = "" if rel_dir == "." else rel_dir.replace("\\", "/")
            dirnames[:] = [d for d in dirnames if not self._excluded(f"{rel_dir}/{d}".lstrip("/"))]
            for name in filenames:
                rel = f"{rel_dir}/{name}".lstrip("/")
                if self._excluded(rel):
                    continue
                if name.endswith(".py") and "python" in self.config.languages or name.endswith(JS_EXTENSIONS) and "javascript" in self.config.languages or name.endswith(JAVA_EXTENSIONS) and "java" in self.config.languages:
                    files.append(Path(dirpath) / name)
                else:
                    lang = UNSUPPORTED_EXTENSIONS.get(os.path.splitext(name)[1].lower())
                    if lang:
                        self.unsupported[lang] += 1
                        self.unsupported_files.append(Path(dirpath) / name)
        return sorted(files)

    # ------------------------------------------------------------------ execução
    def scan_path(self, target: str | Path) -> ScanResult:
        started = time.perf_counter()
        root = Path(target).resolve()
        base = root.parent if root.is_file() else root
        result = ScanResult(target=str(target))
        engines = ["ast", "taint"]

        self.unsupported = Counter()
        self.unsupported_files = []
        files = self.discover(root)
        self.progress(f"{len(files)} arquivos encontrados", 0.05)
        modules: list[ParsedModule] = []
        sources: dict[str, str] = {}
        findings: list[Finding] = []
        languages: Counter[str] = Counter()

        for idx, path in enumerate(files):
            rel = path.relative_to(base).as_posix()
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    result.errors.append({"file": rel, "error": "arquivo maior que 1MB ignorado"})
                    continue
                source = path.read_text(encoding="utf-8-sig", errors="replace")  # utf-8-sig: aceita BOM (padrão de editores Windows)
            except OSError as exc:
                result.errors.append({"file": rel, "error": str(exc)})
                continue
            sources[rel] = source
            result.lines_of_code += sum(1 for ln in source.splitlines() if ln.strip())
            if path.suffix == ".py":
                languages["python"] += 1
                try:
                    module = parse_python(rel, source)
                except SyntaxError as exc:
                    result.errors.append({"file": rel, "error": f"SyntaxError linha {exc.lineno}: {exc.msg}"})
                    continue
                modules.append(module)
                rule_findings, suppressed = run_python_rules(module)
                findings.extend(rule_findings)
                result.suppressed += suppressed
            elif path.suffix == ".java":
                languages["java"] += 1
                java_findings, suppressed = analyze_java(rel, source)
                findings.extend(java_findings)
                result.suppressed += suppressed
            else:
                languages["javascript"] += 1
                js_findings, suppressed = analyze_javascript(rel, source)
                findings.extend(js_findings)
                result.suppressed += suppressed
            if idx % 25 == 0:
                self.progress(f"parsing {rel}", 0.05 + 0.35 * idx / max(1, len(files)))

        if languages["javascript"] or languages["java"]:
            if (languages["javascript"] and TREE_SITTER_AVAILABLE) or (languages["java"] and JAVA_AVAILABLE):
                engines.append("treesitter")
            if languages["javascript"] and not TREE_SITTER_AVAILABLE:
                result.errors.append({"file": "*", "error": "tree-sitter não instalado: arquivos JS não analisados"})
            if languages["java"] and not JAVA_AVAILABLE:
                result.errors.append({"file": "*", "error": "tree-sitter-java não instalado: arquivos Java não analisados"})

        self.progress("taint analysis", 0.45)
        try:
            findings.extend(analyze_project(modules))
        except Exception as exc:  # noqa: BLE001 - um construto inesperado nao derruba o scan inteiro
            result.errors.append({"file": "*", "error": f"taint analysis falhou: {type(exc).__name__}: {exc}"})

        excludes = [e for e in self.config.excludes if "*" not in e]
        if self.config.use_bandit and languages["python"]:
            self.progress("executando bandit", 0.55)
            extra, err = run_bandit(base if root.is_file() else root, excludes)
            findings.extend(extra)
            engines.append("bandit") if err is None else result.errors.append({"file": "*", "error": err})
        if self.config.use_semgrep:
            self.progress("executando semgrep", 0.6)
            extra, err = run_semgrep(base if root.is_file() else root, excludes, self.config.semgrep_registry)
            findings.extend(extra)
            engines.append("semgrep") if err is None else result.errors.append({"file": "*", "error": err})

        if self.unsupported:
            self._semgrep_fallback(root, base, excludes, findings, sources, languages, engines, result)

        findings = [f for f in deduplicate(findings) if f.severity >= self.config.min_severity]
        findings = [f for f in findings if f.file in sources and not self._is_suppressed_line(sources[f.file], f.line)]

        if self.config.use_ai and findings:
            self.progress("triagem com IA", 0.7)
            from .ai import AIAnalyzer, AIConfig
            analyzer = AIAnalyzer(config=AIConfig(max_llm_findings=self.config.ai_max_findings))
            stats = analyzer.enrich(findings, sources)
            engines.append(f"ai:{stats['mode']}")
            result.ai_stats = stats

        findings.sort(key=lambda f: (-int(f.effective_severity), f.file, f.line))
        result.findings = findings
        result.files_scanned = len(sources)
        if not sources:
            result.errors.append({"file": "*", "error": "nenhum arquivo de linguagem suportada encontrado: nada foi analisado"})
        result.languages = dict(languages)
        result.engines = engines
        result.duration_seconds = time.perf_counter() - started
        self.progress("concluído", 1.0)
        return result

    def _semgrep_fallback(self, root: Path, base: Path, excludes: list[str], findings: list[Finding],
                          sources: dict[str, str], languages: Counter, engines: list[str], result: ScanResult) -> None:
        """Linguagens sem motor próprio: tenta o Semgrep com os pacotes de regras da comunidade."""
        langs = ", ".join(f"{n} arquivo(s) {lang}" for lang, n in self.unsupported.most_common())
        if not self.config.semgrep_fallback:
            result.errors.append({"file": "*", "error": f"linguagem não suportada, não analisado: {langs}"})
            return
        self.progress("semgrep (outras linguagens)", 0.65)
        rulesets = sorted({SEMGREP_RULESETS[lang] for lang in self.unsupported if lang in SEMGREP_RULESETS})
        exts = sorted({f"*{p.suffix}" for p in self.unsupported_files})
        extra, err = run_semgrep(base if root.is_file() else root, excludes, rulesets=rulesets, includes=exts)
        if err is not None:
            result.errors.append({"file": "*", "error": f"linguagem sem motor próprio e Semgrep indisponível "
                                                        f"({err}), não analisado: {langs}"})
            return
        for path in self.unsupported_files:
            if path.stat().st_size <= MAX_FILE_BYTES:
                rel = path.relative_to(base).as_posix()
                sources[rel] = path.read_text(encoding="utf-8-sig", errors="replace")
                result.lines_of_code += sum(1 for ln in sources[rel].splitlines() if ln.strip())
        for lang, n in self.unsupported.items():
            languages[f"{lang.lower()} (semgrep)"] += n
        findings.extend(extra)
        engines.append("semgrep:" + ",".join(rulesets))
        result.errors.append({"file": "*", "error": f"analisado apenas com regras da comunidade Semgrep "
                                                    f"({', '.join(rulesets)}), sem taint nem IA verificada: {langs}"})

    @staticmethod
    def _is_suppressed_line(source: str, line: int) -> bool:
        lines = source.splitlines()
        if 0 < line <= len(lines):
            text = lines[line - 1]
            return "nosec" in text or "sast: ignore" in text or "sast-ignore" in text
        return False


def deduplicate(findings: list[Finding], line_tolerance: int = 2) -> list[Finding]:
    """Une achados do mesmo problema (arquivo + CWE + linha próxima) vindos de motores diferentes.

    Ferramentas externas as vezes apontam a linha onde o SQL e montado e o motor
    próprio a linha do sink; por isso toleramos +-2 linhas entre motores distintos.
    """
    groups: dict[tuple[str, int, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault((f.file, f.line, f.cwe), []).append(f)

    # anexa achados externos ao grupo vizinho de um motor próprio
    external = {"bandit", "semgrep"}
    for key in list(groups):
        group = groups[key]
        if not all(f.engine in external for f in group):
            continue
        file, line, cwe = key
        for delta in sorted(range(-line_tolerance, line_tolerance + 1), key=abs):
            target = groups.get((file, line + delta, cwe))
            if delta and target and any(f.engine not in external for f in target):
                target.extend(group)
                del groups[key]
                break

    merged: list[Finding] = []
    for group in groups.values():
        group.sort(key=lambda f: (ENGINE_PRIORITY.get(f.engine, 9), -int(f.severity)))
        best = group[0]
        best.severity = max(f.severity for f in group)
        others = sorted({f.engine for f in group[1:] if f.engine != best.engine})
        if others:
            best.confirmed_by = others
            best.confidence = "HIGH"  # consenso entre motores
        merged.append(best)
    return merged


def top_files(findings: list[Finding], n: int = 5) -> list[tuple[str, int]]:
    return Counter(f.file for f in findings if f.status == "open").most_common(n)


def top_cwes(findings: list[Finding], n: int = 5) -> list[tuple[str, int]]:
    return Counter(f.cwe for f in findings if f.status == "open").most_common(n)
