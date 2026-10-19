"""Interface de linha de comando.

Exemplos:
    sast scan ./meu-projeto
    sast scan . --fail-on HIGH --sarif results.sarif --markdown summary.md
    sast scan . --ai --verbose
    sast baseline . -o .sast-baseline.json
    sast benchmark ../samples
    sast rules
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess
import sys
from pathlib import Path

from . import __version__
from .gate import GatePolicy, evaluate, load_baseline, write_baseline
from .models import Severity
from .reporting import to_json, to_markdown, to_sarif, to_terminal
from .rules.catalog import RULES
from .scanner import ScanConfig, Scanner


def _git(*args: str) -> str | None:
    try:
        out = subprocess.run(["git", *args], capture_output=True, text=True, timeout=5, check=False)  # nosec - comando fixo
        return out.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _build_config(args: argparse.Namespace) -> tuple[ScanConfig, GatePolicy]:
    target = Path(args.path)
    config_path = Path(args.config) if args.config else (target if target.is_dir() else target.parent) / ".sast.yml"
    if config_path.exists():
        cfg, gate_data = ScanConfig.from_file(config_path)
    else:
        cfg, gate_data = ScanConfig(), {}
    cfg.excludes += args.exclude or []
    if args.bandit:
        cfg.use_bandit = True
    if args.semgrep:
        cfg.use_semgrep = True
    if args.ai is not None:
        cfg.use_ai = args.ai
    policy = GatePolicy.from_dict(gate_data)
    if args.fail_on:
        policy.fail_on = None if args.fail_on.upper() == "NONE" else Severity.parse(args.fail_on)
    if args.baseline:
        policy.baseline = args.baseline
    elif policy.baseline and not Path(policy.baseline).is_absolute():
        policy.baseline = str(config_path.parent / policy.baseline)
    return cfg, policy


def cmd_scan(args: argparse.Namespace) -> int:
    cfg, policy = _build_config(args)
    progress = None
    if args.verbose:
        progress = lambda msg, pct: print(f"[{pct:4.0%}] {msg}", file=sys.stderr)  # noqa: E731
    result = Scanner(cfg, progress).scan_path(args.path)
    gate = evaluate(result, policy, load_baseline(policy.baseline))

    if args.json:
        Path(args.json).write_text(to_json(result, gate), encoding="utf-8")
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(result), indent=2), encoding="utf-8")
    md = to_markdown(result, gate)
    if args.markdown:
        Path(args.markdown).write_text(md, encoding="utf-8")
    if args.pdf:
        _write_pdf(args, result, gate)
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_file and args.github_summary:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(md + "\n")

    if args.format == "json":
        print(to_json(result, gate))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(result), indent=2))
    elif args.format == "markdown":
        print(md)
    else:
        color = sys.stdout.isatty() and not args.no_color
        print(to_terminal(result, gate, color=color, verbose=args.verbose))

    if args.upload:
        _upload(args, result, gate)
    return 0 if gate.passed or args.no_fail else 1


def _write_pdf(args: argparse.Namespace, result, gate) -> None:
    try:
        from .pdf_report import build_pdf
    except ImportError:  # pragma: no cover
        print("aviso: PDF requer reportlab: pip install \"sast-engine[pdf]\"", file=sys.stderr)
        return
    data = result.to_dict()
    meta = {
        "project": args.project or Path(args.path).resolve().name,
        "source": "ci" if os.getenv("CI") else "cli",
        "source_ref": os.getenv("GITHUB_REPOSITORY") or str(Path(args.path).resolve()),
        "branch": os.getenv("GITHUB_HEAD_REF") or os.getenv("GITHUB_REF_NAME") or _git("rev-parse", "--abbrev-ref", "HEAD"),
        "commit": os.getenv("GITHUB_SHA") or _git("rev-parse", "HEAD"),
        **{k: data.get(k) for k in ("files_scanned", "lines_of_code", "engines", "counts", "ai_stats")},
    }
    try:
        Path(args.pdf).write_bytes(build_pdf(meta, data["findings"], gate.to_dict(), errors=data.get("errors")))
    except ImportError:
        print("aviso: PDF requer reportlab: pip install \"sast-engine[pdf]\"", file=sys.stderr)


def _upload(args: argparse.Namespace, result, gate) -> None:
    import httpx

    payload = {
        "project": args.project or Path(args.path).resolve().name,
        "repo_url": os.getenv("GITHUB_SERVER_URL", "") + "/" + os.getenv("GITHUB_REPOSITORY", "") if os.getenv("GITHUB_REPOSITORY") else None,
        "branch": os.getenv("GITHUB_HEAD_REF") or os.getenv("GITHUB_REF_NAME") or _git("rev-parse", "--abbrev-ref", "HEAD"),
        "commit": os.getenv("GITHUB_SHA") or _git("rev-parse", "HEAD"),
        "triggered_by": "ci" if os.getenv("CI") else "cli",
        "result": result.to_dict(),
        "gate": gate.to_dict(),
    }
    headers = {"X-API-Key": os.getenv("SAST_API_KEY", "")}
    try:
        resp = httpx.post(args.upload.rstrip("/") + "/api/scans/import", json=payload, headers=headers, timeout=30)
        resp.raise_for_status()
        print(f"Resultado enviado ao dashboard: scan #{resp.json().get('id')}", file=sys.stderr)
    except httpx.HTTPError as exc:
        print(f"aviso: falha ao enviar resultado para o dashboard: {exc}", file=sys.stderr)


def cmd_baseline(args: argparse.Namespace) -> int:
    args.fail_on, args.baseline, args.exclude, args.bandit, args.semgrep, args.ai = None, None, [], False, False, False
    cfg, _ = _build_config(args)
    result = Scanner(cfg).scan_path(args.path)
    n = write_baseline(result, args.output)
    print(f"Baseline com {n} achados gravado em {args.output}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    for r in RULES.values():
        print(f"{r.id:<15} {r.severity.name:<9} {r.cwe:<8} {r.language:<11} {r.title}")
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    from .benchmark import run_benchmark

    report = run_benchmark(args.path, compare_bandit=not args.no_bandit, use_ai=args.ai)
    print(report)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sast", description="SAST Sentinel - análise estática de segurança")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="analisa um diretório ou arquivo")
    s.add_argument("path")
    s.add_argument("--config", help="arquivo .sast.yml (padrão: <path>/.sast.yml)")
    s.add_argument("--format", choices=["terminal", "json", "sarif", "markdown"], default="terminal")
    s.add_argument("--json", help="grava relatório JSON neste arquivo")
    s.add_argument("--sarif", help="grava SARIF neste arquivo")
    s.add_argument("--markdown", help="grava resumo Markdown neste arquivo")
    s.add_argument("--pdf", help="grava relatório em PDF (leitura humana) neste arquivo; requer o extra [pdf]")
    s.add_argument("--github-summary", action="store_true", help="anexa resumo em $GITHUB_STEP_SUMMARY")
    s.add_argument("--fail-on", help="severidade mínima que reprova o gate (CRITICAL/HIGH/MEDIUM/LOW/NONE)")
    s.add_argument("--baseline", help="arquivo de baseline: achados conhecidos não reprovam")
    s.add_argument("--exclude", action="append", help="padrão glob a excluir (repetivel)")
    s.add_argument("--bandit", action="store_true", help="executa Bandit e cruza os resultados")
    s.add_argument("--semgrep", action="store_true", help="executa Semgrep e cruza os resultados")
    ai = s.add_mutually_exclusive_group()
    ai.add_argument("--ai", dest="ai", action="store_true", default=None, help="triagem com LLM local (Ollama)")
    ai.add_argument("--no-ai", dest="ai", action="store_false")
    s.add_argument("--upload", help="URL da API para enviar o resultado ao dashboard")
    s.add_argument("--project", help="nome do projeto no dashboard")
    s.add_argument("--no-fail", action="store_true", help="sempre retorna 0 (modo auditoria)")
    s.add_argument("--no-color", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_scan)

    b = sub.add_parser("baseline", help="gera baseline dos achados atuais")
    b.add_argument("path")
    b.add_argument("-o", "--output", default=".sast-baseline.json")
    b.add_argument("--config")
    b.set_defaults(func=cmd_baseline)

    r = sub.add_parser("rules", help="lista as regras disponiveis")
    r.set_defaults(func=cmd_rules)

    bm = sub.add_parser("benchmark", help="mede precisão/recall sobre corpus anotado")
    bm.add_argument("path")
    bm.add_argument("-o", "--output")
    bm.add_argument("--no-bandit", action="store_true")
    bm.add_argument("--ai", action="store_true", help="mede também a triagem por LLM (lento em CPU)")
    bm.set_defaults(func=cmd_benchmark)
    return p


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        with contextlib.suppress(ValueError, OSError):
            sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
