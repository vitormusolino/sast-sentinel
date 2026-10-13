"""Security Gate: decide se um build/PR deve ser bloqueado.

Política (secao `gate` do .sast.yml):

    gate:
      fail_on: HIGH                      # qualquer achado >= HIGH bloqueia
      max_counts: {MEDIUM: 10}           # limites por severidade
      min_confidence: MEDIUM             # ignora achados de baixa confianca
      ignore_likely_false_positives: true  # respeita a triagem da IA
      baseline: .sast-baseline.json      # so achados NOVOS bloqueiam (dívida técnica conhecida não trava o time)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding, ScanResult, Severity

CONFIDENCE_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


@dataclass
class GatePolicy:
    fail_on: Severity | None = Severity.HIGH
    max_counts: dict[str, int] = field(default_factory=dict)
    min_confidence: str = "LOW"
    ignore_likely_false_positives: bool = True
    baseline: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> GatePolicy:
        data = data or {}
        fail_on = data.get("fail_on", "HIGH")
        return cls(
            fail_on=None if str(fail_on).lower() in {"none", "off", "false"} else Severity.parse(fail_on),
            max_counts={k.upper(): int(v) for k, v in (data.get("max_counts") or {}).items()},
            min_confidence=str(data.get("min_confidence", "LOW")).upper(),
            ignore_likely_false_positives=bool(data.get("ignore_likely_false_positives", True)),
            baseline=data.get("baseline"),
        )


@dataclass
class GateResult:
    passed: bool
    reasons: list[str]
    blocking: list[Finding]
    considered: int
    baseline_matched: int
    analyzed: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "status": "NOT_ANALYZED" if not self.analyzed else ("PASSED" if self.passed else "FAILED"),
            "analyzed": self.analyzed,
            "reasons": self.reasons,
            "blocking_count": len(self.blocking),
            "blocking": [f.fingerprint for f in self.blocking],
            "considered": self.considered,
            "baseline_matched": self.baseline_matched,
        }


def load_baseline(path: str | Path | None) -> set[str]:
    if not path or not Path(path).exists():
        return set()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        return {f.get("fingerprint") for f in data["findings"] if f.get("fingerprint")}
    if isinstance(data, list):
        return set(data)
    return set()


def write_baseline(result: ScanResult, path: str | Path) -> int:
    fps = sorted({f.fingerprint for f in result.findings})
    Path(path).write_text(json.dumps(fps, indent=2), encoding="utf-8")
    return len(fps)


def evaluate(result: ScanResult, policy: GatePolicy, baseline: set[str] | None = None) -> GateResult:
    if result.files_scanned == 0 and not result.findings:
        # nada analisado não é o mesmo que "seguro": o gate não aprova
        return GateResult(passed=False, reasons=["nenhum arquivo de linguagem suportada foi analisado"],
                          blocking=[], considered=0, baseline_matched=0, analyzed=False)
    baseline = baseline if baseline is not None else load_baseline(policy.baseline)
    min_conf = CONFIDENCE_ORDER.get(policy.min_confidence, 0)
    considered: list[Finding] = []
    matched = 0
    for f in result.findings:
        if f.status in {"false_positive", "accepted", "fixed"}:
            continue
        if policy.ignore_likely_false_positives and f.status == "likely_false_positive":
            continue
        if CONFIDENCE_ORDER.get(f.confidence.upper(), 1) < min_conf:
            continue
        if f.fingerprint in baseline:
            matched += 1
            continue
        considered.append(f)

    reasons: list[str] = []
    blocking: list[Finding] = []
    if policy.fail_on is not None:
        over = [f for f in considered if f.effective_severity >= policy.fail_on]
        if over:
            blocking.extend(over)
            reasons.append(f"{len(over)} achado(s) com severidade >= {policy.fail_on.name}")
    for sev_name, limit in policy.max_counts.items():
        same = [f for f in considered if f.effective_severity.name == sev_name]
        if len(same) > limit:
            blocking.extend(f for f in same if f not in blocking)
            reasons.append(f"{len(same)} achado(s) {sev_name} (limite {limit})")
    if not reasons:
        reasons.append("nenhum achado viola a política")
    return GateResult(passed=not blocking, reasons=reasons, blocking=blocking, considered=len(considered),
                      baseline_matched=matched)
