"""Modelos de dados compartilhados por todo o motor."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(max(0, min(4, value)))
        return cls[str(value).strip().upper()]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class TraceStep:
    """Um passo do fluxo de dados (source -> propagação -> sink)."""

    file: str
    line: int
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    rule_id: str
    title: str
    message: str
    severity: Severity
    cwe: str
    file: str
    line: int
    column: int = 0
    end_line: int | None = None
    snippet: str = ""
    owasp: str = ""
    confidence: str = "MEDIUM"  # HIGH | MEDIUM | LOW
    engine: str = "ast"  # ast | taint | treesitter | bandit | semgrep
    trace: list[TraceStep] = field(default_factory=list)
    remediation: str = ""
    confirmed_by: list[str] = field(default_factory=list)
    ai: dict[str, Any] | None = None
    status: str = "open"  # open | likely_false_positive | false_positive | accepted | fixed

    @property
    def fingerprint(self) -> str:
        """Identificador estavel: não muda se o código apenas se desloca de linha."""
        normalized = re.sub(r"\s+", " ", self.snippet.strip())
        raw = f"{self.rule_id}|{self.file}|{normalized}"
        return hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()[:16]

    @property
    def effective_severity(self) -> Severity:
        """Severidade final: a da IA prevalece quando ha triagem por LLM."""
        if self.ai and self.ai.get("severity") and self.ai.get("mode") == "llm":
            try:
                return Severity.parse(self.ai["severity"])
            except KeyError:
                pass
        return self.severity

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name
        data["effective_severity"] = self.effective_severity.name
        data["fingerprint"] = self.fingerprint
        data["trace"] = [t.to_dict() if isinstance(t, TraceStep) else t for t in self.trace]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        allowed = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        kwargs = {k: v for k, v in data.items() if k in allowed}
        kwargs["severity"] = Severity.parse(kwargs.get("severity", "MEDIUM"))
        kwargs["trace"] = [TraceStep(**t) if isinstance(t, dict) else t for t in kwargs.get("trace", [])]
        return cls(**kwargs)


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    lines_of_code: int = 0
    duration_seconds: float = 0.0
    errors: list[dict[str, Any]] = field(default_factory=list)
    suppressed: int = 0
    engines: list[str] = field(default_factory=list)
    languages: dict[str, int] = field(default_factory=dict)
    ai_stats: dict[str, Any] | None = None

    def counts(self) -> dict[str, int]:
        result = {s.name: 0 for s in reversed(Severity)}
        for f in self.findings:
            if f.status in ("open",):
                result[f.effective_severity.name] += 1
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "lines_of_code": self.lines_of_code,
            "duration_seconds": round(self.duration_seconds, 3),
            "suppressed": self.suppressed,
            "engines": self.engines,
            "languages": self.languages,
            "ai_stats": self.ai_stats,
            "counts": self.counts(),
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }
