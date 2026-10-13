from __future__ import annotations

from typing import Any

from . import models


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def scan_out(scan: models.Scan) -> dict[str, Any]:
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "project": scan.project.name if scan.project else None,
        "status": scan.status,
        "source_type": scan.source_type,
        "source_ref": scan.source_ref,
        "branch": scan.branch,
        "commit_sha": scan.commit_sha,
        "triggered_by": scan.triggered_by,
        "options": scan.options,
        "progress": scan.progress,
        "message": scan.message,
        "created_at": _iso(scan.created_at),
        "started_at": _iso(scan.started_at),
        "finished_at": _iso(scan.finished_at),
        "files_scanned": scan.files_scanned,
        "lines_of_code": scan.lines_of_code,
        "duration_seconds": scan.duration_seconds,
        "counts": scan.counts or {},
        "engines": scan.engines or [],
        "errors": scan.errors or [],
        "ai_stats": scan.ai_stats,
        "ai_summary": scan.ai_summary,
        "gate_passed": scan.gate_passed,
        "gate": scan.gate,
        "new_count": scan.new_count,
        "fixed_count": scan.fixed_count,
    }


def finding_out(f: models.Finding, full: bool = True) -> dict[str, Any]:
    data = {
        "id": f.id,
        "scan_id": f.scan_id,
        "fingerprint": f.fingerprint,
        "rule_id": f.rule_id,
        "title": f.title,
        "message": f.message,
        "severity": f.severity,
        "effective_severity": f.effective_severity,
        "confidence": f.confidence,
        "cwe": f.cwe,
        "owasp": f.owasp,
        "file": f.file,
        "line": f.line,
        "engine": f.engine,
        "confirmed_by": f.confirmed_by or [],
        "status": f.status,
        "is_new": f.is_new,
        "ai_verdict": (f.ai or {}).get("verdict"),
        "fix_verified": (f.ai or {}).get("fix_verified", False),
    }
    if full:
        data.update({"snippet": f.snippet, "trace": f.trace or [], "remediation": f.remediation, "ai": f.ai,
                     "column": f.column, "end_line": f.end_line})
    return data
