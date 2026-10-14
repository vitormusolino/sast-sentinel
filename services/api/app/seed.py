"""Popula o banco com um HISTÓRICO DE DEMONSTRAÇÃO (para a apresentação).

Roda o motor real sobre os corpora de `samples/` e grava scans retroativos
(últimos N dias) simulando um time corrigindo vulnerabilidades aos poucos,
para que o gráfico de tendência tenha histórico. Os projetos criados recebem
o sufixo "(demo)".

    python -m app.seed --samples ../../samples --days 10
"""

from __future__ import annotations

import argparse
import random
from datetime import timedelta
from pathlib import Path

from sast_engine import ScanConfig, Scanner
from sast_engine.gate import GatePolicy, evaluate

from .db import SessionLocal, init_db
from .models import Scan, utcnow
from .services import get_or_create_project, persist_result


def seed(samples: Path, days: int) -> None:
    init_db()
    rng = random.Random(42)  # nosec B311 - dados de demonstração, sem uso criptográfico
    db = SessionLocal()
    # (projeto, corpus, mínimo de achados que sobram ao final)
    targets = [("loja-online (demo)", samples / "vulnerable_app", 6), ("api-pagamentos (demo)", samples / "hard_cases", 0)]
    for name, folder, keep in targets:
        result = Scanner(ScanConfig()).scan_path(folder)
        project = get_or_create_project(db, name, "https://github.com/exemplo/" + name.split()[0])
        remaining = list(result.findings)
        for day in range(days, -1, -1):
            # a cada dia o time corrige 0-2 achados (os mais graves primeiro, como numa sprint real)
            if day != days and remaining:
                for _ in range(rng.randint(0, 2)):
                    if len(remaining) > keep:
                        remaining.pop(0 if rng.random() < 0.6 else rng.randrange(len(remaining)))
            result.findings = list(remaining)
            gate = evaluate(result, GatePolicy(), baseline=set())
            when = utcnow() - timedelta(days=day, hours=rng.randint(0, 6))
            scan = Scan(project_id=project.id, source_type="ci", source_ref=project.repo_url, branch="main",
                        commit_sha=f"{rng.getrandbits(160):040x}", triggered_by="ci", status="running", created_at=when,
                        started_at=when)
            db.add(scan)
            db.flush()
            persist_result(db, scan, result.to_dict(), gate.to_dict())
            scan.finished_at = when + timedelta(seconds=result.duration_seconds + 1)
            db.commit()
        print(f"{name}: {days + 1} scans de demonstração criados")
    db.close()


def find_samples() -> Path:
    """Procura a pasta samples/ subindo a partir deste arquivo; no contêiner fica em /opt/samples."""
    here = Path(__file__).resolve()
    candidates = [p / "samples" for p in here.parents] + [Path("/opt/samples")]
    return next((c for c in candidates if c.is_dir()), Path("samples"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", default=None, help="pasta samples/ (padrão: raiz do repositório ou /opt/samples)")
    parser.add_argument("--days", type=int, default=10)
    args = parser.parse_args()
    seed(Path(args.samples) if args.samples else find_samples(), args.days)
