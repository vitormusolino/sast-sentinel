"""Endpoint de diagnóstico de rede para o time de suporte.

ATENÇÃO: este arquivo existe apenas no PR de DEMONSTRAÇÃO do Security Gate.
Ele contém uma Command Injection proposital e NÃO deve ser mesclado.
"""

import subprocess

from fastapi import APIRouter

router = APIRouter(prefix="/api/diagnostico", tags=["diagnostico"])


@router.get("/ping")
def ping(host: str):
    # "rápido de implementar": monta o comando com o valor recebido na URL
    saida = subprocess.check_output(f"ping -c 1 {host}", shell=True, timeout=10)
    return {"host": host, "saida": saida.decode(errors="replace")}
