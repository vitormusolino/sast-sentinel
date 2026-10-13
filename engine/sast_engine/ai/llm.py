"""Cliente mínimo para LLM local via Ollama (API HTTP /api/generate)."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import httpx

DEFAULT_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")


class OllamaClient:
    def __init__(self, base_url: str = DEFAULT_URL, model: str = DEFAULT_MODEL, timeout: float = 120.0,
                 cache_dir: str | None = os.getenv("LLM_CACHE_DIR") or None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self._available: bool | None = None

    def available(self) -> bool:
        """Verifica se o Ollama responde e se o modelo já foi baixado."""
        if self._available is not None:
            return self._available
        try:
            resp = httpx.get(f"{self.base_url}/api/tags", timeout=3.0)
            models = {m.get("name", "") for m in resp.json().get("models", [])}
            base = self.model.split(":")[0]
            self._available = resp.status_code == 200 and any(
                m == self.model or m.split(":")[0] == base for m in models)
        except (httpx.HTTPError, ValueError):
            self._available = False
        return self._available

    def _cache_path(self, key: str) -> Path | None:
        if not self.cache_dir:
            return None
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        return self.cache_dir / f"{key}.json"

    def generate_json(self, prompt: str, system: str = "", temperature: float = 0.1) -> dict[str, Any] | None:
        key = hashlib.sha256(f"{self.model}|{system}|{prompt}".encode()).hexdigest()[:24]
        cache = self._cache_path(key)
        if cache and cache.exists():
            return json.loads(cache.read_text(encoding="utf-8"))
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "format": "json",
            "stream": False,
            "options": {"temperature": temperature, "num_ctx": 4096, "num_predict": 900},
        }
        try:
            resp = httpx.post(f"{self.base_url}/api/generate", json=payload, timeout=self.timeout)
            resp.raise_for_status()
            text = resp.json().get("response", "")
        except (httpx.HTTPError, ValueError):
            return None
        data = parse_json_loose(text)
        if data is not None and cache:
            cache.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return data

    def generate_text(self, prompt: str, system: str = "", temperature: float = 0.3) -> str | None:
        payload = {"model": self.model, "prompt": prompt, "system": system, "stream": False,
                   "options": {"temperature": temperature, "num_ctx": 4096}}
        try:
            resp = httpx.post(f"{self.base_url}/api/generate", json=payload, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json().get("response", "").strip() or None
        except (httpx.HTTPError, ValueError):
            return None


def parse_json_loose(text: str) -> dict[str, Any] | None:
    """LLMs pequenos as vezes envolvem o JSON em markdown; extraimos o primeiro objeto."""
    text = text.strip()
    text = re.sub(r"^```(json)?|```$", "", text, flags=re.MULTILINE).strip()
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                value = json.loads(match.group(0))
                return value if isinstance(value, dict) else None
            except json.JSONDecodeError:
                return None
    return None
