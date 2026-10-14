"""Clientes de LLM: Ollama local (/api/generate) ou API compatível com OpenAI (nuvem)."""

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


class OpenAICompatClient:
    """LLM hospedado via API compatível com OpenAI (/chat/completions).

    Usado quando não há Ollama disponível (ex.: deploy gratuito na nuvem, sem RAM para um
    modelo local). Funciona com Groq, OpenRouter, Together, Gemini (endpoint OpenAI), a própria
    OpenAI ou até um Ollama remoto (/v1). Mesma interface do OllamaClient, então a triagem, os
    guardrails e a verificação de patch continuam idênticos.
    """

    def __init__(self, base_url: str, api_key: str, model: str, timeout: float = 60.0,
                 cache_dir: str | None = os.getenv("LLM_CACHE_DIR") or None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self._available: bool | None = None
        self._json_mode = True

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def available(self) -> bool:
        if self._available is not None:
            return self._available
        if not self.api_key:
            self._available = False
            return False
        try:
            resp = httpx.get(f"{self.base_url}/models", headers=self._headers, timeout=5.0)
            self._available = resp.status_code == 200
        except httpx.HTTPError:
            self._available = False
        return self._available

    def _chat(self, prompt: str, system: str, temperature: float, max_tokens: int, json_mode: bool) -> str | None:
        messages = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
        payload: dict[str, Any] = {"model": self.model, "messages": messages, "temperature": temperature,
                                   "max_tokens": max_tokens}
        if json_mode and self._json_mode:
            payload["response_format"] = {"type": "json_object"}
        try:
            resp = httpx.post(f"{self.base_url}/chat/completions", json=payload, headers=self._headers,
                              timeout=self.timeout)
            if resp.status_code == 400 and "response_format" in payload:
                # provedor sem modo JSON: tenta de novo sem ele (parse_json_loose resolve o resto)
                self._json_mode = False
                return self._chat(prompt, system, temperature, max_tokens, json_mode)
            resp.raise_for_status()
            return (resp.json()["choices"][0]["message"].get("content") or "").strip() or None
        except (httpx.HTTPError, ValueError, KeyError, IndexError):
            return None

    def generate_json(self, prompt: str, system: str = "", temperature: float = 0.1) -> dict[str, Any] | None:
        key = hashlib.sha256(f"{self.model}|{system}|{prompt}".encode()).hexdigest()[:24]
        cache = self.cache_dir / f"{key}.json" if self.cache_dir else None
        if cache and cache.exists():
            return json.loads(cache.read_text(encoding="utf-8"))
        # alguns provedores exigem a palavra "JSON" no prompt para ativar o modo JSON
        text = self._chat(prompt + "\n\nResponda apenas com um objeto JSON.", system, temperature, 900, True)
        data = parse_json_loose(text) if text else None
        if data is not None and cache:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return data

    def generate_text(self, prompt: str, system: str = "", temperature: float = 0.3) -> str | None:
        return self._chat(prompt, system, temperature, 600, False)


def make_client(timeout: float | None = None) -> OllamaClient | OpenAICompatClient:
    """Escolhe o backend do LLM pelas variáveis de ambiente.

    * `LLM_API_KEY` definida -> API compatível com OpenAI (`LLM_BASE_URL`, `LLM_MODEL`; padrão: Groq)
    * caso contrário -> Ollama local (`OLLAMA_URL`, `OLLAMA_MODEL`), comportamento original
    """
    api_key = os.getenv("LLM_API_KEY", "").strip()
    if api_key:
        return OpenAICompatClient(
            base_url=os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1"),
            api_key=api_key,
            model=os.getenv("LLM_MODEL", "llama-3.1-8b-instant"),
            **({"timeout": timeout} if timeout else {}),
        )
    return OllamaClient(**({"timeout": timeout} if timeout else {}))


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
