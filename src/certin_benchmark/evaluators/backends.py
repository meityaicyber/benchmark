"""Language and vision model backends.

Inside the CERT-In environment the models run locally at a fixed version behind an
OpenAI-compatible endpoint (for example vLLM). No backend contacts an external service.

A backend returns raw text for one sampled call; parsing and aggregation are in sampling.py.
"""

from __future__ import annotations

import base64
import json
import mimetypes
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol


@dataclass
class ModelCall:
    system: str
    user: str
    seed: int
    temperature: float
    image_path: str | None = None


class Backend(Protocol):
    name: str
    model: str
    model_version: str

    def complete(self, call: ModelCall) -> str: ...


class BackendUnavailable(RuntimeError):
    pass


class OpenAICompatibleBackend:
    """Chat completions against a local server; the seed is passed per request."""

    def __init__(self, base_url: str, model: str, model_version: str = "unset", timeout_seconds: float = 120,
                 api_key: str | None = None, name: str = "openai_compatible"):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.model_version = model_version
        self.timeout = timeout_seconds
        self.api_key = api_key
        self.name = name

    def complete(self, call: ModelCall) -> str:
        content: list | str
        if call.image_path:
            p = Path(call.image_path)
            if not p.exists():
                raise BackendUnavailable(f"image not found: {call.image_path}")
            mime = mimetypes.guess_type(p.name)[0] or "image/png"
            data = base64.b64encode(p.read_bytes()).decode()
            content = [{"type": "text", "text": call.user},
                       {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{data}"}}]
        else:
            content = call.user
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": call.system}, {"role": "user", "content": content}],
            "temperature": call.temperature,
            "seed": call.seed,
            "max_tokens": 400,
        }
        req = urllib.request.Request(self.base_url + "/chat/completions", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BackendUnavailable(str(exc)) from exc
        return payload["choices"][0]["message"]["content"]


class ReplayBackend:
    """Replays responses recorded in an earlier evaluation record, keyed by (prompt digest, seed).

    Used to recompute an evaluation exactly from its record (Section 11) without the model.
    """

    def __init__(self, responses: dict[str, str], model: str = "replay", model_version: str = "replay"):
        self.responses = responses
        self.model = model
        self.model_version = model_version
        self.name = "replay"

    @staticmethod
    def key(call: ModelCall) -> str:
        import hashlib
        h = hashlib.sha256((call.system + "\x00" + call.user + "\x00" + (call.image_path or "")).encode()).hexdigest()
        return f"{h}:{call.seed}"

    def complete(self, call: ModelCall) -> str:
        k = self.key(call)
        if k not in self.responses:
            raise BackendUnavailable("no recorded response for this item and seed")
        return self.responses[k]


class FunctionBackend:
    """Backend from a Python callable; used in tests and for scripted evaluators."""

    def __init__(self, fn: Callable[[ModelCall], str], model: str = "function", model_version: str = "test"):
        self.fn = fn
        self.model = model
        self.model_version = model_version
        self.name = "function"

    def complete(self, call: ModelCall) -> str:
        return self.fn(call)


class RecordingBackend:
    """Wraps a backend and records every response for later replay."""

    def __init__(self, inner):
        self.inner = inner
        self.model = inner.model
        self.model_version = inner.model_version
        self.name = inner.name
        self.recorded: dict[str, str] = {}

    def complete(self, call: ModelCall) -> str:
        out = self.inner.complete(call)
        self.recorded[ReplayBackend.key(call)] = out
        return out


def backend_from_config(cfg: dict | None):
    """Build a backend from the `models.text` or `models.vision` block of suite.yaml."""
    if not cfg:
        return None
    kind = cfg.get("backend", "none")
    if kind == "openai_compatible":
        return OpenAICompatibleBackend(cfg["base_url"], cfg["model"], cfg.get("model_version", "unset"),
                                       cfg.get("timeout_seconds", 120), cfg.get("api_key"))
    if kind == "replay":
        responses = json.loads(Path(cfg["path"]).read_text())
        return ReplayBackend(responses.get("responses", responses), cfg.get("model", "replay"),
                             cfg.get("model_version", "replay"))
    return None
