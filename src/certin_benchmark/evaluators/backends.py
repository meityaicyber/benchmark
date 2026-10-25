"""Language and vision model backends.

Inside the CERT-In environment the models run locally at a fixed version behind an
OpenAI-compatible endpoint (for example vLLM). No backend contacts an external service.

A backend returns raw text for one sampled call; parsing and aggregation are in sampling.py.

Every request states its sampling settings and template arguments itself, rather than leaving them to the server:
vLLM fills any setting a request leaves out from the model's own generation_config.json, and a reasoning model
such as Nemotron 3 Nano Omni reasons before answering unless the request turns it off (chat_template_kwargs
enable_thinking false), which a short rating reply cannot hold.
"""

from __future__ import annotations

import base64
import io
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
JPEG_SIGNATURE = b"\xff\xd8\xff"


@dataclass
class ModelCall:
    system: str
    user: str
    seed: int
    temperature: float
    image_path: str | None = None
    extra_images: list = field(default_factory=list)     # further images, after image_path, in order

    def images(self) -> list[str]:
        return ([self.image_path] if self.image_path else []) + list(self.extra_images)


class Backend(Protocol):
    name: str
    model: str
    model_version: str

    def complete(self, call: ModelCall) -> str: ...


class BackendUnavailable(RuntimeError):
    pass


def image_data_url(path: str | Path) -> str:
    """The image as a data URL. JPEG and PNG, the formats the models list, are sent as stored; any other format
    (JPEG 2000, JPEG XR, TIFF, BMP, GIF, PNM, which Objective 1 stores as embedded in the PDF) is converted to PNG,
    so the server is never asked to decode a format it may not read. The stored file itself is never changed."""
    p = Path(path)
    if not p.is_file():
        raise BackendUnavailable(f"image not found: {path}")
    data = p.read_bytes()
    if data.startswith(PNG_SIGNATURE):
        mime = "image/png"
    elif data.startswith(JPEG_SIGNATURE):
        mime = "image/jpeg"
    else:
        try:
            from PIL import Image
        except ImportError:
            raise BackendUnavailable(f"image {p.name} is neither JPEG nor PNG, and converting it needs Pillow "
                                     "(pip install Pillow)") from None
        try:
            with Image.open(io.BytesIO(data)) as im:
                buf = io.BytesIO()
                im.convert("RGBA" if "A" in im.getbands() else "RGB").save(buf, format="PNG")
        except Exception as exc:                       # an unreadable or truncated file
            raise BackendUnavailable(f"image {p.name} could not be read for conversion to PNG: {exc}") from None
        data, mime = buf.getvalue(), "image/png"
    return f"data:{mime};base64,{base64.b64encode(data).decode()}"


class OpenAICompatibleBackend:
    """Chat completions against a local server; the seed is passed per request.

    Optional settings, each sent only when given: max_tokens (default 400), top_p, top_k, min_p,
    chat_template_kwargs (for example {"enable_thinking": false}), and mm_processor_kwargs, sent with requests
    that carry images. concurrency is how many samples of one item the evaluator sends at once."""

    def __init__(self, base_url: str, model: str, model_version: str = "unset", timeout_seconds: float = 120,
                 api_key: str | None = None, name: str = "openai_compatible", max_tokens: int = 400,
                 top_p: float | None = None, top_k: int | None = None, min_p: float | None = None,
                 chat_template_kwargs: dict | None = None, mm_processor_kwargs: dict | None = None,
                 concurrency: int = 1):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.model_version = model_version
        self.timeout = timeout_seconds
        self.api_key = api_key
        self.name = name
        self.max_tokens = int(max_tokens)
        self.sampling: dict[str, Any] = {k: v for k, v in (("top_p", top_p), ("top_k", top_k), ("min_p", min_p))
                                         if v is not None}
        self.chat_template_kwargs = dict(chat_template_kwargs or {})
        self.mm_processor_kwargs = dict(mm_processor_kwargs or {})
        self.concurrency = max(1, int(concurrency or 1))

    def _open(self, req: urllib.request.Request, timeout: float) -> Any:
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            # the server's own explanation (for example a limit on images per request) is kept with the error
            detail = exc.read().decode("utf-8", errors="replace").strip()[:500]
            raise BackendUnavailable(f"{req.full_url} returned HTTP {exc.code}: {detail or exc.reason}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BackendUnavailable(f"{req.full_url}: {exc}") from exc
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise BackendUnavailable(f"{req.full_url} did not return JSON: {raw[:200]!r}") from None

    def check(self) -> list[str]:
        """The models the server serves; BackendUnavailable when it cannot be reached or does not serve this one."""
        reply = self._open(urllib.request.Request(self.base_url + "/models", method="GET"), min(self.timeout, 30))
        served = [str(m.get("id")) for m in (reply.get("data") or []) if isinstance(m, dict)] \
            if isinstance(reply, dict) else []
        if self.model not in served:
            raise BackendUnavailable(f"{self.base_url} does not serve {self.model!r} (it serves "
                                     f"{', '.join(served) or 'nothing'})")
        return served

    def complete(self, call: ModelCall) -> str:
        content: list | str
        if call.images():
            content = [{"type": "text", "text": call.user}]
            for img in call.images():
                content.append({"type": "image_url", "image_url": {"url": image_data_url(img)}})
        else:
            content = call.user
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": call.system}, {"role": "user", "content": content}],
            "temperature": call.temperature,
            "seed": call.seed,
            "max_tokens": self.max_tokens,
            **self.sampling,
        }
        if self.chat_template_kwargs:
            body["chat_template_kwargs"] = self.chat_template_kwargs
        if self.mm_processor_kwargs and call.images():
            body["mm_processor_kwargs"] = self.mm_processor_kwargs
        req = urllib.request.Request(self.base_url + "/chat/completions", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        payload = self._open(req, self.timeout)
        try:
            content_out = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise BackendUnavailable(f"unexpected response from {self.base_url}: {str(payload)[:300]}") from None
        return content_out or ""


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
        # images enter the key by their content, so a replay does not depend on where the files are
        digests = [hashlib.sha256(Path(i).read_bytes()).hexdigest() if Path(i).is_file() else i for i in call.images()]
        h = hashlib.sha256((call.system + "\x00" + call.user + "\x00" + "\x00".join(digests)).encode()).hexdigest()
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
        self.concurrency = getattr(inner, "concurrency", 1)
        self.recorded: dict[str, str] = {}

    def check(self):
        return self.inner.check() if hasattr(self.inner, "check") else None

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
                                       cfg.get("timeout_seconds", 120), cfg.get("api_key"),
                                       max_tokens=cfg.get("max_tokens", 400), top_p=cfg.get("top_p"),
                                       top_k=cfg.get("top_k"), min_p=cfg.get("min_p"),
                                       chat_template_kwargs=cfg.get("chat_template_kwargs"),
                                       mm_processor_kwargs=cfg.get("mm_processor_kwargs"),
                                       concurrency=cfg.get("concurrency", 1))
    if kind == "replay":
        responses = json.loads(Path(cfg["path"]).read_text())
        return ReplayBackend(responses.get("responses", responses), cfg.get("model", "replay"),
                             cfg.get("model_version", "replay"))
    return None
