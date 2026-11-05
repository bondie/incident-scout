"""Turn an evidence pack into a short diagnosis with a local model.

The model gets one prepared pack and answers once, in a fixed JSON schema; no tool calls and
no free-form agent loop, which small local models handle poorly.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

from .evidence import EvidencePack

CATEGORIES = (
    "application_error",
    "dependency",
    "resources",
    "infrastructure",
    "traffic",
    "certificate",
    "unknown",
)
SCOPES = ("single_shop", "multiple_shops", "unknown")
CONFIDENCE = ("low", "medium", "high")

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "scope": {"type": "string", "enum": list(SCOPES)},
        "category": {"type": "string", "enum": list(CATEGORIES)},
        "likely_cause": {"type": "string"},
        "confidence": {"type": "string", "enum": list(CONFIDENCE)},
        "key_evidence": {"type": "array", "items": {"type": "string"}},
        "next_steps": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "summary",
        "scope",
        "category",
        "likely_cause",
        "confidence",
        "key_evidence",
        "next_steps",
    ],
}

SYSTEM_PROMPT = """\
You are the on-call engineer's assistant for a fleet of e-commerce shops. An alert has just
fired and an evidence pack was collected automatically. Diagnose the incident from that pack.

Rules:
- Use only the evidence. Never invent error messages, class names, numbers or tickets.
- Decide the scope: one shop, or several shops at the same time (which points to shared
  infrastructure rather than one application).
- Pick a category: application_error (a bug or exception in the shop's code), dependency
  (database, cache, queue, search or an external API failing), resources (disk, memory, CPU),
  infrastructure (network, hosting, load balancer, monitoring path), traffic (unusual load),
  certificate, or unknown.
- If the evidence does not show a cause, say so and use low confidence.
- summary: one sentence on what is happening. likely_cause: the most probable cause, citing
  the decisive evidence. key_evidence: up to 4 facts copied from the pack. next_steps: up to
  3 concrete checks or fixes.
- Write summary, likely_cause, key_evidence and next_steps in {language}.
Respond with JSON only."""


class InvestigationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Diagnosis:
    summary: str
    scope: str
    category: str
    likely_cause: str
    confidence: str
    key_evidence: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    model: str = ""
    seconds: float = 0.0

    def headline(self) -> str:
        return f"{self.likely_cause} ({self.confidence})"

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


@dataclass(frozen=True)
class OllamaInvestigator:
    model: str
    url: str = "http://localhost:11434"
    language: str = "English"
    think: bool | str | None = None
    timeout: float = 300
    num_ctx: int = 16384
    transport: httpx.BaseTransport | None = None

    def diagnose(self, pack: EvidencePack) -> Diagnosis:
        payload: dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "format": SCHEMA,
            "options": {"temperature": 0, "num_ctx": self.num_ctx},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT.format(language=self.language)},
                {"role": "user", "content": pack.render()},
            ],
        }
        if self.think is not None:
            payload["think"] = self.think
        started = time.perf_counter()
        try:
            with httpx.Client(transport=self.transport, timeout=self.timeout) as client:
                response = client.post(f"{self.url.rstrip('/')}/api/chat", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as error:
            raise InvestigationError(f"{self.model}: {error}") from error
        content = response.json().get("message", {}).get("content", "")
        return parse_diagnosis(content, self.model, time.perf_counter() - started)

    def warm_up(self) -> None:
        """Load the model so that the first timed diagnosis does not pay for it."""
        self._generate({"prompt": "", "keep_alive": "10m"})

    def unload(self) -> None:
        self._generate({"keep_alive": 0})

    def _generate(self, extra: dict[str, Any]) -> None:
        with httpx.Client(transport=self.transport, timeout=self.timeout) as client:
            response = client.post(
                f"{self.url.rstrip('/')}/api/generate", json={"model": self.model, **extra}
            )
            response.raise_for_status()


def parse_diagnosis(content: str, model: str = "", seconds: float = 0.0) -> Diagnosis:
    try:
        data = json.loads(content)
    except ValueError as error:
        raise InvestigationError(f"{model} returned invalid JSON: {content[:200]!r}") from error
    if not isinstance(data, dict):
        raise InvestigationError(f"{model} returned {type(data).__name__}, expected an object")
    missing = [key for key in SCHEMA["required"] if key not in data]
    if missing:
        raise InvestigationError(f"{model} left out {', '.join(missing)}")
    return Diagnosis(
        summary=str(data["summary"]),
        scope=_choice(data["scope"], SCOPES),
        category=_choice(data["category"], CATEGORIES),
        likely_cause=str(data["likely_cause"]),
        confidence=_choice(data["confidence"], CONFIDENCE),
        key_evidence=[str(item) for item in data.get("key_evidence") or []][:4],
        next_steps=[str(item) for item in data.get("next_steps") or []][:3],
        model=model,
        seconds=round(seconds, 1),
    )


def _choice(value: Any, allowed: tuple[str, ...]) -> str:
    text = str(value)
    return text if text in allowed else "unknown"
