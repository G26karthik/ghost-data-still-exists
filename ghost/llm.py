"""Small, cached Responses API client for the two interpretation tasks."""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import openai


PRICES = {"gpt-6-luna": (0.10, 0.01, 0.50)}
EFFORT = "low"
CACHE = Path(__file__).resolve().parents[1] / "cache"


def _key() -> str:
    value = (os.environ.get("OPENAI_API_KEY") or os.environ.get("OPEN_AI_API") or
             os.environ.get("open_ai_key"))
    if not value:
        raise RuntimeError("Set OPENAI_API_KEY before a live cache miss")
    return value


def _hash(model: str, instructions: str, content: Any, schema: dict) -> str:
    raw = json.dumps({"model": model, "effort": EFFORT, "instructions": instructions,
                      "content": content, "schema": schema}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def ask(kind: str, model: str, instructions: str, content: Any, schema: dict,
        run_dir: Path, offline: bool = False, max_output: int = 5000) -> tuple[dict, Path, bool]:
    """Return parsed JSON; write successful raw output and corrected result separately."""
    # ponytail: one transport transaction owns cache identity, retry, and usage receipt.
    if model not in PRICES:
        raise ValueError(f"No verified price for {model}")
    digest = _hash(model, instructions, content, schema)
    path = CACHE / kind / f"{digest}.json"
    if path.exists():
        saved = json.loads(path.read_text(encoding="utf-8"))
        if (saved.get("request_hash"), saved.get("model"), saved.get("reasoning_effort")) != \
                (digest, model, EFFORT):
            raise ValueError(f"Cache identity mismatch: {path.name}")
        return saved["result"], path, False
    if offline:
        raise FileNotFoundError(f"Missing offline cache: {kind}/{digest}")
    client = openai.OpenAI(api_key=_key(), max_retries=0, timeout=120)
    request = {"model": model, "reasoning": {"effort": EFFORT}, "instructions": instructions,
               "input": [{"role": "user", "content": content}], "max_output_tokens": max_output,
               "text": {"format": {"type": "json_schema", "name": kind,
                                   "strict": True, "schema": schema}}}
    for attempt in range(3):
        started = time.perf_counter()
        try:
            response = client.responses.create(**request)
            if response.status != "completed" or not response.output_text:
                raise RuntimeError(f"Response incomplete: {response.status}")
            result = json.loads(response.output_text)
            usage = response.usage
            tokens_in = usage.input_tokens
            tokens_out = usage.output_tokens
            cached = getattr(getattr(usage, "input_tokens_details", None), "cached_tokens", 0) or 0
            input_price, cached_price, output_price = PRICES[model]
            cost = ((tokens_in - cached) * input_price + cached * cached_price +
                    tokens_out * output_price) / 1_000_000
            receipt = {"at": datetime.now(timezone.utc).isoformat(), "kind": kind,
                       "request_hash": digest, "model": model, "reasoning_effort": EFFORT,
                       "input_tokens": tokens_in, "cached_input_tokens": cached,
                       "output_tokens": tokens_out, "cost_usd": cost,
                       "latency_seconds": round(time.perf_counter() - started, 3),
                       "attempt": attempt + 1, "response_id": response.id}
            run_dir.mkdir(parents=True, exist_ok=True)
            with (run_dir / "usage.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(receipt, sort_keys=True) + "\n")
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps({"request_hash": digest, "model": model,
                                             "reasoning_effort": EFFORT, "raw": result,
                                             "result": result, "receipt": receipt},
                                            ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(temporary, path)
            return result, path, True
        except (openai.APIConnectionError, openai.APIStatusError) as exc:
            status = getattr(exc, "status_code", None)
            if attempt == 2 or status not in (408, 409, 429) and not (status and status >= 500) and \
                    not isinstance(exc, openai.APIConnectionError):
                raise
            wait = 2 ** attempt
            headers = getattr(getattr(exc, "response", None), "headers", {})
            if value := headers.get("retry-after"):
                try:
                    wait = max(wait, float(value))
                except ValueError:
                    pass
            time.sleep(wait)
    raise AssertionError("unreachable")
