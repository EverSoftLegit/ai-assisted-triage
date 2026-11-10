"""The only component that talks to the LLM. Everything here is advisory.

Design rules, so the tool stays a triage aid and not an autonomous actor:
- The model receives finding metadata and returns *analysis only*: cluster naming,
  a suggested priority order with rationale, likely false positives to check,
  validation steps a human would run, and business-context questions.
- The model is never asked for, and nothing here executes, any action against a
  target. There is no tool use, no shell, no network except the API call itself.
- Output is parsed defensively; a malformed reply degrades to "no AI enrichment"
  rather than raising.

The transport is injectable (`call_transport`) so tests run fully offline.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Callable

API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")
ANTHROPIC_VERSION = "2023-06-01"

SYSTEM_PROMPT = (
    "You are a senior penetration-test analyst helping to triage findings from an "
    "AUTHORISED security assessment. You receive a list of finding clusters produced "
    "by non-exploitative scanners. Your job is analysis only: you do not and cannot "
    "run any action against the targets, and you must never provide exploit code or "
    "step-by-step attack instructions. For each cluster, assess likely priority and "
    "whether it may be a false positive, and suggest how a human analyst would validate "
    "it manually. Treat every scanner result as unconfirmed. Identifiers may be redacted "
    "to placeholders such as HOST_1; reason about them as opaque labels.\n\n"
    "Respond with ONLY a JSON object of this shape:\n"
    '{"clusters": [{"cluster_id": "C1", "suggested_priority": 1, '
    '"likely_false_positive": false, "rationale": "...", '
    '"validation_steps": ["..."], "business_questions": ["..."]}], '
    '"summary": "2-3 sentence analyst-facing overview"}'
)


class LLMError(RuntimeError):
    pass


def _anthropic_transport(api_key: str, model: str, timeout: float) -> Callable[[str], str]:
    def transport(user_content: str) -> str:
        body = json.dumps({
            "model": model,
            "max_tokens": 2000,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_content}],
        }).encode("utf-8")
        request = urllib.request.Request(API_URL, data=body, method="POST", headers={
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        })
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raise LLMError(f"Anthropic API returned HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:300]}") from exc
        except (OSError, ValueError) as exc:
            raise LLMError(f"Anthropic API call failed: {exc}") from exc
        try:
            return "".join(block.get("text", "") for block in payload["content"] if block.get("type") == "text")
        except (KeyError, TypeError) as exc:
            raise LLMError("Unexpected Anthropic response shape") from exc

    return transport


def build_user_content(clusters_payload: list[dict[str, Any]]) -> str:
    return ("Here are the finding clusters to triage (already de-duplicated across tools). "
            "Return the JSON object described in the system prompt.\n\n"
            + json.dumps({"clusters": clusters_payload}, indent=2))


def parse_response(text: str) -> dict[str, Any]:
    """Pull the JSON object out of the model's reply; tolerate surrounding prose/fences."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise LLMError("No JSON object found in model response")
    try:
        data = json.loads(text[start:end + 1])
    except ValueError as exc:
        raise LLMError(f"Model response was not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("clusters"), list):
        raise LLMError("Model JSON missing a 'clusters' list")
    return data


def triage(
    clusters_payload: list[dict[str, Any]],
    *,
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
    timeout: float = 60.0,
    call_transport: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    """Return the model's advisory analysis. Raises LLMError on any failure."""
    if call_transport is None:
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise LLMError("No ANTHROPIC_API_KEY set and no transport supplied")
        call_transport = _anthropic_transport(key, model, timeout)
    return parse_response(call_transport(build_user_content(clusters_payload)))
