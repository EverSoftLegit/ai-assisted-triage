#!/usr/bin/env python3
"""AI-assisted triage of authorised-assessment findings.

Pipeline:
  load toolkit JSON -> correlate/de-duplicate (offline) -> redact identifiers
  -> ask Claude to prioritise and suggest validation (optional) -> write enriched
  JSON + a Markdown briefing.

This tool never touches a target. It reads findings your scanners already produced
and helps you triage them faster. Every AI output is advisory and must be validated
by an analyst. Exploitation, brute force and any action against a host are out of
scope by design.

Exit codes: 0 completed, 1 completed without AI enrichment (e.g. no key / API error),
2 bad input.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from triage import llm
from triage.findings import correlate, load_findings, to_prompt_payload
from triage.redact import Redactor


def redact_payload(payload: list[dict[str, Any]], redactor: Redactor) -> list[dict[str, Any]]:
    """Return a copy of the cluster payload with identifiers replaced by placeholders."""
    redacted = []
    for cluster in payload:
        item = dict(cluster)
        item["title"] = redactor.redact(item["title"])
        item["description"] = redactor.redact(item["description"])
        item["evidence"] = redactor.redact(item["evidence"])
        item["reported_by"] = [redactor.redact(source) for source in item["reported_by"]]
        redacted.append(item)
    return redacted


def expand(text: str, redactor: Redactor | None) -> str:
    """Re-expand placeholders locally so the human-facing report is readable."""
    return redactor.restore(text) if redactor else text


def build_markdown(clusters_payload: list[dict[str, Any]], ai: dict[str, Any] | None,
                   redactor: Redactor | None) -> str:
    ai_by_id = {}
    if ai:
        ai_by_id = {str(c.get("cluster_id")): c for c in ai.get("clusters", []) if isinstance(c, dict)}

    lines = ["# AI-assisted triage briefing", "",
             "> Draft triage aid. Every AI suggestion below is unconfirmed and must be "
             "validated by an analyst before it appears in a client report. This tool does "
             "not test or exploit any system.", ""]
    if ai and ai.get("summary"):
        lines += ["## Analyst-facing summary (AI-generated)", "", expand(str(ai["summary"]), redactor), ""]

    # Order clusters by the AI's suggested priority when available, else keep severity order.
    def priority(cluster: dict[str, Any]) -> tuple[int, int]:
        entry = ai_by_id.get(cluster["cluster_id"], {})
        suggested = entry.get("suggested_priority")
        return (0, suggested) if isinstance(suggested, int) else (1, 0)

    lines += ["## Finding clusters", ""]
    for cluster in sorted(clusters_payload, key=priority):
        entry = ai_by_id.get(cluster["cluster_id"], {})
        header = f"### {cluster['cluster_id']}: {expand(cluster['title'], redactor)} — {cluster['tool_severity']}"
        if entry.get("likely_false_positive"):
            header += " · possible false positive"
        lines.append(header)
        reported = ", ".join(expand(s, redactor) for s in cluster["reported_by"])
        lines += ["", f"Reported by {reported} ({cluster['times_reported']}x). "
                      f"Finding IDs: {', '.join(cluster['finding_ids'])}.", ""]
        if entry.get("rationale"):
            lines += [f"**AI priority rationale:** {expand(str(entry['rationale']), redactor)}", ""]
        steps = [s for s in entry.get("validation_steps", []) if isinstance(s, str)]
        if steps:
            lines += ["**Suggested validation (perform manually):**",
                      *[f"- {expand(s, redactor)}" for s in steps], ""]
        questions = [q for q in entry.get("business_questions", []) if isinstance(q, str)]
        if questions:
            lines += ["**Business-context questions:**", *[f"- {expand(q, redactor)}" for q in questions], ""]
    lines += ["## Analyst checklist", "",
              "- [ ] Confirm every cluster was in the approved scope.",
              "- [ ] Manually validate each finding; dismiss AI-flagged false positives only after checking.",
              "- [ ] Set final severity and business impact yourself.",
              "- [ ] Remove any AI text that cannot be substantiated.", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inputs", nargs="+", help="Toolkit JSON result files (scripts 02-06/08 output)")
    parser.add_argument("--output-json", default="triage.json", help="Enriched analysis output")
    parser.add_argument("--output-md", default="triage-briefing.md", help="Markdown briefing output")
    parser.add_argument("--no-redact", action="store_true",
                        help="Do NOT redact identifiers before the API call (sends raw client data)")
    parser.add_argument("--no-ai", action="store_true", help="Correlate and de-duplicate only; never call the API")
    parser.add_argument("--model", default=llm.DEFAULT_MODEL, help="Anthropic model id (or set ANTHROPIC_MODEL)")
    args = parser.parse_args()

    findings, errors = load_findings(args.inputs)
    if not findings:
        parser.error("No findings loaded. " + ("; ".join(errors) if errors else "Inputs had empty 'findings'."))

    clusters = correlate(findings)
    payload = to_prompt_payload(clusters)

    redactor = None if args.no_redact else Redactor()
    sent_payload = payload if redactor is None else redact_payload(payload, redactor)

    ai: dict[str, Any] | None = None
    ai_error: str | None = None
    if not args.no_ai:
        try:
            ai = llm.triage(sent_payload, model=args.model)
        except llm.LLMError as exc:
            ai_error = str(exc)

    document = {
        "schema_version": "1.0",
        "tool": "ai-assisted-triage",
        "finding_count": len(findings),
        "cluster_count": len(clusters),
        "redacted": redactor is not None,
        "ai_enrichment": ai is not None,
        "ai_error": ai_error,
        "load_errors": errors,
        "clusters": payload,  # local copy keeps the real identifiers
        "ai_analysis": ai,
    }
    Path(args.output_json).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    Path(args.output_md).write_text(build_markdown(payload, ai, redactor), encoding="utf-8")

    note = "with AI enrichment" if ai else f"without AI enrichment ({ai_error or 'disabled'})"
    print(f"Triaged {len(findings)} finding(s) into {len(clusters)} cluster(s) {note}.")
    print(f"Wrote {args.output_json} and {args.output_md}; validate before use.")
    return 0 if (ai is not None or args.no_ai) else 1


if __name__ == "__main__":
    raise SystemExit(main())
