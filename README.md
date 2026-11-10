# AI-Assisted Triage

![tests](https://github.com/EverSoftLegit/ai-assisted-triage/actions/workflows/tests.yml/badge.svg)

Reads the JSON that [authorised-security-assessment-toolkit](https://github.com/EverSoftLegit/authorised-security-assessment-toolkit) produces, de-duplicates findings across tools, and uses Claude to prioritise them, flag likely false positives, and suggest how an analyst would validate each one — turning a long first-pass triage into a short one.

It is a **triage aid, not an autonomous tester**. It never connects to, scans, or exploits a target. It only reads findings your scanners already produced, and every AI suggestion is labelled as unconfirmed for a human to check.

## What it does

1. **Load** one or more toolkit result files (scripts 02–06 and 08).
2. **Correlate (offline):** group findings that describe the same issue, so the same missing header reported by the header audit and by ZAP becomes one cluster, keeping the higher severity.
3. **Redact (default on):** replace hostnames, IPs and URLs with placeholders (`HOST_1`, `IP_1`, `URL_1`) before anything is sent to the API. The mapping stays on your machine; the local report expands the placeholders back.
4. **Triage with Claude (optional):** the model returns a suggested priority order with rationale, likely false positives, manual validation steps, and business-context questions — analysis only.
5. **Write** an enriched `triage.json` and a readable `triage-briefing.md`.

## Why no exploitation

This deliberately stops at triage. Automatically exploiting findings against live infrastructure risks outages, breaches the rules of engagement, and produces results no analyst can stand behind. The judgement of what is real and what to touch stays with the human. See the design notes in `triage/llm.py`.

## Install

No runtime dependencies — standard library only. Python 3.10+.

```bash
git clone https://github.com/EverSoftLegit/ai-assisted-triage
cd ai-assisted-triage
python3 -m pytest -q            # optional: pip install "pytest>=8.0" first
```

## Use

```bash
# Offline: correlate and de-duplicate only, no API call.
python3 ai_triage.py results/*.json --no-ai

# With Claude (connect your own token):
export ANTHROPIC_API_KEY=sk-ant-...
export ANTHROPIC_MODEL=claude-sonnet-4-5          # optional; set the model you have access to
python3 ai_triage.py results/nmap.json results/zap.json results/headers.json \
  --output-json triage.json --output-md triage-briefing.md
```

Full pipeline from a scan:

```bash
# 1. produce findings with the toolkit (examples)
python3 ../authorised-security-assessment-toolkit/scripts/05_nmap_xml_analyzer.py scan.xml --output nmap.json
# 2. triage them
python3 ai_triage.py nmap.json --output-md briefing.md
```

### Options

| Flag | Effect |
|---|---|
| `--no-ai` | Correlate and de-duplicate only; never call the API. |
| `--no-redact` | Send findings unmodified (raw client identifiers leave the machine). Off by default. |
| `--model` | Anthropic model id (or set `ANTHROPIC_MODEL`). |
| `--output-json` / `--output-md` | Output paths. |

Exit codes: `0` completed with AI enrichment (or `--no-ai`), `1` completed without enrichment (no key or API error — outputs still written), `2` bad input.

See `examples/triage-briefing.md` for a sample built offline from synthetic data.

## Privacy and limits

- **Redaction is best-effort.** It covers IPv4, IPv6, URLs and dotted hostnames; it will not catch an identifier written in prose. Review before using `--no-redact`, and prefer a local model for highly sensitive data (the provider is isolated in `triage/llm.py` for that reason).
- **The model can be wrong.** Priorities, false-positive calls and validation steps are suggestions. The briefing and JSON both state this; your analyst sign-off is what matters.
- **Scope is inherited, not enforced here.** This tool reads findings; keep targets in scope at scan time with the toolkit's scope checks.

## License

MIT
