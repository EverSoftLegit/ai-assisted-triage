"""Tests for the triage pipeline. The LLM transport is always injected, so no test
makes a network call and no API key is needed."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triage import llm
from triage.findings import Finding, correlate, load_findings, to_prompt_payload
from triage.redact import Redactor


# --- redaction -------------------------------------------------------------------

def test_redactor_replaces_and_restores():
    r = Redactor()
    text = "https://app.example.test/login on 192.0.2.10 and app.example.test again"
    red = r.redact(text)
    assert "example.test" not in red and "192.0.2.10" not in red
    assert "URL_1" in red and "IP_1" in red
    # The same host gets the same placeholder both times.
    assert red.count("HOST_1") == 1
    assert r.restore(red) == text


def test_redactor_leaves_version_strings_alone():
    r = Redactor()
    assert r.redact("Werkzeug/3.1.9 Python/3.12.7") == "Werkzeug/3.1.9 Python/3.12.7"


def test_redactor_redacts_bare_custom_scheme():
    # Regression: "labapp://" (an app identifier) must not leak just because nothing follows "://".
    r = Redactor()
    assert "labapp" not in r.redact("Custom scheme labapp:// registered")


def test_redactor_handles_ipv6():
    r = Redactor()
    red = r.redact("host 2001:db8::1 responded")
    assert "2001:db8::1" not in red and "IP_1" in red


def test_restore_longest_placeholder_first():
    r = Redactor()
    for i in range(11):
        r.redact(f"h{i}.example.test")
    # HOST_11 must not be corrupted by replacing HOST_1 first.
    assert r.restore("HOST_11") == "h10.example.test"


# --- loading & correlation --------------------------------------------------------

def _doc(tmp_path, name, findings, tool="t"):
    path = tmp_path / name
    path.write_text(json.dumps({"tool": tool, "findings": findings}))
    return path


def test_load_reports_bad_files(tmp_path):
    good = _doc(tmp_path, "g.json", [{"title": "X", "severity": "LOW"}])
    (tmp_path / "bad.json").write_text("{not json")
    (tmp_path / "wrong.json").write_text('{"no": "findings"}')
    findings, errors = load_findings([good, tmp_path / "bad.json", tmp_path / "wrong.json", tmp_path / "missing.json"])
    assert len(findings) == 1 and len(errors) == 3


def test_correlation_merges_same_issue_across_tools(tmp_path):
    a = _doc(tmp_path, "a.json", [{"title": "Missing x-content-type-options",
                                   "severity": "INFO", "evidence": "https://app.example.test/ returned HTTP 200"}], "header-audit")
    b = _doc(tmp_path, "b.json", [{"title": "X-Content-Type-Options Header Missing",
                                   "severity": "LOW", "evidence": "Affected URI(s): https://app.example.test/"}], "zap")
    findings, _ = load_findings([a, b])
    clusters = correlate(findings)
    assert len(clusters) == 1
    assert clusters[0].max_severity == "LOW"          # keeps the higher of the two
    assert len(clusters[0].sources) == 2              # both tools recorded


def test_correlation_keeps_distinct_issues_apart(tmp_path):
    doc = _doc(tmp_path, "a.json", [
        {"title": "Telnet exposed", "severity": "HIGH", "evidence": "192.0.2.10 port 23"},
        {"title": "SMB exposed", "severity": "MEDIUM", "evidence": "192.0.2.10 port 445"},
    ])
    findings, _ = load_findings([doc])
    clusters = correlate(findings)
    assert len(clusters) == 2
    assert clusters[0].max_severity == "HIGH"  # highest severity sorts first


def test_prompt_payload_shape():
    findings = [Finding("F1", "Telnet exposed", "HIGH", "d", "192.0.2.10 port 23", "r", "nmap", "c", "a.json")]
    payload = to_prompt_payload(correlate(findings))
    assert payload[0]["cluster_id"] == "C1"
    assert payload[0]["finding_ids"] == ["F1"]
    assert payload[0]["tool_severity"] == "HIGH"


# --- llm module (parsing & contract; transport injected) --------------------------

def test_parse_response_extracts_json_from_prose():
    text = "Here is the analysis:\n```json\n{\"clusters\": [{\"cluster_id\": \"C1\"}], \"summary\": \"ok\"}\n```"
    assert llm.parse_response(text)["summary"] == "ok"


@pytest.mark.parametrize("text", ["no json here", "{}", '{"clusters": "notalist"}'])
def test_parse_response_rejects_bad_output(text):
    with pytest.raises(llm.LLMError):
        llm.parse_response(text)


def test_triage_uses_injected_transport_and_sees_redacted_input():
    captured = {}

    def fake_transport(user_content: str) -> str:
        captured["content"] = user_content
        return '{"clusters": [{"cluster_id": "C1", "suggested_priority": 1}], "summary": "s"}'

    payload = [{"cluster_id": "C1", "finding_ids": ["F1"], "title": "HOST_1 issue",
                "tool_severity": "HIGH", "reported_by": ["nmap"], "times_reported": 1,
                "description": "d", "evidence": "e"}]
    result = llm.triage(payload, call_transport=fake_transport)
    assert result["summary"] == "s"
    assert "HOST_1" in captured["content"] and "example.test" not in captured["content"]


def test_triage_without_key_or_transport_raises(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(llm.LLMError, match="No ANTHROPIC_API_KEY"):
        llm.triage([], call_transport=None)


# --- CLI end to end (offline via --no-ai) -----------------------------------------

def test_cli_no_ai_produces_outputs(tmp_path):
    doc = _doc(tmp_path, "nmap.json", [{"title": "Telnet exposed", "severity": "HIGH",
                                        "evidence": "Host: 192.0.2.10; port: 23"}], "nmap")
    out_json, out_md = tmp_path / "t.json", tmp_path / "t.md"
    run = subprocess.run([sys.executable, str(ROOT / "ai_triage.py"), str(doc),
                          "--no-ai", "--output-json", str(out_json), "--output-md", str(out_md)],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    data = json.loads(out_json.read_text())
    assert data["ai_enrichment"] is False and data["redacted"] is True
    assert "AI-assisted triage briefing" in out_md.read_text()


def test_cli_missing_input_exits_2(tmp_path):
    run = subprocess.run([sys.executable, str(ROOT / "ai_triage.py"), str(tmp_path / "none.json"), "--no-ai"],
                         capture_output=True, text=True)
    assert run.returncode == 2
