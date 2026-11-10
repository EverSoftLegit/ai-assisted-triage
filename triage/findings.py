"""Load toolkit JSON result files and correlate findings across tools (offline, deterministic).

Input is the JSON emitted by authorised-security-assessment-toolkit scripts 02-06/08
(any object with a "findings" list of finding objects). This module does the work that
does not need an LLM: load, tag with source, and group findings that describe the same
issue so the same missing header reported by the header audit and by ZAP is not counted
twice.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_SEV_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
_STOPWORDS = {"the", "a", "an", "is", "are", "missing", "absent", "review", "header",
              "without", "not", "for", "and", "of", "to", "component", "s"}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    description: str
    evidence: str
    recommendation: str
    source: str
    confidence: str
    source_file: str

    @property
    def severity_rank(self) -> int:
        return _SEV_RANK.get(self.severity.upper(), len(SEVERITIES))


@dataclass
class Cluster:
    """A group of findings judged to be the same underlying issue."""
    key: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        return min((f.severity for f in self.findings), key=lambda s: _SEV_RANK.get(s.upper(), 99))

    @property
    def sources(self) -> list[str]:
        return sorted({f.source or f.source_file for f in self.findings})


def load_findings(paths: list[str | Path]) -> tuple[list[Finding], list[str]]:
    """Return (findings, errors). Each file is validated before any of it is used."""
    findings: list[Finding] = []
    errors: list[str] = []
    counter = 0
    for path in paths:
        try:
            document = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"{path}: {exc}")
            continue
        if not isinstance(document, dict) or not isinstance(document.get("findings"), list):
            errors.append(f"{path}: not a toolkit result document (no 'findings' list)")
            continue
        tool = str(document.get("tool", "unknown"))
        for raw in document["findings"]:
            if not isinstance(raw, dict):
                continue
            counter += 1
            findings.append(Finding(
                id=f"F{counter}",
                title=str(raw.get("title", "Untitled")),
                severity=str(raw.get("severity", "INFO")).upper(),
                description=str(raw.get("description", "")),
                evidence=str(raw.get("evidence", "")),
                recommendation=str(raw.get("recommendation", "")),
                source=str(raw.get("source", tool)),
                confidence=str(raw.get("confidence", "")),
                source_file=str(path),
            ))
    return findings, errors


def _signature(finding: Finding) -> str:
    """A rough identity for a finding: significant title words + the first host/URL in evidence."""
    words = re.findall(r"[a-z0-9-]+", finding.title.lower())
    keywords = "-".join(sorted(w for w in words if w not in _STOPWORDS and len(w) > 2))
    locus = ""
    match = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9_-]+\.)+[a-z][a-z0-9-]*)", finding.evidence, re.IGNORECASE)
    if match:
        locus = match.group(1).lower()
    return f"{keywords}|{locus}"


def correlate(findings: list[Finding]) -> list[Cluster]:
    """Group findings with the same signature; sort clusters by highest severity first."""
    groups: dict[str, Cluster] = {}
    for finding in findings:
        key = _signature(finding)
        groups.setdefault(key, Cluster(key=key)).findings.append(finding)
    clusters = list(groups.values())
    clusters.sort(key=lambda c: (_SEV_RANK.get(c.max_severity.upper(), 99), -len(c.findings)))
    return clusters


def to_prompt_payload(clusters: list[Cluster]) -> list[dict[str, Any]]:
    """Compact, already-redacted-by-the-caller structure handed to the LLM."""
    payload = []
    for index, cluster in enumerate(clusters, 1):
        first = cluster.findings[0]
        payload.append({
            "cluster_id": f"C{index}",
            "finding_ids": [f.id for f in cluster.findings],
            "title": first.title,
            "tool_severity": cluster.max_severity,
            "reported_by": cluster.sources,
            "times_reported": len(cluster.findings),
            "description": first.description,
            "evidence": first.evidence,
        })
    return payload
