"""Replace client identifiers with stable placeholders before anything leaves the machine.

Redaction is reversible *locally*: the Redactor keeps a mapping (placeholder ->
original) that is never sent anywhere, so the LLM sees HOST_1 / IP_1 / URL_1 and
the local report can expand the placeholders back afterwards.

This is a best-effort privacy aid, not a guarantee. It covers IPv4, IPv6, URLs
and dotted hostnames; it will not catch an identifier embedded in free prose
("the Lagos branch firewall"). Review redacted text before disabling it.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# URL first (longest match), then IPv6, IPv4, then bare hostnames.
# Trailing part is optional so a bare scheme like "labapp://" is still redacted.
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s,\"'<>]*", re.IGNORECASE)
_IPV6 = re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# A dotted name with a letter somewhere (so pure version strings like 3.1.9 are left alone).
_HOST = re.compile(r"\b(?:[a-z0-9_-]+\.)+[a-z][a-z0-9-]*\b", re.IGNORECASE)


def _is_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
        return True
    except ValueError:
        return False


@dataclass
class Redactor:
    """Assigns a stable placeholder to each distinct identifier it sees."""

    _map: dict[str, str] = field(default_factory=dict)      # original -> placeholder
    _counters: dict[str, int] = field(default_factory=dict)  # kind -> next number

    def _placeholder(self, kind: str, original: str) -> str:
        if original not in self._map:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            self._map[original] = f"{kind}_{self._counters[kind]}"
        return self._map[original]

    def redact(self, text: str) -> str:
        if not text:
            return text

        def url_sub(match: re.Match[str]) -> str:
            return self._placeholder("URL", match.group(0))

        def ipv6_sub(match: re.Match[str]) -> str:
            token = match.group(0)
            if token.count(":") < 2:  # avoid matching e.g. "80:tcp"
                return token
            return self._placeholder("IP", token)

        def ipv4_sub(match: re.Match[str]) -> str:
            token = match.group(0)
            return self._placeholder("IP", token) if _is_ipv4(token) else token

        def host_sub(match: re.Match[str]) -> str:
            return self._placeholder("HOST", match.group(0))

        text = _URL.sub(url_sub, text)
        text = _IPV6.sub(ipv6_sub, text)
        text = _IPV4.sub(ipv4_sub, text)
        text = _HOST.sub(host_sub, text)
        return text

    @property
    def mapping(self) -> dict[str, str]:
        """placeholder -> original, for local re-expansion. Never send this to the LLM."""
        return {placeholder: original for original, placeholder in self._map.items()}

    def restore(self, text: str) -> str:
        """Expand placeholders back to the originals in text produced locally."""
        if not text:
            return text
        # Longest placeholders first so HOST_11 is replaced before HOST_1.
        for placeholder, original in sorted(self.mapping.items(), key=lambda kv: -len(kv[0])):
            text = text.replace(placeholder, original)
        return text
