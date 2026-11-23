"""Loads proxy lists from a local file. One entry per line:
  host:port
  user:pass@host:port
  user:pass@host:port country=de        (explicit exit-country annotation)

The exit country is used to align the browser locale (language / timezone /
geolocation) with the proxy - see evasion.locale_profiles. It is resolved in
two ways, in order:
  1. an explicit `country=xx` token at the end of the line;
  2. a Bright Data style `-country-xx` parameter inside the username.
"""
from __future__ import annotations

import re
from pathlib import Path

from models import ProxyRecord

_BRIGHTDATA_COUNTRY_RE = re.compile(r"-country-([a-z]{2})\b", re.IGNORECASE)


def _extract_country(line: str, username: str | None) -> str | None:
    m = re.search(r"\bcountry=([a-z]{2})\b", line, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    if username:
        m = _BRIGHTDATA_COUNTRY_RE.search(username)
        if m:
            return m.group(1).lower()
    return None


def load_from_file(path: str | Path, scheme: str = "http") -> list[ProxyRecord]:
    path = Path(path)
    records: list[ProxyRecord] = []
    if not path.exists():
        return records

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        country_annotation = re.search(r"\s+country=[a-z]{2}\b", line, re.IGNORECASE)
        proxy_part = line[: country_annotation.start()].strip() if country_annotation else line

        username = password = None
        if "@" in proxy_part:
            creds, address = proxy_part.rsplit("@", 1)
            username, _, password = creds.partition(":")
        else:
            address = proxy_part

        country = _extract_country(line, username)

        records.append(
            ProxyRecord(
                address=address,
                scheme=scheme,
                username=username,
                password=password,
                country=country,
            )
        )

    return records
