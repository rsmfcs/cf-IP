"""Aggregate China-oriented Cloudflare IPv6 candidate sources.

External lists are candidate discovery only. Every address must still pass
our own Globalping HTTPS checks from China Telecom, Unicom and Mobile probes.
"""
from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from datetime import datetime, timezone
from typing import Any
from urllib.request import Request, urlopen

WETEST_IPV6_URL = "https://www.wetest.vip/page/cloudflare/address_v6.html"
CMLIU_MOBILE_IPV6_URL = "https://addressesapi.090227.xyz/cmcc-ipv6"
CLOUDFLARE_IPV6_RANGES_URL = "https://www.cloudflare.com/ips-v6"
USER_AGENT = "Cloudflare-IP-Auto/3.9"


def _fetch_text(url: str, timeout: float = 20.0) -> str:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


class _TableRows(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.rows: list[list[str]] = []
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag == "tr":
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            if self._row:
                self.rows.append(self._row)
            self._row = None
            self._cell = None


def _valid_global_v6(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value.strip().strip("[](),;"))
    except ValueError:
        return None
    if address.version != 6 or not address.is_global:
        return None
    return address.compressed


def parse_wetest_ipv6(html: str) -> list[dict[str, str]]:
    """Parse WeTest's carrier-labelled IPv6 table without trusting its ranking."""
    parser = _TableRows()
    parser.feed(html)
    carrier_names = {"移动": "CM", "联通": "CU", "电信": "CT"}
    items: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in parser.rows:
        if len(row) < 2:
            continue
        carrier = next((carrier_names[name] for name in carrier_names if name in row[0]), None)
        if not carrier:
            continue
        ip = next((_valid_global_v6(cell) for cell in row[1:] if _valid_global_v6(cell)), None)
        if not ip or (ip, carrier) in seen:
            continue
        seen.add((ip, carrier))
        items.append({"ip": ip, "source": "WeTest", "source_carrier": carrier})
    return items


def parse_plain_ipv6(text: str, *, source: str, carrier: str) -> list[dict[str, str]]:
    """Extract IPv6 literals from a plain-text community source."""
    candidates = re.findall(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:]{2,}(?![0-9A-Fa-f:])", text)
    items: list[dict[str, str]] = []
    seen: set[str] = set()
    for candidate in candidates:
        ip = _valid_global_v6(candidate)
        if ip and ip not in seen:
            seen.add(ip)
            items.append({"ip": ip, "source": source, "source_carrier": carrier})
    return items


def collect_ipv6_candidates(hostmonit_items: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Merge HostMonit, WeTest and CMLiu seed lists; enforce Cloudflare IPv6 CIDRs."""
    candidates: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    source_counts: dict[str, int] = {}

    for item in hostmonit_items:
        ip = _valid_global_v6(str(item.get("ip") or ""))
        if ip:
            candidates.append({
                "ip": ip,
                "source": "HostMonit",
                "source_carrier": str(item.get("source") or ""),
            })

    try:
        parsed = parse_wetest_ipv6(_fetch_text(WETEST_IPV6_URL))
        candidates.extend(parsed)
        source_counts["WeTest"] = len(parsed)
    except Exception as exc:
        errors["WeTest"] = f"{type(exc).__name__}: {exc}"
        source_counts["WeTest"] = 0

    try:
        parsed = parse_plain_ipv6(
            _fetch_text(CMLIU_MOBILE_IPV6_URL),
            source="CMLiu",
            carrier="CM",
        )
        candidates.extend(parsed)
        source_counts["CMLiu"] = len(parsed)
    except Exception as exc:
        errors["CMLiu"] = f"{type(exc).__name__}: {exc}"
        source_counts["CMLiu"] = 0

    # The official prefix list is mandatory: third-party feeds are discovery
    # sources, not authority for deciding whether an address belongs to CF.
    prefixes_text = _fetch_text(CLOUDFLARE_IPV6_RANGES_URL)
    networks = [
        ipaddress.ip_network(line.strip())
        for line in prefixes_text.splitlines()
        if line.strip() and ":" in line
    ]
    if not networks:
        raise ValueError("Cloudflare official IPv6 prefix list was empty")

    merged: dict[str, dict[str, Any]] = {}
    for item in candidates:
        ip = _valid_global_v6(str(item.get("ip") or ""))
        if not ip:
            continue
        address = ipaddress.ip_address(ip)
        if not any(address in network for network in networks):
            continue
        row = merged.setdefault(ip, {
            "ip": ip,
            "version": 6,
            "port": 443,
            "source": [],
            "source_carriers": [],
            "country_code": "ZZ",
            "city": "",
            "region_zh": "未知地区",
            "quality_status": "source_candidate_unverified",
        })
        source = str(item.get("source") or "unknown")
        carrier = str(item.get("source_carrier") or "")
        if source not in row["source"]:
            row["source"].append(source)
        if carrier and carrier not in row["source_carriers"]:
            row["source_carriers"].append(carrier)
        source_counts[source] = source_counts.get(source, 0) + 1

    result = list(merged.values())
    metadata = {
        "sources": [ "HostMonit", "WeTest", "CMLiu" ],
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_counts": source_counts,
        "source_errors": errors,
        "official_prefix_validation": CLOUDFLARE_IPV6_RANGES_URL,
        "candidate_count": len(result),
        "quality_status": "source_candidate_unverified",
        "note": "Community sources are candidate discovery only; publication requires fresh domestic IPv6 HTTPS verification.",
    }
    return result, metadata
