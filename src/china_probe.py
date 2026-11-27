"""China mainland carrier probing for Cloudflare edge IP ranking.

Uses Globalping's public probes on China Telecom, Unicom and Mobile eyeball
networks. The GitHub Actions runner's own RTT is retained as a fallback only.
"""
from __future__ import annotations

import ipaddress
import json
import os
import statistics
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from typing import Any

API = "https://api.globalping.io/v1"
ISPS = {
    4134: "CT", 4812: "CT", 4809: "CT", 134774: "CT", 136188: "CT",
    4837: "CU", 17621: "CU", 17622: "CU", 17623: "CU", 9929: "CU", 4808: "CU",
    9808: "CM", 24400: "CM", 24445: "CM", 56040: "CM", 56041: "CM",
    56042: "CM", 56044: "CM", 56046: "CM", 56047: "CM", 56048: "CM",
}
ISP_LOCATIONS = [
    {"country": "CN", "asn": 4134, "tags": ["eyeball-network"], "limit": 1},
    {"country": "CN", "asn": 4837, "tags": ["eyeball-network"], "limit": 1},
    {"country": "CN", "asn": 9808, "tags": ["eyeball-network"], "limit": 1},
]
KEEP_HOURS = 72
DEFAULT_BUDGET = 12
USER_AGENT = "cf-IP-china-probe (+https://github.com/rsmfcs/cf-IP)"


def _request(url: str, *, method: str = "GET", body: dict | None = None,
             timeout: float = 12.0) -> dict:
    headers = {"User-Agent": USER_AGENT}
    token = os.getenv("GLOBALPING_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    req = Request(url, data=data, headers=headers, method=method)
    with urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _create_measurement(ip: str, locations: list | str) -> dict:
    body = {
        "type": "http",
        "target": ip,
        "locations": locations,
        "measurementOptions": {
            "protocol": "HTTPS",
            "port": 443,
            "request": {
                "host": "www.cloudflare.com",
                "path": "/cdn-cgi/trace",
                "method": "GET",
            },
        },
    }
    return _request(f"{API}/measurements", method="POST", body=body, timeout=15)


def _wait_measurement(measurement_id: str, timeout_seconds: int = 24) -> dict | None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        time.sleep(1.2)
        try:
            result = _request(f"{API}/measurements/{measurement_id}", timeout=10)
        except (OSError, ValueError):
            continue
        if result.get("status") and result.get("status") != "in-progress":
            return result
    return None


def _parse_probe_result(item: dict) -> dict | None:
    result = item.get("result") or {}
    probe = item.get("probe") or {}
    asn = int(probe.get("asn") or 0)
    isp = ISPS.get(asn)
    if not isp:
        network = str(probe.get("network") or "").lower()
        isp = ("CU" if "unicom" in network else "CM" if "mobile" in network
               else "CT" if "telecom" in network or "chinanet" in network else None)
    if not isp:
        return None

    status_code = int(result.get("statusCode") or 0)
    body = str(result.get("rawBody") or "")
    trace_ok = any(line.startswith("fl=") for line in body.splitlines()) and any(
        line.startswith("colo=") for line in body.splitlines()
    )
    timings = result.get("timings") or {}
    tcp_ms = timings.get("tcp")
    total_ms = timings.get("total")
    ok = (
        result.get("status") == "finished"
        and 200 <= status_code < 400
        and trace_ok
        and tcp_ms is not None
    )
    colo = ""
    for line in body.splitlines():
        if line.startswith("colo="):
            colo = line.split("=", 1)[1].strip().upper()[:3]
    return {
        "isp": isp,
        "ok": bool(ok),
        "rtt_ms": round(float(tcp_ms), 2) if ok else None,
        "total_ms": round(float(total_ms), 2) if ok and total_ms is not None else None,
        "colo": colo if ok else "",
        "asn": asn,
    }


def _load_history(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            return value
    except (OSError, ValueError):
        pass
    return {"cursor": 0, "records": []}


def _save_history(path: Path, history: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def probe_and_rank(results: list[dict[str, Any]], history_path: Path) -> list[dict[str, Any]]:
    """Probe a rotating subset, then rank using recent mainland carrier results."""
    if not results:
        return results
    history = _load_history(history_path)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=KEEP_HOURS)
    records = [
        row for row in history.get("records", [])
        if isinstance(row, dict)
        and isinstance(row.get("at"), str)
        and _parse_time(row["at"]) is not None
        and _parse_time(row["at"]) >= cutoff
    ]
    # Do not call Globalping when the public quota is exhausted.
    budget = max(0, min(30, int(os.getenv("CHINA_PROBE_BUDGET", DEFAULT_BUDGET))))
    try:
        limits = _request(f"{API}/limits", timeout=8)
        remaining = int(limits.get("rateLimit", {}).get("measurements", {}).get("create", {}).get("remaining"))
        budget = min(budget, max(0, (remaining - 15) // 3))
        print(f"Globalping remaining credits={remaining}; China probe budget={budget}")
    except (OSError, ValueError, TypeError, HTTPError, URLError):
        print(f"Globalping quota unavailable; using configured probe budget={budget}")

    pool = []
    seen = set()
    for item in results:
        ip = str(item.get("ip") or "")
        try:
            if ipaddress.ip_address(ip).version != 4:
                continue
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            pool.append(item)
    # Rotate through the first 200 overseas-qualified candidates so a slow
    # overseas route cannot permanently hide a fast China route.
    window = pool[: min(200, len(pool))]
    if budget and window:
        cursor = int(history.get("cursor") or 0) % len(window)
        targets = (window[cursor:] + window[:cursor])[:budget]
        sticky: str | None = None
        fresh = []
        for target in targets:
            ip = str(target["ip"])
            try:
                created = _create_measurement(ip, sticky or ISP_LOCATIONS)
                if not created.get("id") and sticky and created.get("status") == 422:
                    sticky = None
                    created = _create_measurement(ip, ISP_LOCATIONS)
                measurement_id = created.get("id")
                if not measurement_id:
                    print(f"China probe create failed for {ip}: {created}")
                    continue
                if sticky is None and int(created.get("probesCount") or 0) >= 3:
                    sticky = str(measurement_id)
                measured = _wait_measurement(str(measurement_id))
                if not measured:
                    print(f"China probe timed out for {ip}")
                    continue
                for raw in measured.get("results") or []:
                    parsed = _parse_probe_result(raw)
                    if parsed:
                        fresh.append({
                            "ip": ip, **parsed, "at": now.isoformat(timespec="seconds")
                        })
                print(f"China probe {ip}: {sum(1 for x in fresh if x['ip'] == ip)} carrier results")
            except (OSError, ValueError, TypeError, HTTPError, URLError) as exc:
                print(f"China probe failed for {ip}: {type(exc).__name__}: {exc}")
                if isinstance(exc, HTTPError) and exc.code == 429:
                    break
        records = (fresh + records)[:6000]
        history["cursor"] = (cursor + len(targets)) % len(window)
        history["updated_at"] = now.isoformat(timespec="seconds")
        history["records"] = records
        _save_history(history_path, history)
    elif not history_path.exists():
        _save_history(history_path, {"cursor": 0, "records": records})

    by_ip: dict[str, list[dict]] = {}
    for row in records:
        by_ip.setdefault(str(row.get("ip")), []).append(row)

    for item in results:
        rows = by_ip.get(str(item.get("ip")), [])
        by_isp: dict[str, list[dict]] = {}
        for row in rows:
            by_isp.setdefault(str(row.get("isp")), []).append(row)
        metrics = {}
        successful_rtts = []
        for isp in ("CT", "CU", "CM"):
            samples = by_isp.get(isp, [])
            latest = samples[:3]
            successful = [float(x["rtt_ms"]) for x in latest if x.get("ok") and x.get("rtt_ms") is not None]
            metrics[isp] = round(statistics.median(successful), 2) if successful else None
            successful_rtts.extend(successful)
        tested_isps = sum(1 for isp in ("CT", "CU", "CM") if by_isp.get(isp))
        success_isps = sum(1 for isp in ("CT", "CU", "CM") if metrics[isp] is not None)
        item["china_probe"] = {
            "tested_isps": tested_isps,
            "success_isps": success_isps,
            "ct_rtt_ms": metrics["CT"],
            "cu_rtt_ms": metrics["CU"],
            "cm_rtt_ms": metrics["CM"],
            "median_rtt_ms": round(statistics.median(successful_rtts), 2) if successful_rtts else None,
        }

    def rank_key(item: dict) -> tuple:
        china = item.get("china_probe") or {}
        successes = int(china.get("success_isps") or 0)
        tested = int(china.get("tested_isps") or 0)
        # China-verified IPs first; among them favor broad carrier reach and low RTT.
        # Untested candidates remain available as a fallback; failed probes go last.
        group = 0 if successes else (2 if tested else 1)
        median = china.get("median_rtt_ms")
        return (
            group,
            -successes,
            float(median) if median is not None else 999999.0,
            -float(item.get("score") or 0),
            float(item.get("latency_ms") or 999999.0),
        )
    return sorted(results, key=rank_key)


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
