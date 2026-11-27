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
KEEP_HOURS = 168  # Only accept domestic evidence from the last 7 days.
DEFAULT_BUDGET = 24
MIN_PROBES_PER_ISP = 2
MAX_CHINA_RTT_MS = 300.0
REQUIRED_SUBSCRIPTION_CARRIERS = ("CU", "CM")
PROBES_PER_ISP = 2
ISP_LOCATIONS = [
    {"country": "CN", "asn": 4134, "tags": ["eyeball-network"], "limit": PROBES_PER_ISP},
    {"country": "CN", "asn": 4837, "tags": ["eyeball-network"], "limit": PROBES_PER_ISP},
    {"country": "CN", "asn": 9808, "tags": ["eyeball-network"], "limit": PROBES_PER_ISP},
]
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
        "probe_key": "|".join(str(probe.get(key) or "").strip().lower() for key in
                              ("country", "region", "city", "state", "latitude", "longitude")) + f"|{asn}",
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


def _carrier_status(samples: list[dict]) -> dict:
    """Require at least two distinct mainland probes and a median TCP RTT <= 300 ms."""
    latest_by_probe = {}
    for sample in sorted(samples, key=lambda x: str(x.get("at") or ""), reverse=True):
        key = str(sample.get("probe_key") or "legacy-single-probe")
        latest_by_probe.setdefault(key, sample)
    selected = list(latest_by_probe.values())[:PROBES_PER_ISP]
    successful = [
        float(x["rtt_ms"]) for x in selected
        if x.get("ok") and x.get("rtt_ms") is not None
    ]
    median_rtt = round(statistics.median(successful), 2) if successful else None
    return {
        "rtt_ms": median_rtt,
        "probe_count": len(selected),
        "success_probe_count": len(successful),
        "qualified": (
            len(successful) >= MIN_PROBES_PER_ISP
            and median_rtt is not None
            and median_rtt <= MAX_CHINA_RTT_MS
        ),
    }


def is_mobile_unicom_qualified(carrier_qualified: dict[str, bool] | None) -> bool:
    """Public subscription gate: both China Unicom and China Mobile must pass."""
    carrier_qualified = carrier_qualified or {}
    return all(bool(carrier_qualified.get(isp)) for isp in REQUIRED_SUBSCRIPTION_CARRIERS)


def probe_and_rank(
    results: list[dict[str, Any]], history_path: Path, ip_version: int = 4
) -> list[dict[str, Any]]:
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
    budget_name = "CHINA_IPV6_PROBE_BUDGET" if ip_version == 6 else "CHINA_PROBE_BUDGET"
    default_budget = 12 if ip_version == 6 else DEFAULT_BUDGET
    budget = max(0, min(30, int(os.getenv(budget_name, default_budget))))
    try:
        limits = _request(f"{API}/limits", timeout=8)
        remaining = int(limits.get("rateLimit", {}).get("measurements", {}).get("create", {}).get("remaining"))
        # One IP measurement requests up to three probes on each of three carriers.
        budget = min(budget, max(0, (remaining - 15) // (PROBES_PER_ISP * 3)))
        print(f"Globalping remaining credits={remaining}; China probe budget={budget}")
    except (OSError, ValueError, TypeError, HTTPError, URLError):
        print(f"Globalping quota unavailable; using configured probe budget={budget}")

    pool = []
    seen = set()
    for item in results:
        ip = str(item.get("ip") or "")
        try:
            if ipaddress.ip_address(ip).version != ip_version:
                continue
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            pool.append(item)
    # Verify the full candidate pool. Prefer never-tested IPs, then the oldest
    # previous test, so overseas ranking cannot permanently hide China-friendly IPs.
    window = pool
    if budget and window:
        last_tested = {}
        for row in records:
            ip = str(row.get("ip") or "")
            tested_at = _parse_time(row.get("at", ""))
            if ip and tested_at and (ip not in last_tested or tested_at > last_tested[ip]):
                last_tested[ip] = tested_at
        oldest = datetime.min.replace(tzinfo=timezone.utc)
        targets = sorted(
            window,
            key=lambda item: (
                last_tested.get(str(item.get("ip") or ""), oldest),
                -float(item.get("score") or 0),
            ),
        )[:budget]
        cursor = int(history.get("cursor") or 0)
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
                if sticky is None and int(created.get("probesCount") or 0) >= (PROBES_PER_ISP * 3):
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
        history["cursor"] = cursor + len(targets)
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
        carrier_qualified = {}
        successful_rtts = []
        for isp in ("CT", "CU", "CM"):
            status = _carrier_status(by_isp.get(isp, []))
            metrics[isp] = status["rtt_ms"]
            carrier_qualified[isp] = status["qualified"]
            if status["rtt_ms"] is not None:
                successful_rtts.append(status["rtt_ms"])
        tested_isps = sum(1 for isp in ("CT", "CU", "CM") if by_isp.get(isp))
        success_isps = sum(1 for isp in ("CT", "CU", "CM") if metrics[isp] is not None)
        qualified_isps = sum(1 for isp in ("CT", "CU", "CM") if carrier_qualified[isp])
        median_rtt = round(statistics.median(successful_rtts), 2) if successful_rtts else None
        item["china_probe"] = {
            "tested_isps": tested_isps,
            "success_isps": success_isps,
            "qualified_isps": qualified_isps,
            "ct_rtt_ms": metrics["CT"],
            "cu_rtt_ms": metrics["CU"],
            "cm_rtt_ms": metrics["CM"],
            "median_rtt_ms": median_rtt,
            "carrier_qualified": carrier_qualified,
        }
        item["china_tested_isps"] = tested_isps
        item["china_success_isps"] = success_isps
        item["china_qualified_isps"] = qualified_isps
        item["china_carrier_qualified"] = carrier_qualified
        item["china_three_carrier_qualified"] = qualified_isps == 3
        item["china_mobile_unicom_qualified"] = is_mobile_unicom_qualified(carrier_qualified)
        # Backward-compatible public gate: at least China Unicom + China Mobile.
        item["china_qualified"] = item["china_mobile_unicom_qualified"]
        item["quality_status"] = (
            "domestic_three_carrier_verified" if item["china_three_carrier_qualified"]
            else "domestic_mobile_unicom_verified" if item["china_mobile_unicom_qualified"]
            else "not_subscription_qualified"
        )
        item["china_ct_rtt_ms"] = metrics["CT"]
        item["china_cu_rtt_ms"] = metrics["CU"]
        item["china_cm_rtt_ms"] = metrics["CM"]
        item["china_median_rtt_ms"] = median_rtt

    def rank_key(item: dict) -> tuple:
        china = item.get("china_probe") or {}
        successes = int(china.get("success_isps") or 0)
        tested = int(china.get("tested_isps") or 0)
        # Mobile+Unicom-qualified IPs rank first; three-carrier IPs receive a tie-break bonus.
        qualified = bool(item.get("china_mobile_unicom_qualified", item.get("china_qualified")))
        three_carrier = bool(item.get("china_three_carrier_qualified"))
        group = 0 if qualified else (1 if successes else (2 if tested else 3))
        median = china.get("median_rtt_ms")
        return (
            group,
            0 if three_carrier else 1,
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
