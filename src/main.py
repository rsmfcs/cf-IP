from __future__ import annotations

import csv
import ipaddress
import json
import math
import os
import socket
import ssl
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from http.client import HTTPResponse
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "config.yaml"
OUTPUT = ROOT / "output"

CF_IPS_URLS = {
    4: "https://www.cloudflare.com/ips-v4",
}
EGRESS_TEST_IPS = {
    4: ("1.1.1.1", 443),
}


COUNTRY_API_URL = "http://ip-api.com/batch?fields=status,countryCode,query"


def country_flag(country_code: str | None) -> str:
    """Convert an ISO 3166-1 alpha-2 code to its flag emoji."""
    code = (country_code or "").strip().upper()
    if len(code) != 2 or not code.isalpha() or not code.isascii():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code)


def enrich_country_info(results: list[dict[str, Any]]) -> None:
    """Add approximate country codes in batches; never fail a scan on GeoIP errors."""
    if not results:
        return
    ip_to_country: dict[str, str] = {}
    addresses = list(dict.fromkeys(str(item["ip"]) for item in results))
    for offset in range(0, len(addresses), 100):
        batch = addresses[offset:offset + 100]
        try:
            body = json.dumps(batch).encode("utf-8")
            request = Request(
                COUNTRY_API_URL,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Cloudflare-IP-Auto/3.2",
                },
                method="POST",
            )
            with urlopen(request, timeout=20.0) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if isinstance(payload, list):
                for entry in payload:
                    if entry.get("status") == "success":
                        ip_to_country[str(entry.get("query", ""))] = str(entry.get("countryCode", "")).upper()
        except Exception as exc:
            print(f"GeoIP lookup batch {offset // 100 + 1} failed: {type(exc).__name__}: {exc}")

    for item in results:
        code = ip_to_country.get(str(item["ip"]), "")
        item["country_code"] = code or "ZZ"
        item["country_flag"] = country_flag(code)
        

def subscription_line(item: dict[str, Any]) -> str:
    code = str(item.get("country_code") or "ZZ").upper()
    flag = str(item.get("country_flag") or "🌐")
    return f"{item['ip']}:{int(item.get('port', 443))}#{code} {flag}"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fetch_text(url: str, timeout: float = 20.0) -> str:
    request = Request(url, headers={"User-Agent": "Cloudflare-IP-Auto/3.1"})
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")


def load_config() -> dict[str, Any]:
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    scan = config.setdefault("scan", {})

    env_overrides = {
        "SCAN_LIMIT": ("max_candidates_per_family", int),
        "ROUNDS": ("rounds", int),
        "SPEED_TESTS": ("speed_tests", int),
        "MAX_SPEED_CANDIDATES": ("max_speed_candidates", int),
        "WORKERS": ("workers", int),
        "TIMEOUT": ("timeout_seconds", float),
        "PRELIMINARY_ROUNDS": ("preliminary_rounds", int),
    }
    for env_name, (key, converter) in env_overrides.items():
        raw = os.getenv(env_name)
        if raw:
            scan[key] = converter(raw)

    # V3.1 is IPv4-only and probes TCP 443 exclusively.
    scan["ports"] = [443]
    validate_config(config)
    return config


def validate_config(config: dict[str, Any]) -> None:
    scan = config.get("scan", {})
    positive_ints = (
        "max_candidates_per_family", "workers", "rounds",
        "max_speed_candidates", "speed_tests", "speed_test_bytes",
        "samples_per_network", "preliminary_rounds",
    )
    for key in positive_ints:
        value = int(scan.get(key, 0))
        if value <= 0:
            raise ValueError(f"config.scan.{key} must be greater than zero")
    if float(scan.get("timeout_seconds", 0)) <= 0:
        raise ValueError("config.scan.timeout_seconds must be greater than zero")
    success = float(scan.get("min_success_rate", 0))
    if not 0 <= success <= 1:
        raise ValueError("config.scan.min_success_rate must be between 0 and 1")
    if not scan.get("ports"):
        raise ValueError("config.scan.ports must contain at least one port")
    for port in scan["ports"]:
        if not 1 <= int(port) <= 65535:
            raise ValueError(f"invalid TCP port: {port}")
    if not scan.get("top_n"):
        raise ValueError("config.scan.top_n must not be empty")


def parse_custom_networks(version: int, values: list[str]) -> list[ipaddress._BaseNetwork]:
    parsed: list[ipaddress._BaseNetwork] = []
    for value in values or []:
        item = str(value).strip()
        if not item:
            continue
        try:
            address = ipaddress.ip_address(item)
            if address.version != version:
                continue
            parsed.append(ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=False))
        except ValueError:
            network = ipaddress.ip_network(item, strict=False)
            if network.version == version:
                parsed.append(network)
    return parsed


def fetch_networks(version: int, custom: list[str]) -> list[ipaddress._BaseNetwork]:
    raw = fetch_text(CF_IPS_URLS[version])
    networks = [
        ipaddress.ip_network(line.strip(), strict=False)
        for line in raw.splitlines()
        if line.strip()
    ]
    networks.extend(parse_custom_networks(version, custom))
    unique = {str(network): network for network in networks if network.version == version}
    return [unique[key] for key in sorted(unique, key=lambda x: (int(unique[x].network_address), unique[x].prefixlen))]


def candidate_ips(
    networks: list[ipaddress._BaseNetwork],
    limit: int,
    samples_per_network: int = 24,
) -> list[str]:
    """Select a deterministic, evenly distributed sample without enumerating large ranges."""
    if limit <= 0:
        return []
    candidates: list[str] = []
    per_network = max(1, min(samples_per_network, math.ceil(limit / max(1, len(networks)))))

    for network in networks:
        if network.num_addresses <= 2:
            addresses = list(network.hosts())
        else:
            first = int(network.network_address) + 1
            last = int(network.broadcast_address) - (1 if network.version == 4 else 0)
            count = max(0, last - first + 1)
            if count <= 0:
                continue
            sample_count = min(per_network, count)
            if sample_count == 1:
                selected = [first + (count - 1) // 2]
            else:
                selected = sorted({
                    first + (index * (count - 1)) // (sample_count - 1)
                    for index in range(sample_count)
                })
            addresses = [ipaddress.ip_address(number) for number in selected]

        for address in addresses:
            if address.is_global:
                candidates.append(str(address))

    # Preserve order while de-duplicating.
    candidates = list(dict.fromkeys(candidates))
    if len(candidates) > limit:
        # Evenly downsample the union to maintain reproducibility and range coverage.
        if limit == 1:
            candidates = [candidates[len(candidates) // 2]]
        else:
            last = len(candidates) - 1
            indexes = sorted({
                (index * last) // (limit - 1)
                for index in range(limit)
            })
            candidates = [candidates[index] for index in indexes]
    return candidates


def make_socket(ip: str, port: int, version: int, timeout: float) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    return sock


def tcp_connect_probe(ip: str, port: int, timeout: float, version: int = 4) -> bool:
    """Stage 1: verify that the candidate accepts a TCP connection."""
    sock = make_socket(ip, port, version, timeout)
    try:
        sock.connect((ip, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def tls_handshake_probe(
    ip: str, port: int, timeout: float, version: int = 4
) -> bool:
    """Stage 2: verify a certificate-checked TLS handshake with Cloudflare SNI."""
    sock = make_socket(ip, port, version, timeout)
    tls_sock: ssl.SSLSocket | None = None
    try:
        sock.connect((ip, port))
        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(sock, server_hostname="www.cloudflare.com")
        tls_sock.settimeout(timeout)
        return tls_sock.version() is not None
    except (OSError, ssl.SSLError):
        return False
    finally:
        if tls_sock is not None:
            tls_sock.close()
        else:
            sock.close()


def http_response_probe(
    ip: str, port: int, timeout: float, version: int, user_agent: str
) -> bool:
    """Stage 3: verify that the pinned IP serves a valid Cloudflare HTTP response."""
    sock = make_socket(ip, port, version, timeout)
    tls_sock: ssl.SSLSocket | None = None
    response: HTTPResponse | None = None
    try:
        sock.connect((ip, port))
        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(sock, server_hostname="www.cloudflare.com")
        tls_sock.settimeout(timeout)
        request = (
            "GET /cdn-cgi/trace HTTP/1.1\r\n"
            "Host: www.cloudflare.com\r\n"
            f"User-Agent: {user_agent}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        tls_sock.sendall(request.encode("ascii"))
        response = HTTPResponse(tls_sock)
        response.begin()
        return 200 <= response.status < 400
    except (OSError, ssl.SSLError, TimeoutError):
        return False
    finally:
        if response is not None:
            try:
                response.close()
            except OSError:
                pass
        if tls_sock is not None:
            try:
                tls_sock.close()
            except OSError:
                pass
        else:
            try:
                sock.close()
            except OSError:
                pass


def run_probe_stages(
    candidates: list[str], config: dict[str, Any]
) -> list[str]:
    """Progressively filter candidates through TCP, TLS, and HTTP before retesting."""
    scan = config["scan"]
    port = 443
    timeout = float(scan["timeout_seconds"])
    workers = int(scan["workers"])
    user_agent = str(scan.get("user_agent", "Cloudflare-IP-Auto/3.2"))
    stages = (
        ("TCP", lambda ip: tcp_connect_probe(ip, port, timeout, 4)),
        ("TLS", lambda ip: tls_handshake_probe(ip, port, timeout, 4)),
        ("HTTP", lambda ip: http_response_probe(ip, port, timeout, 4, user_agent)),
    )
    survivors = list(candidates)
    for stage_name, probe in stages:
        passed: list[str] = []
        completed = 0
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(probe, ip): ip for ip in survivors}
            for future in as_completed(futures):
                completed += 1
                try:
                    if future.result():
                        passed.append(futures[future])
                except Exception as exc:
                    print(f"IPv4 {stage_name} stage error {futures[future]}: {type(exc).__name__}: {exc}")
                if completed % 100 == 0 or completed == len(futures):
                    print(f"IPv4 {stage_name} stage: {completed}/{len(futures)}; passed={len(passed)}")
        survivors = passed
        print(f"IPv4 {stage_name} stage complete: {len(survivors)} candidates remain")
        if not survivors:
            break
    return survivors


def https_probe(
    ip: str,
    port: int,
    timeout: float,
    version: int,
    user_agent: str,
) -> tuple[bool, float, str | None]:
    """Probe a pinned Cloudflare edge IP using verified TLS and Cloudflare SNI."""
    sock = make_socket(ip, port, version, timeout)
    address = (ip, port)
    started = time.perf_counter()
    tls_sock: ssl.SSLSocket | None = None
    response: HTTPResponse | None = None
    try:
        sock.connect(address)
        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(sock, server_hostname="www.cloudflare.com")
        tls_sock.settimeout(timeout)
        request = (
            "GET /cdn-cgi/trace HTTP/1.1\r\n"
            "Host: www.cloudflare.com\r\n"
            f"User-Agent: {user_agent}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        tls_sock.sendall(request.encode("ascii"))
        response = HTTPResponse(tls_sock)
        response.begin()
        elapsed_ms = (time.perf_counter() - started) * 1000
        status_line = f"HTTP {response.status} {response.reason}".strip()
        # A successful TLS handshake plus a valid 2xx/3xx response confirms
        # the edge can serve the requested Cloudflare hostname.
        if 200 <= response.status < 400:
            return True, elapsed_ms, status_line
        return False, elapsed_ms, status_line
    except ssl.SSLCertVerificationError:
        return False, 0.0, "SSLCertVerificationError"
    except ssl.SSLError as exc:
        return False, 0.0, f"SSLError:{getattr(exc, 'reason', '') or type(exc).__name__}"
    except socket.timeout:
        return False, 0.0, "Timeout"
    except OSError as exc:
        return False, 0.0, f"{type(exc).__name__}:{getattr(exc, 'errno', '')}"
    except Exception as exc:
        return False, 0.0, f"{type(exc).__name__}"
    finally:
        if response is not None:
            try:
                response.close()
            except OSError:
                pass
        if tls_sock is not None:
            try:
                tls_sock.close()
            except OSError:
                pass
        else:
            try:
                sock.close()
            except OSError:
                pass


def download_speed(
    ip: str,
    port: int,
    size: int,
    timeout: float,
    version: int,
    user_agent: str,
) -> float | None:
    """Download a bounded test payload through a pinned IP with valid TLS/SNI."""
    sock = make_socket(ip, port, version, timeout * 4)
    address = (ip, port)
    started = time.perf_counter()
    tls_sock: ssl.SSLSocket | None = None
    response: HTTPResponse | None = None
    try:
        sock.connect(address)
        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(sock, server_hostname="speed.cloudflare.com")
        request = (
            f"GET /__down?bytes={size} HTTP/1.1\r\n"
            "Host: speed.cloudflare.com\r\n"
            f"User-Agent: {user_agent}\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        )
        tls_sock.sendall(request.encode("ascii"))
        response = HTTPResponse(tls_sock)
        response.begin()
        if response.status != 200:
            return None
        payload = response.read(size)
        elapsed = time.perf_counter() - started
        if not payload or elapsed <= 0:
            return None
        return (len(payload) * 8 / elapsed) / 1_000_000
    except (OSError, ssl.SSLError, TimeoutError):
        return None
    finally:
        if response is not None:
            try:
                response.close()
            except OSError:
                pass
        if tls_sock is not None:
            try:
                tls_sock.close()
            except OSError:
                pass
        else:
            try:
                sock.close()
            except OSError:
                pass


def summarize_samples(samples: list[float]) -> dict[str, float]:
    if not samples:
        return {"avg": 0.0, "median": 0.0, "jitter": 0.0, "p95": 0.0}
    ordered = sorted(samples)
    p95_index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * 0.95) - 1))
    return {
        "avg": round(statistics.mean(samples), 2),
        "median": round(statistics.median(samples), 2),
        "jitter": round(statistics.pstdev(samples), 2) if len(samples) > 1 else 0.0,
        "p95": round(ordered[p95_index], 2),
    }


def probe_candidate(
    ip: str, version: int, config: dict[str, Any]
) -> tuple[dict[str, Any] | None, dict[str, int]]:
    """Probe all configured ports and return both a usable result and diagnostics."""
    scan = config["scan"]
    timeout = float(scan["timeout_seconds"])
    rounds = int(scan["rounds"])
    user_agent = str(scan.get("user_agent", "Cloudflare-IP-Auto/3.1"))
    port_results: list[dict[str, Any]] = []
    failure_reasons: dict[str, int] = {}

    for port_value in scan["ports"]:
        port = int(port_value)
        latencies: list[float] = []
        errors: dict[str, int] = {}
        successes = 0
        for _ in range(rounds):
            ok, latency, detail = https_probe(ip, port, timeout, version, user_agent)
            if ok:
                successes += 1
                latencies.append(latency)
            else:
                reason = detail or "probe_failed"
                errors[reason] = errors.get(reason, 0) + 1
                failure_reasons[reason] = failure_reasons.get(reason, 0) + 1

        success_rate = successes / rounds
        if successes:
            stats = summarize_samples(latencies)
            port_results.append({
                "port": port,
                "success_rate": round(success_rate, 4),
                "successful_rounds": successes,
                "total_rounds": rounds,
                "latency_ms": stats["avg"],
                "median_latency_ms": stats["median"],
                "jitter_ms": stats["jitter"],
                "p95_latency_ms": stats["p95"],
                "errors": errors,
            })

    if not port_results:
        return None, failure_reasons

    min_success = float(scan["min_success_rate"])
    eligible_ports = [item for item in port_results if item["success_rate"] >= min_success]
    if not eligible_ports:
        failure_reasons["below_min_success_rate"] = failure_reasons.get("below_min_success_rate", 0) + 1
        return None, failure_reasons

    best = min(
        eligible_ports,
        key=lambda item: (-item["success_rate"], item["latency_ms"], item["jitter_ms"], item["port"]),
    )
    return {
        "ip": ip,
        "version": version,
        "port": best["port"],
        "latency_ms": best["latency_ms"],
        "median_latency_ms": best["median_latency_ms"],
        "jitter_ms": best["jitter_ms"],
        "p95_latency_ms": best["p95_latency_ms"],
        "success_rate": best["success_rate"],
        "successful_rounds": best["successful_rounds"],
        "total_rounds": best["total_rounds"],
        "speed_mbps": None,
        "speed_tested": False,
        "speed_samples_mbps": [],
        "score": 0.0,
        "port_results": port_results,
        "tested_at": utc_now(),
    }, failure_reasons


def preliminary_score(item: dict[str, Any]) -> float:
    latency_component = max(0.0, 1.0 - min(item["latency_ms"], 1000.0) / 1000.0)
    reliability_component = item["success_rate"]
    jitter_component = max(0.0, 1.0 - min(item["jitter_ms"], 300.0) / 300.0)
    return 0.50 * latency_component + 0.30 * reliability_component + 0.20 * jitter_component


def final_score(item: dict[str, Any]) -> float:
    latency_component = max(0.0, 1.0 - min(item["latency_ms"], 1000.0) / 1000.0)
    speed = float(item["speed_mbps"] or 0.0)
    speed_component = min(math.log1p(max(0.0, speed)) / math.log1p(100.0), 1.0)
    reliability_component = float(item["success_rate"])
    jitter_component = max(0.0, 1.0 - min(float(item["jitter_ms"]), 300.0) / 300.0)
    score = (
        0.35 * latency_component
        + 0.30 * speed_component
        + 0.20 * reliability_component
        + 0.15 * jitter_component
    )
    return round(score * 100, 2)


def run_speed_tests(results: list[dict[str, Any]], version: int, config: dict[str, Any]) -> None:
    scan = config["scan"]
    count = min(int(scan["max_speed_candidates"]), len(results))
    candidates = sorted(results, key=lambda item: (-preliminary_score(item), item["latency_ms"]))[:count]
    print(f"IPv{version}: running download tests for {len(candidates)} candidates")

    for index, item in enumerate(candidates, start=1):
        samples: list[float] = []
        for _ in range(int(scan["speed_tests"])):
            value = download_speed(
                item["ip"],
                int(item["port"]),
                int(scan["speed_test_bytes"]),
                float(scan["timeout_seconds"]),
                version,
                str(scan.get("user_agent", "Cloudflare-IP-Auto/3.1")),
            )
            if value is not None:
                samples.append(round(value, 3))
        item["speed_samples_mbps"] = samples
        item["speed_tested"] = bool(samples)
        item["speed_mbps"] = round(statistics.median(samples), 3) if samples else None
        print(f"IPv{version} speed {index}/{len(candidates)}: {item['ip']} -> {item['speed_mbps']} Mbps")


def sort_and_score(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for item in results:
        item["score"] = final_score(item)
    return sorted(
        results,
        key=lambda item: (
            -item["score"],
            item["latency_ms"],
            -item["success_rate"],
            item["ip"],
        ),
    )


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def write_family_outputs(version: int, results: list[dict[str, Any]], top_n: list[int]) -> None:
    family = "ipv4" if version == 4 else "ipv6"
    output_dir = OUTPUT / family
    if not results:
        print(f"IPv{version}: no usable IPs; preserving previous valid result and subscription files")
        return
    output_dir.mkdir(parents=True, exist_ok=True)

    write_json(output_dir / "all.json", results)
    csv_fields = [
        "ip", "version", "port", "latency_ms", "median_latency_ms",
        "jitter_ms", "p95_latency_ms", "speed_mbps", "speed_tested",
        "success_rate", "successful_rounds", "total_rounds", "score", "tested_at",
    ]
    with (output_dir / "all.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=csv_fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    for count in top_n:
        top = results[:int(count)]
        lines = []
        for item in top:
            speed = "" if item["speed_mbps"] is None else str(item["speed_mbps"])
            lines.append(
                f'{item["ip"]},{item["port"]},{item["latency_ms"]},'
                f'{speed},{round(item["success_rate"] * 100, 2)},'
                f'{item["jitter_ms"]},{item["score"]}'
            )
        txt = "\n".join(lines) + ("\n" if lines else "")
        (output_dir / f"top{count}.txt").write_text(txt, encoding="utf-8")
        write_json(output_dir / f"top{count}.json", top)

    # Root-level plain subscription lists: one IPv4 endpoint per line.
    # Both naming conventions are published for convenient client integration.
    for count in top_n:
        top = results[:int(count)]
        endpoints = "\n".join(subscription_line(item) for item in top)
        payload = endpoints + "\n"
        (ROOT / f"best-cf-ip-scanned-top{count}.txt").write_text(payload, encoding="utf-8")
        (ROOT / f"cf-ipv4-top{count}.txt").write_text(payload, encoding="utf-8")


    # Convenience root-level lists for downstream subscription aggregators.
    fast_items = [item for item in results if item.get("speed_mbps") is not None and item["speed_mbps"] >= 25.0]
    stable_items = [item for item in results if item.get("success_rate", 0) >= 1.0 and item.get("jitter_ms", 9999) <= 50.0]
    for name, items in (("all.txt", results), ("fast.txt", fast_items), ("stable.txt", stable_items)):
        lines = [subscription_line(item) for item in items]
        payload = "\n".join(lines) + "\n"
        (ROOT / name).write_text(payload, encoding="utf-8")
        (output_dir / name).write_text(payload, encoding="utf-8")
    write_json(OUTPUT / "summary.json", {
        "project": "Cloudflare-IP-Auto", "version": "3.3", "generated_at": utc_now(),
        "ip_family": "IPv4 only", "port": 443,
        "ranked_count": len(results), "all_count": len(results),
        "fast_count": len(fast_items), "fast_min_mbps": 25.0,
        "stable_count": len(stable_items), "stable_rule": "success_rate=100% and jitter<=50ms",
    })


def check_egress(version: int, timeout: float = 3.0) -> dict[str, Any]:
    ip, port = EGRESS_TEST_IPS[version]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    started = time.perf_counter()
    try:
        address = (ip, port)
        sock.connect(address)
        return {
            "available": True,
            "target": f"{ip}:{port}",
            "connect_ms": round((time.perf_counter() - started) * 1000, 2),
        }
    except OSError as exc:
        return {
            "available": False,
            "target": f"{ip}:{port}",
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        sock.close()


def run_ipv4(config: dict[str, Any]) -> dict[str, Any]:
    scan = config["scan"]
    egress = check_egress(4)
    print(f"IPv4 egress: {egress}")

    networks = fetch_networks(4, scan.get("custom_ipv4", []))
    candidates = candidate_ips(
        networks,
        int(scan["max_candidates_per_family"]),
        int(scan["samples_per_network"]),
    )
    print(f"IPv4: {len(networks)} networks, {len(candidates)} candidate addresses; TCP 443 only")

    # Stages 1-3: progressively require TCP, verified TLS, and HTTP success.
    failure_reasons: dict[str, int] = {}
    preliminary = run_probe_stages(candidates, config)

    # Stage 4: repeat the complete TLS + HTTP probe for stability scoring.
    print(f"IPv4: stability retest for {len(preliminary)} HTTP-qualified candidates")
    results: list[dict[str, Any]] = []
    completed = 0
    with ThreadPoolExecutor(max_workers=int(scan["workers"])) as executor:
        futures = {executor.submit(probe_candidate, ip, 4, config): ip for ip in preliminary}
        for future in as_completed(futures):
            completed += 1
            try:
                item, reasons = future.result()
                if item is not None:
                    results.append(item)
                for reason, count in reasons.items():
                    failure_reasons[reason] = failure_reasons.get(reason, 0) + count
            except Exception as exc:
                reason = f"stability_worker_{type(exc).__name__}"
                failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
                print(f"IPv4 stability error {futures[future]}: {type(exc).__name__}: {exc}")
            if completed % 100 == 0 or completed == len(futures):
                print(f"IPv4 stability progress: {completed}/{len(futures)}; usable={len(results)}")

    print(f"IPv4 failure reasons: {json.dumps(failure_reasons, ensure_ascii=False, sort_keys=True)}")
    run_speed_tests(results, 4, config)
    enrich_country_info(results)
    ranked = sort_and_score(results)
    top_n = [int(value) for value in scan["top_n"]]
    write_family_outputs(4, ranked, top_n)

    return {
        "family": "ipv4",
        "status": "ok" if ranked else "no_usable_ip",
        "egress_check": egress,
        "network_count": len(networks),
        "candidate_count": len(candidates),
        "preliminary_pass_count": len(preliminary),
        "tcp_tls_http_pass_count": len(preliminary),
        "usable_count": len(results),
        "speed_tested_count": sum(1 for item in results if item["speed_tested"]),
        "ranked_count": len(ranked),
        "top_ip": ranked[0]["ip"] if ranked else None,
        "failure_reasons": failure_reasons,
        "output_dir": "output/ipv4/",
        "subscription_format": "IPv4:443",
    }


def main() -> None:
    config = load_config()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {
        "project": "Cloudflare-IP-Auto",
        "version": "3.2",
        "generated_at": utc_now(),
        "schedule": "17 */6 * * * (UTC)",
        "ip_family": "IPv4 only",
        "ports": [443],
        "families": {},
    }
    try:
        summary["families"]["ipv4"] = run_ipv4(config)
    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"
        print(f"IPv4 scan failed: {message}")
        summary["families"]["ipv4"] = {"family": "ipv4", "status": "scan_failed", "error": message}
        write_json(OUTPUT / "summary.json", summary)
        raise

    write_json(OUTPUT / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()