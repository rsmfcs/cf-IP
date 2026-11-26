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


COUNTRY_API_URL = "http://ip-api.com/batch?fields=status,countryCode,country,city,query"
HOSTMONIT_API_URL = "https://api.hostmonit.com/get_optimization_ip"
HOSTMONIT_API_KEY = "o1zrmHAF"


def country_flag(country_code: str | None) -> str:
    """Convert an ISO 3166-1 alpha-2 code to its flag emoji."""
    code = (country_code or "").strip().upper()
    if len(code) != 2 or not code.isalpha() or not code.isascii():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code)



COUNTRY_NAMES_ZH = {
    "US": "美国", "CA": "加拿大", "MX": "墨西哥", "BR": "巴西", "AR": "阿根廷",
    "CL": "智利", "CO": "哥伦比亚", "PE": "秘鲁", "GB": "英国", "IE": "爱尔兰",
    "FR": "法国", "DE": "德国", "NL": "荷兰", "BE": "比利时", "LU": "卢森堡",
    "CH": "瑞士", "AT": "奥地利", "ES": "西班牙", "PT": "葡萄牙", "IT": "意大利",
    "SE": "瑞典", "NO": "挪威", "DK": "丹麦", "FI": "芬兰", "IS": "冰岛",
    "PL": "波兰", "CZ": "捷克", "SK": "斯洛伐克", "HU": "匈牙利", "RO": "罗马尼亚",
    "BG": "保加利亚", "GR": "希腊", "UA": "乌克兰", "RU": "俄罗斯", "TR": "土耳其",
    "IL": "以色列", "AE": "阿联酋", "SA": "沙特阿拉伯", "QA": "卡塔尔", "BH": "巴林",
    "IN": "印度", "PK": "巴基斯坦", "BD": "孟加拉国", "LK": "斯里兰卡", "NP": "尼泊尔",
    "CN": "中国", "HK": "中国香港", "MO": "中国澳门", "TW": "中国台湾", "JP": "日本",
    "KR": "韩国", "SG": "新加坡", "MY": "马来西亚", "TH": "泰国", "VN": "越南",
    "ID": "印度尼西亚", "PH": "菲律宾", "KH": "柬埔寨", "AU": "澳大利亚", "NZ": "新西兰",
    "ZA": "南非", "EG": "埃及", "NG": "尼日利亚", "KE": "肯尼亚", "MA": "摩洛哥",
    "GH": "加纳", "ET": "埃塞俄比亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "GE": "格鲁吉亚", "AM": "亚美尼亚", "AZ": "阿塞拜疆", "CY": "塞浦路斯",
    "HR": "克罗地亚", "SI": "斯洛文尼亚", "RS": "塞尔维亚", "LT": "立陶宛",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "MT": "马耳他", "AL": "阿尔巴尼亚",
    "MK": "北马其顿", "ME": "黑山", "BA": "波斯尼亚和黑塞哥维那",
}
CITY_NAMES_ZH = {
    "Los Angeles": "洛杉矶", "San Francisco": "旧金山", "San Jose": "圣何塞",
    "Seattle": "西雅图", "New York": "纽约", "Chicago": "芝加哥",
    "Dallas": "达拉斯", "Miami": "迈阿密", "Washington": "华盛顿",
    "Ashburn": "阿什本", "Atlanta": "亚特兰大", "Boston": "波士顿",
    "London": "伦敦", "Manchester": "曼彻斯特", "Frankfurt": "法兰克福",
    "Berlin": "柏林", "Paris": "巴黎", "Amsterdam": "阿姆斯特丹",
    "Tokyo": "东京", "Osaka": "大阪", "Singapore": "新加坡",
    "Hong Kong": "香港", "Taipei": "台北", "Seoul": "首尔",
    "Sydney": "悉尼", "Melbourne": "墨尔本", "Toronto": "多伦多",
    "Vancouver": "温哥华", "Montreal": "蒙特利尔", "Mumbai": "孟买",
    "Delhi": "新德里", "Bangalore": "班加罗尔", "Dubai": "迪拜",
    "Sao Paulo": "圣保罗", "Mexico City": "墨西哥城",
}


def region_label(item: dict[str, Any]) -> str:
    """Build a concise Chinese GeoIP label, with city when available."""
    code = str(item.get("country_code") or "").upper()
    country = COUNTRY_NAMES_ZH.get(code, "未知地区")
    city = str(item.get("city") or "").strip()
    city_zh = CITY_NAMES_ZH.get(city, "")
    return f"{country}-{city_zh}" if city_zh else country


def enrich_country_info(results: list[dict[str, Any]]) -> None:
    """Add approximate country codes in batches; never fail a scan on GeoIP errors."""
    if not results:
        return
    ip_to_country: dict[str, dict[str, str]] = {}
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
                        ip_to_country[str(entry.get("query", ""))] = {
                            "country_code": str(entry.get("countryCode", "")).upper(),
                            "city": str(entry.get("city", "") or "").strip(),
                        }
        except Exception as exc:
            print(f"GeoIP lookup batch {offset // 100 + 1} failed: {type(exc).__name__}: {exc}")

    for item in results:
        geo = ip_to_country.get(str(item["ip"]), {})
        item["country_code"] = geo.get("country_code", "") or "ZZ"
        item["city"] = geo.get("city", "")
        item["region_zh"] = region_label(item)
        

def select_region_candidates(
    candidates: list[dict[str, Any]],
    region_targets: dict[str, int],
    multiplier: int = 3,
    fallback_count: int = 60,
) -> list[dict[str, Any]]:
    """Keep an expanded sample for each target GeoIP region plus non-target fallbacks."""
    selected: list[dict[str, Any]] = []
    preferred = {str(code).upper(): max(0, int(count)) for code, count in region_targets.items()}
    for code, target in preferred.items():
        region_items = [item for item in candidates if str(item.get("country_code") or "ZZ").upper() == code]
        selected.extend(region_items[: target * max(1, int(multiplier))])
    fallback = [
        item for item in candidates
        if str(item.get("country_code") or "ZZ").upper() not in preferred
    ]
    selected.extend(fallback[:max(0, int(fallback_count))])
    selected_ips = {str(item["ip"]) for item in selected}
    return [item for item in candidates if str(item["ip"]) in selected_ips]


def parse_colo_code(body: str) -> str | None:
    """Extract the Cloudflare colo code from /cdn-cgi/trace output."""
    for line in body.splitlines():
        if line.startswith("colo="):
            code = line.split("=", 1)[1].strip().upper()
            if len(code) == 3 and code.isascii() and code.isalpha():
                return code
    return None


def fetch_colo_code(ip: str, port: int, timeout: float, user_agent: str) -> str | None:
    """Query Cloudflare trace through a pinned IP and return its observed colo."""
    sock = make_socket(ip, port, 4, timeout)
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
        if not 200 <= response.status < 400:
            return None
        body = response.read(65536).decode("utf-8", errors="replace")
        return parse_colo_code(body)
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


def enrich_colo_info(results: list[dict[str, Any]], config: dict[str, Any]) -> None:
    """Attach the observed Cloudflare colo code without failing the scan."""
    if not results:
        return
    scan = config["scan"]
    timeout = float(scan["timeout_seconds"])
    workers = int(scan["workers"])
    user_agent = str(scan.get("user_agent", "Cloudflare-IP-Auto/3.2"))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(fetch_colo_code, str(item["ip"]), int(item.get("port", 443)), timeout, user_agent): item
            for item in results
        }
        for future in as_completed(futures):
            item = futures[future]
            try:
                item["colo"] = future.result() or ""
            except Exception as exc:
                item["colo"] = ""
                print(f"Cloudflare colo lookup failed for {item['ip']}: {type(exc).__name__}: {exc}")


def subscription_line(item: dict[str, Any]) -> str:
    region = str(item.get("region_zh") or region_label(item))
    address = str(item["ip"])
    endpoint = f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
    return f"{endpoint}:{int(item.get('port', 443))}#{region}"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fetch_text(url: str, timeout: float = 20.0) -> str:
    request = Request(url, headers={"User-Agent": "Cloudflare-IP-Auto/3.1"})
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")


def fetch_hostmonit_ipv6(timeout: float = 25.0) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch HostMonit IPv6 candidates; this does not require IPv6 network egress."""
    request = Request(
        HOSTMONIT_API_URL,
        data=json.dumps({"key": HOSTMONIT_API_KEY, "type": "v6"}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Cloudflare-IP-Auto/3.6",
        },
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))

    if not isinstance(payload, dict) or payload.get("code") != 200:
        raise ValueError(f"HostMonit returned an unexpected response: {str(payload)[:300]}")

    info = payload.get("info")
    if not isinstance(info, dict):
        raise ValueError("HostMonit response is missing the info object")

    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    source_counts: dict[str, int] = {}
    for carrier, entries in info.items():
        if not isinstance(entries, list):
            continue
        accepted = 0
        for entry in entries:
            raw_ip = entry.get("ip") if isinstance(entry, dict) else entry
            if not isinstance(raw_ip, str):
                continue
            try:
                address = ipaddress.ip_address(raw_ip.strip())
            except ValueError:
                continue
            if address.version != 6 or not address.is_global:
                continue
            normalized = address.compressed
            if normalized in seen:
                continue
            seen.add(normalized)
            candidates.append({
                "ip": normalized,
                "version": 6,
                "port": 443,
                "source": str(carrier),
                "country_code": "ZZ",
                "city": "",
                "region_zh": "未知地区",
                "quality_status": "source_candidate_unverified",
            })
            accepted += 1
        source_counts[str(carrier)] = accepted

    metadata = {
        "source": "HostMonit",
        "api": HOSTMONIT_API_URL,
        "fetched_at": utc_now(),
        "source_counts": source_counts,
        "candidate_count": len(candidates),
        "quality_status": "source_candidate_unverified",
        "note": "Collected and validated from HostMonit; not connectivity-tested by this GitHub Actions runner.",
    }
    return candidates, metadata


def write_ipv6_source_outputs(
    candidates: list[dict[str, Any]], metadata: dict[str, Any]
) -> None:
    """Publish HostMonit IPv6 candidates separately; preserve prior files on empty data."""
    if not candidates:
        print("IPv6: no valid HostMonit candidates; preserving previous IPv6 subscriptions")
        return

    output_dir = OUTPUT / "ipv6"
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "source.json", {"metadata": metadata, "items": candidates})
    write_json(output_dir / "all.json", candidates)
    lines = [subscription_line(item) for item in candidates]
    payload = "\n".join(lines) + "\n"
    (output_dir / "source.txt").write_text(payload, encoding="utf-8")
    (output_dir / "all.txt").write_text(payload, encoding="utf-8")
    (ROOT / "ipv6.txt").write_text(payload, encoding="utf-8")


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

    # The measured IPv4 pipeline remains TCP 443 only. IPv6 is source-sync only.
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
    targets = scan.get("region_target_counts", {"HK": 15, "US": 15, "SG": 10, "JP": 10})
    if not isinstance(targets, dict) or not targets:
        raise ValueError("config.scan.region_target_counts must be a non-empty mapping")
    if any(int(value) < 0 for value in targets.values()):
        raise ValueError("region target counts must not be negative")
    if int(scan.get("region_candidate_multiplier", 3)) <= 0:
        raise ValueError("region_candidate_multiplier must be greater than zero")
    if int(scan.get("region_fallback_candidates", 60)) < 0:
        raise ValueError("region_fallback_candidates must not be negative")


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


def sort_and_score(
    results: list[dict[str, Any]],
    preferred_country_codes: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Rank preferred GeoIP regions first, then rank by measured quality."""
    preferred = {
        str(code).strip().upper()
        for code in (preferred_country_codes or ["HK", "US", "SG", "JP"])
    }
    for item in results:
        item["score"] = final_score(item)
        item["region_priority"] = 0 if str(item.get("country_code") or "").upper() in preferred else 1
    return sorted(
        results,
        key=lambda item: (
            item["region_priority"],
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
        "ip", "version", "port", "country_code", "city", "region_zh", "colo",
        "latency_ms", "median_latency_ms", "jitter_ms", "p95_latency_ms",
        "speed_mbps", "speed_tested", "success_rate", "successful_rounds",
        "total_rounds", "score", "tested_at",
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
        "project": "Cloudflare-IP-Auto", "version": "3.5", "generated_at": utc_now(),
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

    # GeoIP is a practical region label, not proof of the actual edge location.
    geo_candidates = [{"ip": ip} for ip in preliminary]
    enrich_country_info(geo_candidates)
    region_targets = {
        str(code).upper(): int(count)
        for code, count in scan.get(
            "region_target_counts", {"HK": 15, "US": 15, "SG": 10, "JP": 10}
        ).items()
    }
    selected_geo = select_region_candidates(
        geo_candidates,
        region_targets,
        int(scan.get("region_candidate_multiplier", 3)),
        int(scan.get("region_fallback_candidates", 60)),
    )
    geo_by_ip = {str(item["ip"]): item for item in geo_candidates}
    selected_ips = [str(item["ip"]) for item in selected_geo]
    print(
        "IPv4 region candidate selection: "
        + json.dumps(
            {code: sum(1 for item in selected_geo if item.get("country_code") == code)
             for code in region_targets},
            ensure_ascii=False,
        )
        + f"; fallback={sum(1 for item in selected_geo if item.get('country_code') not in region_targets)}"
    )

    # Stage 4: repeat the complete TLS + HTTP probe for region-selected candidates.
    print(f"IPv4: stability retest for {len(selected_ips)} region-selected candidates")
    results: list[dict[str, Any]] = []
    completed = 0
    with ThreadPoolExecutor(max_workers=int(scan["workers"])) as executor:
        futures = {executor.submit(probe_candidate, ip, 4, config): ip for ip in selected_ips}
        for future in as_completed(futures):
            completed += 1
            try:
                item, reasons = future.result()
                if item is not None:
                    geo = geo_by_ip.get(str(item["ip"]), {})
                    item["country_code"] = geo.get("country_code", "ZZ")
                    item["city"] = geo.get("city", "")
                    item["region_zh"] = geo.get("region_zh", "未知地区")
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
    enrich_colo_info(results, config)
    ranked = sort_and_score(results, scan.get("preferred_country_codes", ["HK", "US", "SG", "JP"]))
    region_counts: dict[str, int] = {}
    colo_counts: dict[str, int] = {}
    for item in ranked:
        code = str(item.get("country_code") or "ZZ")
        region_counts[code] = region_counts.get(code, 0) + 1
        colo = str(item.get("colo") or "")
        if colo:
            colo_counts[colo] = colo_counts.get(colo, 0) + 1
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
        "region_targets": region_targets,
        "region_counts": region_counts,
        "colo_counts": colo_counts,
        "geoip_note": "GeoIP is approximate; colo is observed from Cloudflare /cdn-cgi/trace.",
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
        "version": "3.6",
        "generated_at": utc_now(),
        "schedule": "17 */6 * * * (UTC)",
        "ip_family": "IPv4 scan + IPv6 source sync",
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

    try:
        ipv6_candidates, ipv6_metadata = fetch_hostmonit_ipv6()
        if ipv6_candidates:
            enrich_country_info(ipv6_candidates)
            write_ipv6_source_outputs(ipv6_candidates, ipv6_metadata)
            summary["families"]["ipv6"] = {
                "family": "ipv6",
                "status": "source_synced_unverified",
                "source": "HostMonit",
                "candidate_count": len(ipv6_candidates),
                "source_counts": ipv6_metadata["source_counts"],
                "output_dir": "output/ipv6/",
                "subscription_file": "ipv6.txt",
                "subscription_format": "[IPv6]:443",
                "quality_note": ipv6_metadata["note"],
            }
        else:
            summary["families"]["ipv6"] = {
                "family": "ipv6",
                "status": "no_valid_source_data",
                "source": "HostMonit",
                "candidate_count": 0,
                "note": "Previous IPv6 subscription files were preserved.",
            }
    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"
        print(f"IPv6 HostMonit sync failed: {message}")
        summary["families"]["ipv6"] = {
            "family": "ipv6",
            "status": "source_sync_failed",
            "source": "HostMonit",
            "error": message,
            "note": "IPv4 scan is independent; previous IPv6 subscription files were preserved.",
        }

    write_json(OUTPUT / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()