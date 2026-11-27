from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import main


def test_country_flag():
    assert main.country_flag("US") == "🇺🇸"
    assert main.country_flag("JP") == "🇯🇵"
    assert main.country_flag(None) == "🌐"


def test_subscription_line_has_chinese_country_and_city():
    item = {"ip": "198.41.199.134", "port": 443, "country_code": "US", "city": "Los Angeles"}
    assert main.subscription_line(item) == "198.41.199.134:443#美国-洛杉矶"


def test_subscription_line_falls_back_to_chinese_country_only():
    item = {"ip": "198.41.199.134", "port": 443, "country_code": "JP", "city": ""}
    assert main.subscription_line(item) == "198.41.199.134:443#日本"


def test_preferred_regions_rank_before_other_regions():
    base = {
        "port": 443, "latency_ms": 50.0, "jitter_ms": 5.0,
        "success_rate": 1.0, "speed_mbps": 100.0,
    }
    results = [
        {**base, "ip": "192.0.2.1", "country_code": "CA"},
        {**base, "ip": "192.0.2.2", "country_code": "JP"},
        {**base, "ip": "192.0.2.3", "country_code": "HK"},
        {**base, "ip": "192.0.2.4", "country_code": "US"},
        {**base, "ip": "192.0.2.5", "country_code": "SG"},
    ]

    ranked = main.sort_and_score(results, ["HK", "US", "SG", "JP"])

    assert [item["country_code"] for item in ranked] == ["JP", "HK", "US", "SG", "CA"]

def test_select_region_candidates_applies_region_quotas_and_fallback():
    candidates = []
    next_ip = 1
    for code, count in (("HK", 10), ("US", 10), ("SG", 6), ("JP", 6), ("CA", 20)):
        for _ in range(count):
            candidates.append({"ip": f"198.51.0.{next_ip}", "country_code": code})
            next_ip += 1

    selected = main.select_region_candidates(
        candidates,
        {"HK": 2, "US": 2, "SG": 1, "JP": 1},
        multiplier=2,
        fallback_count=3,
    )
    counts = {}
    for item in selected:
        counts[item["country_code"]] = counts.get(item["country_code"], 0) + 1

    assert counts == {"HK": 4, "US": 4, "SG": 2, "JP": 2, "CA": 3}


def test_parse_colo_code_from_cloudflare_trace():
    assert main.parse_colo_code("fl=abc\nh=www.cloudflare.com\ncolo=HKG\n") == "HKG"
    assert main.parse_colo_code("fl=abc\ncolo=\n") is None
    assert main.parse_colo_code("colo=HongKong\n") is None


def test_empty_scan_clears_previous_subscriptions(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "ROOT", tmp_path)
    monkeypatch.setattr(main, "OUTPUT", tmp_path / "output")
    (tmp_path / "output" / "ipv4").mkdir(parents=True)
    (tmp_path / "best-cf-ip-scanned-top20.txt").write_text("1.1.1.1:443#美国\n", encoding="utf-8")
    (tmp_path / "output" / "ipv4" / "all.json").write_text('[{"ip": "1.1.1.1"}]', encoding="utf-8")

    main.write_family_outputs(4, [], [20])

    assert (tmp_path / "best-cf-ip-scanned-top20.txt").read_text(encoding="utf-8") == ""
    assert (tmp_path / "output" / "ipv4" / "all.json").read_text(encoding="utf-8") == '[{"ip": "1.1.1.1"}]'



def test_probe_stages_filter_candidates_in_order(monkeypatch):
    calls = []

    def tcp(ip, port, timeout, version=4):
        calls.append(("tcp", ip))
        return ip != "198.51.100.3"

    def tls(ip, port, timeout, version=4):
        calls.append(("tls", ip))
        return ip != "198.51.100.2"

    def http(ip, port, timeout, version, user_agent):
        calls.append(("http", ip))
        return ip == "198.51.100.1"

    monkeypatch.setattr(main, "tcp_connect_probe", tcp)
    monkeypatch.setattr(main, "tls_handshake_probe", tls)
    monkeypatch.setattr(main, "http_response_probe", http)
    config = {"scan": {"timeout_seconds": 1, "workers": 2, "user_agent": "test"}}

    survivors = main.run_probe_stages(
        ["198.51.100.1", "198.51.100.2", "198.51.100.3"], config
    )

    assert survivors == ["198.51.100.1"]
    assert ("tls", "198.51.100.3") not in calls
    assert ("http", "198.51.100.2") not in calls
    assert ("http", "198.51.100.1") in calls


def test_ipv6_subscription_line_uses_brackets():
    item = {"ip": "2606:4700:4700::1111", "port": 443, "country_code": "US", "city": "Los Angeles"}
    assert main.subscription_line(item) == "[2606:4700:4700::1111]:443#美国-洛杉矶"


def test_hostmonit_ipv6_parser_validates_deduplicates_and_filters(monkeypatch):
    payload = {
        "code": 200,
        "info": {
            "CM": [
                {"ip": "2400:cb00::1"},
                {"ip": "2400:cb00::1"},
                {"ip": "not-an-ip"},
                {"ip": "192.0.2.1"},
                {"ip": "fe80::1"},
            ],
            "CU": [{"ip": "2606:4700:4700::1111"}],
        },
    }

    class FakeResponse:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self):
            import json
            return json.dumps(payload).encode("utf-8")

    def fake_urlopen(request, timeout):
        assert request.full_url == main.HOSTMONIT_API_URL
        assert request.get_method() == "POST"
        return FakeResponse()

    monkeypatch.setattr(main, "urlopen", fake_urlopen)
    items, metadata = main.fetch_hostmonit_ipv6()

    assert [item["ip"] for item in items] == ["2400:cb00::1", "2606:4700:4700::1111"]
    assert metadata["candidate_count"] == 2
    assert items[0]["source"] == "CM"
    assert items[0]["quality_status"] == "source_candidate_unverified"


def test_ipv6_source_output_preserves_previous_files_when_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "ROOT", tmp_path)
    monkeypatch.setattr(main, "OUTPUT", tmp_path / "output")
    (tmp_path / "output" / "ipv6").mkdir(parents=True)
    previous = "[2606:4700:4700::1111]:443#美国\n"
    (tmp_path / "ipv6.txt").write_text(previous, encoding="utf-8")

    main.write_ipv6_source_outputs([], {"candidate_count": 0})

    assert (tmp_path / "ipv6.txt").read_text(encoding="utf-8") == previous


def test_ipv6_source_outputs_merge_into_root_all_subscription(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "ROOT", tmp_path)
    monkeypatch.setattr(main, "OUTPUT", tmp_path / "output")
    (tmp_path / "output" / "ipv4").mkdir(parents=True)
    (tmp_path / "all.txt").write_text(
        "1.1.1.1:443#美国\n[2606:4700::old]:443#旧IPv6\n",
        encoding="utf-8",
    )
    candidates = [
        {
            "ip": "2606:4700:4700::1111",
            "port": 443,
            "region_zh": "美国",
            "country_code": "US",
        }
    ]

    main.write_ipv6_source_outputs(candidates, {"candidate_count": 1})

    combined = (tmp_path / "all.txt").read_text(encoding="utf-8").splitlines()
    assert combined == [
        "1.1.1.1:443#美国",
        "[2606:4700:4700::1111]:443#美国",
    ]

    # Every existing client-facing IPv4 subscription list receives the IPv6
    # source candidate, while keeping its original IPv4 entries.
    for name in (
        "fast.txt", "stable.txt",
        "best-cf-ip-scanned-top20.txt", "best-cf-ip-scanned-top50.txt",
        "best-cf-ip-scanned-top100.txt", "best-cf-ip-scanned-top200.txt",
        "best-cf-ip-scanned-top400.txt",
        "cf-ipv4-top20.txt", "cf-ipv4-top50.txt",
        "cf-ipv4-top100.txt", "cf-ipv4-top200.txt", "cf-ipv4-top400.txt",
    ):
        path = tmp_path / name
        path.write_text("2.2.2.2:443#美国\n", encoding="utf-8")

    family_dir = tmp_path / "output" / "ipv4"
    family_dir.mkdir(parents=True, exist_ok=True)
    (family_dir / "all.txt").write_text("3.3.3.3:443#美国\n", encoding="utf-8")
    (family_dir / "fast.txt").write_text("3.3.3.3:443#美国\n", encoding="utf-8")
    (family_dir / "stable.txt").write_text("3.3.3.3:443#美国\n", encoding="utf-8")

    main.write_ipv6_source_outputs(candidates, {"candidate_count": 1})

    for name in (
        "all.txt", "fast.txt", "stable.txt",
        "best-cf-ip-scanned-top20.txt", "cf-ipv4-top400.txt",
    ):
        lines = (tmp_path / name).read_text(encoding="utf-8").splitlines()
        assert "[2606:4700:4700::1111]:443#美国" in lines
    for name in ("all.txt", "fast.txt", "stable.txt"):
        lines = (family_dir / name).read_text(encoding="utf-8").splitlines()
        assert "[2606:4700:4700::1111]:443#美国" in lines
