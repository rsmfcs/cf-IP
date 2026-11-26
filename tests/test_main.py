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

def test_empty_scan_preserves_previous_subscriptions(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "ROOT", tmp_path)
    monkeypatch.setattr(main, "OUTPUT", tmp_path / "output")
    (tmp_path / "output" / "ipv4").mkdir(parents=True)
    (tmp_path / "best-cf-ip-scanned-top20.txt").write_text("1.1.1.1:443#美国\n", encoding="utf-8")
    (tmp_path / "output" / "ipv4" / "all.json").write_text('[{"ip": "1.1.1.1"}]', encoding="utf-8")

    main.write_family_outputs(4, [], [20])

    assert (tmp_path / "best-cf-ip-scanned-top20.txt").read_text(encoding="utf-8") == "1.1.1.1:443#美国\n"
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
