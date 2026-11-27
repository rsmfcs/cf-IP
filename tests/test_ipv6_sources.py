import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import ipv6_sources


def test_parse_wetest_ipv6_maps_carrier_and_deduplicates():
    html = """
    <table>
      <tr><td>移动</td><td>2606:4700:9a92::4b74:61ef</td><td>5 MB</td></tr>
      <tr><td>联通</td><td>2a06:98c1:3101::fc07:ce85</td><td>5 MB</td></tr>
      <tr><td>电信</td><td>2606:4700:440f::6e2c:c20e</td><td>5 MB</td></tr>
      <tr><td>移动</td><td>2606:4700:9a92::4b74:61ef</td><td>5 MB</td></tr>
    </table>
    """
    items = ipv6_sources.parse_wetest_ipv6(html)
    assert items == [
        {"ip": "2606:4700:9a92::4b74:61ef", "source": "WeTest", "source_carrier": "CM"},
        {"ip": "2a06:98c1:3101::fc07:ce85", "source": "WeTest", "source_carrier": "CU"},
        {"ip": "2606:4700:440f::6e2c:c20e", "source": "WeTest", "source_carrier": "CT"},
    ]


def test_parse_plain_ipv6_rejects_non_global_and_ipv4():
    items = ipv6_sources.parse_plain_ipv6(
        "2606:4700:4700::1111\nfe80::1\n192.0.2.1\n2606:4700:4700::1111",
        source="CMLiu",
        carrier="CM",
    )
    assert items == [
        {"ip": "2606:4700:4700::1111", "source": "CMLiu", "source_carrier": "CM"}
    ]


def test_collect_ipv6_candidates_enforces_official_cloudflare_ranges(monkeypatch):
    def fake_fetch(url):
        if url == ipv6_sources.WETEST_IPV6_URL:
            return """
            <table>
              <tr><td>移动</td><td>2606:4700:9a92::4b74:61ef</td></tr>
              <tr><td>电信</td><td>2001:db8::1</td></tr>
            </table>
            """
        if url == ipv6_sources.CMLIU_MOBILE_IPV6_URL:
            return "2606:4700:4700::1111\n2001:db8::2"
        if url == ipv6_sources.CLOUDFLARE_IPV6_RANGES_URL:
            return "2606:4700::/32\n2a06:98c0::/29"
        raise AssertionError(url)

    monkeypatch.setattr(ipv6_sources, "_fetch_text", fake_fetch)
    candidates, metadata = ipv6_sources.collect_ipv6_candidates([
        {"ip": "2606:4700:4700::1111", "source": "CM"},
        {"ip": "2001:db8::3", "source": "CT"},
    ])

    assert {item["ip"] for item in candidates} == {
        "2606:4700:9a92::4b74:61ef",
        "2606:4700:4700::1111",
    }
    merged = next(item for item in candidates if item["ip"] == "2606:4700:4700::1111")
    assert set(merged["source"]) == {"HostMonit", "CMLiu"}
    assert metadata["candidate_count"] == 2
