import sys
from pathlib import Path

# Ensure the repository root is importable when pytest uses importlib mode.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.china_probe import _parse_probe_result


def test_parse_probe_result_accepts_cloudflare_trace():
    item = {
        "probe": {"asn": 4134, "network": "China Telecom"},
        "result": {
            "status": "finished",
            "statusCode": 200,
            "rawBody": "fl=abc\nh=www.cloudflare.com\ncolo=HKG\n",
            "timings": {"tcp": 82.3, "total": 119.7},
        },
    }
    parsed = _parse_probe_result(item)
    assert parsed is not None
    assert parsed["isp"] == "CT"
    assert parsed["ok"] is True
    assert parsed["rtt_ms"] == 82.3
    assert parsed["colo"] == "HKG"


def test_parse_probe_result_rejects_non_trace_response():
    item = {
        "probe": {"asn": 4837},
        "result": {
            "status": "finished",
            "statusCode": 200,
            "rawBody": "<html>not Cloudflare trace</html>",
            "timings": {"tcp": 50},
        },
    }
    parsed = _parse_probe_result(item)
    assert parsed is not None
    assert parsed["isp"] == "CU"
    assert parsed["ok"] is False
    assert parsed["rtt_ms"] is None


def test_parse_probe_result_maps_mobile_asn():
    item = {
        "probe": {"asn": 9808},
        "result": {
            "status": "finished",
            "statusCode": 200,
            "rawBody": "fl=abc\ncolo=LAX\n",
            "timings": {"tcp": 130},
        },
    }
    parsed = _parse_probe_result(item)
    assert parsed["isp"] == "CM"
    assert parsed["ok"] is True


def test_carrier_status_requires_two_successful_probes_and_latency_gate():
    from src.china_probe import _carrier_status

    one_probe = [{"probe_key": "cn|east|city-a|as4134", "ok": True, "rtt_ms": 80}]
    assert _carrier_status(one_probe)["qualified"] is False

    two_fast_probes = [
        {"probe_key": "cn|east|city-a|as4134", "ok": True, "rtt_ms": 180},
        {"probe_key": "cn|south|city-b|as4134", "ok": True, "rtt_ms": 240},
    ]
    status = _carrier_status(two_fast_probes)
    assert status["qualified"] is True
    assert status["rtt_ms"] == 210.0

    two_slow_probes = [
        {"probe_key": "cn|east|city-a|as4134", "ok": True, "rtt_ms": 180},
        {"probe_key": "cn|south|city-b|as4134", "ok": True, "rtt_ms": 520},
    ]
    assert _carrier_status(two_slow_probes)["qualified"] is False


def test_carrier_status_deduplicates_same_probe_location():
    from src.china_probe import _carrier_status

    repeated = [
        {"probe_key": "cn|east|city-a|as4134", "ok": True, "rtt_ms": 100, "at": "2026-11-27T00:00:00+00:00"},
        {"probe_key": "cn|east|city-a|as4134", "ok": True, "rtt_ms": 110, "at": "2026-11-27T01:00:00+00:00"},
    ]
    assert _carrier_status(repeated)["qualified"] is False
