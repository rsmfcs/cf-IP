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
