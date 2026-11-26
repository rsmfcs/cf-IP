from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import main


def test_country_flag():
    assert main.country_flag("US") == "🇺🇸"
    assert main.country_flag("JP") == "🇯🇵"
    assert main.country_flag(None) == "🌐"


def test_subscription_line_has_region():
    item = {"ip": "198.41.199.134", "port": 443, "country_code": "US", "country_flag": "🇺🇸"}
    assert main.subscription_line(item) == "198.41.199.134:443#US 🇺🇸"


def test_empty_scan_preserves_previous_subscriptions(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "ROOT", tmp_path)
    monkeypatch.setattr(main, "OUTPUT", tmp_path / "output")
    (tmp_path / "output" / "ipv4").mkdir(parents=True)
    (tmp_path / "best-cf-ip-scanned-top20.txt").write_text("1.1.1.1:443#US 🇺🇸\n", encoding="utf-8")
    (tmp_path / "output" / "ipv4" / "all.json").write_text('[{"ip": "1.1.1.1"}]', encoding="utf-8")

    main.write_family_outputs(4, [], [20])

    assert (tmp_path / "best-cf-ip-scanned-top20.txt").read_text(encoding="utf-8") == "1.1.1.1:443#US 🇺🇸\n"
    assert (tmp_path / "output" / "ipv4" / "all.json").read_text(encoding="utf-8") == '[{"ip": "1.1.1.1"}]'
