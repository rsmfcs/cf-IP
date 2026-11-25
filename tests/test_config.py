from pathlib import Path
import yaml

def test_config_is_ipv4_443_only():
    root = Path(__file__).resolve().parents[1]
    config = yaml.safe_load((root / "config/config.yaml").read_text(encoding="utf-8"))
    scan = config["scan"]
    assert scan["ports"] == [443]
    assert scan["max_candidates_per_family"] == 1024
    assert scan["preliminary_rounds"] == 1
    assert scan["rounds"] == 3
    assert scan["workers"] == 40
