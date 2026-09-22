import pytest
from backend.app.detectors.url_features import url_extractor
from backend.app.detectors.heuristics import heuristic_engine

def test_punycode_heuristic_trigger():
    url = "https://xn--pple-43d.com/support"
    ext = url_extractor.extract_features(url)
    indicators = heuristic_engine.evaluate(ext["features"], ext["metadata"])
    
    rule_ids = [ind.rule_id for ind in indicators]
    assert "RUL-HOST-002" in rule_ids
    assert any(ind.severity == "CRITICAL" for ind in indicators)

def test_brand_spoofing_heuristic_trigger():
    url = "https://chase.com.billing-update.attacker.net/login"
    ext = url_extractor.extract_features(url)
    indicators = heuristic_engine.evaluate(ext["features"], ext["metadata"])

    rule_ids = [ind.rule_id for ind in indicators]
    assert "RUL-BRAND-004" in rule_ids
    assert any(ind.mitre_attack_id == "T1036.007" for ind in indicators)

def test_ip_address_heuristic_trigger():
    url = "http://45.33.32.156/verify"
    ext = url_extractor.extract_features(url)
    indicators = heuristic_engine.evaluate(ext["features"], ext["metadata"])

    rule_ids = [ind.rule_id for ind in indicators]
    assert "RUL-HOST-001" in rule_ids

def test_benign_url_no_critical_heuristics():
    url = "https://google.com/search?q=cybersecurity"
    ext = url_extractor.extract_features(url)
    indicators = heuristic_engine.evaluate(ext["features"], ext["metadata"])

    assert not any(ind.severity == "CRITICAL" for ind in indicators)
