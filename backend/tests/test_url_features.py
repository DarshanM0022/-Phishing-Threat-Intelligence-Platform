import pytest
from backend.app.detectors.url_features import url_extractor, calculate_shannon_entropy

def test_benign_url_features():
    url = "https://www.github.com/torvalds/linux"
    res = url_extractor.extract_features(url)
    features = res["features"]
    meta = res["metadata"]

    assert features["is_https"] == 1
    assert features["has_ip_hostname"] == 0
    assert features["uses_punycode"] == 0
    assert features["has_at_symbol"] == 0
    assert features["subdomain_count"] == 1  # 'www'
    assert meta["registered_domain"] == "github.com"
    assert features["url_length"] > 10

def test_ip_address_url():
    url = "http://192.168.1.1/admin/login.php"
    res = url_extractor.extract_features(url)
    features = res["features"]

    assert features["has_ip_hostname"] == 1
    assert features["is_https"] == 0
    assert features["has_login_keyword"] == 1

def test_punycode_homograph_detection():
    url = "https://xn--pypal-4ve.com/signin"
    res = url_extractor.extract_features(url)
    features = res["features"]

    assert features["uses_punycode"] == 1
    assert features["has_login_keyword"] == 1

def test_brand_in_subdomain():
    url = "https://paypal.com.verify-account.attacker.xyz/login"
    res = url_extractor.extract_features(url)
    features = res["features"]

    assert features["has_brand_in_subdomain"] == 1
    assert features["suspicious_tld"] == 1
    assert features["subdomain_count"] >= 2
    assert features["has_login_keyword"] == 1
    assert features["has_verify_keyword"] == 1

def test_basic_auth_smuggling():
    url = "https://legitimate-bank.com@attacker-site.com/auth"
    res = url_extractor.extract_features(url)
    features = res["features"]

    assert features["has_at_symbol"] == 1

def test_entropy_calculation():
    low_entropy = calculate_shannon_entropy("aaaaaaa")
    high_entropy = calculate_shannon_entropy("x8q1b9zp20amc")
    assert low_entropy < high_entropy
    assert low_entropy == 0.0
