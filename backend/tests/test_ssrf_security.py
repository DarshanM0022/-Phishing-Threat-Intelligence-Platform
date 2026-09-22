import pytest
from backend.app.core.security import is_ip_address, is_private_or_restricted_ip, safe_resolve_hostname

def test_ip_format_validator():
    assert is_ip_address("127.0.0.1")
    assert is_ip_address("192.168.1.1")
    assert is_ip_address("10.0.0.5")
    assert is_ip_address("8.8.8.8")
    assert is_ip_address("::1")
    assert not is_ip_address("google.com")
    assert not is_ip_address("paypal.com.attacker.com")

def test_private_ip_rejection():
    # RFC 1918 Class A, B, C
    assert is_private_or_restricted_ip("10.0.0.1")
    assert is_private_or_restricted_ip("172.16.0.1")
    assert is_private_or_restricted_ip("192.168.1.1")
    # Loopback
    assert is_private_or_restricted_ip("127.0.0.1")
    assert is_private_or_restricted_ip("127.0.1.1")
    # Link-local / Cloud metadata
    assert is_private_or_restricted_ip("169.254.169.254")

def test_public_ip_allowed():
    # Cloudflare & Google DNS
    assert not is_private_or_restricted_ip("1.1.1.1")
    assert not is_private_or_restricted_ip("8.8.8.8")
    assert not is_private_or_restricted_ip("93.184.216.34")  # example.com

def test_safe_resolve_blocks_private():
    is_safe, ip, reason = safe_resolve_hostname("127.0.0.1")
    assert not is_safe
    assert "blocked" in reason.lower()

    is_safe2, ip2, reason2 = safe_resolve_hostname("169.254.169.254")
    assert not is_safe2
