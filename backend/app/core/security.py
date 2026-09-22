import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, Optional

# Disallowed IP Networks for SSRF immunity
DISALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918 Class A
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918 Class B
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918 Class C
    ipaddress.ip_network("169.254.0.0/16"),   # Link-Local
    ipaddress.ip_network("0.0.0.0/8"),        # Current network
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]

def is_ip_address(host: str) -> bool:
    """Checks whether the given host string is a valid IPv4 or IPv6 address."""
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False

def is_private_or_restricted_ip(ip_str: str) -> bool:
    """Validates if an IP falls within private, loopback, or cloud-metadata ranges."""
    clean_ip = ip_str.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        for network in DISALLOWED_NETWORKS:
            if ip_obj in network:
                return True
        return False
    except ValueError:
        return True

def safe_resolve_hostname(hostname: str, timeout: float = 2.0) -> Tuple[bool, Optional[str], str]:
    """
    Safely resolves a hostname to an IP address with SSRF validation.
    Returns: (is_safe, resolved_ip, reason)
    """
    if not hostname:
        return False, None, "Empty hostname"
        
    clean_host = hostname.strip("[]")
    
    # If it's already an IP address
    if is_ip_address(clean_host):
        if is_private_or_restricted_ip(clean_host):
            return False, clean_host, f"Direct access to private/restricted IP blocked: {clean_host}"
        return True, clean_host, "Public IP validated"
        
    try:
        # Set strict socket timeout
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            resolved_ip = socket.gethostbyname(clean_host)
        finally:
            socket.setdefaulttimeout(old_timeout)
            
        if is_private_or_restricted_ip(resolved_ip):
            return False, resolved_ip, f"Host resolved to private/restricted IP: {resolved_ip}"
            
        return True, resolved_ip, "DNS resolution safe"
    except socket.gaierror:
        return False, None, "DNS resolution failed (host does not exist or unreachable)"
    except Exception as e:
        return False, None, f"DNS lookup error: {str(e)}"

def sanitize_url(raw_url: str) -> str:
    """Normalizes URL scheme, trims whitespace, and canonicalizes representation."""
    cleaned = raw_url.strip()
    if not cleaned:
        return ""
    if not (cleaned.startswith("http://") or cleaned.startswith("https://") or cleaned.startswith("ftp://")):
        cleaned = "https://" + cleaned
    return cleaned
