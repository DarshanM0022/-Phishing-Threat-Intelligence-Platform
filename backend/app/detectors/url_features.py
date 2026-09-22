import re
import math
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List
import tldextract
from backend.app.core.security import is_ip_address, sanitize_url

# Suspicious high-abuse TLDs often correlated with free/throwaway domains in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", 
    "buzz", "pw", "icu", "bar", "live", "rest", "fit", "surf", "monster"
}

# Known URL shortener hostnames
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "rebrand.ly", "cutt.ly", "shorturl.at"
}

# Targeted brand keywords frequently impersonated
BRAND_KEYWORDS = {
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", 
    "bank", "chase", "wellsfargo", "citi", "bankofamerica", "steam",
    "binance", "coinbase", "metamask", "whatsapp", "instagram", "facebook"
}

# Action/Urgency keywords in phishing paths/queries
ACTION_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "confirm", "security", "banking", "billing", "wallet",
    "auth", "authenticate", "passcode", "password", "credential", "suspend"
}

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string to detect random/DGA domain names."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

class URLFeatureExtractor:
    """
    Extracts 32 structural, lexical, and behavioral features from a URL
    without initiating any network requests or scraping untrusted targets.
    """
    def __init__(self):
        # Configure tldextract for instantaneous 100% offline operation
        self.extractor = tldextract.TLDExtract(suffix_list_urls=())

    def extract_features(self, raw_url: str) -> Dict[str, Any]:
        clean_url = sanitize_url(raw_url)
        parsed = urlparse(clean_url)
        
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        
        extracted_tld = self.extractor(clean_url)
        subdomain = extracted_tld.subdomain
        domain = extracted_tld.domain
        suffix = extracted_tld.suffix.lower()
        registered_domain = f"{domain}.{suffix}" if domain and suffix else hostname

        # Keyword matching
        matched_keywords: List[str] = []
        combined_text = f"{hostname} {path} {query}".lower()
        for kw in ACTION_KEYWORDS:
            if kw in combined_text:
                matched_keywords.append(kw)
        for brand in BRAND_KEYWORDS:
            if brand in combined_text:
                matched_keywords.append(f"brand:{brand}")

        # Character counts & ratios
        digit_count = sum(c.isdigit() for c in clean_url)
        alpha_count = sum(c.isalpha() for c in clean_url)
        digit_ratio = round(digit_count / max(1, len(clean_url)), 4)
        hostname_digit_count = sum(c.isdigit() for c in hostname)
        hostname_digit_ratio = round(hostname_digit_count / max(1, len(hostname)), 4)

        # Structural counts
        dot_count = clean_url.count(".")
        hyphen_count = clean_url.count("-")
        slash_count = clean_url.count("/")
        question_count = clean_url.count("?")
        equal_count = clean_url.count("=")
        at_count = clean_url.count("@")
        percent_count = clean_url.count("%")
        subdomain_parts = [p for p in subdomain.split(".") if p] if subdomain else []
        subdomain_count = len(subdomain_parts)

        # Heuristic boolean indicators
        has_ip = is_ip_address(hostname)
        is_https = parsed.scheme.lower() == "https"
        has_at_symbol = "@" in parsed.netloc or at_count > 0
        has_double_slash_path = "//" in path
        uses_punycode = hostname.startswith("xn--") or ".xn--" in hostname
        is_shortened = hostname in URL_SHORTENERS
        is_suspicious_tld = suffix in SUSPICIOUS_TLDS
        has_hex_encoding = bool(re.search(r"%[0-9a-fA-F]{2}", clean_url))

        # Brand in subdomain check (e.g. paypal.com.attacker.com)
        has_brand_in_subdomain = any(b in subdomain.lower() for b in BRAND_KEYWORDS)
        
        # Shannon entropy
        hostname_entropy = calculate_shannon_entropy(hostname)
        url_entropy = calculate_shannon_entropy(clean_url)

        # Normalized feature dictionary
        features = {
            "url_length": len(clean_url),
            "hostname_length": len(hostname),
            "path_length": len(path),
            "query_length": len(query),
            "fragment_length": len(fragment),
            "dot_count": dot_count,
            "hyphen_count": hyphen_count,
            "slash_count": slash_count,
            "question_count": question_count,
            "equal_count": equal_count,
            "at_count": at_count,
            "percent_count": percent_count,
            "special_char_count": dot_count + hyphen_count + slash_count + question_count + equal_count + at_count + percent_count,
            "subdomain_count": subdomain_count,
            "is_https": 1 if is_https else 0,
            "has_ip_hostname": 1 if has_ip else 0,
            "has_at_symbol": 1 if has_at_symbol else 0,
            "has_double_slash_path": 1 if has_double_slash_path else 0,
            "uses_punycode": 1 if uses_punycode else 0,
            "is_shortened_url": 1 if is_shortened else 0,
            "suspicious_tld": 1 if is_suspicious_tld else 0,
            "has_hex_encoding": 1 if has_hex_encoding else 0,
            "has_brand_in_subdomain": 1 if has_brand_in_subdomain else 0,
            "digit_ratio": digit_ratio,
            "hostname_digit_ratio": hostname_digit_ratio,
            "hostname_entropy": hostname_entropy,
            "url_entropy": url_entropy,
            "keyword_count": len(matched_keywords),
            "has_login_keyword": 1 if any(k in matched_keywords for k in ["login", "signin"]) else 0,
            "has_verify_keyword": 1 if any(k in matched_keywords for k in ["verify", "verification", "confirm"]) else 0,
            "has_secure_keyword": 1 if any(k in matched_keywords for k in ["secure", "security", "auth"]) else 0,
            "has_billing_keyword": 1 if any(k in matched_keywords for k in ["banking", "billing", "wallet", "password"]) else 0,
        }

        metadata = {
            "clean_url": clean_url,
            "scheme": parsed.scheme.lower(),
            "hostname": hostname,
            "registered_domain": registered_domain,
            "subdomain": subdomain,
            "suffix": suffix,
            "matched_keywords": matched_keywords,
        }

        return {
            "features": features,
            "metadata": metadata
        }

url_extractor = URLFeatureExtractor()
