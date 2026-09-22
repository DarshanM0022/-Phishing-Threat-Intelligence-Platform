from typing import Dict, Any, List
from backend.app.schemas.analysis import IndicatorSchema

class HeuristicRuleEngine:
    """
    Evaluates rule-based heuristic security indicators mapped to MITRE ATT&CK techniques.
    """
    def evaluate(self, features: Dict[str, Any], metadata: Dict[str, Any]) -> List[IndicatorSchema]:
        indicators: List[IndicatorSchema] = []
        hostname = metadata.get("hostname", "")
        subdomain = metadata.get("subdomain", "")
        clean_url = metadata.get("clean_url", "")
        keywords = metadata.get("matched_keywords", [])

        # Rule 1: Direct IP Hostname
        if features.get("has_ip_hostname", 0) == 1:
            indicators.append(IndicatorSchema(
                id="IND-001",
                rule_id="RUL-HOST-001",
                title="Direct IP Address Hostname",
                category="host",
                severity="HIGH",
                description=f"URL points directly to an IP address ({hostname}) rather than a registered domain name, commonly used to bypass domain reputation checks.",
                mitre_attack_id="T1566.002",
                score_impact=30.0
            ))

        # Rule 2: IDN Homograph / Punycode Spoofing
        if features.get("uses_punycode", 0) == 1:
            indicators.append(IndicatorSchema(
                id="IND-002",
                rule_id="RUL-HOST-002",
                title="Internationalized Domain Name (Punycode) Detected",
                category="syntax",
                severity="CRITICAL",
                description="Hostname uses punycode prefix ('xn--'), frequently deployed in homograph attacks to impersonate legitimate brand characters using Cyrillic or Greek alphabets.",
                mitre_attack_id="T1036.007",
                score_impact=45.0
            ))

        # Rule 3: Excessive Subdomain Depth
        if features.get("subdomain_count", 0) >= 3:
            indicators.append(IndicatorSchema(
                id="IND-003",
                rule_id="RUL-SYNTAX-003",
                title="Excessive Subdomain Nesting Depth",
                category="syntax",
                severity="HIGH",
                description=f"Detected {features['subdomain_count']} subdomain levels. Threat actors use nested subdomains to disguise the root domain on mobile screens.",
                mitre_attack_id="T1566.002",
                score_impact=22.0
            ))

        # Rule 4: Brand Impersonation in Subdomain
        if features.get("has_brand_in_subdomain", 0) == 1:
            indicators.append(IndicatorSchema(
                id="IND-004",
                rule_id="RUL-BRAND-004",
                title="Targeted Brand Impersonation in Subdomain",
                category="lexical",
                severity="CRITICAL",
                description=f"Subdomain '{subdomain}' mimics a recognized trusted brand while pointing to an unrelated registered root domain '{metadata.get('registered_domain', '')}'.",
                mitre_attack_id="T1036.007",
                score_impact=40.0
            ))

        # Rule 5: High-Abuse TLD Combined with Sensitive Keywords
        if features.get("suspicious_tld", 0) == 1 and (features.get("has_login_keyword", 0) == 1 or features.get("has_verify_keyword", 0) == 1):
            indicators.append(IndicatorSchema(
                id="IND-005",
                rule_id="RUL-TLD-005",
                title="High-Abuse Top-Level Domain with Auth Keywords",
                category="reputation",
                severity="HIGH",
                description=f"Domain uses high-abuse top-level domain (.{metadata.get('suffix', '')}) hosting authentication or verification pathways.",
                mitre_attack_id="T1566.002",
                score_impact=28.0
            ))

        # Rule 6: Credential / Basic Auth Smuggling (@ symbol in URL)
        if features.get("has_at_symbol", 0) == 1:
            indicators.append(IndicatorSchema(
                id="IND-006",
                rule_id="RUL-SYNTAX-006",
                title="HTTP Basic Auth Credential Smuggling (@ Symbol)",
                category="syntax",
                severity="CRITICAL",
                description="URL contains an '@' character which leads browsers to ignore preceding content and route to the host that follows it.",
                mitre_attack_id="T1566.002",
                score_impact=35.0
            ))

        # Rule 7: URL Shortener Masking
        if features.get("is_shortened_url", 0) == 1:
            indicators.append(IndicatorSchema(
                id="IND-007",
                rule_id="RUL-HOST-007",
                title="URL Shortening Service Employed",
                category="host",
                severity="MEDIUM",
                description="URL uses a public shortening service (bit.ly, tinyurl, etc.), masking the ultimate target server destination from security filtering.",
                mitre_attack_id="T1566.002",
                score_impact=18.0
            ))

        # Rule 8: High Domain Shannon Entropy (DGA Pattern)
        if features.get("hostname_entropy", 0.0) >= 3.8 and len(hostname) >= 14:
            indicators.append(IndicatorSchema(
                id="IND-008",
                rule_id="RUL-INFO-008",
                title="High Hostname Entropy (Possible DGA / Obfuscation)",
                category="behavioral",
                severity="HIGH",
                description=f"Hostname exhibits unusually high Shannon entropy ({features['hostname_entropy']:.2f}), typical of Domain Generation Algorithms (DGA) or machine-generated throwaway hosts.",
                mitre_attack_id="T1568.002",
                score_impact=24.0
            ))

        # Rule 9: Insecure HTTP Scheme with Authentication Keywords
        if features.get("is_https", 1) == 0 and (features.get("has_login_keyword", 0) == 1 or features.get("has_billing_keyword", 0) == 1):
            indicators.append(IndicatorSchema(
                id="IND-009",
                rule_id="RUL-SEC-009",
                title="Insecure Plaintext HTTP for Sensitive Workflow",
                category="behavioral",
                severity="HIGH",
                description="Login or financial keywords were detected, but the URL transmits over unencrypted HTTP, presenting a credential harvesting or eavesdropping hazard.",
                mitre_attack_id="T1566",
                score_impact=26.0
            ))

        # Rule 10: Deceptive Path / Double Slash Redirection
        if features.get("has_double_slash_path", 0) == 1:
            indicators.append(IndicatorSchema(
                id="IND-010",
                rule_id="RUL-SYNTAX-010",
                title="Double Slash in Path (Open Redirect Technique)",
                category="syntax",
                severity="MEDIUM",
                description="The URL path contains '//' which is frequently leveraged in open redirect exploits or parser confusion attacks.",
                mitre_attack_id="T1566.002",
                score_impact=16.0
            ))

        # Rule 11: Excessive URL Length
        if features.get("url_length", 0) >= 100:
            indicators.append(IndicatorSchema(
                id="IND-011",
                rule_id="RUL-LEX-011",
                title="Anomalous URL Character Length (>100 Chars)",
                category="lexical",
                severity="LOW",
                description=f"Total URL length ({features['url_length']} characters) is significantly longer than standard web links, often used for token padding or visual deception.",
                mitre_attack_id="T1027",
                score_impact=10.0
            ))

        return indicators

heuristic_engine = HeuristicRuleEngine()
