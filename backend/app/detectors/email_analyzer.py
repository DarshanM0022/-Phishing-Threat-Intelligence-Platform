import re
import email
from email import policy
from email.parser import Parser
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from backend.app.schemas.analysis import IndicatorSchema
from backend.app.detectors.url_features import url_extractor
from backend.app.detectors.heuristics import heuristic_engine

URGENCY_PATTERNS = [
    (r"\b(?:within|in)\s+(?:24|12|48)\s+hours?\b", "Tight time constraint (24-48 hours) intended to induce panic."),
    (r"\b(?:immediately|urgent|action required|attention needed)\b", "Direct urgency solicitation demanding rapid interaction."),
    (r"\b(?:account|access|service)\s+(?:suspended|terminated|locked|closed|disabled)\b", "Coercive threat of immediate account or service suspension."),
    (r"\b(?:unauthorized|suspicious)\s+(?:activity|login|transaction|access)\b", "Fabricated security alert to manipulate victim into verifying."),
    (r"\b(?:failure to comply|legal action|law enforcement|penalties)\b", "Coercive legal consequences or enforcement threat."),
]

CREDENTIAL_HARVEST_PATTERNS = [
    (r"\b(?:confirm|verify|update|validate)\s+(?:your\s+)?(?:password|pin|credentials|identity|ssn)\b", "Explicit credential confirmation solicitation."),
    (r"\b(?:click|login|sign in)\s+(?:here|below|immediately)\s+(?:to\s+verify|to\s+restore)\b", "Call-to-action redirecting victim to external authentication portal."),
    (r"\b(?:billing|payment|credit card)\s+(?:declined|expired|suspended|update)\b", "Financial/payment billing pressure to elicit banking information."),
]

URL_REGEX = re.compile(
    r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'\".,<>?«»“”‘’]))'
)

class EmailPhishingAnalyzer:
    """
    Enterprise Email Header & Linguistic Forensics Analyzer.
    Parses RFC 822 / 5322 structures, SPF/DKIM/DMARC authentication headers,
    Received hop chains, and embedded hyperlink indicators.
    """
    def analyze_email(self, raw_content: str) -> Dict[str, Any]:
        subject = ""
        from_header = ""
        reply_to = ""
        return_path = ""
        message_id = ""
        auth_results_header = ""
        received_headers = []
        body_text = raw_content

        # 1. Parse RFC 822 Email Structure
        try:
            msg = Parser(policy=policy.default).parsestr(raw_content)
            subject = msg.get("Subject", "") or ""
            from_header = msg.get("From", "") or ""
            reply_to = msg.get("Reply-To", "") or ""
            return_path = msg.get("Return-Path", "") or ""
            message_id = msg.get("Message-ID", "") or ""
            auth_results_header = msg.get("Authentication-Results", "") or msg.get("ARC-Authentication-Results", "") or ""
            received_headers = msg.get_all("Received", []) or []

            # Extract plain text body
            if msg.is_multipart():
                parts = []
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        parts.append(part.get_content())
                if parts:
                    body_text = "\n".join(parts)
            else:
                body = msg.get_content()
                if body and isinstance(body, str):
                    body_text = body
        except Exception:
            pass

        # 2. Parse Authentication Results (SPF, DKIM, DMARC)
        spf_status = "none"
        dkim_status = "none"
        dmarc_status = "none"
        if auth_results_header:
            auth_lower = auth_results_header.lower()
            if "spf=pass" in auth_lower: spf_status = "pass"
            elif "spf=fail" in auth_lower or "spf=softfail" in auth_lower: spf_status = "fail"
            
            if "dkim=pass" in auth_lower: dkim_status = "pass"
            elif "dkim=fail" in auth_lower: dkim_status = "fail"

            if "dmarc=pass" in auth_lower: dmarc_status = "pass"
            elif "dmarc=fail" in auth_lower: dmarc_status = "fail"

        # 3. Parse Originating IP from Received Header Chain
        originating_ip = None
        for r_hdr in reversed(received_headers):
            ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", r_hdr)
            if ip_match:
                originating_ip = ip_match.group(1)
                break

        # Extract embedded URLs
        found_urls = self._extract_urls(body_text)

        # 4. Header Anomaly Detection
        header_anomalies: List[IndicatorSchema] = []
        sender_mismatch = False
        display_name_spoof = False

        if from_header:
            from_email_match = re.search(r"<([^>]+)>", from_header)
            from_email = from_email_match.group(1) if from_email_match else from_header
            display_name = from_header.split("<")[0].strip("\"' ") if "<" in from_header else ""

            # Check display name impersonation (e.g. "PayPal Support" <admin@random.ru>)
            brand_in_display = any(b in display_name.lower() for b in ["paypal", "microsoft", "apple", "google", "bank", "chase", "netflix"])
            if brand_in_display and from_email:
                domain_part = from_email.split("@")[-1].lower() if "@" in from_email else ""
                if not any(b in domain_part for b in ["paypal", "microsoft", "apple", "google", "chase", "netflix"]):
                    display_name_spoof = True
                    header_anomalies.append(IndicatorSchema(
                        id="IND-EML-001",
                        rule_id="RUL-EML-SPOOF",
                        title="Display Name Brand Masquerading",
                        category="nlp",
                        severity="CRITICAL",
                        description=f"Display name claims trusted brand identity ('{display_name}') while message envelope originates from an unassociated domain ('{domain_part}').",
                        mitre_attack_id="T1566.001",
                        score_impact=40.0
                    ))

            # Sender vs Reply-To Mismatch
            if reply_to and from_email:
                reply_email_match = re.search(r"<([^>]+)>", reply_to)
                reply_clean = reply_email_match.group(1) if reply_email_match else reply_to
                if from_email.strip().lower() != reply_clean.strip().lower():
                    sender_mismatch = True
                    header_anomalies.append(IndicatorSchema(
                        id="IND-EML-002",
                        rule_id="RUL-EML-MISMATCH",
                        title="Sender & Reply-To Address Divergence",
                        category="nlp",
                        severity="HIGH",
                        description=f"Outbound sender address ({from_email}) routes recipient replies to a disconnected destination mailbox ({reply_clean}).",
                        mitre_attack_id="T1566.001",
                        score_impact=30.0
                    ))

            # SPF / DKIM Authentication Failures
            if spf_status == "fail":
                header_anomalies.append(IndicatorSchema(
                    id="IND-EML-003",
                    rule_id="RUL-EML-SPF-FAIL",
                    title="SPF Origin Authentication Failure",
                    category="reputation",
                    severity="HIGH",
                    description="Sending server IP address is not authorized under the domain's published SPF policy record.",
                    mitre_attack_id="T1566.001",
                    score_impact=25.0
                ))

            if dkim_status == "fail":
                header_anomalies.append(IndicatorSchema(
                    id="IND-EML-004",
                    rule_id="RUL-EML-DKIM-FAIL",
                    title="DKIM Cryptographic Signature Failure",
                    category="reputation",
                    severity="HIGH",
                    description="Cryptographic signature verification failed, indicating payload tampering or forged header identity in transit.",
                    mitre_attack_id="T1566.001",
                    score_impact=25.0
                ))

        # 5. NLP Linguistic Intent Analysis
        nlp_indicators: List[IndicatorSchema] = []
        urgency_score = 0.0
        credential_intent_score = 0.0
        combined_text = f"{subject}\n{body_text}"

        for pattern, desc in URGENCY_PATTERNS:
            if re.search(pattern, combined_text, re.IGNORECASE):
                urgency_score += 0.35
                nlp_indicators.append(IndicatorSchema(
                    id=f"IND-URG-{len(nlp_indicators)+1}",
                    rule_id="RUL-NLP-URGENCY",
                    title="Psychological Urgency & Coercion Solicitation",
                    category="nlp",
                    severity="HIGH",
                    description=desc,
                    mitre_attack_id="T1566",
                    score_impact=20.0
                ))

        for pattern, desc in CREDENTIAL_HARVEST_PATTERNS:
            if re.search(pattern, combined_text, re.IGNORECASE):
                credential_intent_score += 0.40
                nlp_indicators.append(IndicatorSchema(
                    id=f"IND-CRED-{len(nlp_indicators)+1}",
                    rule_id="RUL-NLP-CREDENTIAL",
                    title="Credential & Authentication Harvest Vector",
                    category="nlp",
                    severity="CRITICAL",
                    description=desc,
                    mitre_attack_id="T1566",
                    score_impact=35.0
                ))

        urgency_score = min(1.0, urgency_score)
        credential_intent_score = min(1.0, credential_intent_score)

        # 6. Embedded Hyperlinks Scan
        url_evaluations = []
        for u in found_urls[:5]:
            ext = url_extractor.extract_features(u)
            heuristics = heuristic_engine.evaluate(ext["features"], ext["metadata"])
            url_evaluations.append({
                "url": u,
                "domain": ext["metadata"]["registered_domain"],
                "features": ext["features"],
                "indicators": [i.model_dump() for i in heuristics],
                "has_phishing_indicators": len(heuristics) > 0
            })

        forensics = {
            "subject": subject,
            "from": from_header,
            "reply_to": reply_to,
            "return_path": return_path,
            "message_id": message_id,
            "originating_ip": originating_ip,
            "hop_count": len(received_headers),
            "auth_results": {
                "spf": spf_status,
                "dkim": dkim_status,
                "dmarc": dmarc_status
            },
            "embedded_url_count": len(found_urls)
        }

        return {
            "subject": subject,
            "from_header": from_header,
            "reply_to": reply_to,
            "sender_mismatch": sender_mismatch,
            "display_name_spoof": display_name_spoof,
            "urgency_score": round(urgency_score, 2),
            "credential_intent_score": round(credential_intent_score, 2),
            "header_anomalies": header_anomalies,
            "nlp_indicators": nlp_indicators,
            "embedded_urls": url_evaluations,
            "email_forensics": forensics
        }

    def _extract_urls(self, text: str) -> List[str]:
        raw_matches = URL_REGEX.findall(text)
        urls = []
        for m in raw_matches:
            match_str = m[0] if isinstance(m, tuple) else m
            match_str = match_str.rstrip(".,;!?'\")>]} ")
            if not match_str.startswith(("http://", "https://")):
                match_str = "https://" + match_str
            if match_str not in urls:
                urls.append(match_str)
        return urls

email_analyzer = EmailPhishingAnalyzer()
