import os
import json
import numpy as np
from typing import Dict, Any, List, Tuple
from backend.app.core.config import settings
from backend.app.schemas.analysis import ShapContributionSchema
from backend.app.ml.tree_model import PureRandomForest

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count",
    "slash_count",
    "special_char_count",
    "subdomain_count",
    "is_https",
    "has_ip_hostname",
    "has_at_symbol",
    "has_double_slash_path",
    "uses_punycode",
    "is_shortened_url",
    "suspicious_tld",
    "has_hex_encoding",
    "has_brand_in_subdomain",
    "digit_ratio",
    "hostname_digit_ratio",
    "hostname_entropy",
    "url_entropy",
    "keyword_count",
    "has_login_keyword",
    "has_verify_keyword",
    "has_secure_keyword",
    "has_billing_keyword",
]

FRIENDLY_NAMES = {
    "url_length": "URL Total Length",
    "hostname_length": "Hostname Length",
    "path_length": "Path Length",
    "query_length": "Query String Length",
    "dot_count": "Dot Character Count",
    "hyphen_count": "Hyphen Count",
    "slash_count": "Forward Slash Count",
    "special_char_count": "Special Characters Count",
    "subdomain_count": "Subdomain Nesting Count",
    "is_https": "HTTPS Protocol Present",
    "has_ip_hostname": "Direct IP Address Host",
    "has_at_symbol": "Basic Auth @ Symbol",
    "has_double_slash_path": "Double Slash Path Redirect",
    "uses_punycode": "Punycode (xn--) Homograph",
    "is_shortened_url": "URL Shortener Service",
    "suspicious_tld": "High-Abuse Top-Level Domain",
    "has_hex_encoding": "Hexadecimal Encoding",
    "has_brand_in_subdomain": "Brand Impersonation in Subdomain",
    "digit_ratio": "Digit to Character Ratio",
    "hostname_digit_ratio": "Hostname Numeric Ratio",
    "hostname_entropy": "Hostname Shannon Entropy",
    "url_entropy": "Total URL Entropy",
    "keyword_count": "Security Keywords Detected",
    "has_login_keyword": "Login / Signin Terminology",
    "has_verify_keyword": "Verification Request Keyword",
    "has_secure_keyword": "Security Spoofing Keyword",
    "has_billing_keyword": "Banking/Billing Keyword",
}

class PhishingMLClassifier:
    """
    Production-grade ML inference engine with tree-based explainability.
    """
    def __init__(self):
        self.rf: PureRandomForest = None
        self.metrics = {}
        self.feature_names = FEATURE_NAMES
        self._load_model()

    def _load_model(self):
        model_path = os.path.join(settings.BASE_DIR, "ml", "models", "rf_phishing_v1.json")
        metrics_path = os.path.join(settings.BASE_DIR, "ml", "evaluation", "metrics.json")
        
        if os.path.exists(model_path):
            try:
                with open(model_path, "r") as f:
                    model_dict = json.load(f)
                self.rf = PureRandomForest.from_dict(model_dict)
                print(f"[+] Loaded PureRandomForest model from {model_path}")
            except Exception as e:
                print(f"[!] Error loading model JSON: {e}")
                self.rf = None

        if os.path.exists(metrics_path):
            try:
                with open(metrics_path, "r") as f:
                    self.metrics = json.load(f)
            except Exception:
                pass

    def predict(self, feature_dict: Dict[str, Any]) -> Tuple[float, str, List[ShapContributionSchema]]:
        """
        Runs inference and computes feature attribution.
        Returns: (phishing_probability, verdict, list_of_attributions)
        """
        if self.rf is None:
            self._load_model()

        vector = [float(feature_dict.get(fn, 0.0)) for fn in self.feature_names]
        x = np.array(vector, dtype=float)

        if self.rf is None:
            # Fallback heuristic calculation if model not present
            prob = 0.05
            if feature_dict.get("has_ip_hostname"): prob += 0.45
            if feature_dict.get("uses_punycode"): prob += 0.40
            if feature_dict.get("has_brand_in_subdomain"): prob += 0.35
            if feature_dict.get("suspicious_tld"): prob += 0.20
            if feature_dict.get("has_login_keyword"): prob += 0.15
            prob = min(0.99, max(0.01, prob))
            verdict = "phishing" if prob >= 0.5 else "legitimate"
            return prob, verdict, []

        X = np.array([x])
        probabilities = self.rf.predict_proba(X)[0]
        phishing_prob = round(float(probabilities[1]), 4)
        verdict = "phishing" if phishing_prob >= 0.5 else "legitimate"

        # Tree path attribution
        contributions = self.rf.explain_instance(x)
        factors: List[ShapContributionSchema] = []

        for i, val in enumerate(contributions):
            impact = round(float(val), 4)
            if abs(impact) >= 0.005:
                fn = self.feature_names[i]
                friendly = FRIENDLY_NAMES.get(fn, fn)
                direction = "phishing" if impact > 0 else "legitimate"
                factors.append(ShapContributionSchema(
                    feature=fn,
                    display_name=friendly,
                    feature_value=round(float(x[i]), 3),
                    shap_value=impact,
                    impact_direction=direction,
                    impact_percentage=round(abs(impact) * 100, 1)
                ))

        factors.sort(key=lambda item: abs(item.shap_value), reverse=True)
        return phishing_prob, verdict, factors[:8]

ml_classifier = PhishingMLClassifier()
