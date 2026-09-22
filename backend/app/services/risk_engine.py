from typing import Dict, Any, List, Tuple
from backend.app.schemas.analysis import IndicatorSchema, ThreatIntelSchema

class RiskScoringEngine:
    """
    Multi-Signal Calibrated Risk Engine combining ML confidence,
    rule heuristics, threat intelligence, and linguistic NLP signals.
    """
    def compute_risk(
        self,
        ml_probability: float,
        indicators: List[IndicatorSchema],
        threat_intel: ThreatIntelSchema,
        nlp_urgency: float = 0.0,
        nlp_credential: float = 0.0,
        is_email: bool = False
    ) -> Tuple[float, str, str, Dict[str, float], str, str]:
        """
        Calculates calibrated risk score (0-100).
        Returns: (risk_score, risk_level, verdict, breakdown, executive_summary, recommendation)
        """
        # 1. ML Component (0-100)
        s_ml = ml_probability * 100.0

        # 2. Rule Heuristic Component (0-100)
        raw_rule_sum = sum(ind.score_impact for ind in indicators)
        s_rule = min(100.0, raw_rule_sum)

        # 3. Threat Intel Component (0-100)
        s_intel = 20.0  # baseline
        if threat_intel.is_top_domain:
            s_intel = 0.0
        elif threat_intel.reputation_status == "MALICIOUS":
            s_intel = 100.0
        elif threat_intel.reputation_status == "SUSPICIOUS":
            s_intel = 75.0
        else:
            if threat_intel.domain_age_days and threat_intel.domain_age_days < 15:
                s_intel += 35.0
            if threat_intel.details.get("dynamic_dns_flag"):
                s_intel += 30.0
        s_intel = min(100.0, max(0.0, s_intel))

        # 4. NLP Component (0-100)
        s_nlp = ((nlp_urgency * 40.0) + (nlp_credential * 60.0)) if is_email else 0.0
        s_nlp = min(100.0, max(0.0, s_nlp))

        # Critical Veto Boosts
        critical_boost = 0.0
        for ind in indicators:
            if ind.severity == "CRITICAL":
                critical_boost += 15.0
        critical_boost = min(35.0, critical_boost)

        # Calculate Weighted Ensemble
        if is_email:
            final_score = (0.30 * s_ml) + (0.25 * s_rule) + (0.30 * s_nlp) + (0.15 * s_intel) + critical_boost
        else:
            final_score = (0.45 * s_ml) + (0.35 * s_rule) + (0.20 * s_intel) + critical_boost

        # If domain is a verified Alexa top domain and no critical indicators
        if threat_intel.is_top_domain and critical_boost == 0.0:
            final_score = min(20.0, final_score * 0.25)

        final_score = round(min(100.0, max(0.0, final_score)), 1)

        # Determine Tier
        if final_score <= 20.0:
            risk_level = "SAFE"
            verdict = "legitimate"
        elif final_score <= 40.0:
            risk_level = "LOW"
            verdict = "legitimate" if final_score <= 30.0 else "suspicious"
        elif final_score <= 60.0:
            risk_level = "MEDIUM"
            verdict = "suspicious"
        elif final_score <= 80.0:
            risk_level = "HIGH"
            verdict = "phishing"
        else:
            risk_level = "CRITICAL"
            verdict = "phishing"

        breakdown = {
            "ml_confidence_component": round(s_ml, 1),
            "heuristic_rule_component": round(s_rule, 1),
            "threat_intel_component": round(s_intel, 1),
            "nlp_intent_component": round(s_nlp, 1) if is_email else 0.0,
            "critical_penalty_boost": round(critical_boost, 1)
        }

        # Executive Summary & SOC Recommendations
        summary_parts = []
        if risk_level in ["HIGH", "CRITICAL"]:
            summary_parts.append(f"High-confidence phishing indicators detected with {ml_probability*100:.1f}% ML confidence.")
            if critical_boost > 0:
                summary_parts.append("Critical architectural deception detected (e.g. brand impersonation or direct IP access).")
            if threat_intel.domain_age_days and threat_intel.domain_age_days < 30:
                summary_parts.append(f"Target host is a newly registered domain ({threat_intel.domain_age_days} days old).")
            if is_email and (nlp_urgency > 0.5 or nlp_credential > 0.5):
                summary_parts.append("Email contains coercive urgency language and credential harvesting triggers.")
            executive_summary = " ".join(summary_parts)
            recommendation = "CRITICAL ADVISORY: Block URL at perimeter gateway/firewall. Do not click, authenticate, or input credentials. Quarantine associated emails immediately."
        elif risk_level == "MEDIUM":
            executive_summary = "Multiple suspicious structural characteristics observed. Domain does not appear on established reputation registries."
            recommendation = "CAUTION ADVISED: Treat as untrusted. Inspect certificate authenticity and verify through external out-of-band channels before proceeding."
        else:
            executive_summary = "Structural and lexical indicators align with standard benign web conventions. No anomalous deception patterns identified."
            recommendation = "SAFE: No malicious indicators detected. Standard organizational security policies apply."

        return final_score, risk_level, verdict, breakdown, executive_summary, recommendation

risk_engine = RiskScoringEngine()
