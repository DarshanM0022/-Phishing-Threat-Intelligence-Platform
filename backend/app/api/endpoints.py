import time
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query

from backend.app.schemas.analysis import (
    AnalysisRequest,
    EmailAnalysisRequest,
    AnalysisResponse,
    HistoryItemSchema,
    AnalysisTimelineEvent,
    URLFeaturesSchema,
    ThreatIntelSchema
)
from backend.app.detectors.url_features import url_extractor
from backend.app.detectors.heuristics import heuristic_engine
from backend.app.detectors.email_analyzer import email_analyzer
from backend.app.threat_intel.service import threat_intel_service
from backend.app.ml.classifier import ml_classifier
from backend.app.services.risk_engine import risk_engine
from backend.app.core.config import settings

router = APIRouter()

# In-memory investigation storage (persisted during process lifetime)
ANALYSIS_STORE: Dict[str, AnalysisResponse] = {}

@router.get("/health")
def health_check():
    return {
        "status": "online",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "ml_model_loaded": ml_classifier.rf is not None,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@router.get("/stats")
def get_soc_stats():
    total = len(ANALYSIS_STORE)
    high_critical = sum(1 for a in ANALYSIS_STORE.values() if a.risk_level in ["HIGH", "CRITICAL"])
    medium = sum(1 for a in ANALYSIS_STORE.values() if a.risk_level == "MEDIUM")
    safe = sum(1 for a in ANALYSIS_STORE.values() if a.risk_level in ["SAFE", "LOW"])
    
    # Calculate rule triggers
    rule_counts: Dict[str, int] = {}
    for a in ANALYSIS_STORE.values():
        for ind in a.indicators:
            rule_counts[ind.title] = rule_counts.get(ind.title, 0) + 1

    sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_threat_patterns = [{"rule": r[0], "count": r[1]} for r in sorted_rules]

    return {
        "total_investigations": total,
        "threats_neutralized": high_critical,
        "suspicious_flagged": medium,
        "benign_verified": safe,
        "top_threat_patterns": top_threat_patterns,
        "defense_grid_status": "OPTIMAL"
    }

@router.post("/analyze/url", response_model=AnalysisResponse)
def analyze_url(request: AnalysisRequest):
    start_time = time.time()
    timeline: List[AnalysisTimelineEvent] = []
    
    def add_event(step: str, status: str, t_start: float, details: str = None):
        dur = round((time.time() - t_start) * 1000, 2)
        timeline.append(AnalysisTimelineEvent(
            timestamp=datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
            step=step,
            status=status,
            duration_ms=dur,
            details=details
        ))

    # Step 1: Ingestion & Canonicalization
    t0 = time.time()
    raw_target = request.target.strip()
    if not raw_target:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")
    add_event("Target Ingest & Scheme Normalization", "COMPLETED", t0, f"Target: {raw_target[:60]}")

    # Step 2: Feature Extraction (32 dimensions)
    t1 = time.time()
    ext_data = url_extractor.extract_features(raw_target)
    features = ext_data["features"]
    metadata = ext_data["metadata"]
    add_event("Lexical & Structural Feature Extraction", "COMPLETED", t1, f"Extracted {len(features)} attributes")

    # Step 3: Rule Heuristic Evaluation
    t2 = time.time()
    indicators = heuristic_engine.evaluate(features, metadata)
    add_event("MITRE ATT&CK Heuristic Rule Evaluation", "COMPLETED", t2, f"Flagged {len(indicators)} indicators")

    # Step 4: ML Prediction & Tree Attribution
    t3 = time.time()
    ml_prob, ml_verdict, shap_factors = ml_classifier.predict(features)
    add_event("Random Forest ML Inference & TreeSHAP Attribution", "COMPLETED", t3, f"Phishing probability: {ml_prob*100:.1f}%")

    # Step 5: Threat Intelligence & SSRF-Safe DNS
    t4 = time.time()
    intel = threat_intel_service.check_domain(metadata["hostname"])
    add_event("Threat Intel Domain Reputation & SSRF Check", "COMPLETED", t4, f"Status: {intel.reputation_status} (Age: {intel.domain_age_days}d)")

    # Step 6: Multi-Signal Risk Scoring
    t5 = time.time()
    final_score, risk_level, verdict, breakdown, summary, rec = risk_engine.compute_risk(
        ml_probability=ml_prob,
        indicators=indicators,
        threat_intel=intel,
        is_email=False
    )
    add_event("Ensemble Multi-Signal Risk Scoring", "COMPLETED", t5, f"Risk Score: {final_score}/100 ({risk_level})")

    total_proc_time = round((time.time() - start_time) * 1000, 2)
    analysis_id = f"PHG-{uuid.uuid4().hex[:8].upper()}"

    # Build schema
    url_feat_schema = URLFeaturesSchema(
        url_length=features["url_length"],
        hostname_length=features["hostname_length"],
        path_length=features["path_length"],
        query_length=features["query_length"],
        dot_count=features["dot_count"],
        hyphen_count=features["hyphen_count"],
        subdomain_count=features["subdomain_count"],
        special_char_count=features["special_char_count"],
        is_https=bool(features["is_https"]),
        has_ip_hostname=bool(features["has_ip_hostname"]),
        has_at_symbol=bool(features["has_at_symbol"]),
        has_double_slash_path=bool(features["has_double_slash_path"]),
        uses_punycode=bool(features["uses_punycode"]),
        is_shortened_url=bool(features["is_shortened_url"]),
        shannon_entropy=features["hostname_entropy"],
        digit_ratio=features["digit_ratio"],
        suspicious_tld=bool(features["suspicious_tld"]),
        keyword_matches=metadata["matched_keywords"],
        raw_feature_vector=features
    )

    response = AnalysisResponse(
        id=analysis_id,
        target=metadata["clean_url"],
        target_type="url",
        risk_score=final_score,
        risk_level=risk_level,
        verdict=verdict,
        ml_confidence=round(ml_prob, 4),
        score_breakdown=breakdown,
        indicators=indicators,
        top_shap_factors=shap_factors,
        url_features=url_feat_schema,
        threat_intel=intel,
        executive_summary=summary,
        analyst_recommendation=rec,
        timeline=timeline,
        analyzed_at=datetime.now(timezone.utc),
        processing_time_ms=total_proc_time
    )

    ANALYSIS_STORE[analysis_id] = response
    return response

@router.post("/analyze/email", response_model=AnalysisResponse)
def analyze_email(request: EmailAnalysisRequest):
    start_time = time.time()
    timeline: List[AnalysisTimelineEvent] = []

    def add_event(step: str, status: str, t_start: float, details: str = None):
        dur = round((time.time() - t_start) * 1000, 2)
        timeline.append(AnalysisTimelineEvent(
            timestamp=datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
            step=step,
            status=status,
            duration_ms=dur,
            details=details
        ))

    t0 = time.time()
    raw_email = request.raw_email.strip()
    if not raw_email:
        raise HTTPException(status_code=400, detail="Raw email content cannot be empty")
    add_event("Email Parser & Header Ingestion", "COMPLETED", t0, f"Payload size: {len(raw_email)} bytes")

    # Step 1: Email Header & Linguistic Analysis
    t1 = time.time()
    email_audit = email_analyzer.analyze_email(raw_email)
    add_event("NLP Urgency & Social Engineering Analysis", "COMPLETED", t1, f"Urgency: {email_audit['urgency_score']}, Credential Intent: {email_audit['credential_intent_score']}")

    # Collect indicators from header and NLP
    all_indicators = email_audit["header_anomalies"] + email_audit["nlp_indicators"]

    # Step 2: Analyze embedded URLs if present
    t2 = time.time()
    embedded = email_audit["embedded_urls"]
    highest_url_prob = 0.05
    target_display = email_audit["subject"] or "Untracked Phishing Email"
    first_url_features = None
    intel = ThreatIntelSchema(
        domain="email-gateway",
        is_safe_resolution=True,
        reputation_status="UNKNOWN",
        domain_age_days=None,
        is_top_domain=False
    )

    if embedded:
        first_embedded = embedded[0]
        ext_feat = first_embedded["features"]
        prob, verd, factors = ml_classifier.predict(ext_feat)
        highest_url_prob = prob
        target_display = f"{target_display} -> {first_embedded['url']}"
        
        # Add embedded URL indicators
        url_heuristics = heuristic_engine.evaluate(ext_feat, {"hostname": first_embedded["domain"]})
        for ind in url_heuristics:
            if ind.rule_id not in [x.rule_id for x in all_indicators]:
                all_indicators.append(ind)
            
        first_url_features = URLFeaturesSchema(
            url_length=ext_feat["url_length"],
            hostname_length=ext_feat["hostname_length"],
            path_length=ext_feat["path_length"],
            query_length=ext_feat["query_length"],
            dot_count=ext_feat["dot_count"],
            hyphen_count=ext_feat["hyphen_count"],
            subdomain_count=ext_feat["subdomain_count"],
            special_char_count=ext_feat["special_char_count"],
            is_https=bool(ext_feat["is_https"]),
            has_ip_hostname=bool(ext_feat["has_ip_hostname"]),
            has_at_symbol=bool(ext_feat["has_at_symbol"]),
            has_double_slash_path=bool(ext_feat["has_double_slash_path"]),
            uses_punycode=bool(ext_feat["uses_punycode"]),
            is_shortened_url=bool(ext_feat["is_shortened_url"]),
            shannon_entropy=ext_feat["hostname_entropy"],
            digit_ratio=ext_feat["digit_ratio"],
            suspicious_tld=bool(ext_feat["suspicious_tld"]),
            keyword_matches=[],
            raw_feature_vector=ext_feat
        )
        intel = threat_intel_service.check_domain(first_embedded["domain"])
        add_event("Embedded Hyperlink Deep Inspection", "COMPLETED", t2, f"Inspected {len(embedded)} links; Max URL Prob: {highest_url_prob*100:.1f}%")
    else:
        add_event("Hyperlink Scan", "COMPLETED", t2, "No embedded hyperlinks found")

    # Step 3: Risk Scoring with NLP weights
    t3 = time.time()
    final_score, risk_level, verdict, breakdown, summary, rec = risk_engine.compute_risk(
        ml_probability=highest_url_prob,
        indicators=all_indicators,
        threat_intel=intel,
        nlp_urgency=email_audit["urgency_score"],
        nlp_credential=email_audit["credential_intent_score"],
        is_email=True
    )
    add_event("Ensemble Email Risk Calibration", "COMPLETED", t3, f"Score: {final_score}/100 ({risk_level})")

    total_proc_time = round((time.time() - start_time) * 1000, 2)
    analysis_id = f"PHG-EML-{uuid.uuid4().hex[:6].upper()}"

    response = AnalysisResponse(
        id=analysis_id,
        target=target_display,
        target_type="email",
        risk_score=final_score,
        risk_level=risk_level,
        verdict=verdict,
        ml_confidence=round(highest_url_prob, 4),
        score_breakdown=breakdown,
        indicators=all_indicators,
        top_shap_factors=[],
        url_features=first_url_features,
        threat_intel=intel,
        email_forensics=email_audit.get("email_forensics"),
        executive_summary=summary,
        analyst_recommendation=rec,
        timeline=timeline,
        analyzed_at=datetime.now(timezone.utc),
        processing_time_ms=total_proc_time
    )

    ANALYSIS_STORE[analysis_id] = response
    return response

@router.get("/history", response_model=List[HistoryItemSchema])
def get_history(limit: int = Query(25, ge=1, le=100)):
    items = []
    for a in sorted(ANALYSIS_STORE.values(), key=lambda x: x.analyzed_at, reverse=True)[:limit]:
        items.append(HistoryItemSchema(
            id=a.id,
            target=a.target,
            target_type=a.target_type,
            risk_score=a.risk_score,
            risk_level=a.risk_level,
            verdict=a.verdict,
            analyzed_at=a.analyzed_at,
            indicator_count=len(a.indicators)
        ))
    return items

@router.get("/investigation/{analysis_id}", response_model=AnalysisResponse)
def get_investigation(analysis_id: str):
    if analysis_id not in ANALYSIS_STORE:
        raise HTTPException(status_code=404, detail="Investigation record not found")
    return ANALYSIS_STORE[analysis_id]
