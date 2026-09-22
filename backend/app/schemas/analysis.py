from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class IndicatorSchema(BaseModel):
    id: str
    rule_id: str
    title: str
    category: str  # lexical, syntax, host, reputation, nlp, behavioral, crypto
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    mitre_attack_id: Optional[str] = None
    score_impact: float

class ShapContributionSchema(BaseModel):
    feature: str
    display_name: str
    feature_value: Any
    shap_value: float
    impact_direction: str  # 'phishing' or 'legitimate'
    impact_percentage: float

class URLFeaturesSchema(BaseModel):
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    dot_count: int
    hyphen_count: int
    subdomain_count: int
    special_char_count: int
    is_https: bool
    has_ip_hostname: bool
    has_at_symbol: bool
    has_double_slash_path: bool
    uses_punycode: bool
    is_shortened_url: bool
    shannon_entropy: float
    digit_ratio: float
    suspicious_tld: bool
    keyword_matches: List[str]
    raw_feature_vector: Dict[str, Any]

class ThreatIntelSchema(BaseModel):
    domain: str
    resolved_ip: Optional[str] = None
    reverse_dns: Optional[str] = None
    is_safe_resolution: bool = True
    reputation_status: str  # CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN
    domain_age_days: Optional[int] = None
    registration_date: Optional[str] = None
    expiration_date: Optional[str] = None
    registrar: Optional[str] = None
    country_code: Optional[str] = None
    is_top_domain: bool = False
    ssl_issuer: Optional[str] = None
    ssl_valid_to: Optional[str] = None
    ssl_protocol: Optional[str] = None
    details: Dict[str, Any] = {}

class AnalysisTimelineEvent(BaseModel):
    timestamp: str
    step: str
    status: str
    duration_ms: float
    details: Optional[str] = None

class AnalysisRequest(BaseModel):
    target: str = Field(..., description="Target URL, domain, or raw text to inspect")
    target_type: str = Field("url", description="Type of target: url, email, domain")
    include_threat_intel: bool = True
    include_shap: bool = True

class EmailAnalysisRequest(BaseModel):
    raw_email: str = Field(..., description="RFC 822 formatted raw email or pasted text")
    check_embedded_urls: bool = True

class AnalysisResponse(BaseModel):
    id: str
    target: str
    target_type: str
    risk_score: float = Field(..., ge=0.0, le=100.0)
    risk_level: str  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    verdict: str     # legitimate, suspicious, phishing
    ml_confidence: float
    score_breakdown: Dict[str, float]
    indicators: List[IndicatorSchema]
    top_shap_factors: List[ShapContributionSchema]
    url_features: Optional[URLFeaturesSchema] = None
    threat_intel: Optional[ThreatIntelSchema] = None
    email_forensics: Optional[Dict[str, Any]] = None
    executive_summary: str
    analyst_recommendation: str
    timeline: List[AnalysisTimelineEvent]
    analyzed_at: datetime
    processing_time_ms: float

class HistoryItemSchema(BaseModel):
    id: str
    target: str
    target_type: str
    risk_score: float
    risk_level: str
    verdict: str
    analyzed_at: datetime
    indicator_count: int
