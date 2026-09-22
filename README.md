# PhishGuard Enterprise 🛡️
### *Advanced Threat Intelligence, RFC 822 Forensics & Explainable Phishing Analysis Platform*

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.12-blue.svg?logo=python&logoColor=white)](https://python.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1566%20Mapped-red.svg)](https://attack.mitre.org/techniques/T1566/)
[![Explainability](https://img.shields.io/badge/XAI-TreeSHAP%20Attribution-0284c7.svg)](#)
[![ICANN RDAP](https://img.shields.io/badge/RDAP-Live%20Registration%20Telemetry-emerald.svg)](#)

---

## 📌 Product Overview

**PhishGuard Enterprise** is a production-grade cybersecurity platform engineered for defensive triage and deep forensics of URLs, domains, and RFC 822 email messages. Designed in the spirit of modern enterprise security tools (Cloudflare Radar, CrowdStrike Falcon, Wiz, Linear), it replaces superficial "AI wrappers" with a multi-signal detection ensemble:

1. **32-Dimension Lexical & Structural Feature Extractor**: RFC 3986 canonicalization, Shannon entropy, sub-domain nesting depth, punycode IDN homograph decoding, and credential keyword parsing without untrusted page execution.
2. **Explainable Machine Learning Engine**: Pure-ensemble Random Forest with mathematical Saabas/TreeSHAP local feature attribution.
3. **Live Cryptographic & RDAP Telemetry**: Real-time ICANN RDAP domain registration queries (registration date, domain age, registrar) and live TLS/SSL handshake verification (issuer, cipher, validity window).
4. **MITRE ATT&CK Heuristic Engine**: Deterministic detection rules mapped to **T1566.002** (Spearphishing Link), **T1036.007** (Masquerading / Homograph), and **T1568** (DGA).
5. **RFC 822 / 5322 Email Header Forensics**: Envelope inspection analyzing SPF/DKIM/DMARC authentication records, originating MTA Received hop chains, display-name masquerading, and recursive embedded link extraction.
6. **SSRF-Immune Architecture**: Network lookup boundaries strictly prohibiting outbound connections to RFC 1918 private subnets, loopback, and cloud metadata endpoints (`169.254.169.254`).
7. **Enterprise SOC Triage Cockpit**: Dark-first technical interface featuring high-density telemetry, TreeSHAP attribution charts, execution trace timelines, and single-click JSON IOC Dossier export.

---

## ⚡ Quickstart & Local Deployment

### 1. Requirements
- Python 3.10+ (Tested on Python 3.12)
- Modern Web Browser (Chrome, Brave, Firefox, Edge, Safari)

### 2. Environment Setup
```bash
# Clone or navigate to the repository
cd C:\Users\darsh\projects\LLM

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install required dependencies
pip install fastapi uvicorn pydantic pydantic-settings numpy tldextract httpx pytest
```

### 3. Launch the Platform
```bash
$env:PYTHONPATH="."
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

- 👉 **Enterprise SOC Dashboard**: **`http://localhost:8000`**
- 👉 **Interactive OpenAPI / Swagger Docs**: **`http://localhost:8000/docs`**

---

## 🧪 Comprehensive Verification Suite

Run the full pytest suite (19 unit and integration tests):

```bash
$env:PYTHONPATH="."
pytest backend/tests/ -v
```

```
backend/tests/test_api_endpoints.py::test_health_check_endpoint PASSED   [  5%]
backend/tests/test_api_endpoints.py::test_url_analysis_endpoint_phishing PASSED [ 10%]
backend/tests/test_api_endpoints.py::test_url_analysis_endpoint_benign PASSED [ 15%]
backend/tests/test_api_endpoints.py::test_email_analysis_endpoint PASSED [ 21%]
backend/tests/test_api_endpoints.py::test_history_and_stats_endpoints PASSED [ 26%]
backend/tests/test_heuristics.py::test_punycode_heuristic_trigger PASSED [ 31%]
backend/tests/test_heuristics.py::test_brand_spoofing_heuristic_trigger PASSED [ 36%]
backend/tests/test_heuristics.py::test_ip_address_heuristic_trigger PASSED [ 42%]
backend/tests/test_heuristics.py::test_benign_url_no_critical_heuristics PASSED [ 47%]
backend/tests/test_ssrf_security.py::test_ip_format_validator PASSED     [ 52%]
backend/tests/test_ssrf_security.py::test_private_ip_rejection PASSED    [ 57%]
backend/tests/test_ssrf_security.py::test_public_ip_allowed PASSED       [ 63%]
backend/tests/test_ssrf_security.py::test_safe_resolve_blocks_private PASSED [ 68%]
backend/tests/test_url_features.py::test_benign_url_features PASSED      [ 73%]
backend/tests/test_url_features.py::test_ip_address_url PASSED           [ 78%]
backend/tests/test_url_features.py::test_punycode_homograph_detection PASSED [ 84%]
backend/tests/test_url_features.py::test_brand_in_subdomain PASSED       [ 89%]
backend/tests/test_url_features.py::test_basic_auth_smuggling PASSED     [ 94%]
backend/tests/test_url_features.py::test_entropy_calculation PASSED      [100%]
======================= 19 passed in 9.08s =======================
```

---

## 🔒 Enterprise Threat Intelligence Telemetry

When scanning any target (e.g. `https://cloudflare.com`), PhishGuard executes live, real queries:
```json
{
  "id": "PHG-C9492592",
  "risk_score": 0.0,
  "risk_level": "SAFE",
  "verdict": "legitimate",
  "ml_confidence": 0.0029,
  "threat_intel": {
    "domain": "cloudflare.com",
    "resolved_ip": "104.16.133.229",
    "reputation_status": "CLEAN",
    "domain_age_days": 6425,
    "registration_date": "2009-02-17T22:07:54Z",
    "expiration_date": "2033-02-17T22:07:54Z",
    "registrar": "Cloudflare, Inc.",
    "ssl_issuer": "Google Trust Services",
    "ssl_valid_to": "Dec 4 23:29:33 2026 GMT",
    "ssl_protocol": "TLSv1.3",
    "is_top_domain": true
  }
}
```

---

## 🐳 Container Deployment

Deploy multi-service container orchestration (FastAPI + PostgreSQL):

```bash
docker compose up --build -d
```
