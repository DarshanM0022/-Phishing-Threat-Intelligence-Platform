# PhishGuard AI - Antigravity Agent Guidelines & Project Rules

## 1. Project Mission & Identity
**PhishGuard AI** is a production-grade, college-level cybersecurity platform engineered for defensive analysis of URLs, emails, and domains. It combines lexical/statistical feature engineering, machine learning (Random Forest / XGBoost), explainable AI (SHAP), rule-based heuristic engines, and threat intelligence enrichment.

## 2. Core Operational & Security Invariants
All agents and developers contributing to this repository MUST uphold the following rules:

### A. Defensive Cybersecurity Only
- Under no circumstances shall this project develop offensive tooling, weaponized exploit delivery, automated credential harvesters, or phishing simulation dispatchers.
- Any network requests made for domain/URL reputation must be purely observational and defensive.

### B. Safe Analysis & SSRF Prevention
- **NO ARBITRARY SCRAPING / VISITATION**: Basic URL feature extraction must NEVER perform unconstrained HTTP requests or execute scripts on untrusted target URLs.
- **SSRF Immunity**: Any active network enrichment (e.g. DNS lookups, RDAP, threat intel APIs) must validate and reject RFC 1918 private IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), and link-local (`169.254.0.0/16`) addresses before issuing network socket calls.
- Timeouts must be strictly capped (max 3 seconds) for all external network lookups.

### C. No "AI Wrapper" Architectures
- Phishing classification must NEVER simply send a prompt to an LLM saying "Is this phishing?".
- The detection core is a quantitative pipeline:
  1. Lexical & Structural Feature Extraction
  2. Trained Scikit-Learn / XGBoost Machine Learning Model
  3. Rule-Based Heuristic Indicators (anchored to MITRE ATT&CK T1566)
  4. Explainability Attribution (SHAP values & Heuristic contribution weights)
  5. Multi-Signal Calibrated Risk Scoring Engine (0-100)
- Generative AI / LLMs are strictly used in a secondary capacity: translating structured detection signals and SHAP attributions into executive summaries and SOC analyst incident briefs.

### D. Safe Synthetic Datasets
- Model training and test suites must use synthetic, sanitized, or verified public research datasets (e.g., PhishTank feeds, Tranco top domains, synthetic email corpora).
- Never store or log real victim credentials, passwords, session tokens, or personal identifiers (PII).

### E. Architectural Separation of Concerns
- **Backend**: Python 3.12 + FastAPI with strict Pydantic schemas, modular detectors, and SQLAlchemy ORM.
- **ML Layer**: Clean train/eval pipelines with saved serialized model artifacts (`joblib`/`onnx`), tracking Precision, Recall, F1, ROC-AUC, FPR, and FNR.
- **Frontend**: Next.js / React SOC-grade security dashboard with Analyst and User views.
- **Database**: PostgreSQL storing audit logs, scan results, feature vectors, and threat intel cache.

## 3. Development Workflow & Milestones
All work proceeds in staged, verifiable increments:
- **Stage 0**: Project Rules, Architecture & Implementation Roadmap *(Current)*
- **Stage 1**: Foundation & Core Service Infrastructure (FastAPI, Schemas, DB Models, Config, Health)
- **Stage 2**: Safe URL Feature Extraction & Heuristic Engine (Unit-tested, 30+ features)
- **Stage 3**: Machine Learning Model Training, Validation & Inference Pipeline
- **Stage 4**: Explainable AI Engine (SHAP integration & factor decomposition)
- **Stage 5**: Email Phishing & NLP Analyzer (Header parsing, body urgency/intent NLP, link extraction)
- **Stage 6**: Threat Intelligence Layer & Multi-Signal Risk Scoring Engine
- **Stage 7**: Modern SOC Security Dashboard & Analyst Interface
- **Stage 8**: End-to-End Verification, Dockerization & Academic Defense Documentation
