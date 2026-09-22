from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List
import os

class Settings(BaseSettings):
    APP_NAME: str = "PhishGuard AI"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = "phishguard-dev-secret-key-32-bytes-long-super-safe"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    
    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000"
    ]
    
    # Paths & ML
    BASE_DIR: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    MODEL_ARTIFACT_PATH: str = os.path.join(BASE_DIR, "ml", "models", "rf_phishing_v1.json")
    
    # Network Security (SSRF protection)
    DNS_TIMEOUT_SECONDS: float = 2.5
    MAX_EMAIL_BODY_BYTES: int = 128 * 1024  # 128 KB
    
    # Threat Intel API Keys (Optional - gracefully degrades to mock/local registry)
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
