import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from backend.app.core.config import settings
from backend.app.api.endpoints import router as api_router, analyze_url, ANALYSIS_STORE
from backend.app.schemas.analysis import AnalysisRequest

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Seed initial baseline triage records
    if not ANALYSIS_STORE:
        samples = [
            "https://paypal.com.verify-security-login.attacker-88.xyz/auth?user_token=82711",
            "https://github.com/torvalds/linux",
            "http://192.168.1.100/chase-bank/secure-login/update.php",
            "https://netflix-support-billing.icu/account/payment-declined"
        ]
        for s in samples:
            try:
                analyze_url(AnalysisRequest(target=s, target_type="url"))
            except Exception as e:
                print(f"[!] Warning seeding sample {s}: {e}")
    yield
    # Shutdown logic if any

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Explainable AI Phishing Detection & Threat Analysis Platform",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(api_router, prefix=settings.API_V1_STR)

# Static files for Frontend Dashboard
FRONTEND_DIR = os.path.join(settings.BASE_DIR, "frontend")
STATIC_INDEX = os.path.join(FRONTEND_DIR, "index.html")

if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
def serve_dashboard():
    if os.path.exists(STATIC_INDEX):
        return FileResponse(STATIC_INDEX)
    return {
        "message": f"Welcome to {settings.APP_NAME} API. Access /docs for Swagger UI or open the dashboard."
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
