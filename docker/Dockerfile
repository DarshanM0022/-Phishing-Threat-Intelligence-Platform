FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/ backend/
COPY ml/ ml/
COPY frontend/ frontend/
COPY .env.example .env

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    pydantic \
    pydantic-settings \
    numpy \
    tldextract \
    httpx \
    pytest

# Train / verify model weights
RUN python ml/training/train_model.py

EXPOSE 8000

ENV PYTHONPATH=/app

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
