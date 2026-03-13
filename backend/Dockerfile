# Backend Dockerfile for DDoS Attack Visualizer
# Uses Python 3.11 slim image with async PostgreSQL support

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies for asyncpg and psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    libc-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy only ML training code and data first so the training layer is only
# invalidated when these files change, not on every source code edit.
COPY ml/ ./ml/

# Train ML model during build (creates model.pkl).
# Uses the real CICIDS2017 data when CSV files are present (local/full builds),
# and falls back to the synthetic trainer in CI/CD environments where the
# large dataset files are not available.
RUN if ls ml/data/*.csv 1>/dev/null 2>&1; then \
        echo "CICIDS2017 data found – running real trainer"; \
        python -c "import sys; sys.path.insert(0, '.'); from ml.trainer import main; main()"; \
    else \
        echo "No CSV data found – running synthetic trainer"; \
        python -c "import sys; sys.path.insert(0, '.'); from ml.trainer_synthetic import main; main()"; \
    fi || echo "Training failed – continuing build without model.pkl"

# Copy the rest of the application code
COPY . .

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/')" || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--limit-max-requests", "1000"]
