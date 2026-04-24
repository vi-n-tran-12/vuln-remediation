FROM python:3.11-slim AS base

WORKDIR /app

# Install dependencies first for better layer caching
COPY pyproject.toml .
RUN pip install --no-cache-dir . 2>/dev/null || \
    pip install --no-cache-dir \
        "httpx>=0.27,<1" \
        "pydantic>=2.0,<3" \
        "pydantic-settings>=2.0,<3" \
        "fastapi>=0.115,<1" \
        "uvicorn[standard]>=0.30,<1" \
        "structlog>=24.0,<25" \
        "jinja2>=3.1,<4"

# Copy application code
COPY src/ src/

# Create data directory for task persistence
RUN mkdir -p data

ENV PYTHONPATH=/app/src

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "vuln_remediation.main:app", \
     "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
