# ── Build stage ────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ──────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="ThreatLens Project"
LABEL description="AI Network Threat Detection Platform"

# Install system deps for Scapy (libpcap) and PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    libpango-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r threatlens && useradd -r -g threatlens -d /app -s /sbin/nologin threatlens

WORKDIR /app

# Copy pip-installed packages from builder
COPY --from=builder /install /usr/local

# Copy project
COPY . .

# Create data directory for DB + models
RUN mkdir -p /app/data/models && chown -R threatlens:threatlens /app

# Switch to non-root user
USER threatlens

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# NET_ADMIN + NET_RAW capabilities must be granted at runtime for live capture:
#   docker run --cap-add=NET_ADMIN --cap-add=NET_RAW --network=host ...

CMD ["python", "run.py", "--host", "0.0.0.0", "--port", "8000"]
