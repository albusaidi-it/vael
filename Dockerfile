FROM python:3.11-slim AS builder

WORKDIR /build

# Install build deps only in this stage
RUN pip install --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


FROM python:3.11-slim

WORKDIR /app

# curl for HEALTHCHECK; no other extras needed
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -m -s /bin/bash vael

# Copy packages installed by builder
COPY --from=builder /root/.local /home/vael/.local

# Copy source (owned by app user)
COPY --chown=vael:vael . .

# Cache directory must exist and be writable by the app user
RUN mkdir -p /app/feeds && chown vael:vael /app/feeds

USER vael
ENV PATH=/home/vael/.local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -sf http://localhost:8000/health || exit 1

CMD ["gunicorn", "-c", "gunicorn.conf.py", "api.main:app"]
