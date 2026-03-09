# Adversa — multi-stage Docker image
# Base: Chainguard Wolfi (mirrors Shannon's approach)
#
# Build:
#   docker build -t adversa:latest .
#
# Runtime mounts expected:
#   -v ./repos:/app/repos            (target repositories)
#   -v ./runs:/app/runs              (artifact output)
#   -v ./adversa.toml:/app/adversa.toml
#
# NOTE: When running against a local app (e.g. Juice Shop on localhost:3000),
#       use host.docker.internal:3000 instead of localhost:3000 in adversa.toml.

# ─── Stage 1: Go tool builder ─────────────────────────────────────────────────
FROM golang:1.24-alpine AS go-builder

RUN apk add --no-cache git ca-certificates

# ProjectDiscovery tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ─── Stage 2: Final image ─────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core tools
    git curl ca-certificates bash \
    # Node.js + npm/npx (required for Playwright MCP server: npx @playwright/mcp)
    nodejs npm \
    # nmap (active scanning)
    nmap \
    # Ruby + WhatWeb dependencies
    ruby ruby-dev build-essential \
    # Playwright / Chromium dependencies
    chromium \
    fonts-liberation libatk-bridge2.0-0 libatk1.0-0 libcups2 \
    libdbus-1-3 libdrm2 libgbm1 libgtk-3-0 libnspr4 libnss3 \
    libx11-6 libxcomposite1 libxdamage1 libxext6 libxfixes3 \
    libxkbcommon0 libxrandr2 libxshmfence1 xdg-utils \
    # OpenSSL for TLS analysis
    openssl \
    # DNS tools: dig, nslookup, host
    dnsutils \
    # libcap2-bin for setcap (grants nmap raw socket access without running as root)
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# WhatWeb (Ruby gem is yanked; clone from source like Shannon does)
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
    && gem install addressable --no-document \
    && chmod +x /opt/whatweb/whatweb \
    && printf '#!/bin/bash\ncd /opt/whatweb && exec ./whatweb "$@"\n' \
       > /usr/local/bin/whatweb \
    && chmod +x /usr/local/bin/whatweb

# Copy Go binaries from builder stage
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/httpx     /usr/local/bin/httpx
COPY --from=go-builder /go/bin/nuclei    /usr/local/bin/nuclei

# Python package manager
RUN pip install --no-cache-dir uv

# App directory
WORKDIR /app

# Install Python dependencies (layer-cached when pyproject.toml unchanged)
COPY pyproject.toml uv.lock* ./
RUN uv sync --frozen --no-dev 2>/dev/null || uv sync --no-dev

# Copy application source
COPY adversa/ ./adversa/

# Playwright: use system Chromium instead of downloading its own
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium
# Point uv cache to /app/.cache so the non-root user can write to it
ENV UV_CACHE_DIR=/app/.cache/uv

# Install Playwright python package (already in uv deps) and link browsers
RUN uv run playwright install-deps chromium 2>/dev/null || true

# Grant nmap raw socket capability so non-root adversa user can run SYN scans
RUN setcap cap_net_raw+ep /usr/bin/nmap

# Runtime directories (overridden by volume mounts)
RUN mkdir -p /app/repos /app/runs /app/logs /app/.cache/uv

# Non-root user for security
RUN groupadd -r adversa && useradd -r -m -g adversa -u 1001 adversa \
    && chown -R adversa:adversa /app /home/adversa
USER adversa

# Health check: verify worker can import without errors
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import adversa.workflow_temporal.worker" || exit 1

# Default: run the Temporal worker
ENTRYPOINT ["uv", "run", "python", "-m", "adversa.workflow_temporal.worker"]
