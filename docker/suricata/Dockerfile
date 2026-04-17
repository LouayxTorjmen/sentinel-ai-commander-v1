FROM jasonish/suricata:7.0.7
LABEL maintainer="sentinel-ai"

# Install curl for healthcheck
RUN apk add --no-cache curl bash procps || apt-get update && apt-get install -y --no-install-recommends curl bash procps && rm -rf /var/lib/apt/lists/* || true

# Create log directory
RUN mkdir -p /var/log/suricata && chmod 755 /var/log/suricata

COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=60s \
    CMD kill -0 1 2>/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
