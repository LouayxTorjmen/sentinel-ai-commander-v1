FROM nginx:1.25-alpine
RUN apk add --no-cache curl
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:80/nginx-health || exit 1
