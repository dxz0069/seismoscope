FROM vibe-sec-tools:latest

ARG TRIVY_VERSION=0.58.2

USER root
RUN mkdir -p /opt/trivy-cache \
    && TRIVY_CACHE_DIR=/opt/trivy-cache trivy image --download-db-only --cache-dir /opt/trivy-cache \
       --db-repository ghcr.io/aquasecurity/trivy-db:2 \
    && chmod -R a+rX /opt/trivy-cache

# Trivy opens its BoltDB read-write even with --skip-db-update. The container
# overlay is ephemeral; project source remains mounted read-only.
RUN chown -R 65532:65532 /opt/trivy-cache \
    && chmod 0755 /opt/trivy-cache /opt/trivy-cache/db \
    && chmod 0644 /opt/trivy-cache/db/*

LABEL org.opencontainers.image.title="Vibe Sec Trivy Offline Scanner" \
      org.opencontainers.image.version="${TRIVY_VERSION}" \
      io.vibe-sec.capabilities="trivy-fs-vuln,trivy-fs-misconfig,trivy-fs-secret" \
      io.vibe-sec.database="trivy-db-snapshot"

ENV TRIVY_CACHE_DIR=/opt/trivy-cache
WORKDIR /workspace
ENTRYPOINT []
