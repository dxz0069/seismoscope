FROM zricethezav/gitleaks:v8.21.2 AS gitleaks
FROM aquasec/trivy:0.58.2 AS trivy

FROM python:3.12-slim

ARG SEMGREP_VERSION=1.99.0
ARG BANDIT_VERSION=1.8.0

RUN pip install --no-cache-dir "setuptools<81" "semgrep==${SEMGREP_VERSION}" "bandit==${BANDIT_VERSION}"

COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

COPY rules/semgrep /opt/vibe-sec/rules/semgrep

LABEL org.opencontainers.image.title="Vibe Sec Focused Scanner Tools" \
      org.opencontainers.image.version="2026.07.22" \
      io.vibe-sec.capabilities="semgrep,gitleaks,bandit,trivy-cli" \
      io.vibe-sec.tools.semgrep.version="${SEMGREP_VERSION}" \
      io.vibe-sec.tools.bandit.version="${BANDIT_VERSION}" \
      io.vibe-sec.tools.gitleaks.version="8.21.2" \
      io.vibe-sec.tools.trivy.version="0.58.2"

WORKDIR /workspace
ENTRYPOINT []
