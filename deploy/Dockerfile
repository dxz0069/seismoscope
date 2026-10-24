FROM node:20-bookworm-slim AS frontend-build

WORKDIR /build/frontend-v2
COPY frontend-v2/package.json frontend-v2/package-lock.json ./
RUN npm ci
COPY frontend-v2/ ./
RUN npm run build

FROM python:3.11-slim-bookworm AS api

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VIBE_SEC_STATE_HOME=/var/lib/vibe-sec \
    VIBE_SEC_API_DB_PATH=/var/lib/vibe-sec/api-state.sqlite3 \
    VIBE_SEC_VRTM_STATE_DIR=/var/lib/vibe-sec/vrtm

WORKDIR /app
COPY . ./
RUN pip install . \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin vibe-sec \
    && mkdir -p /var/lib/vibe-sec \
    && chown -R vibe-sec:vibe-sec /app /var/lib/vibe-sec \
    && chmod 0555 /app/deploy/entrypoint.sh

USER vibe-sec
VOLUME ["/var/lib/vibe-sec"]
EXPOSE 8000
ENTRYPOINT ["/app/deploy/entrypoint.sh"]
CMD ["python", "-m", "uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8000"]

FROM nginx:1.27-alpine AS web

COPY --from=frontend-build /build/frontend-v2/dist /usr/share/nginx/html
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
