# Stage 1: build the frontend
FROM node:20-slim AS web-build
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ ./
RUN npm run build

# Stage 2: python runtime serving API + built frontend
FROM python:3.12-slim
WORKDIR /srv

COPY server/pyproject.toml ./
COPY server/app ./app
RUN pip install --no-cache-dir . --break-system-packages

COPY --from=web-build /web/dist ./app/static

# Run as a non-root user. UID 1000 matches the default first-user UID on
# most single-user Linux hosts (Docker Desktop, typical homelab boxes), so
# it lines up with the bind-mounted volumes' ownership without extra setup
# in the common case; override via `docker run --user` if your host's
# PIHOLE_ETC_PATH/dnswatch-data need a different UID/GID to be readable.
RUN useradd -r -u 1000 appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /srv /data
USER appuser

EXPOSE 8090
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
