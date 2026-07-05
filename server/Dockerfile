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
COPY server/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Stays root here deliberately — the entrypoint fixes up /data's ownership
# (needed on upgrade: a dnswatch-data volume created by an older, root-run
# image would otherwise be unwritable by appuser) and then drops to appuser
# itself before exec'ing the real command.
ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 8090
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
