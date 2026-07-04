# Dev image for the UAT hot-reload stack.
#
# Installs the backend's real dependencies (from server/pyproject.toml) so the
# image matches production, then at runtime we bind-mount server/app over /srv/app
# and run uvicorn --reload — so editing a .py file on the host reloads the API
# in ~1s without a rebuild. Build context is the repo root.
FROM python:3.12-slim
WORKDIR /srv

# Install deps via the project spec (keeps them in lockstep with prod).
COPY server/pyproject.toml ./
COPY server/app ./app
RUN pip install --no-cache-dir . --break-system-packages

# app/ is bind-mounted at runtime; --reload-dir watches those live files.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090", \
     "--reload", "--reload-dir", "/srv/app"]
