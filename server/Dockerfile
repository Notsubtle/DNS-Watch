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

EXPOSE 8090
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
