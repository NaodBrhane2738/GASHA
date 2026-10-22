# GASHA backend (apps/api) container image.
# Build context is apps/api (see infra/docker/docker-compose.yml).
# Build with:  docker build -t gasha-api apps/api
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first: this layer is cached until requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Then copy the application code.
COPY app ./app

# Non-root user; /data is available if GASHA_DB_DIALECT=sqlite.
RUN useradd --create-home appuser && mkdir /data && chown appuser /data
USER appuser

ENV PORT=4000 \
    GASHA_DATABASE_PATH=/data/gasha_storage.db

EXPOSE 4000

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:' + __import__('os').environ.get('PORT', '4000') + '/health')"

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-4000}"]
