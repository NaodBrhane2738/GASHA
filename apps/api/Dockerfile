# GASHA backend (apps/api) container image.
# Build context is apps/api, so build with:  docker build -t gasha-api apps/api
FROM python:3.13-slim

# Don't write .pyc files; send logs straight to the terminal.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first: this layer is cached until requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Then copy the application code.
COPY app ./app

# Run as a normal user instead of root, and give it a writable data folder
# (the backend stores its SQLite database file here).
RUN useradd --create-home appuser && mkdir /data && chown appuser /data
USER appuser
ENV GASHA_DATABASE_PATH=/data/gasha_storage.db

EXPOSE 4000

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:4000/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "4000"]