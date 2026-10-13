FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FASTMCP_HOME=/data

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /data && chown 10001 /data

COPY gateway.py .

USER 10001
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"]

CMD ["python", "gateway.py"]
