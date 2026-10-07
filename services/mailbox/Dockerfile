# Self-hosted Silk mailbox. Bring your own OAuth provider and PostgreSQL;
# terminate TLS in front of this container. See docs/SELF_HOSTING.md.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin silk

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY silk_live ./silk_live
COPY migrations ./migrations
COPY scripts ./scripts

USER silk
EXPOSE 8790

# The service only answers its configured resource host, so send that Host.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["python", "-c", "import os,urllib.request as u;from urllib.parse import urlsplit;h=urlsplit(os.environ.get('SILK_RESOURCE_URL') or 'http://127.0.0.1').netloc;u.urlopen(u.Request('http://127.0.0.1:8790/health',headers={'Host':h}),timeout=4)"]

# Access logs stay off: they can carry bearer-adjacent request metadata.
CMD ["uvicorn", "silk_live.asgi:app", "--host", "0.0.0.0", "--port", "8790", "--lifespan", "on", "--no-access-log"]
