# MERIDIAN - one image, several roles (api | worker | agents | scheduler | syslog), non-root, read-only friendly.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 MERIDIAN_LOG_FORMAT=json
WORKDIR /app
RUN groupadd -r meridian && useradd -r -g meridian -d /app meridian
COPY requirements.txt .
RUN pip install -r requirements.txt
# DuckDB reads s3:// and abfss:// lakes through extensions; bake them in so containers need no internet egress
RUN HOME=/app python -c "import duckdb; c=duckdb.connect(); c.execute('INSTALL httpfs'); c.execute('INSTALL azure')"
COPY meridian ./meridian
COPY config ./config
RUN mkdir -p /app/data && chown -R meridian:meridian /app/data /app/.duckdb
USER meridian
ENV HOME=/app
EXPOSE 8090 5514/udp 5514
# Health checks are defined per role by the orchestrator (only the api role serves HTTP):
# Compose healthcheck on the api service, ALB / Container Apps probes on /healthz and /readyz.
ENTRYPOINT ["python", "-m", "meridian"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8090"]
