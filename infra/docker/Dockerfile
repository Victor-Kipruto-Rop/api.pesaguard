# PesaGuard API image (ASGI control plane mounting the Flask dashboard API).
#
# Runs as an unprivileged user under uvicorn, not Flask's development server.
# The same image also runs the RQ worker in docker-compose (worker_entrypoint.sh).
#
# Runtime knobs (all optional):
#   PORT             listen port                              (default 5001)
#   WEB_CONCURRENCY  uvicorn worker processes                 (default 2)
#   FORWARDED_ALLOW_IPS  proxy IPs whose X-Forwarded-* headers are trusted
#                    (uvicorn reads this itself; default is 127.0.0.1, so set
#                     it to your load balancer's address behind Render/nginx)
FROM python:3.12-slim

ARG PESAGUARD_BUILD_REVISION=unknown

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app:/app/pesaguard_backend_pipeline \
    PESAGUARD_ENVIRONMENT=production \
    PESAGUARD_BUILD_REVISION=${PESAGUARD_BUILD_REVISION} \
    PESAGUARD_SHARED_METRICS=1 \
    PROMETHEUS_MULTIPROC_DIR=/tmp/pesaguard-prometheus \
    PORT=5001 \
    WEB_CONCURRENCY=2

WORKDIR /app

# Runtime dependencies only (test tools are in requirements-dev.txt). Copied on
# its own so this layer is cached until the requirements change.
COPY pesaguard_backend_pipeline/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

RUN groupadd --system --gid 10001 pesaguard \
    && useradd --uid 10001 --gid pesaguard --home-dir /app --no-create-home --shell /usr/sbin/nologin pesaguard \
    && mkdir -p /tmp/pesaguard-prometheus \
    && chown pesaguard:pesaguard /tmp/pesaguard-prometheus

COPY --chown=pesaguard:pesaguard . .
RUN sed -i 's/\r$//' pesaguard_backend_pipeline/worker_entrypoint.sh

USER pesaguard
EXPOSE 5001

# Liveness only: /livez checks no dependencies, so a Kafka, Redis or Safaricom
# outage never marks the container unhealthy. Readiness, including the database,
# is /health (503 when the database is unreachable).
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/livez' % os.getenv('PORT', '5001'), timeout=4)"]

CMD ["sh", "-c", "exec uvicorn pesaguard_backend_pipeline.fastapi_app:app --host 0.0.0.0 --port ${PORT:-5001} --workers ${WEB_CONCURRENCY:-2} --proxy-headers"]
