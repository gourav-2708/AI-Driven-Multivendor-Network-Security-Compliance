# =============================================================================
# net-audit - self-hosted image: the C auditor, the web dashboard and its
# database (a SQLite file on the /data volume) in one container.
#
#   docker build -t net-audit .
#   docker run -d -p 8080:8080 -v net-audit-data:/data net-audit
#
# No network access is needed at run time, so the image also runs air-gapped:
# see "Self-hosting" in the README for moving it with docker save / docker load.
# =============================================================================

# ---- Stage 1: compile and self-test the auditor ------------------------------
FROM debian:bookworm-slim AS engine
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc make libc6-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY include ./include
COPY src ./src
COPY tests ./tests
# CI enforces -Werror; an image build must not fail because a newer compiler
# adds a warning, so warnings are not fatal here (as in scripts/vercel-build.sh).
RUN make EXTRA_CFLAGS=-Wno-error \
 && make test EXTRA_CFLAGS=-Wno-error

# ---- Stage 2: the dashboard ---------------------------------------------------
FROM python:3.12-slim-bookworm
# git: only needed for "Git repository" sources.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin netaudit \
 && mkdir -p /data /backups \
 && chown netaudit:netaudit /data

WORKDIR /app
COPY frontends/web/requirements.txt frontends/web/requirements.txt
RUN pip install --no-cache-dir -r frontends/web/requirements.txt gunicorn==23.0.0

COPY --from=engine /src/build/release/net-audit /usr/local/bin/net-audit
COPY frontends/web frontends/web
COPY README.md DATA-HANDLING.md ./

ENV NET_AUDIT_BIN=/usr/local/bin/net-audit \
    NET_AUDIT_DATA_DIR=/data \
    NET_AUDIT_INTAKE_ROOT=/backups \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER netaudit
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=4).status == 200 else 1)"

# One worker process: the scheduler for sources and reports runs inside it, and
# two workers would run every schedule twice. Threads handle concurrent users.
# The long timeout lets a large fleet audit or a slow Git clone finish.
CMD ["gunicorn", "--chdir", "/app/frontends/web", "--bind", "0.0.0.0:8080", \
     "--workers", "1", "--threads", "8", "--timeout", "900", \
     "--access-logfile", "-", "app:app"]
