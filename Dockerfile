# syntax=docker/dockerfile:1

# NIDS v11 dashboard/API runtime. The default command serves Streamlit; Compose
# can override it to run the read-only REST API from the same immutable image.
ARG PYTHON_VERSION=3.11
FROM python:${PYTHON_VERSION}-slim-bookworm

LABEL org.opencontainers.image.title="Smart Network Intrusion Detection System" \
      org.opencontainers.image.description="Policy-governed autonomous network intrusion detection" \
      org.opencontainers.image.version="11.0.0" \
      org.opencontainers.image.source="https://github.com/SufiyanAasim/network-analysis-intrusion-system" \
      org.opencontainers.image.licenses="MIT"

ENV HOME=/home/nids \
    NIDS_DB_PATH=/data/history.db \
    PATH=/home/nids/.local/bin:${PATH} \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1

# Scapy uses libpcap inside Linux containers. Keep update/install together so
# the package index cannot be reused independently from the install layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        iptables \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 nids \
    && useradd --create-home --no-log-init --uid 10001 --gid 10001 nids \
    && install -d -o nids -g nids /app /data

WORKDIR /app

# Dependency metadata changes less frequently than source, preserving the
# expensive scientific-Python layer across code-only rebuilds.
COPY requirements.txt ./requirements.txt
RUN python -m pip install --requirement requirements.txt

# Copy only runtime inputs. The build context is constrained by .dockerignore.
COPY --chown=nids:nids src/ ./src/
COPY --chown=nids:nids models/ ./models/
COPY --chown=nids:nids assets/ ./assets/
COPY --chown=nids:nids config/ ./config/
COPY --chown=nids:nids .streamlit/ ./.streamlit/
COPY --chown=nids:nids data/nsl-kdd/KDDTrain+.txt data/nsl-kdd/KDDTest+.txt ./data/nsl-kdd/

USER 10001:10001

EXPOSE 8501
STOPSIGNAL SIGTERM

# Read the effective port at runtime: local Docker defaults to 8501 while
# Render injects PORT. This avoids a false-unhealthy container on Render.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen(f\"http://127.0.0.1:{os.getenv('PORT','8501')}/_stcore/health\", timeout=4)"]

# `exec` makes Streamlit PID 1 after the shell expands Render's PORT, so
# SIGTERM reaches the application and graceful shutdown works.
CMD ["sh", "-c", "exec streamlit run src/nids/app.py --server.port=${PORT:-8501} --server.address=0.0.0.0 --server.headless=true --browser.gatherUsageStats=false"]
