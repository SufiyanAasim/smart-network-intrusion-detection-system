# NIDS dashboard image.
#
# Build:  docker build -t nids:latest .
# Run:    docker run -p 8501:8501 -v nids-data:/data nids:latest
#
# Notes:
# - Runs as a non-root user, so live packet capture does NOT work here by
#   default (it needs CAP_NET_RAW). Pcap upload and everything else does.
#   See docker-compose.yml for the opt-in capture setup.
# - History is written to /data (a volume), not into the container layer, so
#   it survives restarts and redeploys.

FROM python:3.11-slim

# libpcap is needed for scapy to import cleanly; tcpdump is only useful if the
# container is later run with capture privileges.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Requirements first, so the pip layer caches across code-only changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only what the app needs — `COPY . .` previously dragged in the 54 MB
# dataset tree, the notebook, dist/ and the .git directory.
COPY src/ ./src/
COPY models/ ./models/
COPY assets/ ./assets/
COPY config/ ./config/
COPY .streamlit/ ./.streamlit/
# Only the two files load_resources() actually reads.
COPY data/nsl-kdd/KDDTrain+.txt data/nsl-kdd/KDDTest+.txt ./data/nsl-kdd/

ENV NIDS_DB_PATH=/data/history.db \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1

# Run unprivileged.
RUN mkdir -p /data \
    && useradd --create-home --uid 1000 nids \
    && chown -R nids:nids /app /data
USER nids

EXPOSE 8501

# Streamlit's own health endpoint — lets Docker/Render notice a hung app.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8501/_stcore/health', timeout=4).status==200 else 1)"

# $PORT is honoured so the same image runs on Render (which injects its own
# port); falls back to 8501 locally.
CMD ["sh", "-c", "streamlit run src/nids/app.py --server.port=${PORT:-8501} --server.address=0.0.0.0 --server.headless=true --browser.gatherUsageStats=false"]
