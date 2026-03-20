# Stage 1 – download the Bitwarden CLI binary
FROM debian:bookworm-slim AS bw-downloader

ARG BW_CLI_VERSION=2026.1.0
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && curl -sSL \
       "https://github.com/bitwarden/clients/releases/download/cli-v${BW_CLI_VERSION}/bw-linux-${BW_CLI_VERSION}.zip" \
       -o /tmp/bw.zip \
    && unzip /tmp/bw.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/bw \
    && bw --version

# Stage 2 – final image
FROM python:3.12-slim

LABEL description="Bitwarden → KeePass backup container"

# libxml2 required by pykeepass
RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2 \
        ca-certificates \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bw-downloader /usr/local/bin/bw /usr/local/bin/bw

RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bitwarden_backup.py .

RUN mkdir -p /backups && chown appuser:appuser /backups

ENV BACKUP_OUTPUT_DIR=/backups

USER appuser

# one-shot: runs the backup and exits; scheduling is handled externally
ENTRYPOINT ["python", "bitwarden_backup.py"]
