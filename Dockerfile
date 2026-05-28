# Stage 1 – download the Bitwarden CLI binary
FROM debian:bookworm-slim AS bw-downloader

ARG BW_CLI_VERSION=2026.1.0
# BW_CLI_SHA256: set to the sha256 of bw-linux-${BW_CLI_VERSION}.zip from the GitHub release page.
# Update both ARGs together when bumping BW_CLI_VERSION.
ARG BW_CLI_SHA256=""
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && curl -sSL \
       "https://github.com/bitwarden/clients/releases/download/cli-v${BW_CLI_VERSION}/bw-linux-${BW_CLI_VERSION}.zip" \
       -o /tmp/bw.zip \
    && if [ -n "${BW_CLI_SHA256}" ]; then \
         echo "${BW_CLI_SHA256}  /tmp/bw.zip" | sha256sum -c - || exit 1; \
       fi \
    && unzip /tmp/bw.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/bw \
    && bw --version

# Stage 2 – final image
FROM python:3.12-slim

LABEL description="Bitwarden → KeePass backup — daemon with built-in scheduler and setup UI"

RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2 \
        ca-certificates \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bw-downloader /usr/local/bin/bw /usr/local/bin/bw

RUN useradd --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bitwarden_backup.py config.py daemon.py setup_server.py ./

RUN mkdir -p /backups /config && chown appuser:appuser /backups /config

ENV BACKUP_OUTPUT_DIR=/backups \
    CONFIG_PATH=/config/config.toml \
    SETUP_PORT=8080

USER appuser

EXPOSE 8080

ENTRYPOINT ["python", "daemon.py"]
