FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VSHIELD_DATA_DIR=/var/lib/vshield

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml setup.py README.md /app/
COPY src/ /app/src/

RUN pip install --no-cache-dir .

RUN mkdir -p /var/lib/vshield /etc/vshield && \
    useradd -u 10001 -r -d /var/lib/vshield -s /usr/sbin/nologin vshield && \
    chown -R vshield:vshield /var/lib/vshield /etc/vshield

USER vshield
WORKDIR /var/lib/vshield

ENTRYPOINT ["vshield"]
CMD ["--help"]
