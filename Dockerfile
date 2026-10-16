FROM python:3.12-slim

# openssl CLI is required by fileguard/checkpoint.py (RFC 3161 anchoring)
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 8000
CMD ["bash", "docker-entrypoint.sh"]
