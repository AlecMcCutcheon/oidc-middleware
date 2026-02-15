# Auth IP NPM Middleware — sanitized reference

API to add IPs to per-app `allowed_ips.conf` with token auth; used with Authentik policies for local-only apps. Set `AUTH_TOKEN` and `NPM_RELOAD_URL` (or env). See the main [app-investigation wiki](../app-investigation-wiki.md) Bonus section for setup.

**Example modifications:** This service has no frontend (API only). `example-modifications.js` and `example-modifications.css` are placeholders so the docs layout is consistent.

---

## Docker setup

### Dockerfile (sanitized)

The image needs Python 3.11, dependencies, the middleware script, `conf/`, and an entrypoint. This service **explicitly installs OpenSSL** in the image so the entrypoint can generate a self-signed cert at runtime.

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*

COPY auth_ip_npm_middleware.py .
COPY conf/ ./conf/
COPY entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

EXPOSE 9216
ENTRYPOINT ["/app/entrypoint.sh"]
```

### Entrypoint requirements

The entrypoint must:

1. **Generate a self-signed TLS certificate** if `/app/cert.pem` and `/app/key.pem` do not exist (e.g. `openssl req -x509 -newkey rsa:4096 ... -subj "/CN=localhost"`).
2. **Start the app** with `uvicorn` over HTTPS, binding to `0.0.0.0`, using that key/cert, and listening on the port from `AUTH_PORT` (default `9216`). Use `exec` so uvicorn receives signals.

Example `entrypoint.sh` (sanitized):

```text
#!/bin/sh
if [ ! -f /app/cert.pem ] || [ ! -f /app/key.pem ]; then
    openssl req -x509 -newkey rsa:4096 -keyout /app/key.pem -out /app/cert.pem -days 365 -nodes \
        -subj "/CN=localhost"
fi
exec uvicorn auth_ip_npm_middleware:app --host 0.0.0.0 --port ${AUTH_PORT:-9216} \
    --ssl-keyfile /app/key.pem --ssl-certfile /app/cert.pem --reload
```

### Docker Compose example

```yaml
auth-ip-npm-middleware:
  build:
    context: ./authentik
    dockerfile: Dockerfile
  container_name: auth-ip-npm-middleware
  restart: unless-stopped
  expose:
    - "9216"
  volumes:
    - ./authentik/auth_ip_npm_middleware.py:/app/auth_ip_npm_middleware.py
    - ./authentik/conf:/app/conf
  environment:
    - AUTH_PORT=9216
  networks:
    - your-network
```

Only other services (e.g. Authentik outpost) need to reach this API on port 9216 (HTTPS); no public proxy is required.
