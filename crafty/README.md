# Crafty OIDC Middleware — sanitized reference

Replace placeholder config (or set env vars) before use. See the main [app-investigation wiki](../app-investigation-wiki.md) for context.

**Example modifications:** We do not inject JS into the Crafty app. We use a `/login` path override and serve our own MFA page (with inline CSS and script). The middleware mounts `static/` and serves our `crafty.css`, which the app loads — we use it to hide in-app user management (add user, edit username/password, MFA/passkey settings), add "Managed by OIDC Middleware" badges, and make email/username read-only. Logout is only exposed via the "Cancel and log out" link on the MFA page (`href="/logout"`). `example-modifications.css` shows our CSS overrides for the app UI; `example-modifications.js` shows the MFA page inline script excerpt and notes that no app JS is overridden.

**Temporary (interstitial) pages:** The middleware serves short-lived HTML pages to apply cookies or redirect after a short delay (see [wiki §3.7](../app-investigation-wiki.md#37-temporary-interstitial-pages)). **Crafty** uses: (1) **Post-login redirect** — after setting the Crafty cookie, for dashboard paths we serve a minimal page with a brief `setTimeout` then `window.location.href = next_url` so the cookie is persisted before the app loads; (2) **Post-MFA redirect** — after successful MFA verify we set the Crafty cookie and serve a similar delay-then-redirect page to `/`. Logout is a direct 302 to the IdP end-session URL (no interstitial; cookie-based only).

---

## Docker setup

### Dockerfile (sanitized)

The image needs Python 3.11, dependencies from `requirements.txt`, the middleware script, overridden `static/`, and an entrypoint. The entrypoint uses **OpenSSL** to generate a self-signed cert at runtime if missing; if your base image does not include `openssl`, add an install step (see Authentik Dockerfile in `docs/authentik/`).

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY crafty_oidc_middleware.py .
COPY static/ ./static/
COPY entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

EXPOSE 9213
ENTRYPOINT ["/app/entrypoint.sh"]
```

### Entrypoint requirements

The entrypoint must:

1. **Generate a self-signed TLS certificate** if `/app/cert.pem` and `/app/key.pem` do not exist (e.g. `openssl req -x509 -newkey rsa:4096 ... -subj "/CN=localhost"`).
2. **Start the app** with `uvicorn` over HTTPS, binding to `0.0.0.0`, using that key/cert, and listening on the port from `CRAFTY_PORT` (default `9213`). Use `exec` so uvicorn receives signals.

Example `entrypoint.sh` (sanitized):

```text
#!/bin/sh
if [ ! -f /app/cert.pem ] || [ ! -f /app/key.pem ]; then
    openssl req -x509 -newkey rsa:4096 -keyout /app/key.pem -out /app/cert.pem -days 365 -nodes \
        -subj "/CN=localhost"
fi
exec uvicorn crafty_oidc_middleware:app --host 0.0.0.0 --port ${CRAFTY_PORT:-9213} \
    --ssl-keyfile /app/key.pem --ssl-certfile /app/cert.pem --reload
```

### Docker Compose example

```yaml
crafty-oidc-middleware:
  build:
    context: ./crafty
    dockerfile: Dockerfile
  container_name: crafty-oidc-middleware
  restart: unless-stopped
  expose:
    - "9213"
  volumes:
    - ./crafty/crafty_oidc_middleware.py:/app/crafty_oidc_middleware.py
    - ./crafty/static:/app/static
  environment:
    - CRAFTY_PORT=9213
  networks:
    - your-network
```

Ensure the proxy forwards to this container on port 9213 (HTTPS).
