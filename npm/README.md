# NPM (Nginx Proxy Manager) OIDC Middleware — sanitized reference

Replace placeholder config (or set env vars) before use. See the main [app-investigation wiki](../app-investigation-wiki.md) for context.

**Example modifications:** `example-modifications.js` and `example-modifications.css` show the pattern we use: (1) hide the app's React login form and render our own form that POSTs to the middleware's `/api/tokens` proxy, and (2) override the app's logout link so OIDC users go to `/logout` (middleware clears token and redirects to IdP end-session) and form-login users get localStorage cleared and a hard refresh. The real deployment overrides the app's built bundle (e.g. `index-*.js`), not a separate file; we do not include `login.js` or `UserPortalLogin.js` (those are for another app).

**Temporary (interstitial) pages:** The middleware serves short-lived HTML pages to apply or clear tokens in the browser (see [wiki §3.7](../app-investigation-wiki.md#37-temporary-interstitial-pages)). **NPM** uses: (1) **OIDC callback success** — page that clears `authentications` and `oidc_login`, sets the new token and `oidc_login` in localStorage, sets the OIDC cookie, then redirects to `state`; (2) **Logout** — page that removes `authentications` from localStorage, deletes the OIDC cookie, then redirects to the IdP end-session URL.

---

## Docker setup

### Dockerfile (sanitized)

The image needs Python 3.11, dependencies from `requirements.txt`, the middleware script, overridden `assets/`, and an entrypoint. The entrypoint uses **OpenSSL** to generate a self-signed cert at runtime if missing; if your base image does not include `openssl`, add an install step (see Authentik Dockerfile in `docs/authentik/`).

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY npm_oidc_middleware.py .
COPY assets/ ./assets/
COPY entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

EXPOSE 9215
ENTRYPOINT ["/app/entrypoint.sh"]
```

### Entrypoint requirements

The entrypoint must:

1. **Generate a self-signed TLS certificate** if `/app/cert.pem` and `/app/key.pem` do not exist (e.g. `openssl req -x509 -newkey rsa:4096 ... -subj "/CN=localhost"`).
2. **Start the app** with `uvicorn` over HTTPS, binding to `0.0.0.0`, using that key/cert, and listening on the port from `NPM_PORT` (default `9215`). Use `exec` so uvicorn receives signals.

Example `entrypoint.sh` (sanitized):

```text
#!/bin/sh
if [ ! -f /app/cert.pem ] || [ ! -f /app/key.pem ]; then
    openssl req -x509 -newkey rsa:4096 -keyout /app/key.pem -out /app/cert.pem -days 365 -nodes \
        -subj "/CN=localhost"
fi
exec uvicorn npm_oidc_middleware:app --host 0.0.0.0 --port ${NPM_PORT:-9215} \
    --ssl-keyfile /app/key.pem --ssl-certfile /app/cert.pem --reload
```

### Docker Compose example

```yaml
npm-oidc-middleware:
  build:
    context: ./npm
    dockerfile: Dockerfile
  container_name: npm-oidc-middleware
  restart: unless-stopped
  expose:
    - "9215"
  volumes:
    - ./npm/npm_oidc_middleware.py:/app/npm_oidc_middleware.py
    - ./npm/assets:/app/assets
  environment:
    - NPM_PORT=9215
  networks:
    - your-network
```

Ensure the proxy forwards to this container on port 9215 (HTTPS).
