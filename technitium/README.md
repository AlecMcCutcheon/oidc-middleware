# Technitium DNS OIDC Middleware — sanitized reference

Replace placeholder config (or set env vars) before use. See the main [app-investigation wiki](../app-investigation-wiki.md) for context.

**Example modifications:** `example-auth-modifications.js` and `example-main-modifications.css` contain only the modifications we add: (1) Inject OIDC "Login With SSO" section; form class swap to `form-login-stacked`; placeholder and panel title text; inline feedback divs under username/password; Cloudflare Turnstile widget and script; form submit prevented and routed to `login()`. (2) CSS for the OIDC section, hide Forgot Password link, full-width Login button, stacked form layout, hide duplicate dividers, dark-mode panel. (3) Override `logout()` so OIDC users go to middleware `/logout`, form-login users use the app's API logout. The full app serves `/js/auth.js` and `/css/main.css` from the middleware; our copy is the app's original plus these injections and the logout override.

**Temporary (interstitial) pages:** The middleware serves short-lived HTML pages to apply or clear tokens (see [wiki](https://github.com/AlecMcCutcheon/oidc-middleware/blob/main/README.md)). **Technitium** uses: (1) **OIDC callback success** — page that clears `token` and `oidc_login`, sets the new Technitium token and `oidc_login` in localStorage, sets OIDC and Technitium cookies, then redirects to `state`; (2) **Logout** — when an OIDC session exists, page that clears `token` and `oidc_login` from localStorage, deletes both cookies, then redirects to the IdP end-session URL (middleware also calls Technitium API logout before responding).

---

## Docker setup

### Dockerfile (sanitized)

The image needs Python 3.11, dependencies from `requirements.txt`, the middleware script, overridden `css/` and `js/`, and an entrypoint. The entrypoint uses **OpenSSL** to generate a self-signed cert at runtime if missing; if your base image does not include `openssl`, add an install step (see Authentik Dockerfile in `docs/authentik/`).

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY technitium_oidc_middleware.py .
COPY css/ ./css/
COPY js/ ./js/
COPY entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

EXPOSE 9214
ENTRYPOINT ["/app/entrypoint.sh"]
```

### Entrypoint requirements

The entrypoint must:

1. **Generate a self-signed TLS certificate** if `/app/cert.pem` and `/app/key.pem` do not exist (e.g. `openssl req -x509 -newkey rsa:4096 -keyout /app/key.pem -out /app/cert.pem -days 365 -nodes -subj "/CN=localhost"`).
2. **Start the app** with `uvicorn` over HTTPS, binding to `0.0.0.0`, using that key/cert, and listening on the port from `TECHNITIUM_PORT` (default `9214`). Use `exec` so uvicorn receives signals.

Example `entrypoint.sh` (sanitized):

```text
#!/bin/sh
if [ ! -f /app/cert.pem ] || [ ! -f /app/key.pem ]; then
    openssl req -x509 -newkey rsa:4096 -keyout /app/key.pem -out /app/cert.pem -days 365 -nodes \
        -subj "/CN=localhost"
fi
exec uvicorn technitium_oidc_middleware:app --host 0.0.0.0 --port ${TECHNITIUM_PORT:-9214} \
    --ssl-keyfile /app/key.pem --ssl-certfile /app/cert.pem --reload
```

### Docker Compose example

```yaml
technitium-oidc-middleware:
  build:
    context: ./technitium
    dockerfile: Dockerfile
  container_name: technitium-oidc-middleware
  restart: unless-stopped
  expose:
    - "9214"
  # Optional: publish to host, e.g. for LAN access
  # ports:
  #   - "0.0.0.0:9214:9214"
  volumes:
    - ./technitium/technitium_oidc_middleware.py:/app/technitium_oidc_middleware.py
    - ./technitium/css:/app/css
    - ./technitium/js:/app/js
  environment:
    - TECHNITIUM_PORT=9214
  networks:
    - your-network
```

Ensure the proxy (e.g. NPM) forwards to this container on port 9214 (HTTPS).
