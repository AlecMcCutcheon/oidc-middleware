/**
 * Auth IP middleware has no frontend. It only exposes:
 *   POST /auth  (Bearer token + JSON { ip, uuid, app }) -> adds IP to allowed_ips.conf
 *   GET  /health
 * No JavaScript is used. This file is a placeholder so the docs folder has an example.
 */
