from fastapi import FastAPI, Request, Response, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import httpx
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError
import asyncio
import logging
import time
from urllib.parse import urlencode
import hashlib
import hmac
import base64
import os
import json
from datetime import datetime, timezone

# ==============================
# Configs (sanitized: set your own IdP, NPM, and Turnstile values)
# ==============================
AUTHENTIK_ISSUER = os.environ.get("AUTHENTIK_ISSUER", "https://your-idp.example.com")
AUTHENTIK_CLIENT_ID = os.environ.get("AUTHENTIK_CLIENT_ID", "YOUR_CLIENT_ID")
AUTHENTIK_CLIENT_SECRET = os.environ.get("AUTHENTIK_CLIENT_SECRET", "YOUR_CLIENT_SECRET")
AUTHENTIK_REDIRECT_URI = os.environ.get("AUTHENTIK_REDIRECT_URI", "https://your-npm-domain.example.com/oidc/callback")
OPENID_DISCOVERY = f"{AUTHENTIK_ISSUER}/application/o/npm/.well-known/openid-configuration"

# NPM API (FQDN only for redirect_uri / browser; use internal URL for server-side calls)
NPM_EMAIL = os.environ.get("NPM_EMAIL", "your-service-account@example.com")
NPM_PASS = os.environ.get("NPM_PASS", "YOUR_SERVICE_ACCOUNT_PASSWORD")

# NPM internal: direct to container/host so requests don't go through the proxy.
NPM_INTERNAL_BASE = os.environ.get("NPM_INTERNAL_BASE", "http://your-npm-container:3000")

# Cloudflare Turnstile (server-side verification)
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "YOUR_TURNSTILE_SECRET")

# Login attempt lockout (per email/identity, in-memory)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 3600
_login_attempts: dict = {}
_login_attempts_lock = asyncio.Lock()

# Scheduled task: PUT default-site every 30s so NPM reloads (no user feedback)
NPM_DEFAULT_SITE_PUT_BODY = {"value": "444", "meta": {"redirect": "", "html": ""}}
NPM_DEFAULT_SITE_RELOAD_INTERVAL = 30

COOKIE_OIDC = "oidc_session"
COOKIE_NPM = "npm_token"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("npm_oidc")

app = FastAPI()




# Mount static files directory (assets)
assets_dir = os.path.join(os.path.dirname(__file__), "assets")
if os.path.exists(assets_dir):
    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

# ==============================
# Helpers
# ==============================
def log_http_error(operation: str, error: httpx.HTTPStatusError, context: str = "", expected: bool = False):
    """
    Log detailed HTTP error information for debugging.
    
    Args:
        operation: Description of what operation was being performed
        error: The HTTPStatusError exception
        context: Additional context information
        expected: If True, log as warning instead of error (for expected errors like 403)
    """
    response = error.response
    status_code = response.status_code
    url = str(response.url)
    
    # Try to get response body
    try:
        response_text = response.text
        try:
            response_json = response.json()
            response_body = f"JSON: {response_json}"
        except:
            response_body = f"Text: {response_text[:500]}"  # Limit to 500 chars
    except:
        response_body = "Unable to read response body"
    
    # Use warning for expected errors, error for unexpected ones
    log_level = logger.warning if expected else logger.error
    log_level(f"HTTP Error in {operation} (Status {status_code})")
    if context:
        logger.debug(f"  Context: {context}")
    logger.debug(f"  URL: {url}")
    logger.debug(f"  Response Body: {response_body}")

async def fetch_jwks():
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.get(OPENID_DISCOVERY)
            resp.raise_for_status()
            jwks_uri = resp.json()["jwks_uri"]
            jwk_resp = await client.get(jwks_uri)
            jwk_resp.raise_for_status()
            return jwk_resp.json()
        except httpx.HTTPStatusError as e:
            log_http_error("fetch_jwks", e, "Failed to fetch JWKS from Authentik")
            raise

def decode_oidc_token(id_token: str, jwks: dict):
    header = jwt.get_unverified_header(id_token)
    key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    return jwt.decode(id_token, key, algorithms=["RS256"], audience=AUTHENTIK_CLIENT_ID)

async def login_to_npm(email: str, password: str) -> tuple[str, str]:
    """
    Authenticate with NPM API using email and password.
    Returns tuple: (token, expires)
    """
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.post(
                f"{NPM_INTERNAL_BASE.rstrip('/')}/tokens",
                json={"identity": email, "secret": password},
                headers={"Content-Type": "application/json"}
            )
            resp.raise_for_status()
            data = resp.json()
            token = data.get("token")
            expires = data.get("expires")
            if not token:
                raise ValueError("No token in NPM API response")
            return token, expires
        except httpx.HTTPStatusError as e:
            log_http_error("NPM login", e, f"Email: {email}")
            raise

async def get_npm_users(npm_token: str) -> list[dict]:
    """
    Get list of NPM users using Bearer token authentication.
    Returns list of user objects with id, email, name, roles, permissions, etc.
    """
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.get(
                f"{NPM_INTERNAL_BASE.rstrip('/')}/users?expand=permissions",
                headers={"Authorization": f"Bearer {npm_token}"}
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            log_http_error("get NPM users", e, "Fetching user list")
            raise

async def find_npm_user_by_email(npm_token: str, email: str) -> tuple[dict | None, int | None]:
    """
    Find an NPM user by email address.
    Returns tuple: (user dict if found, None otherwise, user_id for login endpoint)
    The login endpoint uses the user ID (user.get('id'))
    """
    users = await get_npm_users(npm_token)
    for user in users:
        if user.get("email", "").lower() == email.lower():
            user_id = user.get("id")
            return user, user_id
    return None, None

async def create_npm_user(npm_token: str, email: str, name: str, nickname: str, groups: list[str]) -> dict:
    """
    Create a new NPM user using the admin token.
    
    Args:
        npm_token: Admin service account token
        email: User's email address
        name: User's name (will use UUID hash or similar)
        nickname: User's preferred username/nickname
        groups: List of groups from OIDC (to determine roles)
    
    Returns:
        Created user dict
    """
    async with httpx.AsyncClient(verify=False) as client:
        try:
            # Determine roles based on groups - check if user is in Authentik "admins" group
            roles = ["admin"] if "admins" in groups else []
            
            create_data = {
                "email": email,
                "name": name,
                "nickname": nickname,
                "roles": roles,
                "is_disabled": False
            }
            
            resp = await client.post(
                f"{NPM_INTERNAL_BASE.rstrip('/')}/users",
                headers={"Authorization": f"Bearer {npm_token}"},
                json=create_data
            )
            resp.raise_for_status()
            created_user = resp.json()
            logger.info(f"User created successfully: {email} (ID: {created_user.get('id')})")
            return created_user
        except httpx.HTTPStatusError as e:
            log_http_error("create NPM user", e, f"Creating user {email}")
            raise

async def login_as_user(npm_token: str, user_id: int) -> dict:
    """
    Call the login endpoint to create a new token for the user.
    The endpoint returns the token in the response.
    
    Args:
        npm_token: Admin service account token (used for authentication)
        user_id: User ID (from user.get('id'))
    
    Returns:
        Dict with 'token' and 'expires' keys
    """
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.post(
                f"{NPM_INTERNAL_BASE.rstrip('/')}/users/{user_id}/login",
                headers={"Authorization": f"Bearer {npm_token}"}
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            log_http_error("login as user", e, f"User ID: {user_id}")
            raise


async def _put_default_site_setting(token: str) -> bool:
    """
    PUT to NPM settings/default-site to trigger proxy manager reload.
    Returns True on success, False on auth failure or error (caller should refresh token).
    """
    url = f"{NPM_INTERNAL_BASE.rstrip('/')}/settings/default-site"
    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        try:
            resp = await client.put(
                url,
                json=NPM_DEFAULT_SITE_PUT_BODY,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
            if resp.status_code in (401, 403):
                logger.debug("default-site PUT auth failed (status %s), token may be expired", resp.status_code)
                return False
            resp.raise_for_status()
            return True
        except httpx.HTTPStatusError as e:
            log_http_error("default-site PUT", e, "NPM reload trigger")
            return False
        except Exception as e:
            logger.warning("default-site PUT failed: %s", e)
            return False


async def _npm_reload_loop() -> None:
    """
    Background task: get service token, then every 30s PUT default-site to trigger NPM reload.
    On PUT auth failure, re-login and continue.
    """
    token = None
    while True:
        try:
            await asyncio.sleep(1)  # brief delay before first login
            if token is None:
                token, _ = await login_to_npm(NPM_EMAIL, NPM_PASS)
                logger.info("NPM reload task: got service token")
            ok = await _put_default_site_setting(token)
            if not ok:
                token = None  # force re-login on next iteration
            await asyncio.sleep(NPM_DEFAULT_SITE_RELOAD_INTERVAL)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning("NPM reload task error: %s", e)
            token = None
            await asyncio.sleep(NPM_DEFAULT_SITE_RELOAD_INTERVAL)


async def verify_turnstile(token: str, remote_ip: str | None = None) -> bool:
    """
    Verify a Turnstile token with Cloudflare Siteverify API.
    Returns True if valid, False otherwise.
    """
    if not token or not TURNSTILE_SECRET:
        return False
    async with httpx.AsyncClient(verify=True, timeout=10.0) as client:
        try:
            payload = {"secret": TURNSTILE_SECRET, "response": token}
            if remote_ip:
                payload["remoteip"] = remote_ip
            resp = await client.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            return bool(data.get("success") is True)
        except Exception as e:
            logger.warning("Turnstile siteverify failed: %s", e)
            return False

def _client_signature(request: Request) -> str:
    """
    Stable identifier for the client (IP + User-Agent hash).
    Lockout is per client, not per identity, so one client cannot lock out another user's account.
    """
    client_host = request.client.host if request.client else None
    forwarded = request.headers.get("x-forwarded-for")
    remote_ip = (forwarded or "").split(",")[0].strip() if forwarded else client_host or "unknown"
    ua = (request.headers.get("user-agent") or "").strip()[:200]
    ua_part = hashlib.sha256(ua.encode()).hexdigest()[:16] if ua else "no-ua"
    return f"{remote_ip}|{ua_part}"


def _npm_error_json(message: str, lockout: bool = False, attempts_left: int | None = None) -> dict:
    """NPM-style error JSON with optional lockout/attempts_left for client."""
    out = {
        "error": {
            "code": 400,
            "message": message,
            "message_i18n": "error.invalid-auth",
        }
    }
    if lockout:
        out["lockout"] = True
    if attempts_left is not None:
        out["attempts_left"] = attempts_left
    return out


def _decode_secret_payload(secret: str) -> tuple[str | None, str | None]:
    """
    Decode secret field: base64(JSON.stringify({ password, turnstile })).
    Returns (password, turnstile_token). turnstile_token may be None.
    If decoding fails, returns (None, None) and caller may treat secret as plain password.
    """
    if not secret:
        return None, None
    try:
        raw = base64.b64decode(secret, validate=True).decode("utf-8")
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            return None, None
        password = obj.get("password") if isinstance(obj.get("password"), str) else None
        turnstile = obj.get("turnstile")
        turnstile = turnstile if isinstance(turnstile, str) and turnstile else None
        return password, turnstile
    except Exception:
        return None, None

# ==============================
# Routes
# ==============================
@app.post("/api/tokens")
async def proxy_tokens(request: Request):
    """
    Proxy for NPM token endpoint. Accepts same shape as NPM:
    { "identity": "<email>", "secret": "<base64 payload>" }.

    Payload format: secret = base64(JSON.stringify({ password, turnstile })).
    Turnstile token is required and verified; invalid or missing token returns "Invalid cloudflare token".
    """
    # Accept JSON or form body
    content_type = request.headers.get("content-type", "") or ""
    if "application/json" in content_type:
        body = await request.json()
    else:
        form = await request.form()
        body = dict(form)

    identity = (body.get("identity") or body.get("email") or "").strip()
    secret = body.get("secret") or body.get("password")
    if isinstance(secret, str):
        secret = secret.strip()
    else:
        secret = ""

    if not identity:
        return Response(
            content=json.dumps({
                "error": {
                    "code": 400,
                    "message": "Invalid email or password",
                    "message_i18n": "error.invalid-auth",
                }
            }),
            status_code=400,
            media_type="application/json",
        )

    password = None
    turnstile_token = None
    decoded = _decode_secret_payload(secret)
    if decoded[0] is None:
        return Response(
            content=json.dumps({
                "error": {
                    "code": 400,
                    "message": "Please complete the verification",
                    "message_i18n": "error.invalid-auth",
                    "reason": "turnstile",
                }
            }),
            status_code=400,
            media_type="application/json",
        )
    password, turnstile_token = decoded

    if not password:
        return Response(
            content=json.dumps({
                "error": {
                    "code": 400,
                    "message": "Invalid email or password",
                    "message_i18n": "error.invalid-auth",
                }
            }),
            status_code=400,
            media_type="application/json",
        )

    if not turnstile_token:
        return Response(
            content=json.dumps({
                "error": {
                    "code": 400,
                    "message": "Please complete the verification",
                    "message_i18n": "error.invalid-auth",
                    "reason": "turnstile",
                }
            }),
            status_code=400,
            media_type="application/json",
        )
    client_host = request.client.host if request.client else None
    forwarded = request.headers.get("x-forwarded-for")
    remote_ip = (forwarded or "").split(",")[0].strip() if forwarded else client_host
    if not await verify_turnstile(turnstile_token, remote_ip):
        return Response(
            content=json.dumps({
                "error": {
                    "code": 400,
                    "message": "Invalid cloudflare token",
                    "message_i18n": "error.invalid-auth",
                    "reason": "turnstile",
                }
            }),
            status_code=400,
            media_type="application/json",
        )

    key = _client_signature(request)
    async with _login_attempts_lock:
        now = time.time()
        rec = _login_attempts.get(key)
        if rec and rec.get("locked_until") and now < rec["locked_until"]:
            return Response(
                content=json.dumps(_npm_error_json("Account locked. Try again in 1 hour.", lockout=True)),
                status_code=400,
                media_type="application/json",
            )
        if rec and rec.get("locked_until") and now >= rec["locked_until"]:
            _login_attempts[key] = {"failed": 0, "locked_until": None}

    # Forward to internal NPM
    try:
        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            url = f"{NPM_INTERNAL_BASE.rstrip('/')}/tokens"
            resp = await client.post(
                url,
                json={"identity": identity, "secret": password},
                headers={"Content-Type": "application/json"},
            )
            content = resp.content
            media_type = resp.headers.get("content-type") or "application/json"

            try:
                data = resp.json()
            except Exception:
                return Response(content=content, status_code=resp.status_code, media_type=media_type)

            if data.get("token"):
                async with _login_attempts_lock:
                    _login_attempts.pop(key, None)
                return Response(content=content, status_code=resp.status_code, media_type=media_type)

            err_obj = data.get("error") or {}
            err_msg = err_obj.get("message") or "Invalid email or password"
            async with _login_attempts_lock:
                rec = _login_attempts.get(key) or {"failed": 0, "locked_until": None}
                rec["failed"] = rec.get("failed", 0) + 1
                if rec["failed"] >= MAX_LOGIN_ATTEMPTS:
                    rec["locked_until"] = time.time() + LOCKOUT_SECONDS
                _login_attempts[key] = rec
                attempts_left = max(0, MAX_LOGIN_ATTEMPTS - rec["failed"])
                just_locked = rec.get("locked_until") and rec["failed"] >= MAX_LOGIN_ATTEMPTS
            if just_locked:
                return Response(
                    content=json.dumps(_npm_error_json("Account locked. Try again in 1 hour.", lockout=True)),
                    status_code=400,
                    media_type="application/json",
                )
            return Response(
                content=json.dumps(_npm_error_json(err_msg, attempts_left=attempts_left)),
                status_code=400,
                media_type="application/json",
            )
    except Exception as e:
        logger.exception("Proxy tokens to NPM failed: %s", e)
        return Response(
            content=json.dumps({
                "error": {
                    "code": 500,
                    "message": "Service temporarily unavailable",
                    "message_i18n": "error.invalid-auth",
                }
            }),
            status_code=500,
            media_type="application/json",
        )


RELOAD_TIMEOUT_SECONDS = 20  # ensure we always return a response within this time


@app.post("/reload")
async def reload_npm():
    """
    Trigger NPM to reload by PUTting default-site settings (no-op value change).
    Uses service account to get a token, then calls internal NPM API. Always
    returns a JSON response within RELOAD_TIMEOUT_SECONDS so callers don't see "disconnected".
    """
    payload_ok = {"ok": True}
    payload_fail = lambda msg: {"ok": False, "error": msg}

    async def _do_reload() -> tuple[dict, int]:
        try:
            token, _ = await login_to_npm(NPM_EMAIL, NPM_PASS)
        except Exception as e:
            logger.exception("Reload: service login failed: %s", e)
            return payload_fail("Service login failed"), 500
        url = f"{NPM_INTERNAL_BASE.rstrip('/')}/settings/default-site"
        body = {"value": "444", "meta": {"redirect": "", "html": ""}}
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                resp = await client.put(
                    url,
                    json=body,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                )
                resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            log_http_error("NPM reload (default-site PUT)", e, "Reload endpoint")
            return payload_fail(f"NPM returned {e.response.status_code}"), 500
        except Exception as e:
            logger.exception("Reload: PUT failed: %s", e)
            return payload_fail("Request failed"), 500
        return payload_ok, 200

    try:
        data, status = await asyncio.wait_for(_do_reload(), timeout=RELOAD_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning("Reload: timed out after %s seconds", RELOAD_TIMEOUT_SECONDS)
        data, status = payload_fail("Reload timed out"), 503
    body_bytes = json.dumps(data).encode("utf-8")
    return Response(
        content=body_bytes,
        status_code=status,
        media_type="application/json",
        headers={"Content-Length": str(len(body_bytes))},
    )


@app.get("/login")
async def login(request: Request):
    """OIDC login endpoint - redirects to Authentik for authentication"""
    next_url = request.query_params.get("next", "/")
    
    # Always proceed with full OIDC login flow - don't check for existing tokens
    # The login flow will clear tokens in the intermediate page and set new ones
    # This ensures a clean login process every time
    state = next_url
    auth_url = (
        f"{AUTHENTIK_ISSUER}/application/o/authorize/"
        f"?client_id={AUTHENTIK_CLIENT_ID}"
        f"&redirect_uri={AUTHENTIK_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=openid email profile"
        f"&state={state}"
    )
    
    # Clear OIDC cookie before starting new login flow
    response = RedirectResponse(url=auth_url)
    is_https = request.url.scheme == "https"
    response.set_cookie(key=COOKIE_OIDC, value="", path="/", max_age=0, httponly=True, secure=is_https)
    return response

@app.get("/oidc/callback")
async def oidc_callback(request: Request):
    """OIDC callback - exchanges code for token, gets NPM token, sets localStorage"""
    code = request.query_params.get("code")
    state = request.query_params.get("state", "/")
    
    if not code:
        logger.error("No authorization code in callback")
        return RedirectResponse(url="/login")
    
    # Exchange code for token
    async with httpx.AsyncClient(verify=False) as client:
        try:
            token_resp = await client.post(
                f"{AUTHENTIK_ISSUER}/application/o/token/",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": AUTHENTIK_REDIRECT_URI,
                    "client_id": AUTHENTIK_CLIENT_ID,
                    "client_secret": AUTHENTIK_CLIENT_SECRET,
                },
            )
            token_resp.raise_for_status()
            token_data = token_resp.json()
            id_token = token_data.get("id_token")
            
            if not id_token:
                logger.error("No id_token in token response")
                return RedirectResponse(url="/login")
            
            # Decode and validate token
            jwks = await fetch_jwks()
            claims = decode_oidc_token(id_token, jwks)
            
            email = claims.get("email")
            if not email:
                logger.error("No email in OIDC claims")
                return RedirectResponse(url="/login")
            
            username = claims.get("preferred_username") or claims.get("sub", "")
            sub = claims.get("sub")  # Get UUID from Authentik
            name = claims.get("name")  # Authentik User.name field (display name)
            groups = claims.get("groups", [])
            
            # Get service account token for user management
            service_token, service_expires = await login_to_npm(NPM_EMAIL, NPM_PASS)
            
            # Find user by email and get their login index (1-indexed array position)
            user, user_index = await find_npm_user_by_email(service_token, email)
            
            if not user or not user_index:
                # User doesn't exist - create them
                logger.info(f"User {email} not found, creating new user")
                try:
                    # Use Authentik name for name field, UUID for nickname
                    created_user = await create_npm_user(
                        service_token,
                        email=email,
                        name=name or email,  # Use Authentik name, fallback to email
                        nickname=sub,  # Use Authentik UUID
                        groups=groups
                    )
                    
                    # Use the created user's ID directly for login
                    user_id = created_user.get("id")
                    if not user_id:
                        logger.error(f"Created user {email} but no ID in response")
                        return HTMLResponse(
                            content=f"""
                            <html>
                            <body>
                                <p>User created but could not retrieve user ID. Please try logging in again.</p>
                                <a href="/login">Try again</a>
                            </body>
                            </html>
                            """,
                            status_code=500
                        )
                    
                    # Set user and user_index from created user
                    user = created_user
                    user_index = user_id  # Use user ID for login endpoint
                    logger.info(f"User {email} created successfully with ID {user_id}")
                except httpx.HTTPStatusError as create_err:
                    log_http_error("user creation", create_err, f"Creating user {email}")
                    return HTMLResponse(
                        content=f"""
                        <html>
                        <body>
                            <p>Failed to create user {email}. Please contact an administrator.</p>
                            <a href="/login">Try again</a>
                        </body>
                        </html>
                        """,
                        status_code=500
                    )
            
            # Call the login endpoint to create a new token for the user
            # The endpoint returns the token directly in the response
            user_id = user.get('id')
            logger.info(f"Creating login token for user {email} (ID: {user_id})")
            login_response = await login_as_user(service_token, user_id)
            
            npm_token = login_response.get("token")
            expires = login_response.get("expires")
            
            if not npm_token:
                logger.error(f"No token in login response for user {email}")
                return HTMLResponse(
                    content=f"""
                    <html>
                    <body>
                        <p>Failed to retrieve token. Please try logging in again.</p>
                        <a href="/login">Try again</a>
                    </body>
                    </html>
                    """,
                    status_code=500
                )
            
            # Set token in localStorage and redirect
            logger.info(f"User {email} authenticated, setting token in browser")
            
            # Escape the token and URL for JavaScript
            token_escaped = json.dumps(npm_token)
            expires_escaped = json.dumps(expires)
            url_escaped = json.dumps(state)
            
            # Set OIDC session cookie and return HTML that sets token in localStorage
            response = HTMLResponse(content=f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Logging in...</title>
                <style>
                    body {{
                        margin: 0;
                        padding: 0;
                        background-color: #000000;
                        color: #000000;
                        font-family: Arial, sans-serif;
                    }}
                </style>
            </head>
            <body>
                <script>
                    // Clear any existing session tokens and flags first
                    localStorage.removeItem('authentications');
                    localStorage.removeItem('oidc_login');
                    
                    // Get existing authentications array or create new one
                    let authentications = [];
                    try {{
                        const existing = localStorage.getItem('authentications');
                        if (existing) {{
                            authentications = JSON.parse(existing);
                        }}
                    }} catch (e) {{
                        console.warn('Failed to parse existing authentications:', e);
                    }}
                    
                    // Add new token to the array
                    authentications.push({{
                        token: {token_escaped},
                        expires: {expires_escaped}
                    }});
                    
                    // Save back to localStorage
                    localStorage.setItem('authentications', JSON.stringify(authentications));
                    // Set flag to indicate OIDC login (for logout detection)
                    localStorage.setItem('oidc_login', 'true');
                    
                    // Redirect to destination
                    window.location.href = {url_escaped};
                </script>
            </body>
            </html>
            """)
            response.set_cookie(key=COOKIE_OIDC, value=id_token, httponly=True, path="/", max_age=86400)
            return response
            
        except httpx.HTTPStatusError as e:
            log_http_error("OIDC token exchange", e, "Failed to exchange authorization code")
            return RedirectResponse(url="/login")
        except Exception as e:
            logger.error(f"Error in OIDC callback: {e}")
            return RedirectResponse(url="/login")

@app.get("/logout")
async def logout(request: Request):
    """Logout endpoint - clears localStorage token and OIDC cookie, redirects to Authentik logout"""
    logger.info("Logging out user")
    
    # Clear OIDC session cookie
    end_session_url = f"{AUTHENTIK_ISSUER}/application/o/npm/end-session/"
    response = HTMLResponse(content=f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Logging out...</title>
        <style>
            body {{
                margin: 0;
                padding: 0;
                background-color: #000000;
                color: #000000;
                font-family: Arial, sans-serif;
            }}
        </style>
    </head>
    <body>
        <script>
            // Clear NPM token from localStorage (NPM uses 'authentications' key)
            localStorage.removeItem('authentications');
            
            // Redirect to Authentik end-session endpoint
            window.location.href = {json.dumps(end_session_url)};
        </script>
    </body>
    </html>
    """)
    response.delete_cookie(COOKIE_OIDC, path="/")
    return response