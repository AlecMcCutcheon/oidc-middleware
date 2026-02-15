from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
import httpx
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError
import asyncio
import logging
import os
import hashlib
import base64
import time
import json

# ==============================
# Configs (sanitized: set your own IdP, Technitium, and Turnstile values)
# ==============================
AUTHENTIK_ISSUER = os.environ.get("AUTHENTIK_ISSUER", "https://your-idp.example.com")
AUTHENTIK_CLIENT_ID = os.environ.get("AUTHENTIK_CLIENT_ID", "YOUR_CLIENT_ID")
AUTHENTIK_CLIENT_SECRET = os.environ.get("AUTHENTIK_CLIENT_SECRET", "YOUR_CLIENT_SECRET")
AUTHENTIK_REDIRECT_URI = os.environ.get("AUTHENTIK_REDIRECT_URI", "https://your-technitium-domain.example.com/oidc/callback")
AUTHENTIK_APP_SLUG = os.environ.get("AUTHENTIK_APP_SLUG", "technitium")
OPENID_DISCOVERY = f"{AUTHENTIK_ISSUER}/application/o/{AUTHENTIK_APP_SLUG}/.well-known/openid-configuration"

# Technitium DNS (direct to container/host)
TECHNITIUM_API_BASE = os.environ.get("TECHNITIUM_API_BASE", "http://your-technitium-container:5380/api")
TECHNITIUM_SERVICE_TOKEN = os.environ.get("TECHNITIUM_SERVICE_TOKEN", "YOUR_SERVICE_TOKEN")

# Cloudflare Turnstile for login form
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "YOUR_TURNSTILE_SITE_KEY")
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "YOUR_TURNSTILE_SECRET")

# Login attempt lockout (per username, in-memory)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 3600
_login_attempts: dict[str, dict] = {}
_login_attempts_lock = asyncio.Lock()

COOKIE_OIDC = "oidc_session"
COOKIE_TECHNITIUM = "technitium_token"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("technitium_oidc")

app = FastAPI()

# Mount static dirs so /css/main.css and /js/auth.js work (proxy and direct)
_app_dir = os.path.dirname(os.path.abspath(__file__))
css_dir = os.path.join(_app_dir, "css")
js_dir = os.path.join(_app_dir, "js")
if os.path.isdir(css_dir):
    app.mount("/css", StaticFiles(directory=css_dir), name="css")
if os.path.isdir(js_dir):
    app.mount("/js", StaticFiles(directory=js_dir), name="js")


async def verify_turnstile(token: str, remote_ip: str | None = None) -> bool:
    """Verify a Turnstile token with Cloudflare Siteverify API. Returns True if valid."""
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


def _technitium_error_json(message: str, lockout: bool = False, attempts_left: int | None = None) -> dict:
    """Return Technitium-style error JSON so the native app can show it."""
    out = {
        "server": "technitium-dns",
        "status": "error",
        "errorMessage": message,
    }
    if lockout:
        out["lockout"] = True
    if attempts_left is not None:
        out["attempts_left"] = attempts_left
    return out


def _client_signature(request: Request) -> str:
    """
    Stable identifier for the client (IP + User-Agent hash).
    Lockout is per client, not per username, so one client cannot lock out another user's account.
    """
    client_host = request.client.host if request.client else None
    forwarded = request.headers.get("x-forwarded-for")
    remote_ip = (forwarded or "").split(",")[0].strip() if forwarded else client_host or "unknown"
    ua = (request.headers.get("user-agent") or "").strip()[:200]
    ua_part = hashlib.sha256(ua.encode()).hexdigest()[:16] if ua else "no-ua"
    return f"{remote_ip}|{ua_part}"


@app.post("/api/user/login")
async def proxy_user_login(request: Request):
    """
    Proxy for Technitium /api/user/login. Accepts form: user, pass, totp, includeInfo, cf-turnstile-response.
    Verifies Turnstile then forwards to Technitium. Returns Technitium response or Turnstile error in same shape.
    """
    form = await request.form()
    user = (form.get("user") or "").strip()
    pass_ = (form.get("pass") or "").strip()
    totp = (form.get("totp") or "").strip()
    include_info = (form.get("includeInfo") or "true").strip().lower() in ("true", "1", "yes")
    turnstile_token = (form.get("cf-turnstile-response") or form.get("turnstile") or "").strip()

    if not turnstile_token:
        return Response(
            content=json.dumps(_technitium_error_json("Please complete the verification.")),
            status_code=200,
            media_type="application/json",
        )
    client_host = request.client.host if request.client else None
    forwarded = request.headers.get("x-forwarded-for")
    remote_ip = (forwarded or "").split(",")[0].strip() if forwarded else client_host
    if not await verify_turnstile(turnstile_token, remote_ip):
        return Response(
            content=json.dumps(_technitium_error_json("Invalid cloudflare token.")),
            status_code=200,
            media_type="application/json",
        )

    key = _client_signature(request)
    async with _login_attempts_lock:
        now = time.time()
        rec = _login_attempts.get(key)
        if rec and rec.get("locked_until") and now < rec["locked_until"]:
            return Response(
                content=json.dumps(_technitium_error_json("Account locked. Try again in 1 hour.", lockout=True)),
                status_code=200,
                media_type="application/json",
            )
        if rec and rec.get("locked_until") and now >= rec["locked_until"]:
            _login_attempts[key] = {"failed": 0, "locked_until": None}

    async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
        try:
            resp = await client.post(
                f"{TECHNITIUM_API_BASE}/user/login",
                data={
                    "user": user,
                    "pass": pass_,
                    "totp": totp,
                    "includeInfo": "true" if include_info else "false",
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                },
            )
            body = resp.content
            headers = {"Content-Type": "application/json"}
            if "set-cookie" in resp.headers:
                headers["Set-Cookie"] = resp.headers["set-cookie"]

            try:
                data = resp.json()
            except Exception:
                return Response(content=body, status_code=resp.status_code, headers=headers)

            status = data.get("status")
            if status == "ok" or status == "2fa-required":
                async with _login_attempts_lock:
                    _login_attempts.pop(key, None)
                return Response(content=body, status_code=resp.status_code, headers=headers)
            if status == "error":
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
                        content=json.dumps(_technitium_error_json("Account locked. Try again in 1 hour.", lockout=True)),
                        status_code=200,
                        media_type="application/json",
                    )
                return Response(
                    content=json.dumps(_technitium_error_json(
                        (data.get("errorMessage") or "Login failed."),
                        attempts_left=attempts_left,
                    )),
                    status_code=200,
                    media_type="application/json",
                )
            return Response(content=body, status_code=resp.status_code, headers=headers)
        except httpx.HTTPStatusError as e:
            try:
                body = e.response.content
            except Exception:
                body = json.dumps(_technitium_error_json("Login request failed.")).encode()
            return Response(content=body, status_code=e.response.status_code, media_type="application/json")
        except Exception as e:
            logger.exception("Technitium login relay failed: %s", e)
            return Response(
                content=json.dumps(_technitium_error_json("Login request failed.")),
                status_code=200,
                media_type="application/json",
            )


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

# ==============================
# Service Integration Functions - Technitium DNS
# ==============================

def derive_password(username: str) -> str:
    """
    Derive a deterministic password from username using SHA256 hash.
    Similar to Crafty's approach for consistent password generation.
    
    Args:
        username: Username to derive password for
    
    Returns:
        Base64-encoded password string
    """
    digest = hashlib.sha256(username.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")

def sub_to_technitium_username(sub: str) -> str:
    """
    Convert Authentik sub (UUID) to a Technitium username.
    Uses SHA256 hash of the sub to get a consistent, unique identifier.
    Similar to Crafty's approach for consistent username generation.
    
    Args:
        sub: The UUID/subject identifier from Authentik OIDC token
    
    Returns:
        A Technitium username (lowercase, first 20 chars of SHA256 hash)
    """
    # Hash the sub to get a consistent, shorter identifier
    # Use SHA256 and take first 20 characters, ensure lowercase
    hash_obj = hashlib.sha256(sub.encode())
    hash_hex = hash_obj.hexdigest()[:20]  # Take first 20 chars, already lowercase
    return hash_hex

async def login_to_service(username: str, password: str, totp: str = "") -> tuple[str, str] | None:
    """
    Authenticate with Technitium DNS API using username and password.
    Reference: https://raw.githubusercontent.com/TechnitiumSoftware/DnsServer/refs/heads/master/APIDOCS.md
    
    Args:
        username: Technitium username
        password: User password
        totp: Time-based one-time password if 2FA is enabled (optional)
    
    Returns:
        Tuple of (token, expires) if successful, None otherwise
        expires is set to empty string as Technitium doesn't provide expiration in login response
        Session tokens expire after 30 minutes (default) from last API call
    """
    async with httpx.AsyncClient(verify=False) as client:
        try:
            # API supports both GET and POST, using POST with form data
            resp = await client.post(
                f"{TECHNITIUM_API_BASE}/user/login",
                data={
                    "user": username,
                    "pass": password,
                    "totp": totp,
                    "includeInfo": "true"
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept": "application/json"
                }
            )
            resp.raise_for_status()
            data = resp.json()
            
            status = data.get("status")
            
            if status == "ok":
                token = data.get("token")
                if not token:
                    logger.error("No token in Technitium login response")
                    return None
                # Technitium doesn't provide expiration in login response
                # Session expires after 30 minutes (default) from last API call
                expires = ""
                logger.info(f"Technitium login successful for user: {username}")
                return token, expires
            elif status == "2fa-required":
                logger.warning(f"Technitium login requires 2FA for user: {username}")
                return None
            elif status == "error":
                error_msg = data.get("errorMessage", "Unknown error")
                logger.error(f"Technitium login failed: {error_msg}")
                return None
            else:
                logger.error(f"Technitium login failed with status: {status}")
                return None
        except httpx.HTTPStatusError as e:
            log_http_error("Technitium login", e, f"Username: {username}")
            return None

async def get_service_users(service_token: str) -> list[dict]:
    """
    Get list of users from Technitium DNS.
    Reference: https://raw.githubusercontent.com/TechnitiumSoftware/DnsServer/refs/heads/master/APIDOCS.md
    
    Args:
        service_token: Admin/service account token
    
    Returns:
        List of user objects with username, displayName, disabled status, etc.
    """
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.get(
                f"{TECHNITIUM_API_BASE}/admin/users/list",
                params={"token": service_token},
                headers={"Accept": "application/json"}
            )
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("status") == "ok":
                users = data.get("response", {}).get("users", [])
                logger.debug(f"Retrieved {len(users)} users from Technitium")
                return users
            elif data.get("status") == "error":
                error_msg = data.get("errorMessage", "Unknown error")
                logger.error(f"Technitium get users failed: {error_msg}")
                return []
            else:
                logger.error(f"Technitium get users failed with status: {data.get('status')}")
                return []
        except httpx.HTTPStatusError as e:
            log_http_error("Technitium get users", e, "Failed to retrieve user list")
            return []

async def find_service_user_by_username(service_token: str, username: str) -> tuple[dict | None, str | None]:
    """
    Find a user in Technitium by username (hashed sub).
    Reference: https://raw.githubusercontent.com/TechnitiumSoftware/DnsServer/refs/heads/master/APIDOCS.md
    
    Args:
        service_token: Admin/service account token
        username: Technitium username (hashed sub)
    
    Returns:
        Tuple of (user dict if found, username for login)
        Returns None, None if user cannot be found
    """
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.get(
                f"{TECHNITIUM_API_BASE}/admin/users/get",
                params={"token": service_token, "user": username},
                headers={"Accept": "application/json"}
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "ok":
                user_details = data.get("response")
                if user_details and user_details.get("username").lower() == username.lower():
                    logger.info(f"Found Technitium user: {username}")
                    return user_details, username
            return None, None
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:  # User not found
                logger.debug(f"Technitium user {username} not found.")
                return None, None
            log_http_error("Technitium find_service_user_by_username", e, f"Username: {username}")
            return None, None

async def create_service_user(service_token: str, username: str, email: str, display_name: str, groups: list[str]) -> dict | None:
    """
    Create a new user in Technitium DNS.
    Reference: https://raw.githubusercontent.com/TechnitiumSoftware/DnsServer/refs/heads/master/APIDOCS.md
    
    Args:
        service_token: Admin/service account token
        username: Technitium username (hashed sub)
        email: User's email address
        display_name: Display name for the user
        groups: List of groups from OIDC (to determine roles/permissions)
    
    Returns:
        Created user dict if successful, None otherwise
    """
    # Derive deterministic password from username (hashed sub)
    password = derive_password(username)
    
    async with httpx.AsyncClient(verify=False) as client:
        try:
            # API supports both GET and POST, using POST with form data
            resp = await client.post(
                f"{TECHNITIUM_API_BASE}/admin/users/create",
                data={
                    "token": service_token,
                    "user": username,
                    "pass": password,
                    "displayName": display_name
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept": "application/json"
                }
            )
            resp.raise_for_status()
            data = resp.json()
            
            status = data.get("status")
            
            if status == "ok":
                created_user = data.get("response", {})
                logger.info(f"Created Technitium user: {username} (displayName: {display_name})")
                
                # Check if user is in admins group and add to Administrators group
                if "admins" in groups:
                    logger.info(f"User {username} is in 'admins' group, adding to Technitium 'Administrators' group")
                    try:
                        set_resp = await client.post(
                            f"{TECHNITIUM_API_BASE}/admin/users/set",
                            data={
                                "token": service_token,
                                "user": username,
                                "memberOfGroups": "Administrators"
                            },
                            headers={
                                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                                "Accept": "application/json"
                            }
                        )
                        set_resp.raise_for_status()
                        set_data = set_resp.json()
                        if set_data.get("status") == "ok":
                            logger.info(f"Successfully added user {username} to Administrators group")
                        else:
                            logger.warning(f"Failed to add user {username} to Administrators group: {set_data.get('errorMessage', 'Unknown error')}")
                    except httpx.HTTPStatusError as set_err:
                        log_http_error("add user to Administrators group", set_err, f"User {username}")
                        # Don't fail user creation if group assignment fails
                
                return created_user
            elif status == "error":
                error_msg = data.get("errorMessage", "Unknown error")
                logger.error(f"Technitium user creation failed: {error_msg}")
                return None
            else:
                logger.error(f"Technitium user creation failed with status: {status}")
                return None
        except httpx.HTTPStatusError as e:
            log_http_error("Technitium create user", e, f"Creating user {username}")
            return None

async def login_as_user(service_token: str, user_identifier: str | int) -> str | None:
    """
    Create a token for a specific user in Technitium using admin API.
    This creates a token without requiring the user's password.
    References: https://raw.githubusercontent.com/TechnitiumSoftware/DnsServer/refs/heads/master/APIDOCS.md#create-api-token
    
    Args:
        service_token: Admin/service account token with Administration: Modify permission
        user_identifier: Username to create token for
    
    Returns:
        User token if successful, None otherwise
    """
    if isinstance(user_identifier, int):
        logger.error("Technitium requires username (string), not integer ID")
        return None
    
    if not service_token:
        logger.error("Service token required to create user token via admin API")
        return None
    
    username = str(user_identifier)
    token_name = f"oidc-{username}-{int(time.time())}"  # Unique token name with timestamp
    
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.get(
                f"{TECHNITIUM_API_BASE}/admin/sessions/createToken",
                params={
                    "token": service_token,
                    "user": username,
                    "tokenName": token_name
                },
                headers={"Accept": "application/json"}
            )
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("status") == "ok":
                token = data.get("response", {}).get("token")
                if token:
                    logger.info(f"Created Technitium token for user: {username}")
                    return token
                else:
                    logger.error("No token in createToken response")
                    return None
            else:
                error_msg = data.get("errorMessage", "Unknown error")
                logger.error(f"Technitium createToken failed: {error_msg}")
                return None
        except httpx.HTTPStatusError as e:
            log_http_error("Technitium createToken", e, f"Username: {username}")
            return None
        except Exception as e:
            logger.error(f"Error creating Technitium token for {username}: {e}")
            return None

async def logout_from_service(token: str) -> bool:
    """
    Logout from Technitium DNS API to invalidate the session token.
    Reference: https://raw.githubusercontent.com/TechnitiumSoftware/DnsServer/refs/heads/master/APIDOCS.md
    
    Args:
        token: Session token to invalidate
    
    Returns:
        True if logout successful, False otherwise
    """
    async with httpx.AsyncClient(verify=False) as client:
        try:
            # Logout is a GET request with token as query parameter
            resp = await client.get(
                f"{TECHNITIUM_API_BASE}/user/logout",
                params={"token": token},
                headers={
                    "Accept": "application/json"
                }
            )
            resp.raise_for_status()
            data = resp.json()
            
            status = data.get("status")
            
            if status == "ok":
                logger.info("Technitium logout successful")
                return True
            elif status == "invalid-token":
                logger.warning("Technitium logout: token already invalid or expired")
                return True  # Consider this success since token is already invalid
            elif status == "error":
                error_msg = data.get("errorMessage", "Unknown error")
                logger.error(f"Technitium logout failed: {error_msg}")
                return False
            else:
                logger.warning(f"Technitium logout returned unexpected status: {status}")
                return False
        except httpx.HTTPStatusError as e:
            log_http_error("Technitium logout", e, "Failed to logout from Technitium")
            return False

def get_user_info_from_claims(claims: dict) -> dict:
    """
    Extract user information from OIDC claims.
    
    Args:
        claims: Decoded OIDC token claims
    
    Returns:
        Dictionary with standardized user info: email, username, name, sub, groups
    """
    return {
        "email": claims.get("email"),
        "username": claims.get("preferred_username") or claims.get("sub", ""),
        "name": claims.get("name"),  # Authentik User.name field (display name)
        "sub": claims.get("sub"),
        "groups": claims.get("groups", [])
    }

async def get_service_token() -> str | None:
    """
    Get service account token for Technitium API operations.
    
    Returns:
        Service token
    """
    return TECHNITIUM_SERVICE_TOKEN

# ==============================
# Routes
# ==============================
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
    return RedirectResponse(url=auth_url)

@app.get("/oidc/callback")
async def oidc_callback(request: Request):
    """
    OIDC callback - exchanges code for token, handles service authentication, and sets session cookie.
    This function handles the OIDC flow and calls service-specific functions for user management.
    """
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
            
            # Extract user information from claims
            user_info = get_user_info_from_claims(claims)
            email = user_info.get("email")
            
            if not email:
                logger.error("No email in OIDC claims")
                return RedirectResponse(url="/login")
            
            logger.info(f"User authenticated: {email}")
            
            # Technitium DNS authentication flow
            # 1. Get sub (UUID) and derive Technitium username from it (like Crafty)
            sub = user_info.get("sub", "")
            if not sub:
                logger.error("No sub (UUID) in OIDC claims")
                return RedirectResponse(url="/login")
            
            technitium_username = sub_to_technitium_username(sub)
            logger.info(f"Derived Technitium username from sub: {technitium_username} (sub: {sub[:8]}...)")
            
            # 2. Get service account token for user management
            service_token = await get_service_token()
            
            # 3. Check if user exists, create if not
            user, found_username = await find_service_user_by_username(service_token or "", technitium_username)
            
            if not user and service_token:
                # User doesn't exist - create them
                logger.info(f"User {technitium_username} not found, creating new user")
                try:
                    # Use name (display name) from Authentik, fallback to preferred_username, then email prefix
                    display_name = user_info.get("name") or user_info.get("username") or email.split("@")[0]
                    logger.info(f"Using display name: '{display_name}' (name: '{user_info.get('name')}', preferred_username: '{user_info.get('username')}', email prefix: '{email.split('@')[0]}')")
                    
                    created_user = await create_service_user(
                        service_token,
                        username=technitium_username,
                        email=email,
                        display_name=display_name,
                        groups=user_info["groups"]
                    )
                    
                    if created_user:
                        logger.info(f"User {technitium_username} created successfully")
                        # After creation, verify user exists
                        user, found_username = await find_service_user_by_username(service_token, technitium_username)
                    else:
                        logger.error(f"Failed to create user {technitium_username}")
                        return HTMLResponse(
                            content=f"""
                            <html>
                            <body>
                                <p>Failed to create user in Technitium DNS. Please contact an administrator.</p>
                                <p>Username: {technitium_username}</p>
                                <a href="/login">Try again</a>
                            </body>
                            </html>
                            """,
                            status_code=500
                        )
                except Exception as create_err:
                    logger.error(f"Error creating Technitium user: {create_err}")
                    return HTMLResponse(
                        content=f"""
                        <html>
                        <body>
                            <p>Error creating user in Technitium DNS. Please contact an administrator.</p>
                            <p>Username: {technitium_username}</p>
                            <a href="/login">Try again</a>
                        </body>
                        </html>
                        """,
                        status_code=500
                    )
            
            # 4. Create token for user using admin API (no password required)
            if not service_token:
                logger.error("Service account token required to create user token")
                return HTMLResponse(
                    content="""
                    <html>
                    <body>
                        <p>Service account not configured. Cannot authenticate with Technitium DNS.</p>
                        <p>Please contact an administrator.</p>
                        <a href="/login">Try again</a>
                    </body>
                    </html>
                    """,
                    status_code=500
                )
            
            technitium_token = await login_as_user(service_token, technitium_username)
            
            if not technitium_token:
                logger.error(f"Failed to create Technitium token for user: {technitium_username}")
                return HTMLResponse(
                    content=f"""
                    <html>
                    <body>
                        <p>Failed to create authentication token for Technitium DNS.</p>
                        <p>Username: {technitium_username}</p>
                        <p>Please contact an administrator.</p>
                        <a href="/login">Try again</a>
                    </body>
                    </html>
                    """,
                    status_code=500
                )
            
            logger.info(f"Successfully authenticated with Technitium: {technitium_username}")
            
            # Set OIDC session cookie and Technitium token cookie
            # Return HTML page that sets token in localStorage and redirects
            # Technitium web UI expects token in localStorage with key "token"
            redirect_url = state if state.startswith("http") else (os.environ.get("TECHNITIUM_BASE_URL", "https://your-technitium.example.com") + state)
            # Properly escape token and URL for JavaScript to prevent XSS
            token_escaped = json.dumps(technitium_token)
            url_escaped = json.dumps(redirect_url)
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authenticating...</title>
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
                    localStorage.removeItem('token');
                    localStorage.removeItem('oidc_login');
                    
                    // Set new token in localStorage (Technitium web UI expects key "token")
                    localStorage.setItem('token', {token_escaped});
                    // Set flag to indicate OIDC login (for logout detection)
                    localStorage.setItem('oidc_login', 'true');
                    // Redirect to destination
                    window.location.href = {url_escaped};
                </script>
            </body>
            </html>
            """
            response = HTMLResponse(content=html_content)
            response.set_cookie(key=COOKIE_OIDC, value=id_token, httponly=True, path="/", max_age=86400)
            response.set_cookie(key=COOKIE_TECHNITIUM, value=technitium_token, httponly=True, path="/", max_age=86400)
            return response
            
        except httpx.HTTPStatusError as e:
            log_http_error("OIDC token exchange", e, "Failed to exchange authorization code")
            return RedirectResponse(url="/login")
        except Exception as e:
            logger.error(f"Error in OIDC callback: {e}")
            return RedirectResponse(url="/login")

@app.get("/logout")
async def logout(request: Request):
    """
    Logout endpoint - logs out from Technitium, clears cookies, and redirects to Authentik logout.
    """
    logger.info("Logging out user")
    
    # Get Technitium token from cookie and logout from Technitium API
    technitium_token = request.cookies.get(COOKIE_TECHNITIUM)
    if technitium_token:
        await logout_from_service(technitium_token)
    else:
        logger.debug("No Technitium token found in cookies")
    
    # Get OIDC session to check if we should redirect to Authentik end-session
    oidc_session = request.cookies.get(COOKIE_OIDC)
    
    # If OIDC session exists, return HTML that clears localStorage and cookies before redirecting
    if oidc_session:
        html_content = """
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
                // Clear localStorage flags
                localStorage.removeItem('token');
                localStorage.removeItem('oidc_login');
                // Redirect to Authentik end-session
                window.location.href = """ + json.dumps(f"{AUTHENTIK_ISSUER}/application/o/{AUTHENTIK_APP_SLUG}/end-session/") + """;
            </script>
        </body>
        </html>
        """
        response = HTMLResponse(content=html_content)
        # Delete cookies by setting them to empty with max_age=0
        # Must match all parameters used when setting (httponly, secure if HTTPS)
        # Check if request is HTTPS
        is_https = request.url.scheme == "https"
        response.set_cookie(key=COOKIE_OIDC, value="", path="/", max_age=0, httponly=True, secure=is_https)
        response.set_cookie(key=COOKIE_TECHNITIUM, value="", path="/", max_age=0, httponly=True, secure=is_https)
        return response
    
    # No OIDC session - just redirect to login
    response = RedirectResponse(url="/login")
    # Delete cookies by setting them to empty with max_age=0
    # Must match all parameters used when setting (httponly, secure if HTTPS)
    is_https = request.url.scheme == "https"
    response.set_cookie(key=COOKIE_OIDC, value="", path="/", max_age=0, httponly=True, secure=is_https)
    response.set_cookie(key=COOKIE_TECHNITIUM, value="", path="/", max_age=0, httponly=True, secure=is_https)
    return response
