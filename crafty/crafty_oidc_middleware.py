from fastapi import FastAPI, Request, Response, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import httpx
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError
import logging
from urllib.parse import urlencode
import hashlib
import hmac
import base64
import os
from datetime import datetime, timezone

# ==============================
# Configs (sanitized: set your own IdP and Crafty API values)
# ==============================
AUTHENTIK_ISSUER = os.environ.get("AUTHENTIK_ISSUER", "https://your-idp.example.com")
AUTHENTIK_CLIENT_ID = os.environ.get("AUTHENTIK_CLIENT_ID", "YOUR_CLIENT_ID")
AUTHENTIK_CLIENT_SECRET = os.environ.get("AUTHENTIK_CLIENT_SECRET", "YOUR_CLIENT_SECRET")
AUTHENTIK_REDIRECT_URI = os.environ.get("AUTHENTIK_REDIRECT_URI", "https://your-crafty-domain.example.com/oidc/callback")
OPENID_DISCOVERY = f"{AUTHENTIK_ISSUER}/application/o/crafty/.well-known/openid-configuration"

CRAFTY_API_BASE = os.environ.get("CRAFTY_API_BASE", "https://your-crafty-domain.example.com/api/v2")
CRAFTY_API_TOKEN = os.environ.get("CRAFTY_API_TOKEN", "YOUR_CRAFTY_ADMIN_API_TOKEN")

COOKIE_OIDC = "oidc_session"
COOKIE_CRAFTY = "token"
COOKIE_MFA_USERNAME = "mfa_username"
COOKIE_MFA_NEXT = "mfa_next"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("crafty_oidc")

app = FastAPI()

# Mount static files directory
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

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

def sub_to_crafty_username(sub: str) -> str:
    """
    Convert Authentik sub (UUID) to a valid Crafty username.
    Crafty requires: lowercase, 4-20 characters.
    
    Args:
        sub: The UUID/subject identifier from Authentik OIDC token
    
    Returns:
        A valid Crafty username (lowercase, 4-20 chars)
    """
    # Hash the sub to get a consistent, shorter identifier
    # Use SHA256 and take first 20 characters, ensure lowercase
    hash_obj = hashlib.sha256(sub.encode())
    hash_hex = hash_obj.hexdigest()[:20]  # Take first 20 chars, already lowercase
    return hash_hex

def derive_password(sub: str) -> str:
    """
    Derive a deterministic password for Crafty:
    HMAC-SHA256 of (sub UUID + time-based 10-day period) keyed with AUTHENTIK_CLIENT_SECRET,
    then base64-url-safe encoded.
    
    The password changes every 10 days based on a time-based secret, forcing periodic
    password resets for enhanced security.
    
    Args:
        sub: The UUID/subject identifier from Authentik OIDC token
    """
    # Calculate 10-day period number (changes every 10 days)
    # Use a fixed epoch date for consistency
    epoch_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    current_date = datetime.now(timezone.utc)
    days_since_epoch = (current_date - epoch_date).days
    period_number = days_since_epoch // 10
    
    # Combine sub UUID with time-based period
    # This ensures the password changes every 10 days
    combined_input = f"{sub}:{period_number}"
    
    digest = hmac.new(AUTHENTIK_CLIENT_SECRET.encode(), combined_input.encode(), hashlib.sha256).digest()
    # remove padding since crafty login should handle base64-url-safe
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")

async def ensure_crafty_user_and_get_password(username: str, email: str, groups: list[str]):
    """
    Create user if missing. For existing user:
    - try login with derived password
    - if login fails, reset user password via PATCH and then return derived password
    """
    deterministic_password = derive_password(username)
    headers_api = {"Authorization": f"Bearer {CRAFTY_API_TOKEN}"}
    # Log token info for debugging (first/last 10 chars only for security)
    token_preview = f"{CRAFTY_API_TOKEN[:10]}...{CRAFTY_API_TOKEN[-10:]}" if len(CRAFTY_API_TOKEN) > 20 else "***"
    logger.debug(f"Using API token in ensure_crafty_user_and_get_password: {token_preview}")

    async with httpx.AsyncClient(verify=False) as client:
        # Try to create user with deterministic password
        create_resp = await client.post(
            f"{CRAFTY_API_BASE}/users",
            headers=headers_api,
            json={
                "username": username,
                "password": deterministic_password,
                "email": email,
                "lang": "en_US",
                "superuser": "admins" in groups or "Minecraft Admins" in groups
            }
        )

        # If user already exists
        if create_resp.status_code == 400 and create_resp.json().get("error") == "USER_EXISTS":
            # fetch existing user data
            list_resp = await client.get(f"{CRAFTY_API_BASE}/users", headers=headers_api)
            list_resp.raise_for_status()
            users = list_resp.json().get("data", [])
            existing = next((u for u in users if u["username"].lower() == username.lower()), None)
            if not existing:
                raise RuntimeError("User exists but could not be found in list")

            user_id = existing["user_id"]

            # Try login with deterministic password
            try:
                login_resp = await client.post(
                    f"{CRAFTY_API_BASE}/auth/login",
                    json={"username": username, "password": deterministic_password}
                )
                
                if login_resp.status_code == 401:
                    try:
                        error_data = login_resp.json()
                        logger.info(f"Login attempt for existing user {username} returned 401: {error_data}")
                    except:
                        logger.info(f"Login attempt for existing user {username} returned 401: {login_resp.text}")
                    
                    # Reset existing user's password to our deterministic one
                    try:
                        patch_resp = await client.patch(
                            f"{CRAFTY_API_BASE}/users/{user_id}",
                            headers=headers_api,
                            json={"password": deterministic_password}
                        )
                        if patch_resp.status_code == 200:
                            logger.info(f"Password reset successful for existing user {username}")
                        else:
                            try:
                                error_data = patch_resp.json()
                                logger.warning(f"Password reset for existing user {username} returned {patch_resp.status_code}: {error_data}")
                            except:
                                logger.warning(f"Password reset for existing user {username} returned {patch_resp.status_code}: {patch_resp.text}")
                    except httpx.HTTPStatusError as patch_err:
                        log_http_error("password reset for existing user", patch_err, f"User {username} (ID: {user_id})")
                        raise
            except httpx.HTTPStatusError as login_err:
                log_http_error("login attempt for existing user", login_err, f"User {username}")
                raise

            return existing, deterministic_password

        # If creation was successful
        try:
            create_resp.raise_for_status()
            new_data = create_resp.json().get("data", {})
            return new_data, deterministic_password
        except httpx.HTTPStatusError as create_err:
            log_http_error("user creation", create_err, f"Creating new user {username}")
            raise

async def login_to_crafty(username: str, password: str, totp_code: str = None, backup_code: str = None, assume_mfa_on_401: bool = False):
    """
    Call Crafty's /auth/login to get session token and id.
    Supports optional MFA via totp_code or backup_code.
    Returns tuple: (token, requires_mfa)
    
    Args:
        assume_mfa_on_401: If True, assume 401 means MFA is required (use after password reset attempts)
    """
    async with httpx.AsyncClient(verify=False) as client:
        login_data = {"username": username, "password": password}
        if totp_code:
            login_data["totp"] = totp_code  # API expects "totp" not "totp_code"
        if backup_code:
            login_data["backup_code"] = backup_code
        
        login_resp = await client.post(
            f"{CRAFTY_API_BASE}/auth/login",
            json=login_data
        )
        
        # Check if MFA is required (for 401 or 400 responses - Crafty can return either for auth failures)
        if login_resp.status_code in (401, 400):
            # If we're assuming MFA on 401/400 (after password reset), return MFA required
            if assume_mfa_on_401:
                logger.info(f"Assuming MFA required for {username} after password reset")
                return None, True
            
            # Log the error response for debugging
            try:
                error_data = login_resp.json()
                logger.debug(f"Login {login_resp.status_code} error response: {error_data}")
            except:
                logger.debug(f"Login {login_resp.status_code} error response (non-JSON): {login_resp.text}")
            
            # Don't check for MFA indicators in generic "INCORRECT_CREDENTIALS" errors
            # These are generic and could mean wrong password OR MFA needed
            # We'll let the caller handle password reset first, then check for MFA after
            # If it's a 401/400, raise the error for the caller to handle (password reset, then MFA check)
            login_resp.raise_for_status()
        
        # Success - return token
        if login_resp.status_code >= 400:
            # This shouldn't happen for 401/400 (handled above), but handle other errors
            try:
                error_data = login_resp.json()
                logger.error(f"Login failed with status {login_resp.status_code}: {error_data}")
            except:
                logger.error(f"Login failed with status {login_resp.status_code}: {login_resp.text}")
            login_resp.raise_for_status()
        return login_resp.json()["data"]["token"], False

# Removed crafty_logout_api() function - invalidating tokens was invalidating the API token itself
# Instead, we just remove the cookie which is sufficient for logout

# ==============================
# Routes
# ==============================
@app.get("/login")
async def login(request: Request):
    next_url = request.query_params.get("next", "/")
    oidc_session = request.cookies.get(COOKIE_OIDC)

    if oidc_session:
        jwks = await fetch_jwks()
        try:
            claims = decode_oidc_token(oidc_session, jwks)
        except (ExpiredSignatureError, JWTError):
            response = RedirectResponse(url="/login")
            response.delete_cookie(COOKIE_OIDC, path="/")
            return response

        username = claims.get("preferred_username") or claims["sub"]
        email = claims.get("email") or f"{username}@example.org"
        groups = claims.get("groups", [])
        sub = claims["sub"]  # Get UUID from Authentik

        derived_pw = derive_password(sub)
        logger.info(f"Derived password for user {username} (sub: {sub[:8]}...): {derived_pw}")

        # Try login first (use hashed sub as username in Crafty)
        crafty_username = sub_to_crafty_username(sub)
        try:
            crafty_token, requires_mfa = await login_to_crafty(crafty_username, derived_pw)
            if requires_mfa:
                # MFA required - redirect to MFA page
                response = RedirectResponse(url=f"/mfa?next={next_url}")
                response.set_cookie(key=COOKIE_MFA_USERNAME, value=username, httponly=True, path="/")
                response.set_cookie(key=COOKIE_MFA_NEXT, value=next_url, httponly=True, path="/")
                return response
        except httpx.HTTPStatusError as login_err:
            if login_err.response.status_code in (401, 400):
                logger.debug(f"Login failed with {login_err.response.status_code} for user {username}; trying user management paths")

                headers_api = {"Authorization": f"Bearer {CRAFTY_API_TOKEN}"}
                # Log token info for debugging (first/last 10 chars only for security)
                token_preview = f"{CRAFTY_API_TOKEN[:10]}...{CRAFTY_API_TOKEN[-10:]}" if len(CRAFTY_API_TOKEN) > 20 else "***"
                logger.debug(f"Using API token for user management: {token_preview}")
                
                async with httpx.AsyncClient(verify=False) as client:
                    # First, check if user exists by fetching user list
                    logger.debug(f"Fetching user list to check if user exists by username")
                    user = None
                    user_id = None
                    try:
                        list_resp = await client.get(f"{CRAFTY_API_BASE}/users", headers=headers_api)
                        list_resp.raise_for_status()
                        users = list_resp.json().get("data", [])
                        logger.debug(f"Found {len(users)} users in Crafty")
                        
                        # Find user by Crafty username (hashed sub) - email is not in list response
                        crafty_username = sub_to_crafty_username(sub)
                        logger.debug(f"Looking for user with Crafty username: {crafty_username}")
                        user = next(
                            (u for u in users if u.get("username", "").lower() == crafty_username.lower()),
                            None,
                        )
                        
                        # If user found by username, get full user details (including email) by ID
                        if user:
                            user_id = user.get("user_id")
                            logger.debug(f"Found user {crafty_username} (ID: {user_id}), fetching full details to verify email")
                            try:
                                user_detail_resp = await client.get(f"{CRAFTY_API_BASE}/users/{user_id}", headers=headers_api)
                                user_detail_resp.raise_for_status()
                                user_full = user_detail_resp.json().get("data", {})
                                user_email = user_full.get("email", "")
                                
                                # Verify email matches
                                if user_email.lower() == email.lower():
                                    logger.info(f"User {crafty_username} (ID: {user_id}, email: {user_email}) found and email matches")
                                    user = user_full  # Use full user details
                                else:
                                    logger.warning(f"User {crafty_username} (ID: {user_id}) found but email mismatch: Crafty={user_email}, OIDC={email}")
                                    # Still use this user for password reset, but log the mismatch
                                    user = user_full
                            except httpx.HTTPStatusError as detail_err:
                                log_http_error("fetch user details", detail_err, f"Fetching details for user ID {user_id}")
                                # If we can't get details, still proceed with basic user info from list
                                logger.warning(f"Could not fetch full user details for ID {user_id}, using basic info from list")
                    except httpx.HTTPStatusError as list_err:
                        if list_err.response.status_code == 403:
                            log_http_error("fetch user list", list_err, f"Fetching user list to find user by email: {email}", expected=True)
                            logger.info("Skipping user check (403): no USER_CONFIG permission - will try to create user")
                        else:
                            raise
                    
                    # If user exists, reset password. Otherwise, try to create user
                    if user:
                        # Get user_id from user object (should be set from full details or list)
                        user_id = user.get('user_id') or user_id
                        user_email = user.get('email', 'unknown')
                        logger.info(f"User {user.get('username', 'unknown')} (ID: {user_id}, email: {user_email}) already exists, attempting password reset")
                        try:
                            patch_resp = await client.patch(
                                f"{CRAFTY_API_BASE}/users/{user_id}",
                                headers=headers_api,
                                json={"password": derived_pw},
                            )
                            if patch_resp.status_code == 200:
                                logger.info(f"Password reset successful for user {user.get('username', 'unknown')} (status: {patch_resp.status_code})")
                            else:
                                try:
                                    error_data = patch_resp.json()
                                    logger.warning(f"Password reset returned status {patch_resp.status_code} for user {user.get('username', 'unknown')}: {error_data}")
                                except:
                                    logger.warning(f"Password reset returned status {patch_resp.status_code} for user {user.get('username', 'unknown')}: {patch_resp.text}")
                        except httpx.HTTPStatusError as patch_err:
                            log_http_error("password reset", patch_err, f"Resetting password for user {user.get('username', 'unknown')} (ID: {user.get('user_id', 'unknown')})")
                            if patch_err.response.status_code == 403:
                                logger.info("Skipping password reset (403): no USER_CONFIG permission")
                            else:
                                raise
                    else:
                        # User doesn't exist, try to create them (use hashed sub as username in Crafty)
                        crafty_username = sub_to_crafty_username(sub)
                        logger.debug(f"User with email {email} not found, attempting to create user with Crafty username: {crafty_username} (from sub: {sub[:8]}...)")
                        create_user_data = {
                            "username": crafty_username,  # Use hashed sub as username in Crafty (lowercase, 4-20 chars)
                            "password": derived_pw,
                            "email": email,
                            "lang": "en_US",
                            "superuser": "admins" in groups or "Minecraft Admins" in groups,
                        }
                        logger.info(f"Creating user with JSON payload: {create_user_data}")
                        try:
                            create_resp = await client.post(
                                f"{CRAFTY_API_BASE}/users",
                                headers=headers_api,
                                json=create_user_data,
                            )
                            create_resp.raise_for_status()
                            logger.info(f"User created successfully with sub/UUID {sub} as username (Authentik username: {username})")
                        except httpx.HTTPStatusError as create_err:
                            if create_err.response.status_code == 403:
                                log_http_error("user creation", create_err, f"Creating user {username}", expected=True)
                                logger.info("Skipping user creation (403): no USER_CONFIG permission")
                            elif create_err.response.status_code == 400:
                                # User already exists (race condition or email/username mismatch)
                                logger.info(f"User creation returned 400 (user may already exist): {create_err.response.text}")
                            elif create_err.response.status_code != 400:
                                raise

                # After password reset, try login again (use hashed sub as username in Crafty)
                crafty_username = sub_to_crafty_username(sub)
                logger.debug(f"Attempting login again for {username} (Crafty username: {crafty_username}) after password reset attempt")
                try:
                    crafty_token, requires_mfa = await login_to_crafty(crafty_username, derived_pw, assume_mfa_on_401=False)
                    if requires_mfa:
                        # MFA required - redirect to MFA page
                        logger.info(f"MFA required for {username}")
                        response = RedirectResponse(url=f"/mfa?next={next_url}")
                        response.set_cookie(key=COOKIE_MFA_USERNAME, value=username, httponly=True, path="/")
                        response.set_cookie(key=COOKIE_MFA_NEXT, value=next_url, httponly=True, path="/")
                        return response
                    # Success - token obtained
                    logger.info(f"Login successful for {username}")
                except httpx.HTTPStatusError as retry_err:
                    if retry_err.response.status_code in (401, 400):
                        # Still 401/400 after password reset - assume MFA is required
                        # We've already tried password reset, so if login still fails, it's likely MFA
                        logger.info(f"Login failed after password reset for {username}, assuming MFA required")
                        log_http_error("retry login after password reset", retry_err, f"User {username}", expected=True)
                        response = RedirectResponse(url=f"/mfa?next={next_url}")
                        response.set_cookie(key=COOKIE_MFA_USERNAME, value=username, httponly=True, path="/")
                        response.set_cookie(key=COOKIE_MFA_NEXT, value=next_url, httponly=True, path="/")
                        return response
                    else:
                        logger.error(f"Unexpected error during retry login: {retry_err.response.status_code} - {retry_err.response.text}")
                        raise
            else:
                raise

        # For dashboard paths, use intermediate page to avoid CSRF issues
        # Crafty needs time to initialize session/CSRF tokens
        is_https = request.url.scheme == "https" if hasattr(request.url, 'scheme') else True
        
        if next_url.startswith("/panel/"):
            # Use intermediate redirect page for dashboard paths
            redirect_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta http-equiv="refresh" content="1;url={next_url}">
                <title>Redirecting...</title>
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
                    // Small delay to ensure cookie is set and Crafty can initialize
                    setTimeout(function() {{
                        window.location.href = "{next_url}";
                    }}, 100);
                </script>
            </body>
            </html>
            """
            response = HTMLResponse(content=redirect_html)
        else:
            response = RedirectResponse(url=next_url)
        
        response.set_cookie(
            key=COOKIE_CRAFTY,
            value=crafty_token, 
            httponly=True, 
            path="/",
            samesite="lax",
            secure=is_https
        )
        return response

    # OIDC redirect
    params = {
        "client_id": AUTHENTIK_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": AUTHENTIK_REDIRECT_URI,
        "scope": "openid groups email profile",
        "state": next_url,
    }
    auth_url = f"{AUTHENTIK_ISSUER}/application/o/authorize/?{urlencode(params)}"
    return RedirectResponse(auth_url)

@app.get("/logout")
async def logout(request: Request):
    logger.info("Logging out user")

    # Clear local cookies (removed invalidate_tokens call to prevent API token invalidation)
    response = RedirectResponse(url=f"{AUTHENTIK_ISSUER}/application/o/crafty/end-session/")
    response.delete_cookie(COOKIE_OIDC, path="/")
    response.delete_cookie(COOKIE_CRAFTY, path="/")

    # Note: We don't call invalidate_tokens anymore because it was invalidating the API token itself
    # Removing the cookie is sufficient for logout

    return response

@app.get("/oidc/callback")
async def oidc_callback(code: str, state: str = "/"):
    logger.info(f"OIDC callback received, code={code}")
    async with httpx.AsyncClient(verify=False) as client:
        try:
            token_resp = await client.post(
                f"{AUTHENTIK_ISSUER}/application/o/token/",
                data={
                    "grant_type": "authorization_code",
                    "client_id": AUTHENTIK_CLIENT_ID,
                    "client_secret": AUTHENTIK_CLIENT_SECRET,
                    "redirect_uri": AUTHENTIK_REDIRECT_URI,
                    "code": code,
                },
            )
            token_resp.raise_for_status()
            data = token_resp.json()
        except httpx.HTTPStatusError as err:
            log_http_error("OIDC token exchange", err, f"Exchanging code for token")
            raise

    id_token = data["id_token"]
    response = RedirectResponse(url=state)
    response.set_cookie(key=COOKIE_OIDC, value=id_token, httponly=True, path="/")
    return response

@app.get("/mfa", response_class=HTMLResponse)
async def mfa_page(request: Request):
    """
    Display MFA code input page.
    """
    username = request.cookies.get(COOKIE_MFA_USERNAME, "")
    next_url = request.cookies.get(COOKIE_MFA_NEXT, request.query_params.get("next", "/"))
    error = request.query_params.get("error", "")
    
    if not username:
        # No username in cookie, redirect to login
        return RedirectResponse(url="/login")
    
    # Get email from OIDC session
    email = f"{username}@example.org"  # Default fallback
    oidc_session = request.cookies.get(COOKIE_OIDC)
    if oidc_session:
        try:
            jwks = await fetch_jwks()
            claims = decode_oidc_token(oidc_session, jwks)
            email = claims.get("email") or email
        except:
            pass  # Use default email if we can't decode
    
    error_display = "display: block;" if error == "invalid_code" else "display: none;"
    error_message = "Invalid code. Please try again." if error == "invalid_code" else ""
    
    # Use Authentik background image URL
    background_url = f"{AUTHENTIK_ISSUER}/media/public/images/Background_2.0.jpg"
    
    # Logo URL
    logo_url = os.environ.get("CRAFTY_BASE_URL", "https://your-crafty.example.com").rstrip("/") + "/static/assets/images/logo_long.svg"
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Multi-Factor Authentication - Crafty</title>
        <link rel="preload" href="{background_url}" as="image" />
        <link rel="preload" href="{logo_url}" as="image" />
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@200;300;400;500;600;700;800&display=swap" rel="stylesheet">
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            html {{
                background-color: #1a1a2e;
            }}
            
            body {{
                font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                font-weight: 300;
                background-color: #1a1a2e;
                background-image: url('{background_url}');
                background-size: cover;
                background-position: center;
                background-repeat: no-repeat;
                background-attachment: fixed;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            
            .mfa-container {{
                background: rgba(255, 255, 255, 0.05);
                backdrop-filter: blur(20px) saturate(130%);
                -webkit-backdrop-filter: blur(20px) saturate(130%);
                border: 1px solid rgba(255, 255, 255, 0.15);
                border-radius: 20px;
                box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.05);
                padding: 40px;
                max-width: 420px;
                width: 100%;
                animation: slideUp 0.3s ease-out;
            }}
            
            @keyframes slideUp {{
                from {{
                    opacity: 0;
                    transform: translateY(20px);
                }}
                to {{
                    opacity: 1;
                    transform: translateY(0);
                }}
            }}
            
            .mfa-header {{
                text-align: center;
                margin-bottom: 32px;
                display: flex;
                flex-direction: column;
                align-items: center;
            }}
            
            .mfa-icon {{
                margin: 0 auto 24px;
                display: flex;
                align-items: center;
                justify-content: center;
                filter: grayscale(100%);
                opacity: 0.9;
                max-width: 300px;
                width: 100%;
                height: auto;
            }}
            
            .mfa-icon img {{
                width: 100%;
                height: auto;
                max-width: 300px;
            }}
            
            .mfa-title {{
                font-size: 24px;
                font-weight: 500;
                color: white;
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
                margin-bottom: 8px;
            }}
            
            .mfa-subtitle {{
                font-size: 14px;
                color: rgba(255, 255, 255, 0.9);
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
                margin-bottom: 4px;
            }}
            
            .mfa-user-badge {{
                display: inline-flex;
                align-items: center;
                gap: 12px;
                margin: 16px auto 8px;
                padding: 10px 20px;
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
                font-size: 13px;
                color: rgba(255, 255, 255, 0.9);
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
            }}
            
            .mfa-user-badge .username {{
                font-weight: 500;
                color: white;
            }}
            
            .mfa-user-badge .separator {{
                width: 1px;
                height: 16px;
                background: rgba(255, 255, 255, 0.3);
            }}
            
            .mfa-user-badge .email {{
                color: rgba(255, 255, 255, 0.8);
            }}
            
            .mfa-form {{
                margin-top: 8px;
            }}
            
            .form-group {{
                margin-bottom: 20px;
            }}
            
            .form-label {{
                display: block;
                font-size: 14px;
                font-weight: 400;
                color: white;
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
                margin-bottom: 8px;
            }}
            
            .form-input {{
                width: 100%;
                padding: 12px 16px;
                font-size: 16px;
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 14px;
                transition: all 0.3s ease;
                font-family: 'Courier New', monospace;
                letter-spacing: 2px;
                text-align: center;
                color: white;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            }}
            
            .form-input:focus {{
                outline: none;
                background: rgba(255, 255, 255, 0.15);
                border-color: rgba(255, 255, 255, 0.4);
                box-shadow: 0 6px 20px rgba(0, 0, 0, 0.2), 0 2px 8px rgba(255, 255, 255, 0.1);
            }}
            
            .form-input::placeholder {{
                letter-spacing: normal;
                color: rgba(255, 255, 255, 0.6);
            }}
            
            .form-hint {{
                font-size: 12px;
                color: rgba(255, 255, 255, 0.8);
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
                margin-top: 6px;
            }}
            
            .form-toggle {{
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                margin-bottom: 16px;
                font-size: 14px;
                color: white;
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
            }}
            
            .toggle-switch {{
                position: relative;
                width: 44px;
                height: 24px;
                background: rgba(255, 255, 255, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.3);
                border-radius: 12px;
                cursor: pointer;
                transition: all 0.3s ease;
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
            }}
            
            .toggle-switch.active {{
                background: rgba(255, 255, 255, 0.3);
                border-color: rgba(255, 255, 255, 0.5);
            }}
            
            .toggle-slider {{
                position: absolute;
                top: 2px;
                left: 2px;
                width: 20px;
                height: 20px;
                background: white;
                border-radius: 50%;
                transition: transform 0.3s ease;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
            }}
            
            .toggle-switch.active .toggle-slider {{
                transform: translateX(20px);
            }}
            
            .submit-btn {{
                width: 100%;
                padding: 12px;
                font-size: 16px;
                font-weight: 600;
                color: white;
                background: rgba(255, 255, 255, 0.15);
                border: 1px solid rgba(255, 255, 255, 0.3);
                border-radius: 14px;
                cursor: pointer;
                transition: all 0.3s ease;
                margin-top: 8px;
                box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15), 0 2px 8px rgba(255, 255, 255, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.2);
                backdrop-filter: blur(20px);
                -webkit-backdrop-filter: blur(20px);
                text-transform: none;
            }}
            
            .submit-btn:hover {{
                background: rgba(255, 255, 255, 0.25);
                border-color: rgba(255, 255, 255, 0.4);
                transform: translateY(-2px);
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2), 0 4px 12px rgba(255, 255, 255, 0.15), inset 0 1px 0 rgba(255, 255, 255, 0.25);
            }}
            
            .submit-btn:active {{
                transform: translateY(0);
            }}
            
            .submit-btn:disabled {{
                opacity: 0.6;
                cursor: not-allowed;
                transform: none;
            }}
            
            .error-message {{
                background: rgba(220, 20, 60, 0.25);
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 100, 100, 0.3);
                color: white;
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
                padding: 12px;
                border-radius: 14px;
                font-size: 14px;
                margin-bottom: 20px;
                display: none;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.15);
            }}
            
            .error-message.show {{
                display: block;
            }}
            
            .back-link {{
                text-align: center;
                margin-top: 20px;
                font-size: 14px;
            }}
            
            .back-link a {{
                color: rgba(255, 255, 255, 0.9);
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
                text-decoration: none;
                transition: color 0.3s ease;
            }}
            
            .back-link a:hover {{
                color: white;
                text-decoration: underline;
            }}
        </style>
    </head>
    <body>
        <div class="mfa-container">
            <div class="mfa-header">
                <div class="mfa-icon">
                    <img src="{logo_url}" alt="Crafty Controller" />
                </div>
                <h1 class="mfa-title">Multi-Factor Authentication</h1>
                <p class="mfa-subtitle">Enter your TOTP code</p>
                <div class="mfa-user-badge">
                    <span class="username">{username}</span>
                    <span class="separator"></span>
                    <span class="email">{email}</span>
                </div>
            </div>
            
            <div class="error-message" id="errorMessage" style="{error_display}">{error_message}</div>
            
            <form class="mfa-form" id="mfaForm" method="POST" action="/mfa/verify">
                <div class="form-toggle">
                    <span>Using backup code?</span>
                    <div class="toggle-switch" id="toggleSwitch" onclick="toggleMode()">
                        <div class="toggle-slider"></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label class="form-label" id="inputLabel">TOTP Code</label>
                    <input 
                        type="text" 
                        class="form-input" 
                        id="mfaCode" 
                        name="mfa_code"
                        placeholder="000000"
                        maxlength="6"
                        autocomplete="off"
                        autofocus
                        required
                    />
                    <p class="form-hint" id="inputHint">Enter the 6-digit code from your authenticator app</p>
                </div>
                
                <input type="hidden" id="isBackupCode" name="is_backup_code" value="false" />
                <input type="hidden" name="next" value="{next_url}" />
                
                <button type="submit" class="submit-btn" id="submitBtn">
                    Verify & Continue
                </button>
            </form>
            
            <div class="back-link">
                <a href="/logout">Cancel and log out</a>
            </div>
        </div>
        
        <script>
            let isBackupMode = false;
            
            function toggleMode() {{
                isBackupMode = !isBackupMode;
                const toggle = document.getElementById('toggleSwitch');
                const label = document.getElementById('inputLabel');
                const hint = document.getElementById('inputHint');
                const input = document.getElementById('mfaCode');
                const hiddenInput = document.getElementById('isBackupCode');
                
                if (isBackupMode) {{
                    toggle.classList.add('active');
                    label.textContent = 'Backup Code';
                    hint.textContent = 'Enter your backup recovery code';
                    input.placeholder = 'Enter backup code';
                    input.maxLength = 20;
                    hiddenInput.value = 'true';
                }} else {{
                    toggle.classList.remove('active');
                    label.textContent = 'TOTP Code';
                    hint.textContent = 'Enter the 6-digit TOTP code from your authenticator app';
                    input.placeholder = '000000';
                    input.maxLength = 6;
                    hiddenInput.value = 'false';
                }}
                
                input.value = '';
                input.focus();
            }}
            
            document.getElementById('mfaForm').addEventListener('submit', function(e) {{
                const btn = document.getElementById('submitBtn');
                const errorMsg = document.getElementById('errorMessage');
                
                btn.disabled = true;
                btn.textContent = 'Verifying...';
                errorMsg.classList.remove('show');
            }});
            
            // Auto-format TOTP code (6 digits)
            document.getElementById('mfaCode').addEventListener('input', function(e) {{
                if (!isBackupMode) {{
                    this.value = this.value.replace(/[^0-9]/g, '').slice(0, 6);
                }}
            }});
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/mfa/verify")
async def mfa_verify(
    request: Request,
    mfa_code: str = Form(...),
    is_backup_code: str = Form("false"),
    next: str = Form("/")
):
    """
    Verify MFA code and complete login.
    """
    username = request.cookies.get(COOKIE_MFA_USERNAME)
    
    if not username:
        return RedirectResponse(url="/login")
    
    # Get sub (UUID) from OIDC session token
    sub = None
    oidc_session = request.cookies.get(COOKIE_OIDC)
    if oidc_session:
        try:
            jwks = await fetch_jwks()
            claims = decode_oidc_token(oidc_session, jwks)
            sub = claims["sub"]
        except (ExpiredSignatureError, JWTError):
            # If OIDC token is invalid, redirect to login
            return RedirectResponse(url="/login")
    
    if not sub:
        return RedirectResponse(url="/login")
    
    derived_pw = derive_password(sub)
    logger.info(f"Derived password for MFA verification for user {username} (sub: {sub[:8]}...): {derived_pw}")
    is_backup = is_backup_code.lower() == "true"
    
    # Convert sub to Crafty username format (lowercase, 4-20 chars)
    crafty_username = sub_to_crafty_username(sub)
    try:
        # Use hashed sub as username in Crafty for login
        if is_backup:
            crafty_token, requires_mfa = await login_to_crafty(crafty_username, derived_pw, backup_code=mfa_code)
        else:
            crafty_token, requires_mfa = await login_to_crafty(crafty_username, derived_pw, totp_code=mfa_code)
        
        if requires_mfa or not crafty_token:
            # MFA verification failed
            response = RedirectResponse(url=f"/mfa?next={next}&error=invalid_code")
            response.set_cookie(key=COOKIE_MFA_USERNAME, value=username, httponly=True, path="/")
            response.set_cookie(key=COOKIE_MFA_NEXT, value=next, httponly=True, path="/")
            return response
        
        # Success - clear MFA cookies and set Crafty token
        # Use an intermediate page to set cookie and redirect, giving Crafty time to initialize
        # Check if request is HTTPS to determine secure cookie flag
        is_https = request.url.scheme == "https" if hasattr(request.url, 'scheme') else True
        
        # Create intermediate redirect page that waits a moment before redirecting
        redirect_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta http-equiv="refresh" content="1;url=/">
            <title>Redirecting...</title>
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
                // Small delay to ensure cookie is set and Crafty can initialize
                setTimeout(function() {{
                    window.location.href = "/";
                }}, 100);
            </script>
        </body>
        </html>
        """
        
        response = HTMLResponse(content=redirect_html)
        response.set_cookie(
            key=COOKIE_CRAFTY, 
            value=crafty_token, 
            httponly=True, 
            path="/",
            samesite="lax",
            secure=is_https
        )
        response.delete_cookie(COOKIE_MFA_USERNAME, path="/")
        response.delete_cookie(COOKIE_MFA_NEXT, path="/")
        return response
        
    except httpx.HTTPStatusError as err:
        log_http_error("MFA verification", err, f"User {username}")
        response = RedirectResponse(url=f"/mfa?next={next}&error=invalid_code")
        response.set_cookie(key=COOKIE_MFA_USERNAME, value=username, httponly=True, path="/")
        response.set_cookie(key=COOKIE_MFA_NEXT, value=next, httponly=True, path="/")
        return response
