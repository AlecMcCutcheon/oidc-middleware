# App Investigation Wiki: Integrating an App with OIDC/SSO via Middleware

This guide is for **integrating a target web application with OpenID Connect (OIDC) and single sign-on (SSO)** by running a **middleware in front of the app behind a reverse proxy**. The middleware handles the OIDC flow (redirect to IdP, callback, token exchange) and then logs the user into the app using the app’s own APIs and session storage.

Successful integration usually depends on **two things**:

1. **Discovering and implementing the app’s APIs** in the middleware (login, user create/list, “login as user” or password change, token storage).  
2. **Finding the app’s front-end assets (JavaScript and CSS)** and **overriding them through the reverse proxy** so the middleware serves modified copies. That lets you **inject** new UI (e.g. an “SSO login” button), redirect logic, or styles without changing the upstream app.

This doc covers what to look for in APIs, how login and tokens work, **and** how to find, copy, and override JS/CSS so you can inject behavior into the target app.

**SSO is only one benefit.** The same setup lets you **harden the app’s existing login**: by **overwriting or proxying the app’s login endpoint** (whether it’s a public or internal API), you can require **Cloudflare Turnstile** (or similar), add **password attempt tracking**, and **block after too many failures**—all before any request reaches the real app. So you add both SSO and stronger protection for local login. See Section 2.1 below.

---

## 1. Overview: What You Need to Discover

Before writing middleware, you need to answer:

| Question | Why it matters |
|----------|----------------|
| How does the app log in? (endpoint, body format) | You will proxy or replicate this. |
| Does it return a token/session after login? | You need to set this in the browser (cookie or localStorage). |
| Where is that token stored? (cookie name, localStorage key) | Your OIDC callback must write to the same place. |
| Can you create users via an API? | For SSO, you create users on first login if they don’t exist. |
| Can you get a **user token** using an **admin token/API key**? | If yes → you can support **both local login and SSO**. If no → see “Password change API” below. |
| Is there a **password change/set** API? | If there is no “admin → user token” path, you need this for SSO (set a deterministic password, then login as user). Then the app is effectively **SSO-only** from the IdP’s perspective. |
| Which **JS and CSS** does the login page load, and at what paths? | You will copy those files into the middleware and override them via the reverse proxy so you can inject an SSO button, proxy the form, or restyle the page. See Section 7. |

**Rule of thumb:**

- **Admin can issue a token for a user (e.g. “login as user” or “create session for user”)**  
  → You can log the user in after OIDC without knowing their app password. **Both local login and SSO** are feasible.

- **No such API, but there is a password change/set API**  
  → You create/update the user with a derived password, then call the normal login API with that password. **SSO-only** (from the IdP); local login still works if users know the app password, but SSO flow doesn’t require the user to know it.

---

## 2. Where to Look: Public vs Internal APIs

- **Public API**  
  Documented, versioned, intended for third-party or scripted use. Check the app’s docs, OpenAPI/Swagger, or “API” section in the UI.

- **Internal API**  
  Used by the app’s own frontend. Not always documented. You discover it by watching network traffic while using the app.

Many apps only expose login and a few endpoints publicly; user creation, user listing, and “login as user” are often internal or admin-only. So you need both:

1. Read any public API docs.
2. Use the app in the browser with DevTools open and inspect every request (see Section 6).

### 2.1 Hardening the login API (not just SSO)

The middleware doesn’t only add SSO—it can **harden the app’s existing login** by **taking over the login endpoint**. Instead of letting the browser (or a client) talk directly to the app’s login API, you:

1. **Route login requests through the middleware**  
   Configure the reverse proxy so that the app’s login URL (e.g. `POST /api/tokens`, `POST /api/user/login`) is sent to the middleware instead of to the app. The middleware then becomes the only way to hit the real login API.

2. **Add checks before forwarding**  
   In the middleware you can:
   - **Require Cloudflare Turnstile** (or similar): the client must send a valid Turnstile token; the middleware verifies it with Cloudflare’s siteverify API. Invalid or missing token → return an error and never call the app. This reduces bots and scripted abuse.
   - **Track login attempts** (e.g. per client IP + User-Agent, or per username): count failed attempts in memory or a small store.
   - **Block after too many failures** (lockout): after N failed attempts, return a “locked” response and do **not** forward the request to the app. Optionally expire the lockout after a time (e.g. 1 hour).

3. **Forward only when allowed**  
   If Turnstile is valid and the client isn’t locked out, the middleware forwards the same body (or a normalized one) to the app’s real login endpoint and returns the app’s response (token or error). On success, clear attempt count for that client; on failure, increment and optionally lock.

So you **overwrite** the app’s login endpoint in the sense that the public URL is your proxy; the app’s internal or public login API is only called by the middleware after hardening checks. The app itself is unchanged; you’ve added Turnstile, attempt tracking, and lockout in front of it.

### 2.2 Middleware talks to the app’s API directly (internal URL)

When the middleware needs to call the app’s backend—for login, user list, create user, “login as user,” password change, etc.—it should **talk to the app internally**, not via the public domain name. Use an **internal base URL**: for example the container name (e.g. `http://app-container:8080`), an internal hostname, or an internal IP. Do **not** use `https://app.example.com` or whatever the user sees in the browser.

**Why:** The public domain is behind the reverse proxy. If the middleware called `https://app.example.com/api/tokens`, the request would go out and come back through the proxy. The proxy might then send that request to the **middleware** (e.g. because `/api/tokens` is configured to go to the middleware for hardening). So the middleware would be calling its own proxied endpoint—wrong, and potentially circular. By using an internal URL, the middleware hits the app’s backend **directly**, bypassing the proxy. The app’s API is only used server-side from the middleware; the browser never talks to that internal URL. So: discover the API paths and behavior from the public/network perspective, but **implement** the middleware’s outbound calls to the app using an internal base URL so they never go through your own proxy.

---

## 3. Important API Details to Find

The endpoints, paths, and request/response shapes below are **examples only**. Real APIs differ a lot by app: different URL paths, HTTP methods, body formats (JSON vs form-encoded), and field names. Use this section as a checklist of *what* to find; your actual discovery (Network tab, docs, Sources) will show *how* that app does it.

### 3.1 Login

- **Endpoint**  
  e.g. `POST /api/tokens`, `POST /api/user/login`, `POST /api/v2/auth/login`.
- **Request body**  
  JSON or form: which fields? Common: `email`/`user`/`username`, `password`/`pass`/`secret`, optional `totp`/`backup_code`.
- **Response (success)**  
  Does it return a token? In the JSON body and/or in a `Set-Cookie` header?
- **Response (failure)**  
  Status code and body shape (e.g. `401` + `{ "error": "Invalid credentials" }`). You may need to mimic this in your middleware for lockout or Turnstile errors.

Example (conceptual):

```http
POST /api/tokens
Content-Type: application/json

{"identity": "user@example.com", "secret": "password123"}
```

```json
200 OK
{"token": "eyJ...", "expires": 1234567890}
```

### 3.2 Where the Token Is Stored

After a successful login, the frontend stores the session. You must do the same after OIDC.

- **localStorage**  
  Open DevTools → Application → Local Storage → pick origin. Note the key(s), e.g. `token`, `authentications` (sometimes an array of `{ token, expires }`).
- **Cookies**  
  Application → Cookies. Note name, path, `HttpOnly`, `Secure`, `SameSite`. Your callback may set the same cookie or inject a page that sets localStorage.

Examples from real integrations (patterns only, no secrets):

- **App A:** Token in `localStorage.authentications` (array). Callback returns HTML that runs `localStorage.setItem('authentications', JSON.stringify([{ token, expires }]))`.
- **App B:** Token in `localStorage.token`. Callback returns HTML that runs `localStorage.setItem('token', token)`.
- **App C:** Token in cookie `token` (HttpOnly, path `/`). Callback does `response.set_cookie("token", value, path="/", httponly=True)`.

If the app expects a cookie, set a cookie; if it expects localStorage, return a short HTML page that sets localStorage then redirects (your middleware cannot set localStorage from the server).

### 3.3 User Creation

- **Endpoint**  
  e.g. `POST /users`, `POST /api/admin/users/create`.
- **Auth**  
  Usually admin token: `Authorization: Bearer <admin_token>` or `?token=<admin_token>`.
- **Body**  
  Required fields: username/id, password, email, display name, etc. Optional: roles, groups, language.
- **Response**  
  Created user object; often includes `id` or `user_id` for later “login as user” or password change.

Example (conceptual):

```http
POST /api/users
Authorization: Bearer <admin_token>
Content-Type: application/json

{"username": "jane", "password": "secret", "email": "jane@example.com", "roles": []}
```

```json
201 Created
{"id": 42, "username": "jane", "email": "jane@example.com", ...}
```

### 3.4 Listing / Finding Users

You need to “find user by OIDC identity” (e.g. email or a stable sub) to decide “create” vs “use existing”.

- **Endpoint**  
  e.g. `GET /users`, `GET /api/admin/users/list`, `GET /api/admin/users/get?user=...`.
- **Auth**  
  Admin or service token.
- **Response**  
  List or single user; note how to match by email or username (e.g. by `email`, or by a derived username from OIDC `sub`).

### 3.5 Getting a User Token With an Admin Token (“Login as user”)

This is the key for **dual login (local + SSO)**.

- **Endpoint**  
  Often something like `POST /users/{id}/login`, `GET /api/admin/sessions/createToken?user=...`, etc.
- **Auth**  
  Admin or API token in header or query.
- **Response**  
  A token (and optionally expiry) that represents that user. Your middleware then sets this token in cookie or localStorage so the browser is “logged in as” that user without their password.

If this exists, after OIDC you can:

1. Find or create the user by email/sub.
2. Call “login as user” with admin token.
3. Return the user token to the browser.

If this does **not** exist, you cannot get a user session without the user’s password, so you rely on a password set/reset API instead (see below).

### 3.6 Password Change / Set (for SSO when there is no “login as user”)

When the app has no “admin → user token” API:

- **Endpoint**  
  e.g. `PATCH /users/{id}`, `POST /api/admin/users/setPassword`.
- **Auth**  
  Admin token.
- **Body**  
  e.g. `{"password": "new_password"}`.
- **Response**  
  Usually 200 and maybe updated user.

Flow then is:

1. After OIDC, derive a deterministic password (e.g. from OIDC `sub` + secret or time period).
2. Find user by email/sub; if not found, create user with that derived password, then log in and set token.
3. **If user exists:** try the **normal login** endpoint with username and derived password first. If login succeeds, set the token in cookie or localStorage and you’re done.
4. If that login **fails** (e.g. 401/400), use the **password-set API** to sync the user’s password to the same derived value, then **try login again**. Often the failure was due to the app password having been changed elsewhere or never set to the derived value.
5. If login **still fails** after the sync, the app may be requiring **MFA** (TOTP or backup code). In that case you can’t complete login without a second factor—so assume the user has MFA enabled in the app and **show your own MFA form** (e.g. a middleware-hosted page where the user enters TOTP or backup code). Submit login again with the derived password plus the MFA value; on success, set the token. (For Crafty we had to design a custom MFA form in the middleware because the app’s login API accepts `totp` / `backup_code` but the SSO flow lands on our side first.)
6. Set the token in cookie or localStorage when login succeeds.

This allows SSO (user never types app password) but does not allow “admin to issue user token”; the app only supports “login with password”. So from the IdP side it’s SSO-only in the sense that you never ask the user for the app password in the SSO flow.

### 3.7 Temporary (interstitial) pages

Because the middleware cannot set **localStorage** from the server, it often serves **short-lived HTML pages** that run a small script in the browser and then redirect. The user may see a brief "Logging in..." or "Logging out..." screen (often with a dark or minimal body so the flash is unobtrusive). These are **temporary interstitial pages** used only to apply tokens, clear state, or hand off to the IdP.

**Common patterns:**

| Purpose | What the page does | When it's used |
|--------|---------------------|----------------|
| **OIDC callback (success)** | Script clears any existing app token and OIDC flag in localStorage; writes the new app token (and optional `oidc_login` flag for logout detection); then `window.location.href = state` to send the user to their original destination. The response also sets an HttpOnly OIDC cookie (e.g. `oidc_session`) so the middleware can read the IdP session later. | After the middleware exchanges the authorization code for tokens and obtains an app session (e.g. via "login as user" or password + login). |
| **Logout** | Script removes app token and OIDC flag from localStorage; then redirects to the IdP's end-session URL (e.g. Authentik `.../end-session/`). The response deletes the OIDC (and any app) cookies. | When the user clicks logout and the app's logout was overridden to hit the middleware's `/logout`. |
| **Post-login redirect (cookie-based apps)** | Minimal HTML with a short `setTimeout` then `window.location.href = next_url`. Gives the browser a moment to persist the cookie before the app loads the next page. | Used by some integrations (e.g. Crafty) when the app expects a cookie and the destination is a dashboard path; avoids race conditions. |
| **Post-MFA redirect** | Same idea: brief delay then redirect to `/` or `next_url` after the middleware has set the app cookie following successful MFA verification. | After the user submits TOTP/backup code on the middleware-hosted MFA form and the middleware logs them in and sets the cookie. |

**Why HTML instead of a 302 redirect?**

- **Callback:** The app token must be written to **localStorage** (or the app would need to accept token via cookie or URL, which many don't). Only a page that runs in the browser can do that; then the script redirects.
- **Logout:** The app may have put the token in localStorage. A 302 to the IdP would not clear that. So the middleware serves a page that clears localStorage (and optionally cookies via the response), then redirects to the IdP end-session URL.

**Implementation notes:**

- Keep the HTML minimal (inline `<style>` and `<script>`; no external resources) so the page loads and runs quickly.
- Escape token and redirect URL when injecting into the script (e.g. JSON-encode for JS) to avoid XSS.
- Set or delete cookies on the **response** that serves the HTML (e.g. `response.set_cookie` / `response.delete_cookie`); the script handles localStorage only.

---

## 4. Summary Table: What Exists vs What You Can Do

| App has… | You can support |
|----------|------------------|
| Login API + token in cookie/localStorage | Proxy login and/or set token after OIDC. |
| Create user API (admin) | Create user on first SSO login. |
| “Login as user” / “create token for user” (admin) | **Both local login and SSO**: after OIDC, get user token with admin token, set in browser. |
| Password set/change API (admin) but no “login as user” | **SSO-only** (from IdP): set derived password, then normal login; local login still works if user knows password. |
| No password change and no “login as user” | You cannot log the user in without their password; SSO not feasible without code changes or vendor support. |

---

## 5. Real Implementation Patterns (from this repo)

The following are **patterns** only; no credentials or environment-specific details.

### 5.1 NPM (Nginx Proxy Manager)

- **Login:** `POST /tokens` with `{ "identity": "<email>", "secret": "<password>" }`. Returns `{ "token", "expires" }`.
- **Token storage:** Frontend uses `localStorage.authentications` (array of `{ token, expires }`).
- **User list:** `GET /users?expand=permissions` with `Authorization: Bearer <token>`.
- **Create user:** `POST /users` with same Bearer token; body includes `email`, `name`, `nickname`, `roles`, `is_disabled`.
- **Admin → user token:** `POST /users/{user_id}/login` with admin Bearer token returns `{ "token", "expires" }`. So both local and SSO are supported: after OIDC, middleware finds or creates user, calls `login` for that `user_id`, then injects the returned token into `localStorage.authentications` via an HTML callback page.

### 5.2 Technitium DNS

- **Login:** `POST /api/user/login` (form: `user`, `pass`, `totp`, `includeInfo`). Returns `{ "status": "ok", "token": "..." }` (or `2fa-required` / `error`).
- **Token storage:** Web UI uses `localStorage.token`.
- **User list:** `GET /api/admin/users/list?token=<admin_token>`.
- **Get user:** `GET /api/admin/users/get?token=...&user=<username>`.
- **Create user:** `POST /api/admin/users/create` with form `token`, `user`, `pass`, `displayName`.
- **Admin → user token:** `GET /api/admin/sessions/createToken?token=...&user=<username>&tokenName=...` returns `{ "response": { "token": "..." } }`. So both local and SSO: middleware finds or creates user (e.g. username = hash of OIDC `sub`), calls `createToken`, then sets that token in `localStorage.token` via callback HTML.

### 5.3 Crafty (game server controller)

- **Login:** `POST /api/v2/auth/login` with `{ "username", "password" }` (optional `totp`, `backup_code`). Returns `{ "data": { "token": "..." } }`.
- **Token storage:** Middleware sets token in an HttpOnly cookie (e.g. `token`).
- **User list:** `GET /api/v2/users` with `Authorization: Bearer <admin_api_token>`.
- **Create user:** `POST /api/v2/users` with same Bearer token; body `username`, `password`, `email`, `lang`, `superuser`.
- **No “login as user”:** There is no admin API that returns a user session token. So the flow uses **try login → sync password if needed → retry → MFA if still failing**:
  - Derive a deterministic password (e.g. HMAC of OIDC `sub` and a time period or secret).
  - Find user by username (e.g. hash of `sub`); if not found, create with derived password, then login and set token.
  - If user exists: try `POST /api/v2/auth/login` with username and derived password. If it fails, call `PATCH /api/v2/users/{user_id}` with `{ "password": derived_password }` to sync, then try login again.
  - If login still fails after sync, assume the user has **MFA** enabled in the app. The middleware serves a **custom MFA form** (TOTP and/or backup code); the user enters it, and we submit login again with `totp` or `backup_code`. On success, set the returned token in a cookie.

So Crafty supports SSO with optional MFA; the mechanism is “try login, sync password if needed, retry, then handle MFA with our own form” when the app has no “admin issues user token”.

**Crafty-specific: hiding in-app MFA setup.** We also used JavaScript injection to **hide the normal ways a user would set up MFA inside Crafty** (the app’s own MFA enrollment UI). That was a personal choice: because login is forced through SSO, we didn’t feel the need for users to configure MFA in the individual app. We still built the **custom middleware MFA page** for two cases: (1) **existing users who already had MFA enabled** in Crafty before SSO was enforced, and (2) **if someone got around the JavaScript hiding** and set up MFA in the app natively—so they can still complete login by entering their TOTP or backup code on our middleware page.

### 5.4 Code pattern: “Admin → user token” (dual login)

When the app exposes an endpoint that returns a user token when called with an admin token:

```python
# After OIDC: you have email, sub, groups from IdP token.
# 1. Get admin token (from env or login with service account).
admin_token, _ = await login_to_app(SERVICE_EMAIL, SERVICE_PASSWORD)

# 2. Find user by email (or by derived username from sub).
user, user_id = await find_user_by_email(admin_token, email)
if not user:
    user = await create_user(admin_token, email=email, name=name, ...)
    user_id = user["id"]

# 3. Get a session token for that user (no user password needed).
user_token_response = await client.post(
    f"{APP_BASE}/users/{user_id}/login",
    headers={"Authorization": f"Bearer {admin_token}"},
)
user_token = user_token_response.json()["token"]

# 4. Set token in browser (e.g. HTML that sets localStorage, or set-cookie).
# Then redirect to app.
```

### 5.5 Code pattern: “Try login → sync if failed → retry → MFA if still failed” (SSO-only style)

When the app has no “login as user” but has password set and login:

```python
# After OIDC: you have sub, email, groups.
derived_password = derive_password(sub)
username_from_sub = username_from_sub(sub)  # e.g. hash of sub

# 1. Find or create user.
users = await list_users(admin_token)
user = find_by_email_or_username(users, email, sub)
if not user:
    user = await create_user(admin_token, username=username_from_sub, password=derived_password, email=email, ...)
    # New user: login and set token.
    login_resp = await client.post(f"{APP_BASE}/auth/login", json={"username": username_from_sub, "password": derived_password})
    app_token = login_resp.json()["data"]["token"]
    # Set token in browser and redirect.
else:
    # 2. User exists: try login first.
    login_resp = await client.post(f"{APP_BASE}/auth/login", json={"username": username_from_sub, "password": derived_password})
    if login_resp.status_code == 200:
        app_token = login_resp.json()["data"]["token"]
        # Set token and redirect.
    else:
        # 3. Login failed: sync password via admin API, then retry.
        await client.patch(f"{APP_BASE}/users/{user['id']}", headers={"Authorization": f"Bearer {admin_token}"}, json={"password": derived_password})
        login_resp = await client.post(f"{APP_BASE}/auth/login", json={"username": username_from_sub, "password": derived_password})
        if login_resp.status_code == 200:
            app_token = login_resp.json()["data"]["token"]
            # Set token and redirect.
        else:
            # 4. Still failing: assume MFA is required. Redirect to your middleware’s MFA form;
            #    user enters TOTP or backup code; POST login again with totp=... or backup_code=...; then set token.
            redirect_to_mfa_form(next=redirect_url)
```

---

## 6. How to Inspect in the Browser (step-by-step)

Use this to discover login, token storage, and internal APIs.

### 6.1 Prepare the environment

1. Open the app in the browser (Chrome/Edge/Firefox).
2. Open DevTools: F12 or right‑click → Inspect.
3. Go to the **Network** tab.
4. **Enable “Preserve log”** (checkbox). This keeps requests across navigations and redirects so you don’t lose the login request when the page changes.
5. Optionally clear the list (trash icon) so you only see traffic from the actions you’re about to do.

### 6.2 Capture login

1. (Optional) Clear network log.
2. Enter credentials and submit the login form.
3. In the Network tab, look for the request that happens on “Log in” (often a POST). Click it.
4. Note:
   - **Request URL** (e.g. `/api/tokens`, `/api/user/login`).
   - **Request method** (usually POST).
   - **Request headers** (Content-Type, etc.).
   - **Request payload** (JSON or form): which fields (email, password, etc.).
   - **Response status** and **response body**: do you see a token? A cookie?
5. If the response sets a cookie, open **Application → Cookies** and see which cookie was set.
6. If the response is JSON with a token, go to **Application → Local Storage** and see which key was updated after login (the frontend may set it in JavaScript). You may need to search the app’s JS for `localStorage.setItem` or `sessionStorage.setItem` to find the key name.

### 6.3 Capture other actions (create user, change password, etc.)

1. If the app has an admin or “Users” section, open it.
2. With “Preserve log” still on, perform the action (e.g. “Add user”, “Change password”).
3. In Network, find the new request(s). Note URL, method, headers, body, and response.
4. Repeat for any “login as user” or “impersonate” feature if present; that request is the “admin → user token” API.

### 6.4 Finding internal APIs (e.g. user list) when no API docs exist

Apps that have a **web UI and a backend server** have to talk to **some** API for that UI to work. There is no way for the “Users” page to show a list of users without the frontend calling an endpoint that returns that data. So even when the vendor doesn’t publish API docs, that internal API is there—you just have to catch it in the network log.

**User list as an example:** If the app has a page where you’re logged in and it **lists all users** (e.g. admin → Users, or Settings → Team), that page **must** be calling an internal API to fetch that list. To find it:

1. **Log in** to the app (so you have a valid session or token).
2. Open DevTools → **Network** tab and turn on **Preserve log**.
3. **Navigate to the page that lists users** (or the admin/settings area where user management lives).
4. In the Network tab, look at the requests that fire when that page loads. Filter by XHR/Fetch if your tools support it. One (or more) of those requests will be the “list users” (or “get users”) call—check the response body to confirm it contains user data (ids, emails, usernames, etc.). Note the **URL**, **method** (usually GET), and **headers** (e.g. `Authorization: Bearer ...` or a cookie). That’s your user-list internal API.

The same idea applies to **create user**, **edit user**, **change password**, or **login as user**: if the UI can do it, there is an HTTP request behind it. Trigger the action in the UI and watch the Network tab to see which endpoint and payload the app uses. No public docs needed—the browser’s network log is the source of truth for that internal API.

### 6.5 When there is no public API doc

- Rely on the Network tab for every action: login, logout, list users, create user, edit user, change password.
- Response bodies often indicate errors (e.g. `USER_EXISTS`, `Invalid credentials`). Use these in your middleware to branch (create vs update, show lockout, etc.).
- If the app uses a different base path (e.g. `/api/v2/`), all internal calls will share that prefix; you can filter by that path in the Network tab.

---

## 7. Overriding JavaScript and CSS (Asset Injection)

Heavily relying on **reverse proxy + middleware** means you often need to **inject new UI and behavior** into the target app’s pages (e.g. an “SSO login” button, MFA field, or custom styles). The app doesn’t know about OIDC, so you don’t change the upstream app—you **override specific JS and CSS files** so the browser loads *your* versions from the middleware. The reverse proxy sends requests for those asset paths to the middleware instead of to the app.

### 7.1 Why override assets?

- **Add SSO login option** – e.g. inject a “Login with SSO” button that redirects to `https://your-domain/login` (your middleware’s OIDC entrypoint).
- **Change where the form posts** – e.g. point the login form to your middleware’s proxy endpoint so you can add Turnstile, lockout, or logging before forwarding to the app.
- **Inject extra UI** – e.g. TOTP/backup code fields, or a divider (“OR”) between local login and SSO.
- **Restyle the login page** – override the app’s CSS so the SSO section matches your branding or layout.
- **Patch behavior** – e.g. in a copy of the app’s `auth.js`, add logic that runs on load (redirect if already OIDC-logged-in, or append MFA to the request).

All of this is done by **serving your own copies** of the app’s JS/CSS from the middleware at the **same URL path** the app would use, and configuring the reverse proxy so those paths hit the middleware first.

### 7.2 Finding which JS and CSS the app loads

1. **Network tab (with Preserve log)**  
   Load the login page (or the page you want to change). In the Network tab, filter by “JS” and “CSS” (or “Doc” to see the HTML). Note the **exact URL path** of every script and stylesheet (e.g. `/js/auth.js`, `/assets/index-abc123.js`, `/css/main.css`). The HTML will reference these with `<script src="...">` and `<link href="...">`.

2. **Sources tab**  
   Open DevTools → **Sources**. The left tree shows all loaded scripts and styles. Match them to the URLs you saw in Network. These are the files you may need to copy and edit.

3. **Inspect the login page HTML**  
   Right‑click the login form → Inspect (or view page source). Find `<script src="...">` and `<link rel="stylesheet" href="...">`. Those URLs are what the browser requests; your middleware must serve files at those paths so the proxy can route them to you.

4. **Hashed / versioned filenames**  
   You may notice these files look an awful lot like **post-build output from React or other frameworks** (minified JS, chunk hashes in names, etc.). That usually means the app’s build generates new filenames when the code changes. So **every time there’s an update to the application, there’s a good chance the generated JS or CSS will have a different name or chunk sequence**. You may need to update your proxying and middleware (re-copy the new file, adjust proxy rules if the path changed). Obviously that’s not ideal, but it’s the reality when overriding built assets. Options: (a) override the **route** in the reverse proxy so that *any* request under e.g. `/assets/` for a certain pattern goes to the middleware and you serve a fixed file; or (b) after an app update, re‑copy the new file and update your proxy/middleware if the path changed.

### 7.3 Copying files and mirroring paths in the middleware

**React and other framework-built apps:** When you’re injecting into an app built with React (or similar), you can run into cases where **the framework is managing the DOM and overwrites what you try to do**. For example, you append an SSO button or change the form—then React re-renders and your changes disappear or get into a fight with the framework’s controlled components. If that happens, you may have to **hide the original login form completely** and **mimic the login process yourself** in your overridden JS (your own form, your own submit handler that calls your middleware’s proxy). We had to do that for **NPM**: every attempt to add functionality directly to their login form resulted in fighting React’s control, so we hid the original form and implemented our own login UI and flow that talks to our middleware. See the NPM example in 7.6.

1. **Download the originals**  
   From Network tab: right‑click the request for the JS or CSS file → “Copy” → “Copy link address”, then download (or “Save as”). Or in Sources, right‑click the file → “Save as”. Save into your middleware project.

2. **Mirror the path structure**  
   The browser requests e.g. `/js/auth.js` or `/assets/index-Dsj4WOhN.js`. Your middleware must serve a file at that **same path**. So create directories that match:

   - App requests `/js/auth.js` → in the middleware project create `js/auth.js` and mount `StaticFiles` at `/js` so that `GET /js/auth.js` serves `./js/auth.js`.
   - App requests `/css/main.css` → create `css/main.css` and mount at `/css`.
   - App requests `/assets/...` → create `assets/` and mount at `/assets`.

3. **Mount in the middleware (e.g. FastAPI)**  
   Before any catch‑all or proxy, mount your static directories so the framework serves your files for those paths:

   ```python
   # Example: mirror app paths so /js/auth.js and /css/main.css are served by middleware
   _dir = os.path.dirname(os.path.abspath(__file__))
   app.mount("/js", StaticFiles(directory=os.path.join(_dir, "js")), name="js")
   app.mount("/css", StaticFiles(directory=os.path.join(_dir, "css")), name="css")
   # Or a single assets folder
   app.mount("/assets", StaticFiles(directory=os.path.join(_dir, "assets")), name="assets")
   ```

4. **Configure the reverse proxy**  
   The proxy (e.g. Nginx Proxy Manager, Traefik, Caddy) must send **asset paths to the middleware** instead of to the backend app. For example:

   - Location `/js/` → proxy to middleware (so `https://app.example.com/js/auth.js` is served by the middleware).
   - Location `/css/` → proxy to middleware.
   - Location `/assets/` → proxy to middleware (if you override assets there).

   So when the user loads the app’s login page, the HTML is still served by the app (or you could override the HTML too if the app serves it at a fixed URL). The browser then requests `/js/auth.js` and `/css/main.css`; those requests go to the middleware, which returns your modified files. The page runs your JS and uses your CSS, so you’ve “injected” SSO button, styles, or behavior.

### 7.4 What to put in your modified JS/CSS

- **JS (e.g. auth.js / login.js)**  
  - Keep the original behavior, then add your logic (e.g. on DOM ready, find the login form and append an SSO section with a link to `window.location.origin + '/login'`).
  - Or intercept the submit: read form values, send to your middleware’s proxy endpoint instead of the app’s, then let the middleware forward to the app after validation (Turnstile, lockout).
  - If the app uses a global (e.g. `callLogin`), you can override it: save the original, then replace it with a wrapper that adds MFA or redirects to OIDC when “SSO” is chosen.
- **CSS**  
  - Add rules for the classes/IDs you inject (e.g. `.oidc-login-section`, `.oidc-login-button`) so the SSO button and divider look correct and match the existing page.

### 7.5 When the app has no dedicated login path (SSO-only at root)

You have to get a bit creative depending on **where** the app shows its login UI.

**Dedicated login path (e.g. `/login`)**  
Some apps use a distinct URL for the login screen—for example Crafty’s default login UI is at `/login`. That’s convenient: you can **overwrite that path in the reverse proxy** so that requests to `https://app.example.com/login` go to your middleware instead of the app. The middleware then redirects the user to your identity provider (OIDC authorize URL). The user never hits the app’s own login page; they go straight to SSO. No need to proxy the whole app or touch the app’s HTML/JS for that path.

**No dedicated login path—login at root `/`**  
Other apps show the login form on the **root** URL (e.g. `https://app.example.com/`). You’ve already decided the app must be **SSO-only** (no admin→user token), so you want everyone to use your IdP. But you’re **not** trying to make your middleware a full proxy for the entire app. Proxying `/` to the middleware would mean the middleware has to serve or proxy the whole app, which is heavy and brittle. So **avoid proxying the root** to the middleware.

**Workaround: hook into the login form with JavaScript**  
Override the **assets** (JS, and CSS if needed) that run on the page where the login form appears. In your modified JS, when that page loads:

- **Redirect immediately to your identity provider** – e.g. `window.location.href = 'https://your-middleware/login'` (or your IdP’s authorize URL). The user lands on the app’s URL, the app’s HTML loads, your script runs, and before they ever see the form they’re sent to SSO.
- Optionally **hide the original login form** (e.g. `document.querySelector('.login-form').style.display = 'none'`) so that even if the redirect is slow or you prefer to show your own “Redirecting to SSO…” message, the native form is never presented.

So you’re not overwriting the path in the proxy; you’re overwriting the **script** that runs on that page. When the login form is loaded (at root or wherever), your code runs and sends the user to your IdP instead. That’s how you can enforce SSO-only when the app doesn’t give you a separate `/login` path to take over.

### 7.6 Examples from this repo (patterns only)

- **Technitium**  
  - Middleware has `js/auth.js` and `css/main.css`, mounted at `/js` and `/css`.  
  - The app’s login page loads `/js/auth.js` and `/css/main.css`. The proxy sends those paths to the middleware.  
  - The middleware’s copy of `auth.js` is the app’s original plus an injected function that runs on load: finds the login form and appends an “OR” divider and an “Login With [SSO]” link to `/login`. The CSS adds styles for that section. So users see both local login and SSO on the same page.

- **NPM (Nginx Proxy Manager)**  
  - Middleware has an `assets/` folder with copies of the app’s built JS/CSS (e.g. `index-*.js`, `index-*.css`). Mounted at `/assets`. The app is React-built, so those are post-build assets; filenames can change on app updates.  
  - The proxy is configured so requests to the app’s `/assets/...` can be served by the middleware. **We had to hide the original login form completely and mimic the login process ourselves**—every attempt to add functionality directly to NPM’s login form (e.g. appending an SSO button or wiring the form to our proxy) resulted in fighting React’s controlled components (re-renders overwrote our changes). So the overridden code hides their form and presents our own login UI and flow that talks to the middleware’s token proxy.

- **Crafty**  
  - Middleware mounts `/static` from a `static/` directory (e.g. custom CSS or assets for the middleware’s own MFA/login pages). Used for the middleware’s pages rather than overriding the game controller’s core assets.

Takeaway: find the exact URLs the login page uses for JS and CSS, copy those files into your middleware with the same path structure, edit them to add SSO UI and behavior, then configure the reverse proxy so those URLs are served by the middleware. That way you inject new CSS and JavaScript into the target app without changing the app itself.

---

## 8. Checklist Before Writing Middleware

- [ ] Login endpoint, method, and body format.
- [ ] Success response: token in body and/or cookie; if cookie, name and options (path, HttpOnly, Secure).
- [ ] If token is in localStorage/sessionStorage: exact key(s) and structure (e.g. array of `{ token, expires }`).
- [ ] Endpoint to list or get users (and how to match by email or OIDC sub).
- [ ] Endpoint to create user (and required fields).
- [ ] Whether “login as user” / “create token for user” exists (admin token → user token). If yes, endpoint and response.
- [ ] If no “login as user”: password change/set endpoint (and how to call it with admin auth).
- [ ] Any 2FA (TOTP/backup codes): which fields and endpoints so you can support MFA in the SSO flow if needed.
- [ ] Logout: does the app expose a logout API that invalidates the token? (Useful for “logout” to clear both IdP and app session.)
- [ ] **Assets:** Which JS and CSS the login (or target) page loads; their URL paths. Copy those files into the middleware and mirror paths; add SSO button / proxy form / styles; configure reverse proxy to serve those paths from the middleware.

Once you have this, you can implement the OIDC callback and asset overrides: exchange code for IdP token, get email/sub/groups, find or create the app user, obtain an app token (via “login as user” or “set password + login”), set that token in the browser the same way the app does (cookie or localStorage), and serve your modified JS/CSS so the app’s UI shows SSO and any injected behavior.

---

## Bonus: Local-only apps with automatic IP allowlist (Auth IP)

If your **firewall or router** is giving the reverse proxy the **real client IPs** (e.g. via `X-Forwarded-For`), you can make certain apps **local-only** while still letting remote users who have rights in your identity provider access them: when a user tries to open the app, a policy in the IdP calls a small “auth IP” middleware that **temporarily adds their IP** to an allowlist used by the proxy. Local traffic (e.g. your private subnet) is always allowed; everyone else is denied unless their IP has been added by that automation. Entries can expire after a few hours so the list doesn’t grow forever.

**Prerequisite:** The proxy must be configured to trust the upstream (e.g. firewall) and set `$remote_addr` from `X-Forwarded-For` (see below). Otherwise the proxy only sees the firewall’s IP, not the user’s.

### How it fits together

1. **Auth IP middleware** – A small service that exposes an API (e.g. `POST /auth` with Bearer token and body `{ "ip", "uuid", "app" }`). It appends a line to a per-app allowlist file (e.g. `allow <ip>; # <uuid> - <timestamp>`) and runs a **proxy reload** so the proxy picks up the change. It can also run a cleanup job that removes entries older than N hours.
2. **IdP policy** – When a user attempts to access an application, a policy (e.g. Authentik “Python” expression policy) runs. It reads the client IP (e.g. `ak_client_ip`), the user’s UUID, and the application slug, and calls the auth IP middleware API. The policy can always return “allow” from the IdP’s point of view; the **actual** access control is done at the proxy via the allowlist. If the API call fails (e.g. timeout), you typically still allow the request and log the error, so a broken middleware doesn’t lock everyone out.
3. **Proxy config** – For that app’s server/location, you allow your private subnet, then `include` the allowlist file, then `deny all`. So: local IPs and any IP added by the middleware are allowed; everyone else gets 403 (or 444 if you want to close the connection without response).

### Where to attach the policy (per-app vs flow) and policy mode

**Per-app (provider/application) binding:** The policy is written to run in the context of “user is accessing an application” and uses the application slug (`request.obj.slug`) so the middleware can write to the right allowlist file. A straightforward approach is to **attach the policy to each application** in Authentik that you want to be local-only: for every provider/app where this flow should apply, add this policy to that app’s policy list. That way only those apps trigger the IP registration; others are unchanged. You could instead trigger this from a **flow** (e.g. after login or at another stage), but you’d likely need to adjust the policy—for example the application slug might not be in the same place in the request context, or you’d pass it differently. Per-app binding keeps the policy simple and explicit.

**Policy mode when using groups:** If you also restrict access by **group** (e.g. only users in “VPN-users” may use the app) and you want this IP-allowlist policy to run **together** with the group check, set the policy **mode to “all”** instead of “any.” With **all**, the user must satisfy every bound policy (e.g. “in group X” **and** “this Python policy”). With **any**, only one policy needs to pass, so the group restriction might be bypassed or the IP registration might not run when you expect. So for “only these groups, and also register their IP for the proxy allowlist,” use mode **all**.

### Sanitized Authentik policy (Python expression)

This runs when a user tries to access an application. It calls your auth IP middleware so the user’s IP gets added to that app’s allowlist. Use your own API URL and token; store the token in Authentik’s secret/outpost config if possible instead of hardcoding.

```python
# Policy: On app access, register client IP with auth-IP middleware for allowlist
import logging
logger = logging.getLogger("authentik.policies")

current_ip = str(ak_client_ip) if ak_client_ip else "unknown"
user_uuid = str(request.user.uuid)
app_slug = getattr(getattr(request, "obj", None), "slug", "unknown")

logger.info("App access attempt - User: %s (UUID: %s), App: %s, IP: %s",
            getattr(request.user, "username", "?"), user_uuid, app_slug, current_ip)

try:
    import requests
    url = "https://your-auth-ip-middleware:PORT/auth"   # Your middleware URL
    token = "YOUR_BEARER_TOKEN"                          # Use env/secret in production
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"ip": current_ip, "uuid": user_uuid, "app": app_slug},
        timeout=5,
        verify=False  # Only if using self-signed certs
    )
    logger.info("Auth API response - User: %s, App: %s, Status: %s",
                getattr(request.user, "username", "?"), app_slug, resp.status_code)
except Exception as e:
    logger.error("Policy error - User: %s, Error: %s",
                 getattr(request.user, "username", "unknown"), str(e))
    # Don't block access if the API fails

# IdP policy: always allow; actual restriction is at the proxy via allowlist
return True
```

### Proxy config (example: nginx-style)

You need to (1) trust the upstream so `$remote_addr` becomes the real client IP, (2) allow your private subnet, (3) include the per-app allowlist file, (4) deny everyone else. Example (paths and IPs are placeholders):

```nginx
# Trust the upstream (e.g. firewall) and take client IP from X-Forwarded-For
set_real_ip_from 172.16.16.16;
real_ip_header X-Forwarded-For;
add_header X-Client-IP $remote_addr always;

# Allow private subnet, then dynamically allowed IPs, then deny rest
allow 172.16.16.0/24;
include /path/to/conf/<app>/allowed_ips.conf;
deny all;

# Optional: close connection without 403 body (return 444)
error_page 403 =444 @close;
location @close {
    return 444;
}
```

**Paths:** If the proxy runs in Docker, the path **inside the container** to the allowlist file may differ from the path on the host (e.g. host volume `./conf` → container `/app/authconf`). Use the path the proxy process actually sees.

**Include-file caveats (e.g. Nginx Proxy Manager):** On some setups, **if an included file doesn’t exist, the proxy may refuse to save** the config. And **if you save a config that includes a file and later delete that file**, the proxy can fail to load that app’s config and **all endpoints for that domain can stop working** until you restore the file or remove the include. So: create the allowlist file (or at least an empty valid include) **before** adding the `include` line, and avoid deleting the file without updating the proxy config first.

### Reloading the proxy after allowlist changes

When the auth IP middleware adds or removes an IP, the allowlist file on disk changes, but the proxy won’t use the new rules until it **reloads**. So the middleware should **trigger a reload** after each change (and optionally the cleanup job can trigger one when it removes expired entries). How to trigger it depends on the proxy: some expose an HTTP endpoint (e.g. `POST /reload`), or you might hit an internal admin API or send a signal.

**What we did for Nginx Proxy Manager (NPM):** NPM doesn’t expose a dedicated “reload config” API. We use an **admin setting** instead: the “default site” (or similar) setting—the page NPM shows when no host matches. We don’t plan on ever changing that setting. So we trigger a reload by **PUTting that setting to the same value** it already has (e.g. a fixed body like `{"value": "444", "meta": {"redirect": "", "html": ""}}`). Writing the setting causes NPM to reload the proxy config and pick up the updated allowlist file; because we’re not actually changing the value, it’s a no-op from a user perspective. The auth IP middleware calls a reload endpoint (e.g. on our NPM OIDC middleware), which authenticates to NPM and performs that PUT to the internal settings API. So: no dedicated reload endpoint on NPM, but using an unused admin setting as a reload trigger works and doesn’t affect behavior.

### Debugging: check that the proxy sees the real client IP

To confirm the proxy is getting the real public IP (and not the firewall’s), add a small location that returns `$remote_addr` with the same `set_real_ip_from` and `real_ip_header` in scope:

```nginx
location = /client-ip {
    set_real_ip_from 172.16.16.16;
    real_ip_header X-Forwarded-For;
    add_header X-Client-IP $remote_addr always;
    add_header Content-Type text/plain;
    return 200 $remote_addr;
}
```

Then open `https://your-domain/client-ip` from a device outside your LAN (e.g. phone off Wi‑Fi). You should see that device’s public IP in the response. If you see the firewall’s IP instead, the upstream isn’t sending or the proxy isn’t trusting `X-Forwarded-For` correctly.
