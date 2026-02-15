"""
Auth IP NPM Middleware: API to add IPs to allowed_ips.conf with token auth.
Entries are removed automatically after 6 hours.

Sanitized reference: replace AUTH_TOKEN and NPM_RELOAD_URL with your values.
"""
import asyncio
import ipaddress
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel, field_validator

# -----------------------------------------------------------------------------
# Config (sanitized: set your own token and reload URL)
# -----------------------------------------------------------------------------
AUTH_TOKEN = os.environ.get("AUTH_IP_TOKEN", "YOUR_BEARER_TOKEN")
CONF_DIR = Path(__file__).resolve().parent / "conf"
ALLOWED_IPS_FILENAME = "allowed_ips.conf"
ENTRY_MAX_AGE_HOURS = 6
CLEANUP_INTERVAL_SECONDS = 300  # run cleanup every 5 minutes

# NPM reload URL: called after adding an IP so proxy manager reloads (e.g. picks up allowed_ips.conf)
NPM_RELOAD_URL = os.environ.get("NPM_RELOAD_URL", "https://your-npm-middleware:9215/reload")

# Safe folder name: only alphanumeric, underscore, hyphen (no path traversal)
APP_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("auth_ip_npm")

app = FastAPI(title="Auth IP NPM Middleware")

# Line format: allow 192.168.1.100; # <UUID> - <ISO datetime> (nginx only accepts # comments)
ALLOW_LINE_RE = re.compile(
    r"^\s*allow\s+(\S+)\s*;\s*#\s*(.+?)\s*-\s*(\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)\s*$"
)
COMMENT_OR_EMPTY_RE = re.compile(r"^\s*(#.*)?$")


def _path_for_app(app: str) -> Path:
    """Path to allowed_ips.conf for this app (conf/<app>/allowed_ips.conf)."""
    return CONF_DIR / app / ALLOWED_IPS_FILENAME


def _ensure_app_conf(path: Path) -> None:
    """Create app subdir and allowed_ips.conf with header if they don't exist."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(
            "# Allowed IPs - one per line: allow <IP>; # <UUID> - <ISO datetime>\n"
            "# Entries are removed automatically after 6 hours.\n",
            encoding="utf-8",
        )


async def _verify_token(authorization: str | None = Header(None)) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization[7:].strip()
    if token != AUTH_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")


class AddIPRequest(BaseModel):
    ip: str
    uuid: str
    app: str

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("IP is required")
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Invalid IP address")
        return v

    @field_validator("uuid")
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("UUID is required")
        return v

    @field_validator("app")
    @classmethod
    def validate_app(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("app is required")
        if not APP_NAME_RE.match(v):
            raise ValueError("app must be alphanumeric, underscore, or hyphen only")
        return v


def _read_entries(path: Path) -> list[tuple[str, str, datetime]]:
    """Read conf file; return list of (ip, uuid, added_at)."""
    if not path.exists():
        return []
    entries: list[tuple[str, str, datetime]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if COMMENT_OR_EMPTY_RE.match(line):
            continue
        m = ALLOW_LINE_RE.match(line)
        if not m:
            continue
        ip_part, uuid_part, date_str = m.groups()
        try:
            added_at = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            if added_at.tzinfo is None:
                added_at = added_at.replace(tzinfo=timezone.utc)
            entries.append((ip_part, uuid_part.strip(), added_at))
        except ValueError:
            continue
    return entries


def _write_entries(path: Path, header_lines: list[str], entries: list[tuple[str, str, datetime]]) -> None:
    """Write conf file from header lines and entries."""
    lines = list(header_lines)
    for ip, uuid, added_at in entries:
        lines.append(f"allow {ip}; # {uuid} - {added_at.isoformat()}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _remove_expired_entries(path: Path) -> int:
    """Remove entries older than ENTRY_MAX_AGE_HOURS. Returns number removed."""
    if not path.exists():
        return 0
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    header_lines: list[str] = []
    entries = []
    now = datetime.now(timezone.utc)
    cutoff = now.timestamp() - (ENTRY_MAX_AGE_HOURS * 3600)
    removed = 0

    for line in lines:
        if COMMENT_OR_EMPTY_RE.match(line):
            header_lines.append(line)
            continue
        m = ALLOW_LINE_RE.match(line)
        if not m:
            header_lines.append(line)
            continue
        ip_part, uuid_part, date_str = m.groups()
        try:
            added_at = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            if added_at.tzinfo is None:
                added_at = added_at.replace(tzinfo=timezone.utc)
            if added_at.timestamp() < cutoff:
                removed += 1
                continue
            entries.append((ip_part, uuid_part.strip(), added_at))
        except ValueError:
            header_lines.append(line)
    if removed > 0:
        _write_entries(path, header_lines, entries)
        logger.info("Removed %d expired IP entries from %s (older than %s hours)", removed, path, ENTRY_MAX_AGE_HOURS)
    return removed


async def _trigger_npm_reload() -> bool:
    """POST to NPM reload endpoint (retries 3x). Returns True if any attempt succeeded."""
    for attempt in range(3):
        try:
            async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
                reload_resp = await client.post(NPM_RELOAD_URL)
                if reload_resp.status_code == 200:
                    logger.info("NPM reload completed successfully")
                    return True
                logger.warning("NPM reload returned %s (attempt %s)", reload_resp.status_code, attempt + 1)
        except Exception as e:
            logger.warning("NPM reload attempt %s failed: %s", attempt + 1, e)
        if attempt < 2:
            await asyncio.sleep(1)
    logger.error("NPM reload failed after 3 attempts")
    return False


async def _cleanup_loop() -> None:
    while True:
        try:
            await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
            if not CONF_DIR.exists():
                continue
            any_removed = False
            for app_dir in CONF_DIR.iterdir():
                if app_dir.is_dir() and not app_dir.name.startswith("."):
                    path = app_dir / ALLOWED_IPS_FILENAME
                    if _remove_expired_entries(path) > 0:
                        any_removed = True
            if any_removed:
                await _trigger_npm_reload()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.exception("Cleanup task error: %s", e)


@app.on_event("startup")
async def startup() -> None:
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    asyncio.create_task(_cleanup_loop())
    logger.info("Auth IP NPM Middleware started; conf dir: %s", CONF_DIR)


@app.post("/auth")
async def add_ip(
    body: AddIPRequest,
    _: None = Depends(_verify_token),
) -> dict:
    """
    Add an IP to conf/<app>/allowed_ips.conf. Requires Authorization: Bearer <token>.
    Body: { "ip": "192.168.1.100", "uuid": "user-uuid", "app": "npm" }
    Creates app folder and file if they don't exist. Entry is removed after 6 hours.
    """
    path = _path_for_app(body.app)
    _ensure_app_conf(path)
    added_at = datetime.now(timezone.utc)
    new_line = f"allow {body.ip}; # {body.uuid} - {added_at.isoformat()}"

    text = path.read_text(encoding="utf-8").rstrip()
    if text and not text.endswith("\n"):
        text += "\n"
    # One entry per user UUID: remove any existing line for this UUID (so old IP is overwritten when they connect from a new IP)
    lines = text.splitlines()
    new_lines = []
    had_existing_for_uuid = False
    for line in lines:
        if COMMENT_OR_EMPTY_RE.match(line):
            new_lines.append(line)
            continue
        m = ALLOW_LINE_RE.match(line)
        if m and m.group(2).strip() == body.uuid:
            had_existing_for_uuid = True
            continue  # drop old entry for this user (same or different IP)
        new_lines.append(line)
    new_lines.append(new_line)

    path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    logger.info("Added IP %s for app=%s UUID %s (overwrote_existing=%s)", body.ip, body.app, body.uuid, had_existing_for_uuid)

    await _trigger_npm_reload()

    return {
        "ok": True,
        "ip": body.ip,
        "uuid": body.uuid,
        "app": body.app,
        "expires_hours": ENTRY_MAX_AGE_HOURS,
        "overwrote_existing": had_existing_for_uuid,
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
