"""Grab a DUPR access token from a real logged-in browser session.

DUPR's dashboard authenticates with HttpOnly cookies on api.dupr.com:
    __Host-dupr_at  -> access token (JWT)
    __Host-dupr_rt  -> refresh token

Playwright can read those cookies even though JS can't. This opens Chromium on
a separate app-only profile; you log in by hand, then it validates and writes
the access token to `.env` as DUPR_BEARER_TOKEN. No personal browser profile
is opened.

Run:
    .venv\\Scripts\\python.exe get_token.py
"""

import argparse
import base64
import binascii
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import requests

from dupr_session import API_HOST, AT_COOKIE, BASE_URL, RT_COOKIE, DuprClient

HERE = Path(__file__).parent
ENV_PATH = HERE / ".env"
START_URL = "https://dashboard.dupr.com/login"
BROWSERS = ("chrome", "chromium", "msedge")
LOGIN_ERRORS = {
    1: "Login timed out after 10 minutes. Retry and finish signing in in the browser window.",
    2: "Could not open the login browser. Install the selected browser, or choose Chromium "
       "and run: python -m playwright install chromium. Close any other app login window and retry.",
    3: "Could not load DUPR's login page. Check your connection and try DUPR in your normal browser.",
    4: "The login browser was closed before login finished. Click Log in with browser to retry.",
    5: "Could not verify the session with DUPR. Check your connection and try again.",
    6: "DUPR did not return a usable profile for the new session. Try signing in again.",
    7: "Could not save the session to the local .env file. Check folder permissions and retry.",
}


class LoginError(Exception):
    def __init__(self, code: int):
        self.code = code
        super().__init__(LOGIN_ERRORS[code])


def log(*a) -> None:
    print(*a, flush=True)


def decode_jwt(tok: str) -> dict:
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, IndexError, binascii.Error, UnicodeDecodeError):
        return {}


def usable_access(access: str | None) -> bool:
    if not access:
        return False
    expiry = decode_jwt(access).get("exp")
    return isinstance(expiry, (int, float)) and expiry > time.time() + 30


def validate_access(access: str) -> bool:
    """Check only the access cookie: a refresh cookie must not mask its rejection."""
    client = DuprClient()
    client.session.cookies.set(AT_COOKIE, access, domain=API_HOST, secure=True)
    try:
        response = client.session.get(f"{BASE_URL}/user/v1.0/profile", timeout=15)
        if response.status_code in (401, 403):
            return False
        response.raise_for_status()
        profile = response.json().get("result")
        if not isinstance(profile, dict) or not profile:
            raise LoginError(6)
        return True
    except requests.RequestException:
        raise LoginError(5) from None
    except (ValueError, AttributeError):
        raise LoginError(6) from None
    finally:
        client.session.close()


def write_env(access: str, refresh: str | None) -> None:
    keep = []
    if ENV_PATH.exists():
        keep = [
            ln for ln in ENV_PATH.read_text().splitlines()
            if not ln.split("=", 1)[0].strip()
            in {"DUPR_BEARER_TOKEN", "DUPR_REFRESH_TOKEN"}
        ]
    keep.append(f"DUPR_BEARER_TOKEN={access}")
    if refresh:
        keep.append(f"DUPR_REFRESH_TOKEN={refresh}")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=ENV_PATH.parent, prefix=".env-", delete=False
        ) as file:
            temporary = Path(file.name)
            file.write("\n".join(keep) + "\n")
        os.replace(temporary, ENV_PATH)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    log("\nSaved the verified session to the local .env file.")


def find_cookies(ctx) -> tuple[str | None, str | None]:
    at = rt = None
    for c in ctx.cookies(BASE_URL):
        if c["domain"] != API_HOST:
            continue
        if c["name"] == AT_COOKIE:
            at = c["value"]
        elif c["name"] == RT_COOKIE:
            rt = c["value"]
    return at, rt


def prepare_context(ctx) -> tuple[str | None, str | None]:
    access, refresh = find_cookies(ctx)
    if usable_access(access) and validate_access(access):
        return access, refresh
    # Remove only rejected DUPR auth cookies, not browser preferences or other sites.
    for name in (AT_COOKIE, RT_COOKIE):
        ctx.clear_cookies(name=name, domain=API_HOST)
    return None, None


def wait_for_login(ctx, timeout: float = 600) -> tuple[str, str | None]:
    deadline = time.monotonic() + timeout
    checked = None
    while time.monotonic() < deadline:
        if not ctx.pages:
            raise LoginError(4)
        access, refresh = find_cookies(ctx)
        if usable_access(access) and access != checked:
            checked = access
            if validate_access(access):
                return access, refresh
            log("DUPR rejected the session cookie. Finish signing in or retry.")
        ctx.pages[0].wait_for_timeout(1000)
    raise LoginError(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=BROWSERS, default="chrome")
    args = parser.parse_args()
    try:
        from playwright.sync_api import Error, sync_playwright
    except ImportError:
        log(LOGIN_ERRORS[2])
        return 2

    profile = HERE / (".pw-profile" if args.browser == "chromium"
                      else f".pw-profile-{args.browser}")
    try:
        with sync_playwright() as p:
            try:
                ctx = p.chromium.launch_persistent_context(
                    user_data_dir=str(profile), headless=False, channel=args.browser,
                    viewport={"width": 1280, "height": 900},
                )
            except Error:
                raise LoginError(2) from None
            try:
                access, refresh = prepare_context(ctx)
                if not access:
                    page = ctx.pages[0] if ctx.pages else ctx.new_page()
                    try:
                        page.goto(START_URL, wait_until="domcontentloaded", timeout=60000)
                    except Error:
                        raise LoginError(3) from None
                    log(f"Sign in to DUPR in the {args.browser} window. Waiting up to 10 minutes.")
                    access, refresh = wait_for_login(ctx)
                try:
                    write_env(access, refresh)
                except OSError:
                    raise LoginError(7) from None
            finally:
                ctx.close()
    except LoginError as error:
        log(str(error))
        return error.code
    except (Error, KeyboardInterrupt):
        log(LOGIN_ERRORS[4])
        return 4
    log("Login verified. The app will pick up the saved session automatically.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
