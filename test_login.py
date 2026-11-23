import base64
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

import dupr_session
import get_token

# Importing the app must not create a roster as a test side effect.
with patch("shutil.copy"):
    import match_app


def token(expiry):
    payload = base64.urlsafe_b64encode(json.dumps({"exp": expiry}).encode()).decode()
    return f"test-header.{payload.rstrip('=')}.not-a-signature"


def response(status=200, body=None):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(body if body is not None else {"result": {"id": 1}}).encode()
    return result


class BrowserLoginTests(unittest.TestCase):
    def test_expired_or_malformed_access_is_not_usable(self):
        for access in (None, "invalid", token(time.time() - 60), token("tomorrow")):
            with self.subTest(access=access):
                self.assertFalse(get_token.usable_access(access))
        self.assertTrue(get_token.usable_access(token(time.time() + 3600)))

    def test_cookie_lookup_is_scoped_to_api_host(self):
        ctx = Mock()
        ctx.cookies.return_value = [
            {"name": get_token.AT_COOKIE, "value": "other-site", "domain": "example.test"},
            {"name": get_token.AT_COOKIE, "value": "api-access", "domain": get_token.API_HOST},
            {"name": get_token.RT_COOKIE, "value": "api-refresh", "domain": get_token.API_HOST},
        ]
        self.assertEqual(get_token.find_cookies(ctx), ("api-access", "api-refresh"))
        ctx.cookies.assert_called_once_with(get_token.BASE_URL)

    def test_expired_saved_cookie_is_cleared_before_login(self):
        ctx = Mock()
        with patch.object(get_token, "find_cookies", return_value=(token(1), "old-refresh")), \
             patch.object(get_token, "validate_access") as validate:
            self.assertEqual(get_token.prepare_context(ctx), (None, None))
        validate.assert_not_called()
        self.assertEqual(ctx.clear_cookies.call_count, 2)
        ctx.clear_cookies.assert_any_call(name=get_token.AT_COOKIE, domain=get_token.API_HOST)
        ctx.clear_cookies.assert_any_call(name=get_token.RT_COOKIE, domain=get_token.API_HOST)

    def test_revoked_saved_cookie_is_cleared_and_valid_cookie_is_reused(self):
        access = token(time.time() + 3600)
        for accepted in (False, True):
            with self.subTest(accepted=accepted):
                ctx = Mock()
                with patch.object(get_token, "find_cookies", return_value=(access, "refresh")), \
                     patch.object(get_token, "validate_access", return_value=accepted):
                    actual = get_token.prepare_context(ctx)
                self.assertEqual(actual, (access, "refresh") if accepted else (None, None))
                self.assertEqual(ctx.clear_cookies.call_count, 0 if accepted else 2)

    def test_wait_ignores_expired_cookie_until_new_login_is_verified(self):
        ctx = Mock()
        ctx.pages = [Mock()]
        fresh = token(time.time() + 3600)
        with patch.object(get_token, "find_cookies", side_effect=[(token(1), None), (fresh, "refresh")]), \
             patch.object(get_token, "validate_access", return_value=True) as validate:
            self.assertEqual(get_token.wait_for_login(ctx), (fresh, "refresh"))
        validate.assert_called_once_with(fresh)
        ctx.pages[0].wait_for_timeout.assert_called_once_with(1000)

    def test_rejected_cookie_is_checked_once_while_waiting_for_replacement(self):
        ctx = Mock()
        ctx.pages = [Mock()]
        rejected = token(time.time() + 3600)
        fresh = token(time.time() + 7200)
        with patch.object(get_token, "find_cookies",
                          side_effect=[(rejected, None), (rejected, None), (fresh, None)]), \
             patch.object(get_token, "validate_access", side_effect=[False, True]) as validate, \
             patch.object(get_token, "log"):
            self.assertEqual(get_token.wait_for_login(ctx), (fresh, None))
        self.assertEqual(validate.call_count, 2)

    def test_closed_browser_and_timeout_are_explicit_errors(self):
        ctx = Mock()
        ctx.pages = []
        with self.assertRaises(get_token.LoginError) as closed:
            get_token.wait_for_login(ctx)
        self.assertEqual(closed.exception.code, 4)
        with self.assertRaises(get_token.LoginError) as timeout:
            get_token.wait_for_login(ctx, timeout=0)
        self.assertEqual(timeout.exception.code, 1)

    def test_profile_validation_uses_only_access_cookie_and_read_only_get(self):
        client = Mock()
        client.session.cookies = requests.cookies.RequestsCookieJar()
        client.session.get.return_value = response()
        with patch.object(get_token, "DuprClient", return_value=client):
            self.assertTrue(get_token.validate_access("test-access"))
        self.assertEqual(client.session.cookies.get_dict(), {get_token.AT_COOKIE: "test-access"})
        client.session.get.assert_called_once_with(
            f"{get_token.BASE_URL}/user/v1.0/profile", timeout=15
        )
        client.session.close.assert_called_once()

    def test_profile_rejection_network_failure_and_invalid_response(self):
        for reply, code in ((response(401), None), (response(403), None),
                            (response(503), 5), (response(body={"result": None}), 6)):
            with self.subTest(status=reply.status_code, code=code):
                client = Mock()
                client.session.get.return_value = reply
                with patch.object(get_token, "DuprClient", return_value=client):
                    if code is None:
                        self.assertFalse(get_token.validate_access("test-access"))
                    else:
                        with self.assertRaises(get_token.LoginError) as error:
                            get_token.validate_access("test-access")
                        self.assertEqual(error.exception.code, code)
        client = Mock()
        client.session.get.side_effect = requests.ConnectionError("sensitive-detail")
        with patch.object(get_token, "DuprClient", return_value=client), \
             self.assertRaises(get_token.LoginError) as error:
            get_token.validate_access("test-access")
        self.assertNotIn("sensitive-detail", str(error.exception))

    def test_main_uses_separate_chrome_profile_and_never_saves_failed_login(self):
        with patch("sys.argv", ["get_token.py"]), \
             patch("playwright.sync_api.sync_playwright") as playwright, \
             patch.object(get_token, "prepare_context", return_value=(None, None)), \
             patch.object(get_token, "wait_for_login", side_effect=get_token.LoginError(4)), \
             patch.object(get_token, "write_env") as save, \
             patch.object(get_token, "log"):
            self.assertEqual(get_token.main(), 4)
        launch = playwright.return_value.__enter__.return_value.chromium.launch_persistent_context
        self.assertEqual(launch.call_args.kwargs["channel"], "chrome")
        self.assertEqual(Path(launch.call_args.kwargs["user_data_dir"]).name, ".pw-profile-chrome")
        launch.return_value.close.assert_called_once()
        save.assert_not_called()


class SavedLoginTests(unittest.TestCase):
    def test_saved_login_overrides_inherited_tokens_without_stale_refresh(self):
        with tempfile.TemporaryDirectory() as folder:
            env = Path(folder) / ".env"
            env.write_text("# keep this\nOTHER_SETTING=yes\nDUPR_BEARER_TOKEN=old\nDUPR_REFRESH_TOKEN=old\n")
            with patch.object(get_token, "ENV_PATH", env), \
                 patch.object(dupr_session, "ENV_PATH", env), \
                 patch.dict(os.environ, {"DUPR_BEARER_TOKEN": "inherited-old",
                                         "DUPR_REFRESH_TOKEN": "inherited-refresh"}), \
                 patch.object(get_token, "log"):
                get_token.write_env("new-access", None)
                self.assertEqual(dupr_session.get_token(), "new-access")
                client = dupr_session.make_client()
                try:
                    self.assertEqual(client.session.cookies.get_dict(),
                                     {dupr_session.AT_COOKIE: "new-access"})
                finally:
                    client.session.close()
            self.assertIn("# keep this\nOTHER_SETTING=yes", env.read_text())
            self.assertNotIn("DUPR_REFRESH_TOKEN", env.read_text())

    def test_failed_atomic_save_preserves_existing_env(self):
        with tempfile.TemporaryDirectory() as folder:
            env = Path(folder) / ".env"
            env.write_text("DUPR_BEARER_TOKEN=old\n")
            with patch.object(get_token, "ENV_PATH", env), \
                 patch.object(get_token.os, "replace", side_effect=PermissionError), \
                 self.assertRaises(PermissionError):
                get_token.write_env("new", None)
            self.assertEqual(env.read_text(), "DUPR_BEARER_TOKEN=old\n")
            self.assertEqual(list(Path(folder).iterdir()), [env])


class ManualCookieTests(unittest.TestCase):
    def test_raw_access_and_full_header_extract_only_auth_cookies(self):
        access = token(time.time() + 3600)
        refresh = token(time.time() + 7200)
        self.assertEqual(get_token.parse_session_cookie(access), (access, None))
        header = f"Cookie: tracking=ignore; {get_token.AT_COOKIE}={access}; {get_token.RT_COOKIE}={refresh}; other=ignore"
        self.assertEqual(get_token.parse_session_cookie(header), (access, refresh))

    def test_invalid_expired_missing_and_duplicate_cookies_are_rejected(self):
        access = token(time.time() + 3600)
        array_payload = base64.urlsafe_b64encode(b"[]").decode().rstrip("=")
        for text in ("", token(1), "tracking=ignore",
                     f"{get_token.AT_COOKIE}={access}; {get_token.AT_COOKIE}={access}",
                     f"{get_token.AT_COOKIE}={access}; {get_token.RT_COOKIE}=bad",
                     access + "\nOTHER_SETTING=injected",
                     f"test-header.{array_payload}.not-a-signature"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                get_token.parse_session_cookie(text)


class AppLoginTests(unittest.TestCase):
    def setUp(self):
        self.web = match_app.app.test_client()
        self.process = patch.object(match_app, "_relogin_proc", None)
        self.start_error = patch.object(match_app, "_relogin_start_error", None)
        self.process.start()
        self.start_error.start()
        self.addCleanup(self.process.stop)
        self.addCleanup(self.start_error.stop)

    def test_status_without_env_returns_unauthenticated_instead_of_exiting(self):
        with patch.object(match_app, "make_client", side_effect=SystemExit("missing")):
            reply = self.web.get("/api/status")
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.json, {"authenticated": False, "login": {"state": "idle"}})

    def test_relogin_browser_selection_and_process_reuse(self):
        proc = Mock()
        proc.poll.return_value = None
        with patch.object(match_app.subprocess, "Popen", return_value=proc) as launch:
            self.assertTrue(self.web.post("/api/relogin", json={"browser": "chrome"}).json["started"])
            self.assertTrue(self.web.post("/api/relogin", json={"browser": "chrome"}).json["alreadyRunning"])
        launch.assert_called_once()
        self.assertEqual(launch.call_args.args[0][-2:], ["--browser", "chrome"])
        self.assertEqual(match_app.login_status(), {"state": "running"})

    def test_invalid_browser_is_rejected_without_launch(self):
        with patch.object(match_app.subprocess, "Popen") as launch:
            for data in ({"browser": "invalid"}, ["chrome"], {"browser": None}):
                self.assertEqual(self.web.post("/api/relogin", json=data).status_code, 400)
        launch.assert_not_called()

    def test_start_failure_is_reported_and_retry_can_succeed(self):
        proc = Mock()
        proc.poll.return_value = None
        with patch.object(match_app.subprocess, "Popen",
                          side_effect=[OSError("sensitive-detail"), proc]):
            failed = self.web.post("/api/relogin", json={"browser": "chrome"})
            self.assertEqual(failed.status_code, 500)
            self.assertNotIn("sensitive-detail", failed.json["error"])
            self.assertEqual(match_app.login_status()["state"], "failed")
            self.assertEqual(self.web.post("/api/relogin").status_code, 200)
            self.assertEqual(match_app.login_status()["state"], "running")

    def test_helper_failure_is_visible_in_status_and_allows_retry(self):
        match_app._relogin_proc = Mock()
        match_app._relogin_proc.poll.return_value = 4
        with patch.object(match_app, "make_client", side_effect=SystemExit):
            state = self.web.get("/api/status").json["login"]
        self.assertEqual(state, {"state": "failed", "error": get_token.LOGIN_ERRORS[4]})
        with patch.object(match_app.subprocess, "Popen") as launch:
            self.assertTrue(self.web.post("/api/relogin").json["started"])
        launch.assert_called_once()

    def test_network_error_is_not_misreported_as_session_expiration(self):
        client = Mock()
        client.session.get.side_effect = requests.ConnectionError("sensitive-detail")
        with patch.object(match_app, "make_client", return_value=client):
            reply = self.web.get("/api/status")
        self.assertEqual(reply.status_code, 200)
        self.assertFalse(reply.json["authenticated"])
        self.assertIn("connection", reply.json["authError"])
        self.assertNotIn("sensitive-detail", reply.json["authError"])
        client.session.close.assert_called_once()

    def test_successful_status_picks_up_saved_session(self):
        proc = Mock()
        proc.poll.return_value = 0
        match_app._relogin_proc = proc
        client = Mock()
        client.session.get.return_value = response(body={"result": {"id": 1, "fullName": "Test User"}})
        with patch.object(match_app, "make_client", return_value=client), \
             patch.object(match_app, "load_roster", return_value={}), \
             patch.object(match_app, "get_submission_mode", return_value={"mode": "fallback"}):
            reply = self.web.get("/api/status")
        self.assertTrue(reply.json["authenticated"])
        self.assertEqual(reply.json["login"], {"state": "succeeded"})

    def test_manual_header_is_verified_and_saved_without_tracking_cookies(self):
        access = token(time.time() + 3600)
        refresh = token(time.time() + 7200)
        with tempfile.TemporaryDirectory() as folder:
            env = Path(folder) / ".env"
            env.write_text("OTHER_SETTING=keep\n")
            with patch.object(get_token, "ENV_PATH", env), \
                 patch.object(match_app, "validate_access", return_value=True) as validate, \
                 patch.object(get_token, "log"):
                reply = self.web.post("/api/session-cookie", json={
                    "cookie": f"tracking=ignore; {get_token.AT_COOKIE}={access}; {get_token.RT_COOKIE}={refresh}"
                })
            self.assertEqual(reply.json, {"ok": True})
            validate.assert_called_once_with(access)
            self.assertEqual(env.read_text(),
                             f"OTHER_SETTING=keep\nDUPR_BEARER_TOKEN={access}\nDUPR_REFRESH_TOKEN={refresh}\n")
            self.assertNotIn(access, reply.get_data(as_text=True))

    def test_manual_invalid_input_is_rejected_without_saving_or_network_calls(self):
        with patch.object(match_app, "validate_access") as validate, \
             patch.object(match_app, "write_env") as save:
            for data in ({}, {"cookie": None}, [], {"cookie": "invalid"}, {"cookie": token(1)}):
                self.assertEqual(self.web.post("/api/session-cookie", json=data).status_code, 400)
            self.assertEqual(self.web.post("/api/session-cookie", data="not-json").status_code, 400)
            self.assertEqual(self.web.post("/api/session-cookie", data="x" * 65537).status_code, 413)
        validate.assert_not_called()
        save.assert_not_called()

    def test_manual_cookie_rejection_and_network_failure_preserve_saved_session(self):
        access = token(time.time() + 3600)
        for accepted, code in ((False, 401), (get_token.LoginError(5), 502)):
            with self.subTest(code=code):
                validate = Mock(side_effect=accepted) if isinstance(accepted, Exception) else Mock(return_value=accepted)
                with patch.object(match_app, "validate_access", validate), \
                     patch.object(match_app, "write_env") as save:
                    reply = self.web.post("/api/session-cookie", json={"cookie": access})
                self.assertEqual(reply.status_code, code)
                self.assertNotIn(access, reply.get_data(as_text=True))
                save.assert_not_called()

    def test_manual_save_failure_is_reported_without_sensitive_details(self):
        with patch.object(match_app, "validate_access", return_value=True), \
             patch.object(match_app, "write_env", side_effect=PermissionError("sensitive-detail")):
            reply = self.web.post("/api/session-cookie", json={"cookie": token(time.time() + 3600)})
        self.assertEqual(reply.status_code, 500)
        self.assertNotIn("sensitive-detail", reply.json["error"])

    def test_manual_cookie_cannot_race_login_helper_or_be_saved_cross_origin(self):
        access = token(time.time() + 3600)
        match_app._relogin_proc = Mock()
        match_app._relogin_proc.poll.return_value = None
        with patch.object(match_app, "validate_access") as validate, \
             patch.object(match_app, "write_env") as save:
            self.assertEqual(self.web.post("/api/session-cookie", json={"cookie": access}).status_code, 409)
            self.assertEqual(self.web.post("/api/session-cookie", json={"cookie": access},
                                          headers={"Origin": "https://other.test"}).status_code, 403)
            self.assertEqual(self.web.post("/api/session-cookie", json={"cookie": access},
                                          environ_overrides={"REMOTE_ADDR": "192.0.2.1"}).status_code, 403)
        validate.assert_not_called()
        save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
