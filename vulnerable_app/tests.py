"""Confirms the lab's vulnerable/safe endpoint pairs actually behave as
advertised -- this is what DjangoShield's own detector tests rely on being
true. If one of these breaks, the detector tests built against this lab
would be validating nothing.
"""

import os

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings

from .models import Order, Profile


class LabFixtureTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user(username="alice", password="pw12345")
        self.bob = User.objects.create_user(username="bob", password="pw12345")
        self.alice_order = Order.objects.create(owner=self.alice, item_name="A", amount="10.00")
        self.bob_order = Order.objects.create(owner=self.bob, item_name="B", amount="20.00")

    def test_xss_vulnerable_reflects_script_unescaped(self):
        response = self.client.get("/xss/", {"q": "<script>alert(1)</script>"})
        self.assertIn(b"<script>alert(1)</script>", response.content)

    def test_xss_safe_escapes_script(self):
        response = self.client.get("/search-safe/", {"q": "<script>alert(1)</script>"})
        self.assertNotIn(b"<script>alert(1)</script>", response.content)
        self.assertIn(b"&lt;script&gt;", response.content)

    def test_sqli_vulnerable_boolean_injection_returns_all_rows(self):
        response = self.client.get("/sqli/", {"id": "1 OR 1=1"})
        data = response.json()
        self.assertEqual(len(data["results"]), 2)

    def test_sqli_vulnerable_syntax_error_surfaces_db_error(self):
        response = self.client.get("/sqli/", {"id": "1'"})
        self.assertEqual(response.status_code, 500)
        self.assertIn(b"Database error", response.content)

    def test_sqli_safe_ignores_injection_payload(self):
        response = self.client.get("/sqli-safe/", {"id": "1 OR 1=1"})
        data = response.json()
        self.assertEqual(len(data["results"]), 0)

    def test_transfer_vulnerable_accepts_post_without_csrf_token(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post("/transfer/", {"note": "x"})
        self.assertEqual(response.status_code, 200)

    def test_transfer_safe_rejects_post_without_csrf_token(self):
        client = Client(enforce_csrf_checks=True)
        client.login(username="alice", password="pw12345")
        response = client.post("/transfer-safe/", {"note": "x"})
        self.assertEqual(response.status_code, 403)

    def test_idor_vulnerable_allows_cross_user_access(self):
        self.client.login(username="alice", password="pw12345")
        response = self.client.get(f"/orders/{self.bob_order.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["owner"], "bob")

    def test_idor_safe_denies_cross_user_access(self):
        self.client.login(username="alice", password="pw12345")
        response = self.client.get(f"/orders/{self.bob_order.id}/safe/")
        self.assertEqual(response.status_code, 404)

    def test_admin_panel_accessible_to_non_staff_user(self):
        self.assertFalse(self.alice.is_staff)
        self.client.login(username="alice", password="pw12345")
        response = self.client.get("/admin-panel/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["orders"]), 2)

    @override_settings(DEBUG=True)
    def test_trigger_error_shows_debug_traceback(self):
        client = Client(raise_request_exception=False)
        response = client.get("/trigger-error/")
        self.assertEqual(response.status_code, 500)
        self.assertIn(b"Traceback", response.content)

    def test_weak_cookie_missing_security_flags(self):
        response = self.client.get("/set-cookie/")
        cookie = response.cookies["lab_session_token"]
        self.assertEqual(cookie["secure"], "")
        self.assertEqual(cookie["httponly"], "")

    def test_safe_cookie_has_security_flags(self):
        response = self.client.get("/set-cookie-safe/")
        cookie = response.cookies["lab_session_token_safe"]
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Strict")

    def test_cors_vulnerable_reflects_arbitrary_origin_with_credentials(self):
        response = self.client.get("/api/cors/", HTTP_ORIGIN="https://evil.example")
        self.assertEqual(response["Access-Control-Allow-Origin"], "https://evil.example")
        self.assertEqual(response["Access-Control-Allow-Credentials"], "true")

    def test_cors_safe_has_no_cors_headers(self):
        response = self.client.get("/api/cors-safe/", HTTP_ORIGIN="https://evil.example")
        self.assertNotIn("Access-Control-Allow-Origin", response)

    def test_backup_file_exposes_fake_secrets(self):
        response = self.client.get("/backup.sql.bak")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"DB_PASSWORD", response.content)

    # -- Path traversal -----------------------------------------------------

    def test_file_read_vulnerable_escapes_sandbox_via_traversal(self):
        response = self.client.get("/files/read/", {"name": "../../lab_config/settings.py"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SECRET_KEY", response.content)

    def test_file_read_safe_blocks_traversal(self):
        response = self.client.get("/files/read-safe/", {"name": "../../lab_config/settings.py"})
        self.assertEqual(response.status_code, 400)

    def test_file_read_safe_allows_sandboxed_file(self):
        response = self.client.get("/files/read-safe/", {"name": "notes.txt"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"public lab notes", response.content)

    # -- OS command injection ------------------------------------------------

    def test_ping_vulnerable_executes_injected_command(self):
        marker = "DJANGOGOAT_INJECTION_MARKER"
        separator = "&" if os.name == "nt" else ";"
        payload = f"127.0.0.1 {separator} echo {marker}"
        response = self.client.get("/tools/ping/", {"host": payload})
        self.assertEqual(response.status_code, 200)
        self.assertIn(marker.encode(), response.content)

    def test_ping_safe_rejects_shell_metacharacters(self):
        response = self.client.get("/tools/ping-safe/", {"host": "127.0.0.1; echo hi"})
        self.assertEqual(response.status_code, 400)

    # -- Open redirect --------------------------------------------------------

    def test_redirect_vulnerable_follows_arbitrary_external_url(self):
        response = self.client.get("/go/", {"next": "https://evil.example/phish"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "https://evil.example/phish")

    def test_redirect_safe_ignores_unlisted_target(self):
        response = self.client.get("/go-safe/", {"next": "https://evil.example/phish"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")

    # -- SSRF -------------------------------------------------------------

    def test_fetch_vulnerable_attempts_arbitrary_url(self):
        """A port nothing listens on: the vulnerable endpoint should still
        *attempt* the request (proving it has no allowlist) and surface a
        connection failure, rather than refusing up front."""
        response = self.client.get("/fetch/", {"url": "http://127.0.0.1:1/"})
        self.assertEqual(response.status_code, 502)

    def test_fetch_safe_rejects_non_allowlisted_url(self):
        response = self.client.get("/fetch-safe/", {"url": "http://127.0.0.1:1/"})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"allowlist", response.content)

    # -- Mass assignment --------------------------------------------------

    def test_profile_update_vulnerable_allows_role_escalation(self):
        Profile.objects.create(user=self.alice, role="user")
        self.client.login(username="alice", password="pw12345")
        response = self.client.post(
            "/profile/update/",
            data='{"role": "admin"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["role"], "admin")
        self.alice.profile.refresh_from_db()
        self.assertEqual(self.alice.profile.role, "admin")

    def test_profile_update_safe_ignores_role_field(self):
        Profile.objects.create(user=self.alice, role="user")
        self.client.login(username="alice", password="pw12345")
        response = self.client.post(
            "/profile/update-safe/",
            data='{"role": "admin", "bio": "hi"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["role"], "user")
        self.alice.profile.refresh_from_db()
        self.assertEqual(self.alice.profile.role, "user")
        self.assertEqual(self.alice.profile.bio, "hi")
