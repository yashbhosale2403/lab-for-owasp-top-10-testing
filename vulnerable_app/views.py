"""Intentionally vulnerable views for validating DjangoShield's detectors.

Every vulnerable view has a "-safe" counterpart demonstrating the correct
pattern, so detectors can be tested for both true positives and true
negatives. Nothing here is destructive: the SQL injection demo can only read
from a small local table, and no view touches anything outside this lab's
own sqlite database.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.csrf import csrf_exempt

from .models import Order, Profile

LAB_FILES_DIR = Path(__file__).resolve().parent / "lab_files"


def home(request):
    return render(request, "vulnerable_app/home.html")


def login_view(request):
    error = None
    if request.method == "POST":
        user = authenticate(
            request, username=request.POST.get("username"), password=request.POST.get("password")
        )
        if user is not None:
            login(request, user)
            return redirect("home")
        error = "Invalid credentials."
    return render(request, "vulnerable_app/login.html", {"error": error})


def logout_view(request):
    logout(request)
    return redirect("home")


# ---------------------------------------------------------------------------
# 1. Reflected XSS
# ---------------------------------------------------------------------------


def xss_vulnerable(request):
    """VULNERABLE: the query param is written into the page with autoescape
    off, so <script> etc. is reflected verbatim."""
    query = request.GET.get("q", "")
    html = f"""
    <html><body>
        <h1>Search results</h1>
        <p>You searched for: {query}</p>
    </body></html>
    """
    return HttpResponse(html)


def xss_safe(request):
    """SAFE: Django's template autoescaping neutralizes the same input."""
    query = request.GET.get("q", "")
    return render(request, "vulnerable_app/search_safe.html", {"query": query})


# ---------------------------------------------------------------------------
# 2. SQL injection
# ---------------------------------------------------------------------------


def sqli_vulnerable(request):
    """VULNERABLE: builds a raw SQL string via f-string interpolation.
    A payload like `1 OR 1=1` returns every order; a syntax-breaking payload
    like `1'` triggers a visible SQLite error -- both are what
    DjangoShield's SQLi detector should key off.
    """
    order_id = request.GET.get("id", "1")
    with connection.cursor() as cursor:
        query = f"SELECT id, item_name, amount FROM vulnerable_app_order WHERE id = {order_id}"
        try:
            cursor.execute(query)
            rows = cursor.fetchall()
        except Exception as exc:  # intentionally broad: we want the raw DB error surfaced
            return HttpResponse(f"Database error: {exc}", status=500)
    return JsonResponse({"query": query, "results": rows})


def sqli_safe(request):
    """SAFE: parameterized query via the ORM, with basic input validation so
    a non-numeric id returns an empty result instead of a 500."""
    raw_id = request.GET.get("id", "1")
    if not raw_id.lstrip("-").isdigit():
        return JsonResponse({"results": []})
    orders = Order.objects.filter(id=int(raw_id)).values("id", "item_name", "amount")
    return JsonResponse({"results": list(orders)})


# ---------------------------------------------------------------------------
# 3. CSRF weakness
# ---------------------------------------------------------------------------


@csrf_exempt
def transfer_vulnerable(request):
    """VULNERABLE: a state-changing POST endpoint with CSRF protection
    explicitly disabled and no token check of any kind."""
    if request.method == "POST":
        note = request.POST.get("note", "")
        return JsonResponse({"status": "transferred", "note": note})
    return render(request, "vulnerable_app/transfer_vulnerable.html")


@login_required
def transfer_safe(request):
    """SAFE: normal Django POST, protected by CsrfViewMiddleware."""
    if request.method == "POST":
        note = request.POST.get("note", "")
        return JsonResponse({"status": "transferred", "note": note})
    return render(request, "vulnerable_app/transfer_safe.html")


# ---------------------------------------------------------------------------
# 4. IDOR / broken access control
# ---------------------------------------------------------------------------


@login_required
def order_detail_vulnerable(request, order_id: int):
    """VULNERABLE: returns any order to any logged-in user, regardless of
    who owns it."""
    order = get_object_or_404(Order, id=order_id)
    return JsonResponse(
        {
            "id": order.id,
            "owner": order.owner.username,
            "item": order.item_name,
            "amount": str(order.amount),
        }
    )


@login_required
def order_detail_safe(request, order_id: int):
    """SAFE: checks the requesting user owns the order."""
    order = get_object_or_404(Order, id=order_id, owner=request.user)
    return JsonResponse(
        {
            "id": order.id,
            "owner": order.owner.username,
            "item": order.item_name,
            "amount": str(order.amount),
        }
    )


@login_required
def admin_panel_vulnerable(request):
    """VULNERABLE (broken access control): only checks that *someone* is
    logged in, not that they're staff, before exposing every user's orders."""
    orders = Order.objects.select_related("owner").all()
    return JsonResponse(
        {
            "orders": [
                {
                    "id": o.id,
                    "owner": o.owner.username,
                    "item": o.item_name,
                    "amount": str(o.amount),
                }
                for o in orders
            ]
        }
    )


# ---------------------------------------------------------------------------
# 5. Django DEBUG exposure
# ---------------------------------------------------------------------------


def trigger_error(request):
    """With DEBUG=True (always, in this lab) this renders Django's full
    technical error page: traceback, settings, request metadata."""
    raise RuntimeError("Intentional error to demonstrate Django's DEBUG error page.")


# ---------------------------------------------------------------------------
# 6/7. Weak cookies
# ---------------------------------------------------------------------------


def set_cookie_vulnerable(request):
    """VULNERABLE: sets a session-like cookie with none of Secure/HttpOnly/SameSite."""
    response = HttpResponse("Cookie set (insecure).")
    response.set_cookie("lab_session_token", "not-a-real-secret-abc123")
    return response


def set_cookie_safe(request):
    """SAFE: Secure + HttpOnly + SameSite=Strict."""
    response = HttpResponse("Cookie set (secure).")
    response.set_cookie(
        "lab_session_token_safe",
        "not-a-real-secret-abc123",
        secure=True,
        httponly=True,
        samesite="Strict",
    )
    return response


# ---------------------------------------------------------------------------
# 8. CORS misconfiguration
# ---------------------------------------------------------------------------


def cors_vulnerable(request):
    """VULNERABLE: reflects any Origin and allows credentials -- the classic
    dangerous CORS combination."""
    response = JsonResponse({"data": "sensitive-looking payload"})
    origin = request.headers.get("Origin", "*")
    response["Access-Control-Allow-Origin"] = origin
    response["Access-Control-Allow-Credentials"] = "true"
    return response


def cors_safe(request):
    """SAFE: no CORS headers at all -- same-origin only."""
    return JsonResponse({"data": "sensitive-looking payload"})


# ---------------------------------------------------------------------------
# 9. Information disclosure
# ---------------------------------------------------------------------------


def backup_file(request):
    """VULNERABLE: an accidentally-exposed backup file containing what looks
    like real configuration secrets (all fake, but shaped like the real thing)."""
    content = (
        "# database backup config (should never be web-accessible)\n"
        "DB_HOST=127.0.0.1\n"
        "DB_USER=lab_admin\n"
        "DB_PASSWORD=not-a-real-password-example123\n"
        "DJANGO_SECRET_KEY=insecure-lab-only-key-do-not-reuse-anywhere-else\n"
    )
    return HttpResponse(content, content_type="text/plain")


# ---------------------------------------------------------------------------
# 10. Path traversal / local file inclusion
# ---------------------------------------------------------------------------


def file_read_vulnerable(request):
    """VULNERABLE: joins user input onto a base directory with no
    normalization or boundary check, so `../` sequences escape the
    lab_files/ sandbox and read arbitrary files the process can access."""
    name = request.GET.get("name", "notes.txt")
    target = LAB_FILES_DIR / name
    try:
        content = target.read_text(errors="replace")
    except OSError as exc:
        return HttpResponse(f"Could not read file: {exc}", status=404, content_type="text/plain")
    return HttpResponse(content, content_type="text/plain")


def file_read_safe(request):
    """SAFE: resolves the final path and rejects anything that escapes the
    sandbox directory, instead of trying to blocklist `..`."""
    name = request.GET.get("name", "notes.txt")
    sandbox = LAB_FILES_DIR.resolve()
    target = (LAB_FILES_DIR / name).resolve()
    if target != sandbox and sandbox not in target.parents:
        return HttpResponse("Invalid file name.", status=400, content_type="text/plain")
    try:
        content = target.read_text(errors="replace")
    except OSError as exc:
        return HttpResponse(f"Could not read file: {exc}", status=404, content_type="text/plain")
    return HttpResponse(content, content_type="text/plain")


# ---------------------------------------------------------------------------
# 11. OS command injection
# ---------------------------------------------------------------------------


def ping_vulnerable(request):
    """VULNERABLE: builds a shell command string by concatenating
    unsanitized input and runs it with shell=True, so shell metacharacters
    (`;`, `&&`, `|`, backticks) let an attacker run arbitrary commands
    alongside the intended `ping`."""
    host = request.GET.get("host", "127.0.0.1")
    count_flag = "-n" if os.name == "nt" else "-c"
    command = f"ping {count_flag} 1 {host}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
    except Exception as exc:  # intentionally broad: surface whatever the shell did
        output = str(exc)
    return HttpResponse(output, content_type="text/plain")


def ping_safe(request):
    """SAFE: validates the host against a strict allow-pattern and passes an
    argument list (shell=False) instead of a shell string, so
    metacharacters have no special meaning."""
    host = request.GET.get("host", "127.0.0.1")
    if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host):
        return HttpResponse("Invalid host.", status=400, content_type="text/plain")
    count_flag = "-n" if os.name == "nt" else "-c"
    try:
        result = subprocess.run(
            ["ping", count_flag, "1", host], shell=False, capture_output=True, text=True, timeout=5
        )
        output = result.stdout + result.stderr
    except Exception as exc:
        output = str(exc)
    return HttpResponse(output, content_type="text/plain")


# ---------------------------------------------------------------------------
# 12. Open redirect
# ---------------------------------------------------------------------------

_ALLOWED_REDIRECT_PATHS = {"/", "/login/", "/admin-panel/"}


def redirect_vulnerable(request):
    """VULNERABLE: redirects to whatever `next` the caller supplies, with no
    validation -- classic phishing-enabling open redirect
    (`/go/?next=https://evil.example`)."""
    next_url = request.GET.get("next", "/")
    return redirect(next_url)


def redirect_safe(request):
    """SAFE: only redirects to a fixed allowlist of known-local paths."""
    next_url = request.GET.get("next", "/")
    if next_url not in _ALLOWED_REDIRECT_PATHS:
        next_url = "/"
    return redirect(next_url)


# ---------------------------------------------------------------------------
# 13. Server-side request forgery (SSRF)
# ---------------------------------------------------------------------------


def internal_status(request):
    """A stand-in for an internal-only service: the only URL the safe fetch
    endpoint below is allowed to reach."""
    return JsonResponse({"internal": True, "service": "status"})


def fetch_vulnerable(request):
    """VULNERABLE: makes a server-side request to whatever URL the caller
    supplies, with no allowlist -- lets an attacker reach internal services,
    loopback, or (on a cloud host) the instance metadata endpoint."""
    url = request.GET.get("url", "")
    if not url:
        return JsonResponse({"error": "missing url param"}, status=400)
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            body = resp.read(2048).decode(errors="replace")
        return JsonResponse({"status": resp.status, "body": body})
    except (urllib.error.URLError, ValueError) as exc:
        return JsonResponse({"error": str(exc)}, status=502)


def fetch_safe(request):
    """SAFE: only allows fetching a fixed, explicitly-allowlisted internal
    URL -- allowlisting the destination, not trying to blocklist attacker
    input."""
    url = request.GET.get("url", "")
    allowed_url = request.build_absolute_uri("/internal/status/")
    if url != allowed_url:
        return JsonResponse({"error": "url is not on the allowlist"}, status=400)
    with urllib.request.urlopen(allowed_url, timeout=3) as resp:
        body = resp.read(2048).decode(errors="replace")
    return JsonResponse({"status": resp.status, "body": body})


# ---------------------------------------------------------------------------
# 14. Mass assignment
# ---------------------------------------------------------------------------


@login_required
@csrf_exempt
def profile_update_vulnerable(request):
    """VULNERABLE: applies every field in the request body directly onto
    the model with no whitelist, so a client can set `role: "admin"` even
    though the UI only ever means to let a user edit their own bio."""
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    try:
        data = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    profile, _ = Profile.objects.get_or_create(user=request.user)
    for field, value in data.items():
        if hasattr(profile, field) and field not in {"id", "user", "user_id"}:
            setattr(profile, field, value)
    profile.save()
    return JsonResponse({"bio": profile.bio, "role": profile.role})


@login_required
@csrf_exempt
def profile_update_safe(request):
    """SAFE: whitelists exactly the fields the client is allowed to change;
    `role` can never be touched through this endpoint."""
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    try:
        data = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    profile, _ = Profile.objects.get_or_create(user=request.user)
    if "bio" in data:
        profile.bio = str(data["bio"])[:200]
        profile.save()
    return JsonResponse({"bio": profile.bio, "role": profile.role})


# ---------------------------------------------------------------------------
# Seed helper endpoint (dev convenience, not a vulnerability demo)
# ---------------------------------------------------------------------------


def whoami(request):
    if request.user.is_authenticated:
        return JsonResponse({"username": request.user.username})
    return JsonResponse({"username": None})
