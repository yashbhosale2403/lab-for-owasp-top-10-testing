"""Optional HTTP Basic Auth gate for hosted deployments.

When LAB_AUTH_USER and LAB_AUTH_PASS are set (e.g. on Render), every request
must carry matching Basic credentials. When they are unset (local dev), this
middleware does nothing, so the lab behaves exactly as before.
"""
import base64
import hmac
import os

from django.http import HttpResponse


class BasicAuthGate:
    def __init__(self, get_response):
        self.get_response = get_response
        self.user = os.environ.get("LAB_AUTH_USER", "")
        self.password = os.environ.get("LAB_AUTH_PASS", "")

    def __call__(self, request):
        if not (self.user and self.password):
            return self.get_response(request)
        header = request.META.get("HTTP_AUTHORIZATION", "")
        if header.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(header[6:]).decode().partition(":")
            except Exception:
                user = pw = ""
            if hmac.compare_digest(user, self.user) and hmac.compare_digest(pw, self.password):
                return self.get_response(request)
        resp = HttpResponse("Authentication required", status=401)
        resp["WWW-Authenticate"] = 'Basic realm="DjangoGoat lab"'
        return resp
