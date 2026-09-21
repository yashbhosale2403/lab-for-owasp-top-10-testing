# DjangoGoat — "ByteForge" storefront edition

An intentionally vulnerable Django application, skinned as **ByteForge**, a
fictional laptop & PC-parts e-commerce site, in the same spirit as OWASP
Juice Shop: real vulnerabilities woven into realistic shopping flows (search,
order tracking, account settings, support tools) instead of a bare checklist.
Named in the tradition of OWASP's WebGoat/NodeGoat.

Every vulnerable flow has a `-safe` counterpart demonstrating the correct
pattern (reachable directly by URL — see [Endpoint reference](#endpoint-reference)),
so a scanner (or a person) can be exercised for both true positives and true
negatives. A full tester-facing index lives at `/challenges/` (linked from the
footer as "For Security Testers").

This project started as the internal test fixture for
[DjangoShield](https://github.com/yashbhosale2403/web-venerability-scanner-),
a DAST scanner, and was split out as its own standalone project with a
broader set of vulnerability categories and a realistic storefront UI.

**ByteForge is a fictional brand invented for this project** — it is not
affiliated with, endorsed by, or representative of any real retailer or
hardware maker. All product names, specs, and prices are made up.

## Where the vulnerabilities live in the storefront

| Storefront feature | Vulnerability | Backend endpoint |
|---|---|---|
| Nav search bar | Reflected XSS | `GET /xss/` |
| "Track your order" | SQL injection | `GET /track-order/` |
| Product "Download Spec Sheet" | Path traversal | `GET /files/read/` |
| Support → "Network diagnostics" | OS command injection | `GET /tools/ping/` |
| Support → "Build compatibility check" | SSRF | `GET /fetch/` |
| Support → "Partner deals" | Open redirect | `GET /go/` |
| Support / footer → "Report a site issue" | Django DEBUG exposure | `GET /trigger-error/` |
| Account settings (hidden `role` field) | Mass assignment | `POST /account/settings/` |
| "Redeem a gift card" | CSRF | `POST /transfer/` |
| My Orders → "View details" | Broken access control / IDOR | `GET /orders/<id>/` |
| Footer → "Employee Portal" | Broken access control | `GET /admin-panel/` |
| `/robots.txt` hints at it | Information disclosure | `GET /backup.sql.bak` |

## ⚠️ Read this before running it

**This application is intentionally insecure.** A few endpoints go further
than the usual "missing header" or "unescaped output" demo:

- `/tools/ping/` runs a real shell command built from unsanitized input
  (OS command injection).
- `/fetch/` makes a real outbound HTTP request to whatever URL you give it
  (SSRF).
- `/files/read/` reads arbitrary files the server process can access
  (path traversal).

**Never run this anywhere but `127.0.0.1` on your own machine.** Do not run
it on a shared network, a cloud VM, or any host with an internal service or
metadata endpoint you wouldn't want probed. Do not expose port 9000 outside
localhost.

## Setup

```bash
python -m venv venv
source venv/bin/activate  # venv\Scripts\activate on Windows
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_lab_data
python manage.py runserver 9000
```

Then open `http://127.0.0.1:9000/`.

Seeded accounts (password for both: `lab-password-123`):

- `alice`
- `bob`

Each has one private `Order` and one `Profile`, used to demonstrate
broken access control / IDOR and mass assignment.

### Docker

```bash
docker build -t djangogoat .
docker run --rm -p 127.0.0.1:9000:9000 djangogoat
```

The `-p 127.0.0.1:9000:9000` binding (rather than just `-p 9000:9000`) keeps
the container reachable only from localhost.

### Tests

```bash
pytest
```

`vulnerable_app/tests.py` confirms every vulnerable/safe pair actually
behaves as advertised — this is what any scanner built against this lab
should be validated against.

## Endpoint reference
<a id="endpoint-reference"></a>

| Category | OWASP | Vulnerable | Safe |
|---|---|---|---|
| Reflected XSS | A03 Injection | `GET /xss/?q=` | `GET /search-safe/?q=` |
| SQL injection | A03 Injection | `GET /sqli/?id=` | `GET /sqli-safe/?id=` |
| OS command injection | A03 Injection | `GET /tools/ping/?host=` | `GET /tools/ping-safe/?host=` |
| Path traversal | A01 Broken Access Control | `GET /files/read/?name=` | `GET /files/read-safe/?name=` |
| Open redirect | A01 Broken Access Control | `GET /go/?next=` | `GET /go-safe/?next=` |
| SSRF | A10 SSRF | `GET /fetch/?url=` | `GET /fetch-safe/?url=` |
| Mass assignment | A04 Insecure Design | `POST /profile/update/` (JSON, login required) | `POST /profile/update-safe/` |
| CSRF | A01 Broken Access Control | `GET/POST /transfer/` | `GET/POST /transfer-safe/` |
| Broken access control / IDOR | A01 Broken Access Control | `GET /orders/<id>/`, `GET /admin-panel/` | `GET /orders/<id>/safe/` |
| Django DEBUG exposure | A05 Security Misconfiguration | `GET /trigger-error/` | — |
| Weak cookies | A05 Security Misconfiguration | `GET /set-cookie/` | `GET /set-cookie-safe/` |
| CORS misconfiguration | A05 Security Misconfiguration | `GET /api/cors/` | `GET /api/cors-safe/` |
| Information disclosure | A05 Security Misconfiguration | `GET /backup.sql.bak` | — |

Supporting endpoints: `/login/`, `/logout/`, `/whoami/`, `/internal/status/`
(the fixed allowlisted destination `/fetch-safe/` is allowed to reach).

### Notes on the riskier demos

- **OS command injection** (`/tools/ping/?host=`) runs `ping` via
  `subprocess.run(..., shell=True)` with the host string concatenated
  directly into the command. A payload like `127.0.0.1; echo pwned` (or
  `127.0.0.1 & echo pwned` on Windows) demonstrates arbitrary command
  execution, exactly like the classic DVWA/bWAPP command-injection labs.
- **Path traversal** (`/files/read/?name=`) is sandboxed to
  `vulnerable_app/lab_files/` in name only — `../../lab_config/settings.py`
  escapes it and returns the lab's own (already-public, lab-only)
  `SECRET_KEY`, so the demo has no real blast radius even when it "succeeds."
- **SSRF** (`/fetch/?url=`) will genuinely try to reach whatever URL you give
  it, including other services on your machine or network. This is why the
  app must never run anywhere with a metadata endpoint or internal service
  reachable.

## Architecture

- `lab_config/` — Django project settings, URLs, WSGI/ASGI entrypoints.
- `vulnerable_app/` — the single app holding every vulnerable/safe view pair,
  the storefront page views (`home`, `track_order_page`, `support_page`,
  `account_settings_page`, `my_orders_page`), models (`Order`, `Profile`),
  and `management/commands/seed_lab_data.py`.
- `vulnerable_app/lab_files/` — the sandbox directory for the path-traversal
  demo, including per-product spec sheets served by "Download Spec Sheet".
- `templates/vulnerable_app/base.html` — shared nav/footer and the ByteForge
  theme; every page extends it.
- `templates/vulnerable_app/challenges.html` — the full tester-facing
  vulnerable/safe endpoint index (`/challenges/`).

## License

MIT, see [LICENSE](LICENSE). DjangoGoat is for authorized, local security
testing and education only.
