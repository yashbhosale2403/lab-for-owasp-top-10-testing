"""
Settings for DjangoGoat -- an intentionally vulnerable Django application.

*** THIS PROJECT IS INTENTIONALLY INSECURE. ***
It exists to give DAST scanners, and people learning web app security, real,
controlled vulnerabilities to find -- including a couple (OS command
injection, SSRF) that can reach outside the Python process. Never deploy it
anywhere reachable from the internet or any shared network, never reuse this
SECRET_KEY, and never point it at anything but 127.0.0.1 during development.

DEBUG stays True permanently -- the lab's own Django-DEBUG-exposure scenario
depends on it, and this project is never meant to run anywhere but a
developer's own machine.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "insecure-lab-only-key-do-not-reuse-anywhere-else"  # intentionally public, lab-only

DEBUG = True

ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "vulnerable_app",
]

# Intentionally omits django.middleware.clickjacking.XFrameOptionsMiddleware
# so the lab has no clickjacking protection -- part of the "missing security
# headers" scenario DjangoShield's headers detector should catch.
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "lab_config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "lab_config.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db_lab.sqlite3",
    }
}

# Deliberately no password validators -- this is a throwaway lab, not a real auth system.
AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Django 3.0+/4.0+ set these secure-by-default headers automatically. Explicitly
# clearing them so the lab genuinely lacks Referrer-Policy / Cross-Origin-Opener-Policy
# for the headers detector to find, rather than accidentally being secure by inertia.
SECURE_REFERRER_POLICY = None
SECURE_CROSS_ORIGIN_OPENER_POLICY = None

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"
