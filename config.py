"""Configuracion y constantes del proyecto."""

import os
from dotenv import load_dotenv

load_dotenv()

# --- Metadata ---

APP_NAME = "ExposedCheck"
APP_VERSION = "1.1.0"

# --- API Endpoints ---

XPOSEDORNOT_BREACH_URL = "https://api.xposedornot.com/v1/breach-analytics"
XPOSEDORNOT_PASSWORD_URL = "https://passwords.xposedornot.com/v1/pass/anon"

HIBP_PASSWORD_URL = "https://api.pwnedpasswords.com/range"

LEAKCHECK_PUBLIC_URL = "https://leakcheck.io/api/public"

HUDSONROCK_EMAIL_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
HUDSONROCK_USERNAME_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"

GITHUB_API_URL = "https://api.github.com"
GITLAB_API_URL = "https://gitlab.com/api/v4"

# --- API Keys opcionales ---

BREACHDIRECTORY_API_KEY = os.getenv("BREACHDIRECTORY_API_KEY", "")

# --- Configuracion HTTP ---

REQUEST_TIMEOUT = 15  # segundos
USER_AGENT = "DataBreachChecker/1.0 (Security Audit Tool)"

# --- Niveles de riesgo ---

RISK_LEVELS = {
    "critico": {"color": "red", "icon": "!!!"},
    "alto": {"color": "bright_red", "icon": "!!"},
    "medio": {"color": "yellow", "icon": "!"},
    "bajo": {"color": "green", "icon": "~"},
    "limpio": {"color": "bright_green", "icon": "OK"},
    # Ninguna fuente respondio: no se puede afirmar nada sobre el riesgo.
    "desconocido": {"color": "bright_black", "icon": "??"},
}
