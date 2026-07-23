"""HIBP Pwned Passwords API - Verificacion de passwords con k-anonymity."""

import hashlib

from models import BreachDetail, PasswordResult
from config import HIBP_API_KEY, HIBP_BREACH_URL, HIBP_PASSWORD_URL
from .base import BaseAPI
from .errors import describe_exception


class HIBPPasswordsAPI(BaseAPI):
    """Proveedor HIBP Pwned Passwords (solo passwords, no requiere API key)."""

    name = "HIBP Pwned Passwords"

    def check(self, query: str) -> dict:
        """No aplica para email/username. Usar check_password / check_email."""
        return {"error": "HIBP Pwned Passwords solo soporta verificacion de passwords"}

    def _auth_headers(self) -> dict:
        """Cabeceras de autenticacion para el endpoint de brechas.

        Vacio si no hay HIBP_API_KEY (el endpoint de brechas por email
        siempre requiere key de pago, asi que sin ella la llamada fallara
        con 401 - ver check_email).
        """
        if HIBP_API_KEY:
            return {"hibp-api-key": HIBP_API_KEY}
        return {}

    def check_email(self, email: str) -> dict:
        """Busca brechas asociadas a un email via el endpoint breachedaccount.

        Requiere HIBP_API_KEY (endpoint de pago). Sin la key configurada,
        HIBP responde 401 igualmente; se traduce a un error legible sin
        necesidad de adivinarlo de antemano.
        """
        result = {"breaches": [], "error": None}
        headers = self._auth_headers()

        try:
            resp = self._get(
                f"{HIBP_BREACH_URL}/{email}",
                params={"truncateResponse": "false"},
                headers=headers,
            )

            if resp.status_code == 200:
                data = resp.json()
                if not isinstance(data, list):
                    result["error"] = "HIBP: respuesta con formato inesperado"
                    return result
                for b in data:
                    if not isinstance(b, dict):
                        continue
                    result["breaches"].append(
                        BreachDetail(
                            source_api=self.name,
                            breach_name=b.get("Title") or b.get("Name", "Desconocida"),
                            date=b.get("BreachDate", "Desconocida"),
                            exposed_data=b.get("DataClasses", []) or [],
                            risk_level="alto" if b.get("IsSensitive") else "medio",
                            description=b.get("Description", ""),
                            industry=b.get("Domain", ""),
                            logo_url=b.get("LogoPath", ""),
                        )
                    )
            elif resp.status_code == 404:
                result["breaches"] = []
            elif resp.status_code == 401:
                if HIBP_API_KEY:
                    result["error"] = "HIBP: API key invalida o expirada (HIBP_API_KEY)"
                else:
                    result["error"] = (
                        "HIBP: la busqueda de brechas por email requiere API key de pago "
                        "(configura HIBP_API_KEY)"
                    )
            elif resp.status_code == 403:
                result["error"] = "HIBP: acceso denegado (403), verifica tu API key"
            elif resp.status_code == 429:
                result["error"] = "HIBP: rate limit alcanzado (429), espera antes de reintentar"
            else:
                result["error"] = f"HIBP: HTTP {resp.status_code}"

        except Exception as e:
            result["error"] = describe_exception("HIBP", e)

        return result

    def check_password(self, password: str) -> PasswordResult:
        """Verifica password usando k-anonymity con SHA-1.

        Solo envia los primeros 5 caracteres del hash SHA-1.
        El servidor retorna todos los sufijos que coinciden con ese prefijo.
        """
        result = PasswordResult()
        try:
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            resp = self._get(f"{HIBP_PASSWORD_URL}/{prefix}")

            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    parts = line.split(":")
                    if len(parts) == 2 and parts[0].strip() == suffix:
                        result.hibp_count = int(parts[1].strip())
                        result.is_compromised = True
                        break
                result.record_source("HIBP")
            else:
                result.record_source("HIBP", error=f"HIBP: HTTP {resp.status_code}")

        except Exception as e:
            # Registrar el fallo: sin esto, un error de red se vería como
            # "password no encontrado en brechas".
            result.record_source("HIBP", error=describe_exception("HIBP", e))

        return result
