"""HIBP Pwned Passwords API - Verificacion de passwords con k-anonymity."""

import hashlib

from models import PasswordResult
from config import HIBP_PASSWORD_URL
from .base import BaseAPI


class HIBPPasswordsAPI(BaseAPI):
    """Proveedor HIBP Pwned Passwords (solo passwords, no requiere API key)."""

    name = "HIBP Pwned Passwords"

    def check(self, query: str) -> dict:
        """No aplica para email/username. Usar check_password."""
        return {"error": "HIBP Pwned Passwords solo soporta verificacion de passwords"}

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

        except Exception:
            pass  # Password check es best-effort

        return result
