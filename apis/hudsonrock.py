"""Hudson Rock OSINT API - Deteccion de infostealers."""

from models import BreachDetail, InfostealerDetail
from config import HUDSONROCK_EMAIL_URL, HUDSONROCK_USERNAME_URL
from .base import BaseAPI


class HudsonRockAPI(BaseAPI):
    """Proveedor Hudson Rock para deteccion de infostealers/malware."""

    name = "Hudson Rock"

    def check(self, query: str, query_type: str = "email") -> dict:
        """Verifica email o username en Hudson Rock OSINT.

        Args:
            query: Email o username a verificar.
            query_type: "email" o "username".
        """
        result = {"infostealers": [], "error": None}
        try:
            if query_type == "email":
                url = HUDSONROCK_EMAIL_URL
                params = {"email": query}
            else:
                url = HUDSONROCK_USERNAME_URL
                params = {"username": query}

            resp = self._get(url, params=params)

            if resp.status_code == 404:
                return result

            if resp.status_code == 200:
                data = resp.json()

                # Hudson Rock retorna stealers en diferentes campos
                stealers = data.get("stealers", [])
                if not stealers and isinstance(data, list):
                    stealers = data

                for s in stealers:
                    detail = InfostealerDetail(
                        computer_name=s.get("computer_name", ""),
                        operating_system=s.get("operating_system", ""),
                        malware_path=s.get("malware_path", ""),
                        date_compromised=s.get("date_compromised", "Desconocida"),
                        antiviruses=s.get("antiviruses", ""),
                    )
                    result["infostealers"].append(detail)
            elif resp.status_code == 429:
                result["error"] = "Hudson Rock: Limite de consultas alcanzado"
            else:
                result["error"] = f"Hudson Rock: HTTP {resp.status_code}"

        except Exception as e:
            result["error"] = f"Hudson Rock: {e}"

        return result
