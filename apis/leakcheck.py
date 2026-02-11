"""LeakCheck Public API - Verificacion de email y username."""

from models import BreachDetail
from config import LEAKCHECK_PUBLIC_URL
from .base import BaseAPI


class LeakCheckAPI(BaseAPI):
    """Proveedor LeakCheck endpoint publico."""

    name = "LeakCheck"

    def check(self, query: str, query_type: str = "email") -> dict:
        """Verifica email o username en LeakCheck.

        Args:
            query: Email o username a verificar.
            query_type: "email" o "username".
        """
        result = {"breaches": [], "error": None}
        try:
            check_type = "email" if query_type == "email" else "login"
            resp = self._get(
                f"{LEAKCHECK_PUBLIC_URL}",
                params={"check": query},
            )

            if resp.status_code == 404:
                return result

            if resp.status_code == 200:
                data = resp.json()

                if not data.get("success", False):
                    # Puede ser rate limit o sin resultados
                    msg = data.get("msg", "")
                    if "not found" in msg.lower():
                        return result
                    if msg:
                        result["error"] = f"LeakCheck: {msg}"
                    return result

                sources = data.get("result", [])
                for src in sources:
                    breach = BreachDetail(
                        source_api=self.name,
                        breach_name=src.get("name", src.get("source", "Desconocida")),
                        date=src.get("date", "Desconocida"),
                        exposed_data=src.get("fields", []),
                        risk_level="medio",
                    )
                    result["breaches"].append(breach)
            elif resp.status_code == 429:
                result["error"] = "LeakCheck: Limite de consultas alcanzado (intentar mas tarde)"
            else:
                result["error"] = f"LeakCheck: HTTP {resp.status_code}"

        except Exception as e:
            result["error"] = f"LeakCheck: {e}"

        return result
