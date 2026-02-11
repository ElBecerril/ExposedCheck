"""XposedOrNot API - Verificacion de email y passwords."""

import hashlib

from models import BreachDetail, PasswordResult
from config import XPOSEDORNOT_BREACH_URL, XPOSEDORNOT_PASSWORD_URL
from .base import BaseAPI


class XposedOrNotAPI(BaseAPI):
    """Proveedor XposedOrNot para brechas de email y passwords."""

    name = "XposedOrNot"

    def check(self, email: str) -> dict:
        """Verifica un email en XposedOrNot breach-analytics."""
        result = {"breaches": [], "error": None}
        try:
            resp = self._get(f"{XPOSEDORNOT_BREACH_URL}", params={"email": email})

            if resp.status_code == 404:
                return result  # No hay brechas

            if resp.status_code != 200:
                result["error"] = f"XposedOrNot: HTTP {resp.status_code}"
                return result

            data = resp.json()

            # La respuesta puede tener diferentes estructuras
            breaches_data = []
            if "ExposedBreaches" in data:
                exposed = data["ExposedBreaches"]
                if "breaches_details" in exposed:
                    breaches_data = exposed["breaches_details"]
            elif "breaches_details" in data:
                breaches_data = data["breaches_details"]

            for b in breaches_data:
                exposed_data = []
                if "xposed_data" in b:
                    exposed_data = [d.strip() for d in b["xposed_data"].split(",") if d.strip()]
                elif "data" in b:
                    exposed_data = [d.strip() for d in b["data"].split(",") if d.strip()]

                risk = self._map_risk(b.get("xposed_records", 0))

                breach = BreachDetail(
                    source_api=self.name,
                    breach_name=b.get("breach", b.get("domain", "Desconocida")),
                    date=b.get("xposed_date", b.get("date", "Desconocida")),
                    exposed_data=exposed_data,
                    risk_level=risk,
                    description=b.get("details", b.get("description", "")),
                    industry=b.get("industry", ""),
                    logo_url=b.get("logo", ""),
                )
                result["breaches"].append(breach)

        except Exception as e:
            result["error"] = f"XposedOrNot: {e}"

        return result

    def check_password(self, password: str) -> PasswordResult:
        """Verifica password usando k-anonymity con SHA3-Keccak-512."""
        result = PasswordResult()
        try:
            sha3_hash = hashlib.sha3_512(password.encode()).hexdigest()
            prefix = sha3_hash[:10]

            resp = self._get(f"{XPOSEDORNOT_PASSWORD_URL}/{prefix}")

            if resp.status_code == 404:
                return result

            if resp.status_code == 200:
                data = resp.json()
                # Buscar el hash completo en la respuesta
                hashes = data if isinstance(data, list) else data.get("SearchPassAnon", [])
                for h in hashes:
                    if isinstance(h, str) and sha3_hash.upper() in h.upper():
                        result.xon_count = 1
                        result.is_compromised = True
                        break
                    elif isinstance(h, dict) and h.get("anon", "").upper() == sha3_hash.upper():
                        result.xon_count = 1
                        result.is_compromised = True
                        break

        except Exception:
            pass  # Password check es best-effort

        return result

    @staticmethod
    def _map_risk(records: int) -> str:
        if records >= 1_000_000:
            return "critico"
        if records >= 100_000:
            return "alto"
        if records >= 1_000:
            return "medio"
        return "bajo"
