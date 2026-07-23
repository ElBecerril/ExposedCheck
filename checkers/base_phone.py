"""BreachDirectory API (RapidAPI) - Verificacion de telefono (opcional)."""

import requests

from models import BreachDetail
from config import BREACHDIRECTORY_API_KEY, REQUEST_TIMEOUT


class BreachDirectoryAPI:
    """Proveedor BreachDirectory via RapidAPI para telefono."""

    name = "BreachDirectory"

    def check(self, phone: str) -> dict:
        """Verifica un telefono en BreachDirectory."""
        result = {"breaches": [], "error": None}
        try:
            resp = requests.get(
                "https://breachdirectory.p.rapidapi.com/",
                params={"func": "auto", "term": phone},
                headers={
                    "X-RapidAPI-Key": BREACHDIRECTORY_API_KEY,
                    "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
                },
                timeout=REQUEST_TIMEOUT,
            )

            if resp.status_code == 200:
                data = resp.json()
                entries = data.get("result") if isinstance(data, dict) else None
                if data.get("success") and entries:
                    # "result" suele ser una lista de entradas, pero la API
                    # tambien devuelve un dict suelto; normalizamos para no
                    # iterar las claves como si fueran entradas.
                    if isinstance(entries, dict):
                        entries = [entries]
                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue
                        sources = entry.get("sources", [])
                        for src in sources:
                            breach = BreachDetail(
                                source_api=self.name,
                                breach_name=src.get("name", "Desconocida"),
                                date=src.get("date", "Desconocida"),
                                exposed_data=["telefono"],
                                risk_level="alto",
                            )
                            result["breaches"].append(breach)
            elif resp.status_code == 429:
                result["error"] = "BreachDirectory: Limite mensual alcanzado (10/mes en plan gratuito)"
            else:
                result["error"] = f"BreachDirectory: HTTP {resp.status_code}"

        except Exception as e:
            result["error"] = f"BreachDirectory: {e}"

        return result
