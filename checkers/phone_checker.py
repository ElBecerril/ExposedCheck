"""Orquestador de verificacion de telefono."""

from rich.console import Console

from models import CheckReport
from config import BREACHDIRECTORY_API_KEY
from .base_phone import BreachDirectoryAPI

console = Console()


class PhoneChecker:
    """Verifica un numero de telefono en APIs disponibles."""

    def check(self, phone: str) -> CheckReport:
        """Ejecuta verificacion de telefono."""
        report = CheckReport(query=phone, query_type="phone")

        if not BREACHDIRECTORY_API_KEY:
            report.errors.append(
                "No se configuro BREACHDIRECTORY_API_KEY en .env. "
                "La verificacion de telefono requiere una API key gratuita de RapidAPI. "
                "Registrate en: https://rapidapi.com/rohan-patra/api/breachdirectory"
            )
            return report

        with console.status("[bold blue]Consultando BreachDirectory..."):
            bd = BreachDirectoryAPI()
            bd_result = bd.check(phone)
            if bd_result.get("error"):
                report.errors.append(bd_result["error"])
            report.breaches.extend(bd_result.get("breaches", []))

        return report
