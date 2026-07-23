"""Orquestador de verificacion de username."""

from rich.console import Console

from models import CheckReport
from apis import LeakCheckAPI, HudsonRockAPI

console = Console()


class UsernameChecker:
    """Verifica un username en multiples APIs de brechas."""

    def __init__(self):
        self.leakcheck = LeakCheckAPI()
        self.hudson = HudsonRockAPI()

    def check(self, username: str) -> CheckReport:
        """Ejecuta verificacion completa de username."""
        report = CheckReport(query=username, query_type="username")

        # 1. Hudson Rock (primario para username)
        with console.status("[bold blue]Consultando Hudson Rock..."):
            hr_result = self.hudson.check(username, query_type="username")
            report.record_source("Hudson Rock", hr_result.get("error"))
            report.infostealers.extend(hr_result.get("infostealers", []))

        # 2. LeakCheck
        with console.status("[bold blue]Consultando LeakCheck..."):
            lc_result = self.leakcheck.check(username, query_type="username")
            report.record_source("LeakCheck", lc_result.get("error"))
            report.breaches.extend(lc_result.get("breaches", []))

        return report
