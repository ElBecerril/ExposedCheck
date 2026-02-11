"""Orquestador de verificacion de email."""

from rich.console import Console

from models import CheckReport
from apis import XposedOrNotAPI, LeakCheckAPI, HudsonRockAPI

console = Console()


class EmailChecker:
    """Verifica un email en multiples APIs de brechas."""

    def __init__(self):
        self.xon = XposedOrNotAPI()
        self.leakcheck = LeakCheckAPI()
        self.hudson = HudsonRockAPI()

    def check(self, email: str) -> CheckReport:
        """Ejecuta verificacion completa de email."""
        report = CheckReport(query=email, query_type="email")

        # 1. XposedOrNot (primario)
        with console.status("[bold blue]Consultando XposedOrNot..."):
            xon_result = self.xon.check(email)
            if xon_result.get("error"):
                report.errors.append(xon_result["error"])
            report.breaches.extend(xon_result.get("breaches", []))

        # 2. LeakCheck
        with console.status("[bold blue]Consultando LeakCheck..."):
            lc_result = self.leakcheck.check(email, query_type="email")
            if lc_result.get("error"):
                report.errors.append(lc_result["error"])
            # Evitar duplicados por nombre de brecha
            existing_names = {b.breach_name.lower() for b in report.breaches}
            for breach in lc_result.get("breaches", []):
                if breach.breach_name.lower() not in existing_names:
                    report.breaches.append(breach)
                    existing_names.add(breach.breach_name.lower())

        # 3. Hudson Rock (infostealers)
        with console.status("[bold blue]Consultando Hudson Rock..."):
            hr_result = self.hudson.check(email, query_type="email")
            if hr_result.get("error"):
                report.errors.append(hr_result["error"])
            report.infostealers.extend(hr_result.get("infostealers", []))

        return report
