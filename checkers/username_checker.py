"""Orquestador de verificacion de username."""

from concurrent.futures import ThreadPoolExecutor

from rich.console import Console

from models import CheckReport
from apis import LeakCheckAPI, HudsonRockAPI
from .parallel import run_provider

console = Console()


class UsernameChecker:
    """Verifica un username en multiples APIs de brechas."""

    def __init__(self):
        self.leakcheck = LeakCheckAPI()
        self.hudson = HudsonRockAPI()

    def check(self, username: str) -> CheckReport:
        """Ejecuta verificacion completa de username.

        Ambas fuentes se consultan en paralelo; el reporte se ensambla en
        orden fijo (Hudson Rock primario) para un resultado determinista.
        """
        report = CheckReport(query=username, query_type="username")

        with console.status("[bold blue]Consultando 2 fuentes de brechas..."):
            with ThreadPoolExecutor(max_workers=2) as executor:
                f_hr = executor.submit(
                    run_provider, self.hudson.check, username, query_type="username"
                )
                f_lc = executor.submit(
                    run_provider, self.leakcheck.check, username, query_type="username"
                )
                hr_result = f_hr.result()
                lc_result = f_lc.result()

        # 1. Hudson Rock (primario para username)
        report.record_source("Hudson Rock", hr_result.get("error"))
        report.infostealers.extend(hr_result.get("infostealers", []))

        # 2. LeakCheck
        report.record_source("LeakCheck", lc_result.get("error"))
        report.breaches.extend(lc_result.get("breaches", []))

        return report
