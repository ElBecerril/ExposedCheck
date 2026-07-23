"""Orquestador de verificacion de email."""

from concurrent.futures import ThreadPoolExecutor

from rich.console import Console

from models import CheckReport
from config import HIBP_API_KEY
from apis import XposedOrNotAPI, LeakCheckAPI, HudsonRockAPI
from apis.hibp import HIBPPasswordsAPI
from .parallel import run_provider

console = Console()


class EmailChecker:
    """Verifica un email en multiples APIs de brechas."""

    def __init__(self):
        self.xon = XposedOrNotAPI()
        self.leakcheck = LeakCheckAPI()
        self.hudson = HudsonRockAPI()
        self.hibp = HIBPPasswordsAPI()

    def check(self, email: str) -> CheckReport:
        """Ejecuta verificacion completa de email.

        Las tres fuentes se consultan en paralelo, pero el reporte se
        ensambla en orden fijo (XON primario) para que el resultado sea
        determinista sin importar cual respondio antes.
        """
        report = CheckReport(query=email, query_type="email")

        # HIBP solo se consulta si hay API key: el endpoint es de pago y sin
        # key responde 401 siempre, lo que marcaria la cobertura como parcial
        # en cada consulta sin aportar nada.
        use_hibp = bool(HIBP_API_KEY)
        total_sources = 4 if use_hibp else 3

        with console.status(f"[bold blue]Consultando {total_sources} fuentes de brechas..."):
            with ThreadPoolExecutor(max_workers=total_sources) as executor:
                f_hibp = (
                    executor.submit(run_provider, self.hibp.check_email, email)
                    if use_hibp
                    else None
                )
                f_xon = executor.submit(run_provider, self.xon.check, email)
                f_lc = executor.submit(
                    run_provider, self.leakcheck.check, email, query_type="email"
                )
                f_hr = executor.submit(
                    run_provider, self.hudson.check, email, query_type="email"
                )
                xon_result = f_xon.result()
                lc_result = f_lc.result()
                hr_result = f_hr.result()
                hibp_result = f_hibp.result() if f_hibp else None

        # 1. XposedOrNot (primario)
        report.record_source("XposedOrNot", xon_result.get("error"))
        report.breaches.extend(xon_result.get("breaches", []))

        # 2. LeakCheck (evitar duplicados por nombre de brecha)
        report.record_source("LeakCheck", lc_result.get("error"))
        existing_names = {b.breach_name.lower() for b in report.breaches}
        for breach in lc_result.get("breaches", []):
            if breach.breach_name.lower() not in existing_names:
                report.breaches.append(breach)
                existing_names.add(breach.breach_name.lower())

        # 3. HIBP (opcional, solo con API key), mismo dedup por nombre
        if hibp_result is not None:
            report.record_source("HIBP", hibp_result.get("error"))
            for breach in hibp_result.get("breaches", []):
                if breach.breach_name.lower() not in existing_names:
                    report.breaches.append(breach)
                    existing_names.add(breach.breach_name.lower())

        # 4. Hudson Rock (infostealers)
        report.record_source("Hudson Rock", hr_result.get("error"))
        report.infostealers.extend(hr_result.get("infostealers", []))

        return report
