"""Orquestador de verificacion de password."""

from concurrent.futures import ThreadPoolExecutor

from rich.console import Console

from models import PasswordResult
from apis import HIBPPasswordsAPI, XposedOrNotAPI

console = Console()


class PasswordChecker:
    """Verifica passwords en HIBP y XposedOrNot usando k-anonymity."""

    def __init__(self):
        self.hibp = HIBPPasswordsAPI()
        self.xon = XposedOrNotAPI()

    def check(self, password: str) -> PasswordResult:
        """Verifica password en ambas fuentes, en paralelo.

        Nunca muestra el password. El ensamblado es en orden fijo (HIBP
        primero) para que sources_ok/failed sea determinista.
        """
        combined = PasswordResult()

        with console.status("[bold blue]Verificando password en 2 fuentes..."):
            with ThreadPoolExecutor(max_workers=2) as executor:
                f_hibp = executor.submit(self.hibp.check_password, password)
                f_xon = executor.submit(self.xon.check_password, password)
                hibp_result = f_hibp.result()
                xon_result = f_xon.result()

        # 1. HIBP Pwned Passwords
        combined.hibp_count = hibp_result.hibp_count
        combined.sources_ok.extend(hibp_result.sources_ok)
        combined.sources_failed.extend(hibp_result.sources_failed)

        # 2. XposedOrNot Passwords
        combined.xon_count = xon_result.xon_count
        combined.sources_ok.extend(xon_result.sources_ok)
        combined.sources_failed.extend(xon_result.sources_failed)

        combined.is_compromised = combined.hibp_count > 0 or combined.xon_count > 0
        return combined
