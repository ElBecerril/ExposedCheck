"""Orquestador de verificacion de password."""

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
        """Verifica password en ambas fuentes. Nunca muestra el password."""
        combined = PasswordResult()

        # 1. HIBP Pwned Passwords
        with console.status("[bold blue]Verificando password en HIBP..."):
            hibp_result = self.hibp.check_password(password)
            combined.hibp_count = hibp_result.hibp_count

        # 2. XposedOrNot Passwords
        with console.status("[bold blue]Verificando password en XposedOrNot..."):
            xon_result = self.xon.check_password(password)
            combined.xon_count = xon_result.xon_count

        combined.is_compromised = combined.hibp_count > 0 or combined.xon_count > 0
        return combined
