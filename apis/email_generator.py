"""Generador de emails candidatos y verificador contra bases de brechas."""

import time

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from apis.xposedornot import XposedOrNotAPI
from apis.leakcheck import LeakCheckAPI

console = Console()

CANDIDATE_DOMAINS = [
    "gmail.com",
    "hotmail.com",
    "outlook.com",
    "yahoo.com",
    "protonmail.com",
    "icloud.com",
    "live.com",
    "mail.com",
    "aol.com",
    "yandex.com",
    "zoho.com",
    "gmx.com",
]


def _generate_username_variants(username: str) -> list[str]:
    """Genera variantes inteligentes de un username.

    Ejemplo: 'Charly.dominguez.800672' genera:
      - charly.dominguez.800672 (original)
      - charly.dominguez (sin numeros finales)
      - charlydominguez (sin puntos)
      - charly_dominguez (puntos a guiones bajos)
      - charlydominguez800672 (sin puntos, con numeros)
    """
    import re

    clean = username.lower().strip()
    variants = [clean]

    # Sin numeros finales (ej: charly.dominguez.800672 -> charly.dominguez)
    no_trailing_nums = re.sub(r'[._-]?\d+$', '', clean)
    if no_trailing_nums and no_trailing_nums != clean:
        variants.append(no_trailing_nums)

    # Sin puntos ni guiones (ej: charly.dominguez -> charlydominguez)
    no_separators = re.sub(r'[._-]', '', clean)
    if no_separators != clean:
        variants.append(no_separators)

    # Sin puntos del base limpio (sin numeros)
    if no_trailing_nums and no_trailing_nums != clean:
        no_sep_clean = re.sub(r'[._-]', '', no_trailing_nums)
        if no_sep_clean not in variants:
            variants.append(no_sep_clean)

    # Puntos a guiones bajos (ej: charly.dominguez -> charly_dominguez)
    if '.' in clean:
        underscored = clean.replace('.', '_')
        if underscored not in variants:
            variants.append(underscored)

    # Puntos a guiones bajos del base limpio
    if no_trailing_nums and '.' in no_trailing_nums:
        underscored_clean = no_trailing_nums.replace('.', '_')
        if underscored_clean not in variants:
            variants.append(underscored_clean)

    # Guiones bajos a puntos (si tiene guiones bajos)
    if '_' in clean:
        dotted = clean.replace('_', '.')
        if dotted not in variants:
            variants.append(dotted)
        dotted_clean = no_trailing_nums.replace('_', '.')
        if dotted_clean not in variants:
            variants.append(dotted_clean)

    return list(dict.fromkeys(variants))  # dedup preservando orden


def generate_candidates(username: str) -> list[str]:
    """Genera lista de emails candidatos a partir de un username y sus variantes.

    Args:
        username: Nombre de usuario base.

    Returns:
        Lista de emails candidatos (variante@dominio).
    """
    variants = _generate_username_variants(username)
    candidates = []
    seen = set()
    for variant in variants:
        for domain in CANDIDATE_DOMAINS:
            email = f"{variant}@{domain}"
            if email not in seen:
                candidates.append(email)
                seen.add(email)
    return candidates


class EmailCandidateVerifier:
    """Verifica emails candidatos contra APIs de brechas existentes."""

    def __init__(self):
        self.xon = XposedOrNotAPI()
        self.leakcheck = LeakCheckAPI()

    def verify_candidates(self, candidates: list[str]) -> list[dict]:
        """Verifica cada email candidato en XposedOrNot y LeakCheck.

        Cada candidato queda marcado con ``verified``: True solo si al menos
        una API respondio de forma utilizable. Si ambas fallan (p. ej. por
        rate limit), ``verified`` es False y el candidato NO debe reportarse
        como "no encontrado" -- simplemente no se pudo comprobar.

        Args:
            candidates: Lista de emails a verificar.

        Returns:
            Lista de dicts con resultados de cada candidato.
        """
        results = []
        delay = 0.3  # backoff adaptativo: sube al detectar rate limit

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("Verificando candidatos en brechas...", total=len(candidates))

            for email in candidates:
                candidate_result = {
                    "email": email,
                    "found_in_breaches": False,
                    "breach_count": 0,
                    "sources": [],
                    "verified": False,   # True si alguna API respondio sin error
                    "errors": [],
                }
                rate_limited = False

                for api_name, api in (("XposedOrNot", self.xon), ("LeakCheck", self.leakcheck)):
                    try:
                        api_result = api.check(email)
                    except Exception as e:  # fallo de red inesperado
                        candidate_result["errors"].append(f"{api_name}: {e}")
                        continue

                    err = api_result.get("error")
                    if err:
                        candidate_result["errors"].append(err)
                        if any(t in err.lower() for t in ("rate", "limite", "429")):
                            rate_limited = True
                        continue

                    # Respuesta utilizable (aunque sea sin brechas)
                    candidate_result["verified"] = True
                    breaches = len(api_result.get("breaches", []))
                    if breaches > 0:
                        candidate_result["found_in_breaches"] = True
                        candidate_result["breach_count"] += breaches
                        candidate_result["sources"].append(api_name)

                results.append(candidate_result)
                progress.update(task, advance=1)

                # Backoff adaptativo: si nos limitaron, esperar mas para las
                # siguientes consultas (con tope) en vez de seguir chocando.
                if rate_limited:
                    delay = min(delay * 2, 3.0)
                time.sleep(delay)

        return results
