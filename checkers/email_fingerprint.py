"""Email Fingerprint - OSINT completo de un correo electronico.

Uso responsable: solo con emails propios o con autorizacion expresa del
titular. Ver el aviso mostrado en main.py antes de invocar EmailFingerprint.
"""

import hashlib
import logging
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from config import REQUEST_TIMEOUT, USER_AGENT
from apis import XposedOrNotAPI, LeakCheckAPI, HudsonRockAPI, GitHubOsintAPI, GitLabOsintAPI
from models import (
    FingerprintReport, DomainInfo, GravatarProfile,
    GitHubUser, GitHubPresence, GitLabPresence, ServiceRegistration,
)

console = Console()
logger = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# NOTA: la deteccion de registro en servicios (_check_services y sus metodos
# _check_spotify / _check_wordpress / _check_duolingo) consulta endpoints
# internos de signup/recovery no pensados para lookup publico (no son APIs
# documentadas para este uso). Esto permite enumerar si un email arbitrario
# esta registrado en el servicio, lo cual es sensible fuera del propio email
# del usuario y puede violar los ToS de esas plataformas.


class EmailFingerprint:
    """Realiza un fingerprint OSINT completo de un email."""

    def __init__(self):
        self.xon = XposedOrNotAPI()
        self.leakcheck = LeakCheckAPI()
        self.hudson = HudsonRockAPI()
        self.github = GitHubOsintAPI()
        self.gitlab = GitLabOsintAPI()

    def fingerprint(self, email: str) -> FingerprintReport:
        """Ejecuta fingerprint completo del email.

        Returns:
            FingerprintReport con todas las secciones del fingerprint.
        """
        report = FingerprintReport(
            email=email,
            domain=email.split("@")[1] if "@" in email else "",
            username_part=email.split("@")[0] if "@" in email else "",
        )

        # --- Fase 1: Info del dominio ---
        with console.status("[bold blue]Analizando dominio..."):
            report.domain_info = self._check_domain(report.domain, report.errors)

        # --- Fase 2: Gravatar ---
        with console.status("[bold blue]Consultando Gravatar..."):
            report.gravatar = self._check_gravatar(email, report.errors)

        # --- Fase 3: Brechas de datos (paralelo) ---
        with console.status("[bold blue]Consultando bases de datos de brechas..."):
            self._check_breaches(email, report)

        # --- Fase 4: GitHub/GitLab (buscar por email) ---
        with console.status("[bold blue]Buscando en GitHub/GitLab..."):
            self._check_git_platforms(email, report)

        # --- Fase 5: Deteccion de servicios registrados ---
        with console.status("[bold blue]Verificando registro en servicios..."):
            report.registered_services = self._check_services(email, report.errors)

        # --- Fase 6: Buscar username derivado en plataformas ---
        username = report.username_part
        if username and len(username) >= 3:
            with console.status(f"[bold blue]Buscando perfiles de '{username}'..."):
                report.profiles_found = self._search_profiles(username)

        return report

    def _check_domain(self, domain: str, errors: list) -> DomainInfo:
        """Verifica info basica del dominio (MX, tipo)."""
        info = DomainInfo()
        if not domain:
            return info
        try:
            mx_records = []
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain, "MX")
                mx_records = sorted(
                    [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
                    key=lambda x: x[0],
                )
            except ImportError:
                # Fallback: solo verificar si el dominio resuelve
                socket.getaddrinfo(domain, 25)
                mx_records = [("?", domain)]
            except Exception:
                # Fallo la resolucion MX: reintentar por puerto 80.
                try:
                    socket.getaddrinfo(domain, 80)
                    mx_records = [("?", domain)]
                except Exception:
                    # El dominio no resuelve: negativo valido (info.exists queda False).
                    pass

            if mx_records:
                info.exists = True
                info.mx_records = mx_records

                # Detectar proveedor
                mx_str = str(mx_records).lower()
                if "google" in mx_str or "gmail" in mx_str:
                    info.type = "Google Workspace"
                elif "outlook" in mx_str or "microsoft" in mx_str:
                    info.type = "Microsoft 365"
                elif "zoho" in mx_str:
                    info.type = "Zoho Mail"
                elif "proton" in mx_str:
                    info.type = "ProtonMail"
                else:
                    info.type = "Servidor propio / Otro"

            # Detectar dominios conocidos
            common = {
                "gmail.com": "Google Gmail",
                "outlook.com": "Microsoft Outlook",
                "hotmail.com": "Microsoft Hotmail",
                "yahoo.com": "Yahoo Mail",
                "protonmail.com": "ProtonMail",
                "icloud.com": "Apple iCloud",
                "live.com": "Microsoft Live",
            }
            if domain.lower() in common:
                info.type = common[domain.lower()]
                info.exists = True

        except Exception as e:
            # No enmascarar el fallo como "dominio desconocido": registrarlo.
            logger.debug("Fallo el analisis de dominio %s: %s", domain, e)
            errors.append(f"Dominio ({domain}): {e}")

        return info

    def _check_gravatar(self, email: str, errors: list) -> GravatarProfile | None:
        """Verifica si el email tiene perfil de Gravatar."""
        try:
            email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
            resp = requests.get(
                f"https://www.gravatar.com/{email_hash}.json",
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                entry = data.get("entry", [{}])[0]
                return GravatarProfile(
                    display_name=entry.get("displayName", ""),
                    username=entry.get("preferredUsername", ""),
                    profile_url=entry.get("profileUrl", ""),
                    photo_url=entry.get("thumbnailUrl", ""),
                    about=entry.get("aboutMe", ""),
                    location=entry.get("currentLocation", ""),
                    accounts=[
                        {"platform": a.get("shortname", ""), "url": a.get("url", "")}
                        for a in entry.get("accounts", [])
                    ],
                )
        except Exception as e:
            # Un fallo de red no es lo mismo que "sin Gravatar": registrarlo.
            logger.debug("Fallo la consulta a Gravatar para %s: %s", email, e)
            errors.append(f"Gravatar: {e}")
        return None

    def _check_breaches(self, email: str, report: FingerprintReport) -> None:
        """Consulta APIs de brechas en paralelo."""
        # XposedOrNot
        xon_result = self.xon.check(email)
        if xon_result.get("error"):
            report.errors.append(xon_result["error"])
        report.breaches.extend(xon_result.get("breaches", []))

        # LeakCheck
        lc_result = self.leakcheck.check(email, query_type="email")
        if lc_result.get("error"):
            report.errors.append(lc_result["error"])
        existing = {b.breach_name.lower() for b in report.breaches}
        for b in lc_result.get("breaches", []):
            if b.breach_name.lower() not in existing:
                report.breaches.append(b)
                existing.add(b.breach_name.lower())

        # Hudson Rock
        hr_result = self.hudson.check(email, query_type="email")
        if hr_result.get("error"):
            report.errors.append(hr_result["error"])
        report.infostealers.extend(hr_result.get("infostealers", []))

    def _check_git_platforms(self, email: str, report: FingerprintReport) -> None:
        """Busca presencia del email en GitHub y GitLab."""
        # GitHub: buscar usuarios con ese email
        try:
            resp = requests.get(
                f"https://api.github.com/search/users?q={urllib.parse.quote(email)}+in:email",
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("total_count", 0) > 0:
                    users = data.get("items", [])
                    report.github_presence = GitHubPresence(
                        found=True,
                        users=[
                            GitHubUser(
                                username=u.get("login", ""),
                                profile_url=u.get("html_url", ""),
                                avatar=u.get("avatar_url", ""),
                            )
                            for u in users[:5]
                        ],
                    )
                else:
                    report.github_presence = GitHubPresence(found=False)
        except Exception as e:
            report.errors.append(f"GitHub search: {e}")

        # GitLab: buscar usuarios por email no es posible sin auth,
        # pero podemos probar con el username extraido
        username = email.split("@")[0]
        try:
            gl_result = self.gitlab.check(username)
            if not gl_result.get("error"):
                report.gitlab_presence = GitLabPresence(found=True, username=username)
            else:
                report.gitlab_presence = GitLabPresence(found=False)
        except Exception:
            report.gitlab_presence = GitLabPresence(found=False)

    def _check_services(self, email: str, errors: list) -> list[ServiceRegistration]:
        """Intenta detectar si el email esta registrado en servicios comunes."""
        services = []

        # Gravatar ya se verifica por separado

        # GitHub (ya lo tenemos del paso anterior)

        # Intentar detectar via API publica de Spotify
        checks = [
            ("Spotify", self._check_spotify),
            ("WordPress", self._check_wordpress),
            ("Duolingo", self._check_duolingo),
        ]

        for name, check_fn in checks:
            try:
                registered = check_fn(email)
                if registered is not None:
                    services.append(ServiceRegistration(service=name, registered=registered))
            except Exception as e:
                # Sin esto, un servicio que falla se veria como "no registrado".
                logger.debug("Fallo el check de %s: %s", name, e)
                errors.append(f"{name} (deteccion de registro): {e}")

        return services

    def _check_spotify(self, email: str) -> bool | None:
        """Verifica si un email esta en Spotify via signup endpoint (no documentado para lookup)."""
        resp = requests.get(
            "https://spclient.wg.spotify.com/signup/public/v1/account",
            params={"validate": "1", "email": email},
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            status = data.get("status", 0)
            # status 20 = email ya registrado
            return status == 20
        return None

    def _check_wordpress(self, email: str) -> bool | None:
        """Verifica existencia en WordPress.com via endpoint no documentado para lookup."""
        resp = requests.get(
            "https://public-api.wordpress.com/rest/v1.1/users/suggest",
            params={"email": email},
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        # Si retorna 200 el email esta asociado
        return resp.status_code == 200

    def _check_duolingo(self, email: str) -> bool | None:
        """Verifica existencia en Duolingo."""
        resp = requests.get(
            "https://www.duolingo.com/2017-06-30/users",
            params={"email": email},
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            users = data.get("users", [])
            return len(users) > 0
        return None

    def _search_profiles(self, username: str) -> list[dict]:
        """Busca el username derivado del email en plataformas populares."""
        from checkers.profile_checker import PLATFORMS, _check_platform

        # Subconjunto de plataformas mas relevantes
        priority = {
            "Instagram", "Twitter/X", "TikTok", "Facebook", "Reddit",
            "GitHub", "LinkedIn", "Telegram", "Medium", "Steam",
            "Twitch", "Pinterest", "Spotify", "Keybase",
        }

        tasks = []
        for name, url_template, method in PLATFORMS:
            if name in priority:
                url = url_template.format(username)
                tasks.append((name, url, method))

        found = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(_check_platform, name, url, method): name
                for name, url, method in tasks
            }
            for future in as_completed(futures):
                hit = future.result()
                if hit.found:
                    found.append(hit)

        found.sort(key=lambda x: x.platform)
        return found

    # --- Impresion de resultados ---

    def print_results(self, report: FingerprintReport) -> None:
        """Imprime el fingerprint completo."""
        email = report.email
        domain = report.domain
        domain_info = report.domain_info or DomainInfo()
        gravatar = report.gravatar
        breaches = report.breaches
        infostealers = report.infostealers
        github = report.github_presence
        gitlab = report.gitlab_presence
        services = report.registered_services
        profiles = report.profiles_found
        errors = report.errors

        # === Header ===
        total_findings = (
            len(breaches)
            + len(infostealers)
            + (1 if gravatar else 0)
            + (len(github.users) if github and github.found else 0)
            + len([s for s in services if s.registered])
            + len(profiles)
        )

        if len(infostealers) > 0:
            risk_color = "red"
            risk_text = "CRITICO - Infostealer detectado"
        elif len(breaches) >= 5:
            risk_color = "bright_red"
            risk_text = "ALTO - Multiples brechas"
        elif len(breaches) >= 1 or total_findings >= 5:
            risk_color = "yellow"
            risk_text = "MEDIO - Datos expuestos"
        elif total_findings >= 1:
            risk_color = "cyan"
            risk_text = "BAJO - Presencia minima"
        else:
            risk_color = "green"
            risk_text = "LIMPIO - Sin hallazgos"

        console.print(Panel(
            f"[bold]Email:[/bold] {email}\n"
            f"[bold]Dominio:[/bold] {domain} ({domain_info.type})\n"
            f"[bold]Hallazgos totales:[/bold] {total_findings}\n"
            f"[bold]Brechas:[/bold] {len(breaches)} | "
            f"[bold]Infostealers:[/bold] {len(infostealers)} | "
            f"[bold]Perfiles:[/bold] {len(profiles)}\n\n"
            f"[bold {risk_color}]{risk_text}[/bold {risk_color}]",
            title="[bold]Email Fingerprint[/bold]",
            border_style=risk_color,
            box=box.DOUBLE,
            padding=(1, 2),
        ))

        # === Dominio ===
        if domain_info.mx_records:
            mx_lines = []
            for pref, server in domain_info.mx_records[:3]:
                mx_lines.append(f"  {pref} -> {server}")
            console.print(Panel(
                f"[bold]Proveedor:[/bold] {domain_info.type}\n"
                f"[bold]MX Records:[/bold]\n" + "\n".join(mx_lines),
                title="[bold]Dominio[/bold]",
                border_style="blue",
            ))

        # === Gravatar ===
        if gravatar:
            lines = []
            if gravatar.display_name:
                lines.append(f"[bold]Nombre:[/bold] {gravatar.display_name}")
            if gravatar.username:
                lines.append(f"[bold]Username:[/bold] {gravatar.username}")
            if gravatar.location:
                lines.append(f"[bold]Ubicacion:[/bold] {gravatar.location}")
            if gravatar.about:
                lines.append(f"[bold]Bio:[/bold] {gravatar.about[:200]}")
            if gravatar.profile_url:
                lines.append(f"[bold]Perfil:[/bold] {gravatar.profile_url}")
            if gravatar.accounts:
                lines.append("[bold]Cuentas vinculadas:[/bold]")
                for acc in gravatar.accounts:
                    lines.append(f"  - {acc['platform']}: {acc['url']}")

            console.print(Panel(
                "\n".join(lines),
                title="[bold]Gravatar - Perfil Publico[/bold]",
                border_style="magenta",
            ))

        # === GitHub ===
        if github and github.found:
            lines = []
            for u in github.users:
                lines.append(
                    f"  [bold]{u.username}[/bold] - {u.profile_url}"
                )
            console.print(Panel(
                "[bold]Usuarios asociados a este email:[/bold]\n" + "\n".join(lines),
                title="[bold]GitHub[/bold]",
                border_style="white",
            ))

        # === GitLab ===
        if gitlab and gitlab.found:
            console.print(f"  [dim]GitLab:[/dim] Perfil encontrado como '{gitlab.username}'")

        # === Brechas ===
        if breaches:
            table = Table(
                title="Brechas de Seguridad",
                box=box.ROUNDED,
                show_lines=True,
            )
            table.add_column("Brecha", style="bold", max_width=25)
            table.add_column("Fecha", max_width=12)
            table.add_column("Datos Expuestos", max_width=45)
            table.add_column("Fuente", max_width=12)

            for b in breaches:
                exposed = ", ".join(b.exposed_data) if b.exposed_data else "N/A"
                table.add_row(b.breach_name, b.date, exposed, b.source_api)

            console.print(table)

        # === Infostealers ===
        if infostealers:
            table = Table(
                title="[bold red]ALERTA: Infostealers Detectados[/bold red]",
                box=box.HEAVY,
                show_lines=True,
                border_style="red",
            )
            table.add_column("Equipo", style="bold")
            table.add_column("Sistema")
            table.add_column("Fecha")
            table.add_column("Malware")

            for info in infostealers:
                table.add_row(
                    info.computer_name or "N/A",
                    info.operating_system or "N/A",
                    info.date_compromised,
                    info.malware_path or "N/A",
                )
            console.print(table)

        # === Servicios registrados ===
        registered = [s for s in services if s.registered]
        if registered:
            lines = [f"  [cyan]>[/cyan] {s.service}" for s in registered]
            console.print(Panel(
                "[bold]El email parece estar registrado en:[/bold]\n" + "\n".join(lines),
                title="[bold]Servicios Detectados[/bold]",
                border_style="cyan",
            ))

        # === Perfiles encontrados con username derivado ===
        if profiles:
            username = report.username_part
            table = Table(
                title=f"Perfiles encontrados con username '{username}'",
                box=box.ROUNDED,
                show_lines=True,
            )
            table.add_column("Plataforma", style="bold", max_width=15)
            table.add_column("URL", max_width=55)

            for p in profiles:
                table.add_row(p.platform, p.url)

            console.print(table)

        # === Errores ===
        if errors:
            console.print(f"\n[yellow]Advertencias ({len(errors)}):[/yellow]")
            for e in errors:
                console.print(f"  [dim]- {e}[/dim]")

        # === Resumen y recomendaciones ===
        reco_lines = []
        if infostealers:
            reco_lines.append(
                "[bold red]1. URGENTE:[/bold red] Un infostealer capturo credenciales. "
                "Cambiar TODAS las passwords y revocar sesiones activas."
            )
        if breaches:
            reco_lines.append(
                f"[bold yellow]2.[/bold yellow] El email aparece en {len(breaches)} brechas. "
                "Cambiar passwords de los servicios afectados y activar 2FA."
            )
        if profiles:
            reco_lines.append(
                f"[bold]3.[/bold] Se encontraron {len(profiles)} perfiles con el username "
                f"'{report.username_part}'. Verificar si son del propietario legitimo o "
                "si el atacante creo cuentas falsas."
            )
        if gravatar:
            reco_lines.append(
                "[bold]4.[/bold] Gravatar expone informacion publica. Si fue comprometido, "
                "el atacante puede ver nombre real, ubicacion y cuentas vinculadas."
            )
        if not reco_lines:
            reco_lines.append(
                "[green]No se encontraron hallazgos significativos. "
                "El email tiene una huella digital minima.[/green]"
            )

        console.print(Panel(
            "\n".join(reco_lines),
            title="[bold]Recomendaciones[/bold]",
            border_style="cyan",
            padding=(1, 2),
        ))
