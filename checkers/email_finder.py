"""Orquestador de busqueda de email asociado a un username."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from models import EmailFinderResult, FoundEmail, CandidateResult
from apis.github_osint import GitHubOsintAPI
from apis.gitlab_osint import GitLabOsintAPI
from apis.email_generator import generate_candidates, EmailCandidateVerifier

console = Console()


class EmailFinder:
    """Busca emails asociados a un username usando OSINT y verificacion de brechas."""

    def __init__(self):
        self.github = GitHubOsintAPI()
        self.gitlab = GitLabOsintAPI()
        self.verifier = EmailCandidateVerifier()

    def check(self, username: str) -> EmailFinderResult:
        """Ejecuta busqueda completa de emails asociados a un username.

        Fase 1: Extraccion directa de GitHub y GitLab.
        Fase 2: Generacion de candidatos + verificacion en brechas.

        Args:
            username: Nombre de usuario a investigar.

        Returns:
            EmailFinderResult con todos los hallazgos.
        """
        result = EmailFinderResult(username=username)

        # === FASE 1: Extraccion directa de plataformas ===
        console.print("\n[bold cyan]Fase 1:[/bold cyan] Buscando emails en plataformas de desarrollo...\n")

        # GitHub
        with console.status("[bold blue]Consultando GitHub API..."):
            gh_result = self.github.check(username)
            result.platforms_checked.append("GitHub")
            if gh_result.get("error"):
                result.errors.append(gh_result["error"])
            for email in gh_result.get("emails", []):
                result.found_emails.append(FoundEmail(
                    email=email,
                    source="GitHub (perfil/commits)",
                    confidence="ALTA",
                ))

        # GitLab
        with console.status("[bold blue]Consultando GitLab API..."):
            gl_result = self.gitlab.check(username)
            result.platforms_checked.append("GitLab")
            if gl_result.get("error"):
                result.errors.append(gl_result["error"])
            for email in gl_result.get("emails", []):
                # Evitar duplicados
                existing = {e.email.lower() for e in result.found_emails}
                if email.lower() not in existing:
                    result.found_emails.append(FoundEmail(
                        email=email,
                        source="GitLab (perfil publico)",
                        confidence="ALTA",
                    ))

        found_phase1 = len(result.found_emails)
        if found_phase1 > 0:
            console.print(f"[green]  Se encontraron {found_phase1} email(s) en plataformas.[/green]\n")
        else:
            console.print("[yellow]  No se encontraron emails directamente en plataformas.[/yellow]\n")

        # === FASE 2: Generacion de candidatos + verificacion ===
        console.print("[bold cyan]Fase 2:[/bold cyan] Generando y verificando emails candidatos en brechas...\n")

        candidates = generate_candidates(username)
        existing_emails = {e.email.lower() for e in result.found_emails}

        # Filtrar candidatos que ya encontramos en Fase 1
        candidates_to_check = [c for c in candidates if c.lower() not in existing_emails]

        verified = self.verifier.verify_candidates(candidates_to_check)

        unverified = 0
        for v in verified:
            if v["found_in_breaches"]:
                # Determinar confianza segun fuentes
                if len(v["sources"]) >= 2:
                    confidence = "MEDIA-ALTA"
                else:
                    confidence = "MEDIA"

                result.found_emails.append(FoundEmail(
                    email=v["email"],
                    source=f"Brechas ({', '.join(v['sources'])})",
                    confidence=confidence,
                    breach_count=v["breach_count"],
                ))
            elif v.get("verified"):
                # Comprobado de verdad y sin brechas: negativo real.
                result.candidate_results.append(CandidateResult(
                    email=v["email"],
                    checked=True,
                    found=False,
                ))
            else:
                # No se pudo comprobar (rate limit / error): NO es un negativo.
                unverified += 1

        if unverified:
            result.errors.append(
                f"{unverified} de {len(candidates_to_check)} candidatos no se "
                "pudieron verificar (limite de consultas de las APIs). El "
                "resultado puede estar incompleto; reintenta mas tarde."
            )

        return result

    def print_results(self, result: EmailFinderResult) -> None:
        """Imprime los resultados de la busqueda de emails."""
        found = result.found_emails
        total_candidates = len(result.candidate_results) + len([e for e in found if e.confidence != "ALTA"])

        # Panel de resumen
        if found:
            risk_color = "green" if any(e.confidence == "ALTA" for e in found) else "yellow"
            risk_text = f"Se encontraron {len(found)} email(s) asociados"
        else:
            risk_color = "yellow"
            risk_text = "No se encontraron emails asociados a este username"

        summary_lines = [
            f"[bold]Username:[/bold] {result.username}",
            f"[bold]Plataformas consultadas:[/bold] {', '.join(result.platforms_checked)}",
            f"[bold]Candidatos verificados:[/bold] {total_candidates}",
            f"[bold]Emails encontrados:[/bold] [{risk_color}]{len(found)}[/{risk_color}]",
            f"\n[{risk_color}]{risk_text}[/{risk_color}]",
        ]

        console.print(Panel(
            "\n".join(summary_lines),
            title="[bold]Busqueda de Email por Username[/bold]",
            border_style=risk_color,
            box=box.DOUBLE,
        ))

        # Tabla de resultados
        if found:
            table = Table(
                title="Emails Encontrados",
                box=box.ROUNDED,
                show_lines=True,
            )
            table.add_column("Email", style="bold", max_width=35)
            table.add_column("Fuente", max_width=30)
            table.add_column("Confianza", justify="center", max_width=12)
            table.add_column("Brechas", justify="center", max_width=8)

            for email_info in found:
                confidence = email_info.confidence
                if confidence == "ALTA":
                    conf_style = "[bold green]ALTA[/bold green]"
                elif confidence == "MEDIA-ALTA":
                    conf_style = "[bold yellow]MEDIA-ALTA[/bold yellow]"
                else:
                    conf_style = "[yellow]MEDIA[/yellow]"

                breach_text = str(email_info.breach_count) if email_info.breach_count > 0 else "-"

                table.add_row(
                    email_info.email,
                    email_info.source,
                    conf_style,
                    breach_text,
                )

            console.print(table)

            console.print(Panel(
                "[bold]Como interpretar los resultados:[/bold]\n\n"
                "[bold green]ALTA[/bold green] - Email extraido directamente de un perfil publico (GitHub/GitLab)\n"
                "[bold yellow]MEDIA-ALTA[/bold yellow] - Email candidato encontrado en multiples bases de brechas\n"
                "[yellow]MEDIA[/yellow] - Email candidato encontrado en una base de brechas\n\n"
                "[dim]Los emails con confianza MEDIA o MEDIA-ALTA existen y podrian pertenecer\n"
                "al usuario, pero no hay garantia de que sean suyos.[/dim]",
                title="[bold]Niveles de Confianza[/bold]",
                border_style="cyan",
            ))

        # Errores
        if result.errors:
            error_lines = [f"  - {err}" for err in result.errors if "no encontrado" not in err.lower()]
            if error_lines:
                console.print(f"\n[yellow]Advertencias:[/yellow]")
                for line in error_lines:
                    console.print(f"[dim]{line}[/dim]")
