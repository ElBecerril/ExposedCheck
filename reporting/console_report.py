"""Reporte visual en consola usando Rich."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from models import CheckReport
from config import RISK_LEVELS

console = Console()


class ConsoleReporter:
    """Genera reportes visuales en la terminal."""

    def print_report(self, report: CheckReport) -> None:
        """Imprime el reporte completo en consola."""
        console.print()
        self._print_header(report)
        console.print()

        if report.breaches:
            self._print_breaches_table(report)
            console.print()

        if report.has_infostealers:
            self._print_infostealers(report)
            console.print()

        if report.password_result:
            self._print_password_result(report)
            console.print()

        if report.errors:
            self._print_errors(report)
            console.print()

    def _print_header(self, report: CheckReport) -> None:
        """Panel de resumen con nivel de riesgo."""
        risk = report.overall_risk
        risk_cfg = RISK_LEVELS[risk]

        type_labels = {"email": "Email", "username": "Username", "phone": "Telefono"}
        query_label = type_labels.get(report.query_type, report.query_type)

        summary_lines = [
            f"[bold]{query_label}:[/bold] {report.query}",
            f"[bold]Brechas encontradas:[/bold] {report.total_breaches}",
        ]
        if report.has_infostealers:
            summary_lines.append(
                f"[bold red]Infostealers detectados:[/bold red] {len(report.infostealers)}"
            )
        if report.password_result:
            pw = report.password_result
            if pw.is_compromised:
                summary_lines.append("[bold red]Password: COMPROMETIDO[/bold red]")
            else:
                summary_lines.append("[bold green]Password: No encontrado en brechas[/bold green]")

        summary_text = "\n".join(summary_lines)

        risk_display = f"[bold {risk_cfg['color']}]{risk_cfg['icon']} RIESGO {risk.upper()}[/bold {risk_cfg['color']}]"

        panel = Panel(
            f"{summary_text}\n\n{risk_display}",
            title="[bold]Resultado de Verificacion[/bold]",
            border_style=risk_cfg["color"],
            box=box.DOUBLE,
            padding=(1, 2),
        )
        console.print(panel)

    def _print_breaches_table(self, report: CheckReport) -> None:
        """Tabla de brechas encontradas."""
        table = Table(
            title="Brechas de Seguridad Detectadas",
            box=box.ROUNDED,
            show_lines=True,
            title_style="bold",
        )
        table.add_column("Brecha", style="bold", max_width=25)
        table.add_column("Fecha", max_width=12)
        table.add_column("Datos Expuestos", max_width=40)
        table.add_column("Riesgo", justify="center", max_width=10)
        table.add_column("Fuente", max_width=15)

        for breach in report.breaches:
            risk_cfg = RISK_LEVELS.get(breach.risk_level, RISK_LEVELS["medio"])
            risk_text = Text(
                f"{risk_cfg['icon']} {breach.risk_level.upper()}",
                style=risk_cfg["color"],
            )
            exposed = ", ".join(breach.exposed_data) if breach.exposed_data else "N/A"

            table.add_row(
                breach.breach_name,
                breach.date,
                exposed,
                risk_text,
                breach.source_api,
            )

        console.print(table)

    def _print_infostealers(self, report: CheckReport) -> None:
        """Alerta de infostealers."""
        table = Table(
            title="[bold red]ALERTA: Infecciones por Infostealer Detectadas[/bold red]",
            box=box.HEAVY,
            show_lines=True,
            border_style="red",
        )
        table.add_column("Equipo", style="bold")
        table.add_column("Sistema Operativo")
        table.add_column("Fecha Compromiso")
        table.add_column("Malware")

        for info in report.infostealers:
            table.add_row(
                info.computer_name or "N/A",
                info.operating_system or "N/A",
                info.date_compromised,
                info.malware_path or "N/A",
            )

        console.print(table)
        console.print(
            Panel(
                "[bold red]Un infostealer robo credenciales de este dispositivo.[/bold red]\n"
                "Esto significa que passwords, cookies y datos de sesion fueron extraidos.\n"
                "[bold]Accion inmediata:[/bold] Cambiar TODAS las passwords de las cuentas "
                "asociadas y activar 2FA en cada una.",
                title="Que significa esto?",
                border_style="red",
            )
        )

    def _print_password_result(self, report: CheckReport) -> None:
        """Resultado de verificacion de password."""
        pw = report.password_result
        if pw.is_compromised:
            lines = ["[bold red]Este password aparece en brechas de datos conocidas.[/bold red]"]
            if pw.hibp_count > 0:
                lines.append(f"  HIBP Pwned Passwords: visto {pw.hibp_count:,} veces")
            if pw.xon_count > 0:
                lines.append("  XposedOrNot: encontrado en brechas")
            lines.append("\n[bold]Debes cambiar este password inmediatamente.[/bold]")
            panel_style = "red"
        else:
            lines = ["[bold green]Este password NO aparece en brechas conocidas.[/bold green]"]
            lines.append("Sin embargo, esto no garantiza que sea seguro.")
            panel_style = "green"

        console.print(Panel(
            "\n".join(lines),
            title="Verificacion de Password",
            border_style=panel_style,
        ))

    def _print_errors(self, report: CheckReport) -> None:
        """Errores durante la verificacion."""
        console.print("[bold yellow]Advertencias durante la verificacion:[/bold yellow]")
        for error in report.errors:
            console.print(f"  [yellow]- {error}[/yellow]")
