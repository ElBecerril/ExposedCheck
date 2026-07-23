"""Interfaz TUI (Textual) para ExposedCheck.

MVP: verificacion de brechas (email/username/phone/password) con resultados
navegables. Los checks corren en un worker thread para no bloquear la UI.

Nota: los checkers usan un `console.status(...)` de rich que escribe a stdout;
dentro de Textual eso corromperia la pantalla, asi que al arrancar se
redirigen esos consoles a un buffer nulo (_silence_checker_consoles).
"""

import io

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich import box

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Header, Footer, Input, Button, Select, Static

from config import RISK_LEVELS, APP_NAME, APP_VERSION
from models import CheckReport, PasswordResult
from checkers.email_checker import EmailChecker
from checkers.username_checker import UsernameChecker
from checkers.phone_checker import PhoneChecker
from checkers.password_checker import PasswordChecker

CHECK_TYPES = [
    ("Email", "email"),
    ("Username", "username"),
    ("Telefono", "phone"),
    ("Password", "password"),
]


def _silence_checker_consoles() -> None:
    """Redirige los consoles de los checkers a un buffer para que su
    `console.status(...)` no escriba sobre la pantalla de Textual."""
    import checkers.email_checker as ec
    import checkers.username_checker as uc
    import checkers.phone_checker as pc
    import checkers.password_checker as pwc

    quiet = Console(file=io.StringIO())
    for mod in (ec, uc, pc, pwc):
        mod.console = quiet


# --- Rendering (funciones puras, testeables sin Textual) -----------------

def _risk_badge(risk: str) -> str:
    cfg = RISK_LEVELS.get(risk, {"color": "white", "icon": "?"})
    if risk == "desconocido":
        return (
            f"[bold {cfg['color']}]{cfg['icon']} RESULTADO NO CONCLUYENTE[/]\n"
            "[dim]Ninguna fuente respondio: esto NO significa que estes limpio.[/dim]"
        )
    return f"[bold {cfg['color']}]{cfg['icon']} RIESGO {risk.upper()}[/]"


def _coverage_line(report: CheckReport) -> str:
    total = len(report.sources_ok) + len(report.sources_failed)
    if total == 0:
        return "[dim]Fuentes consultadas: ninguna[/dim]"
    ok = ", ".join(report.sources_ok) if report.sources_ok else "ninguna"
    line = f"[bold]Fuentes:[/bold] {len(report.sources_ok)}/{total} ({ok})"
    if report.sources_failed:
        line += f"  [yellow]Sin respuesta: {', '.join(report.sources_failed)}[/yellow]"
    return line


def render_report(check_type: str, report) -> Group:
    """Convierte un reporte en un renderable de rich para la TUI."""
    if isinstance(report, PasswordResult):
        return _render_password(report)
    return _render_check(report)


def _render_check(report: CheckReport) -> Group:
    parts = []
    if report.has_coverage:
        breaches_line = f"[bold]Brechas encontradas:[/bold] {report.total_breaches}"
    else:
        breaches_line = "[bold]Brechas encontradas:[/bold] sin datos"

    summary = "\n".join([
        f"[bold]{report.query_type.capitalize()}:[/bold] {report.query}",
        breaches_line,
        _coverage_line(report),
        "",
        _risk_badge(report.overall_risk),
    ])
    parts.append(Panel(summary, title=f"{APP_NAME}", border_style="cyan", box=box.DOUBLE))

    if report.breaches:
        table = Table(title="Brechas", box=box.ROUNDED, show_lines=True, expand=True)
        table.add_column("Brecha", style="bold")
        table.add_column("Fecha")
        table.add_column("Datos expuestos")
        table.add_column("Fuente")
        for b in report.breaches:
            exposed = ", ".join(b.exposed_data) if b.exposed_data else "N/A"
            table.add_row(b.breach_name, b.date, exposed, b.source_api)
        parts.append(table)

    if report.infostealers:
        table = Table(title="[red]Infostealers[/red]", box=box.HEAVY, border_style="red", expand=True)
        table.add_column("Equipo", style="bold")
        table.add_column("Sistema")
        table.add_column("Fecha")
        for i in report.infostealers:
            table.add_row(i.computer_name or "N/A", i.operating_system or "N/A", i.date_compromised)
        parts.append(table)

    return Group(*parts)


def _render_password(pw: PasswordResult) -> Group:
    if pw.is_compromised:
        lines = ["[bold red]Password COMPROMETIDO.[/bold red]"]
        if pw.hibp_count:
            lines.append(f"  HIBP: visto {pw.hibp_count:,} veces")
        if pw.xon_count:
            lines.append("  XposedOrNot: encontrado en brechas")
        style = "red"
    elif not pw.has_coverage:
        lines = [
            "[bold yellow]No se pudo verificar este password.[/bold yellow]",
            f"Fuentes sin respuesta: {', '.join(pw.sources_failed) or 'todas'}.",
        ]
        style = "yellow"
    else:
        lines = ["[bold green]Este password NO aparece en brechas conocidas.[/bold green]"]
        if pw.sources_failed:
            lines.append(f"[yellow]Cobertura parcial: {', '.join(pw.sources_failed)} no respondio.[/yellow]")
        style = "green"
    return Group(Panel("\n".join(lines), title="Password", border_style=style))


# --- App -----------------------------------------------------------------

class ExposedCheckApp(App):
    """App TUI de ExposedCheck."""

    TITLE = APP_NAME
    SUB_TITLE = f"v{APP_VERSION}"

    CSS = """
    #controls { height: auto; padding: 1; }
    #check-type { width: 20; }
    #query { width: 1fr; }
    #run { width: 14; }
    #results { padding: 0 1; }
    """

    BINDINGS = [
        ("q", "quit", "Salir"),
        ("s", "save", "Guardar"),
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._last = {}  # {check_type: report} de la ultima verificacion

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="controls"):
            yield Select(CHECK_TYPES, value="email", allow_blank=False, id="check-type")
            yield Input(placeholder="Valor a verificar", id="query")
            yield Button("Verificar", variant="primary", id="run")
        yield VerticalScroll(id="results")
        yield Footer()

    def on_mount(self) -> None:
        _silence_checker_consoles()
        self.query_one("#query", Input).focus()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "check-type":
            inp = self.query_one("#query", Input)
            is_pw = event.value == "password"
            inp.password = is_pw
            inp.placeholder = "Password (no se mostrara)" if is_pw else "Valor a verificar"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run":
            self._launch()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._launch()

    def _launch(self) -> None:
        query = self.query_one("#query", Input).value.strip()
        check_type = self.query_one("#check-type", Select).value
        if not query:
            self.notify("Introduce un valor.", severity="warning")
            return
        results = self.query_one("#results", VerticalScroll)
        results.remove_children()
        results.mount(Static("[dim]Consultando...[/dim]"))
        self._run_check(check_type, query)

    @work(thread=True, exclusive=True)
    def _run_check(self, check_type: str, query: str) -> None:
        try:
            if check_type == "email":
                report = EmailChecker().check(query)
            elif check_type == "username":
                report = UsernameChecker().check(query)
            elif check_type == "phone":
                report = PhoneChecker().check(query)
            else:
                report = PasswordChecker().check(query)
        except Exception as e:  # blindaje: un fallo no debe tumbar la UI
            self.call_from_thread(self._show_error, str(e))
            return
        self.call_from_thread(self._show, check_type, report)

    def _show(self, check_type: str, report) -> None:
        self._last = {check_type: report}
        results = self.query_one("#results", VerticalScroll)
        results.remove_children()
        results.mount(Static(render_report(check_type, report)))

    def _show_error(self, msg: str) -> None:
        results = self.query_one("#results", VerticalScroll)
        results.remove_children()
        results.mount(Static(f"[red]Error: {msg}[/red]"))

    def action_save(self) -> None:
        if not self._last:
            self.notify("No hay resultados que guardar.", severity="warning")
            return
        from reporting.export import export_json, export_html
        base = "exposedcheck_report"
        try:
            export_json(self._last, base + ".json")
            export_html(self._last, base + ".html")
        except OSError as e:
            self.notify(f"No se pudo guardar: {e}", severity="error")
            return
        self.notify(f"Guardado en {base}.json y {base}.html")


def run_tui() -> None:
    """Lanza la app TUI."""
    ExposedCheckApp().run()
