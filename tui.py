"""Interfaz TUI (Textual) para ExposedCheck.

Cubre los 4 checks de brechas (email/username/phone/password) y los 4 checks
OSINT (perfiles, fingerprint de email, busqueda inversa de imagenes, email
finder) con resultados navegables. Los checks corren en un worker thread para
no bloquear la UI.

Nota: los checkers usan un `console.status(...)` / `Progress(...)` de rich
que escribe a stdout; dentro de Textual eso corromperia la pantalla, asi que
al arrancar se redirigen esos consoles a un buffer nulo
(_silence_checker_consoles).

Etica: el fingerprint de email (`checkers/email_fingerprint.py`) consulta
endpoints internos no documentados y permite enumerar cuentas de terceros.
Igual que en el CLI (`main.py:_interactive_fingerprint`), la TUI exige una
confirmacion explicita con el mismo disclaimer antes de ejecutarlo -- no
quitar ni suavizar ese paso.
"""

import io

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich import box

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Header, Footer, Input, Button, Select, Static

from config import RISK_LEVELS, APP_NAME, APP_VERSION
from models import (
    CheckReport, PasswordResult, ProfileReport, FingerprintReport,
    ImageCheckReport, EmailFinderResult,
)
from checkers.email_checker import EmailChecker
from checkers.username_checker import UsernameChecker
from checkers.phone_checker import PhoneChecker
from checkers.password_checker import PasswordChecker
from checkers.profile_checker import ProfileChecker
from checkers.email_fingerprint import EmailFingerprint
from checkers.image_checker import ImageChecker
from checkers.email_finder import EmailFinder

CHECK_TYPES = [
    ("Email", "email"),
    ("Username", "username"),
    ("Telefono", "phone"),
    ("Password", "password"),
    ("Perfiles", "profiles"),
    ("Fingerprint email", "fingerprint"),
    ("Imagen (busqueda inversa)", "image"),
    ("Email finder (por username)", "email_finder"),
]

FINGERPRINT_DISCLAIMER = (
    "Esta herramienta consulta APIs de terceros (Spotify, WordPress, "
    "Duolingo, GitHub, etc.) para saber si un email esta registrado en esos "
    "servicios.\n\n"
    "Usala solo con tu propio email o con autorizacion expresa del titular: "
    "verificar cuentas ajenas sin consentimiento puede ser doxing/stalking y "
    "violar los terminos de servicio de esas plataformas.\n\n"
    "¿Confirmas que este email es tuyo o cuentas con autorizacion del "
    "titular para investigarlo?"
)


def _silence_checker_consoles() -> None:
    """Redirige los consoles de los checkers (y de las APIs que usan
    `Progress`/`console.status`) a un buffer para que no escriban sobre la
    pantalla de Textual."""
    import checkers.email_checker as ec
    import checkers.username_checker as uc
    import checkers.phone_checker as pc
    import checkers.password_checker as pwc
    import checkers.profile_checker as prc
    import checkers.email_fingerprint as efc
    import checkers.image_checker as ic
    import checkers.email_finder as efi
    import apis.email_generator as eg

    quiet = Console(file=io.StringIO())
    for mod in (ec, uc, pc, pwc, prc, efc, ic, efi, eg):
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
    if isinstance(report, ProfileReport):
        return _render_profiles(report)
    if isinstance(report, FingerprintReport):
        return _render_fingerprint(report)
    if isinstance(report, ImageCheckReport):
        return _render_image(report)
    if isinstance(report, EmailFinderResult):
        return _render_email_finder(report)
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


def _render_profiles(report: ProfileReport) -> Group:
    parts = []
    found = report.found
    errors = report.errors

    if not found:
        color, text = "green", "No se encontraron perfiles con este username"
    elif len(found) <= 3:
        color, text = "yellow", f"Se encontraron {len(found)} perfiles - verificar si son tuyos"
    else:
        color, text = "bright_red", f"Se encontraron {len(found)} perfiles - revisar con atencion"

    summary = "\n".join([
        f"[bold]Username:[/bold] {report.username}",
        f"[bold]Perfiles encontrados:[/bold] [{color}]{len(found)}[/{color}]",
        f"[bold]Errores de conexion:[/bold] {len(errors)}",
        "",
        f"[{color}]{text}[/{color}]",
    ])
    parts.append(Panel(summary, title="Busqueda de Perfiles", border_style=color, box=box.DOUBLE))

    if found:
        table = Table(title="Perfiles Encontrados", box=box.ROUNDED, show_lines=True, expand=True)
        table.add_column("Plataforma", style="bold")
        table.add_column("URL")
        table.add_column("Confianza", justify="center")
        for p in found:
            conf = "[yellow]señal débil *[/yellow]" if p.weak else "[green]probable[/green]"
            table.add_row(p.platform, p.url, conf)
        parts.append(table)
        if any(p.weak for p in found):
            parts.append(
                "[dim]* Plataformas que devuelven 200 incluso para usuarios "
                "inexistentes. Abre la URL para confirmar.[/dim]"
            )

    if errors:
        err_lines = "\n".join(f"  [dim]- {e.platform}: {e.error}[/dim]" for e in errors)
        parts.append(Panel(err_lines, title="Errores de conexion", border_style="yellow"))

    return Group(*parts)


def _render_image(report: ImageCheckReport) -> Group:
    if report.errors:
        return Group(Panel("\n".join(f"[red]{e}[/red]" for e in report.errors),
                            title="Busqueda Inversa de Imagenes", border_style="red"))

    parts = []
    table = Table(title="Busqueda Inversa de Imagenes", box=box.ROUNDED, show_lines=True, expand=True)
    table.add_column("Imagen", style="bold")
    table.add_column("Estado")
    table.add_column("Motores / URLs")
    for img in report.images:
        import os
        source = os.path.basename(img.source) if img.type == "local" else img.source
        if img.error:
            table.add_row(source, "[red]Error[/red]", img.error)
        elif img.opened:
            table.add_row(source, "[green]Abierto en navegador[/green]", ", ".join(img.search_urls.keys()))
        else:
            urls = "\n".join(f"{engine}: {u}" for engine, u in img.search_urls.items())
            table.add_row(source, "[cyan]Generado[/cyan]", urls)
    parts.append(table)

    parts.append(Panel(
        "[bold]Que buscar:[/bold] perfiles/sitios que NO sean tuyos usando tu foto. "
        "Si encuentras un perfil falso, captura evidencia y reportalo.",
        title="Guia de Verificacion", border_style="cyan",
    ))
    return Group(*parts)


def _render_email_finder(result: EmailFinderResult) -> Group:
    found = result.found_emails
    color = "yellow"
    if found:
        color = "green" if any(e.confidence == "ALTA" for e in found) else "yellow"
        text = f"Se encontraron {len(found)} email(s) asociados"
    else:
        text = "No se encontraron emails asociados a este username"

    summary = "\n".join([
        f"[bold]Username:[/bold] {result.username}",
        f"[bold]Plataformas consultadas:[/bold] {', '.join(result.platforms_checked) or 'ninguna'}",
        f"[bold]Emails encontrados:[/bold] [{color}]{len(found)}[/{color}]",
        "",
        f"[{color}]{text}[/{color}]",
    ])
    parts = [Panel(summary, title="Busqueda de Email por Username", border_style=color, box=box.DOUBLE)]

    if found:
        table = Table(title="Emails Encontrados", box=box.ROUNDED, show_lines=True, expand=True)
        table.add_column("Email", style="bold")
        table.add_column("Fuente")
        table.add_column("Confianza", justify="center")
        table.add_column("Brechas", justify="center")
        for e in found:
            if e.confidence == "ALTA":
                conf = "[bold green]ALTA[/bold green]"
            elif e.confidence == "MEDIA-ALTA":
                conf = "[bold yellow]MEDIA-ALTA[/bold yellow]"
            else:
                conf = "[yellow]MEDIA[/yellow]"
            table.add_row(e.email, e.source, conf, str(e.breach_count) if e.breach_count else "-")
        parts.append(table)

    if result.errors:
        err_lines = "\n".join(f"  - {e}" for e in result.errors)
        parts.append(Panel(err_lines, title="Advertencias", border_style="yellow"))

    return Group(*parts)


def _render_fingerprint(report: FingerprintReport) -> Group:
    domain_info = report.domain_info
    breaches = report.breaches
    infostealers = report.infostealers
    github = report.github_presence
    services = report.registered_services
    profiles = report.profiles_found
    gravatar = report.gravatar

    total_findings = (
        len(breaches) + len(infostealers) + (1 if gravatar else 0)
        + (len(github.users) if github and github.found else 0)
        + len([s for s in services if s.registered])
        + len(profiles)
    )

    if len(infostealers) > 0:
        color, text = "red", "CRITICO - Infostealer detectado"
    elif len(breaches) >= 5:
        color, text = "bright_red", "ALTO - Multiples brechas"
    elif len(breaches) >= 1 or total_findings >= 5:
        color, text = "yellow", "MEDIO - Datos expuestos"
    elif total_findings >= 1:
        color, text = "cyan", "BAJO - Presencia minima"
    else:
        color, text = "green", "LIMPIO - Sin hallazgos"

    domain_type = domain_info.type if domain_info else "desconocido"
    summary = "\n".join([
        f"[bold]Email:[/bold] {report.email}",
        f"[bold]Dominio:[/bold] {report.domain} ({domain_type})",
        f"[bold]Hallazgos totales:[/bold] {total_findings}",
        f"[bold]Brechas:[/bold] {len(breaches)} | "
        f"[bold]Infostealers:[/bold] {len(infostealers)} | "
        f"[bold]Perfiles:[/bold] {len(profiles)}",
        "",
        f"[bold {color}]{text}[/bold {color}]",
    ])
    parts = [Panel(summary, title="Email Fingerprint", border_style=color, box=box.DOUBLE)]

    if gravatar:
        lines = []
        if gravatar.display_name:
            lines.append(f"[bold]Nombre:[/bold] {gravatar.display_name}")
        if gravatar.username:
            lines.append(f"[bold]Username:[/bold] {gravatar.username}")
        if gravatar.profile_url:
            lines.append(f"[bold]Perfil:[/bold] {gravatar.profile_url}")
        parts.append(Panel("\n".join(lines) or "[dim]Sin datos publicos[/dim]",
                            title="Gravatar", border_style="magenta"))

    if github and github.found:
        lines = "\n".join(f"  [bold]{u.username}[/bold] - {u.profile_url}" for u in github.users)
        parts.append(Panel(lines, title="GitHub", border_style="white"))

    if breaches:
        table = Table(title="Brechas de Seguridad", box=box.ROUNDED, show_lines=True, expand=True)
        table.add_column("Brecha", style="bold")
        table.add_column("Fecha")
        table.add_column("Datos Expuestos")
        table.add_column("Fuente")
        for b in breaches:
            exposed = ", ".join(b.exposed_data) if b.exposed_data else "N/A"
            table.add_row(b.breach_name, b.date, exposed, b.source_api)
        parts.append(table)

    if infostealers:
        table = Table(title="[red]ALERTA: Infostealers Detectados[/red]", box=box.HEAVY,
                      show_lines=True, border_style="red", expand=True)
        table.add_column("Equipo", style="bold")
        table.add_column("Sistema")
        table.add_column("Fecha")
        for i in infostealers:
            table.add_row(i.computer_name or "N/A", i.operating_system or "N/A", i.date_compromised)
        parts.append(table)

    registered = [s for s in services if s.registered]
    if registered:
        lines = "\n".join(f"  [cyan]>[/cyan] {s.service}" for s in registered)
        parts.append(Panel(lines, title="Servicios Detectados", border_style="cyan"))

    if profiles:
        table = Table(title=f"Perfiles con username '{report.username_part}'",
                       box=box.ROUNDED, show_lines=True, expand=True)
        table.add_column("Plataforma", style="bold")
        table.add_column("URL")
        for p in profiles:
            table.add_row(p.platform, p.url)
        parts.append(table)

    if report.errors:
        err_lines = "\n".join(f"  [dim]- {e}[/dim]" for e in report.errors)
        parts.append(Panel(err_lines, title="Advertencias", border_style="yellow"))

    return Group(*parts)


# --- Confirmacion de fingerprint (etica) ----------------------------------

class FingerprintConfirmScreen(ModalScreen[bool]):
    """Modal de confirmacion obligatoria antes de correr el fingerprint.

    Replica el disclaimer + confirmacion explicita del CLI
    (`main.py:_interactive_fingerprint`). No se debe poder saltar: el
    fingerprint solo se ejecuta si el usuario pulsa "Confirmar".
    """

    CSS = """
    FingerprintConfirmScreen { align: center middle; }
    #dialog {
        width: 70; height: auto; border: thick $warning; padding: 1 2;
        background: $surface;
    }
    #dialog-buttons { height: auto; padding-top: 1; align: right middle; }
    #dialog-buttons Button { margin-left: 1; }
    """

    BINDINGS = [("escape", "cancel", "Cancelar")]

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(f"[bold yellow]Uso responsable[/bold yellow]\n\n{FINGERPRINT_DISCLAIMER}")
            with Horizontal(id="dialog-buttons"):
                yield Button("Cancelar", id="cancel")
                yield Button("Confirmar", variant="warning", id="confirm")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm")

    def action_cancel(self) -> None:
        self.dismiss(False)


class SaveAsScreen(ModalScreen[str]):
    """Modal para elegir la ruta/nombre del reporte a guardar."""

    CSS = """
    SaveAsScreen { align: center middle; }
    #save-dialog {
        width: 60; height: auto; border: thick $primary; padding: 1 2;
        background: $surface;
    }
    #save-dialog Input { margin-top: 1; }
    #save-buttons { height: auto; padding-top: 1; align: right middle; }
    #save-buttons Button { margin-left: 1; }
    """

    BINDINGS = [("escape", "cancel", "Cancelar")]

    def compose(self) -> ComposeResult:
        with Vertical(id="save-dialog"):
            yield Static("[bold]Guardar resultados[/bold]\nRuta/nombre del archivo (sin extension o con .json/.html):")
            yield Input(placeholder="exposedcheck_report", id="save-path")
            with Horizontal(id="save-buttons"):
                yield Button("Cancelar", id="save-cancel")
                yield Button("Guardar", variant="primary", id="save-confirm")

    def on_mount(self) -> None:
        self.query_one("#save-path", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-confirm":
            self.dismiss(self.query_one("#save-path", Input).value.strip())
        else:
            self.dismiss("")

    def action_cancel(self) -> None:
        self.dismiss("")


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

    _PLACEHOLDERS = {
        "password": "Password (no se mostrara)",
        "profiles": "Username a buscar",
        "fingerprint": "Email a investigar",
        "image": "Ruta a imagen/carpeta o URL",
        "email_finder": "Username a investigar",
    }

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "check-type":
            inp = self.query_one("#query", Input)
            is_pw = event.value == "password"
            inp.password = is_pw
            inp.placeholder = self._PLACEHOLDERS.get(event.value, "Valor a verificar")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run":
            self._launch()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "query":
            self._launch()

    def _launch(self) -> None:
        query = self.query_one("#query", Input).value.strip()
        check_type = self.query_one("#check-type", Select).value
        if not query:
            self.notify("Introduce un valor.", severity="warning")
            return

        if check_type == "fingerprint":
            # Etica no negociable: sin confirmacion explicita no se ejecuta.
            self.push_screen(
                FingerprintConfirmScreen(),
                lambda confirmed: self._on_fingerprint_confirmed(confirmed, query),
            )
            return

        self._start_check(check_type, query)

    def _on_fingerprint_confirmed(self, confirmed: bool, query: str) -> None:
        if not confirmed:
            self.notify("Cancelado.", severity="warning")
            return
        self._start_check("fingerprint", query)

    def _start_check(self, check_type: str, query: str) -> None:
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
            elif check_type == "password":
                report = PasswordChecker().check(query)
            elif check_type == "profiles":
                report = ProfileChecker().check(query)
            elif check_type == "fingerprint":
                report = EmailFingerprint().fingerprint(query)
            elif check_type == "image":
                report = ImageChecker().check(query, auto_open=False)
            else:
                report = EmailFinder().check(query)
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
        self.push_screen(SaveAsScreen(), self._on_save_path)

    def _on_save_path(self, path: str) -> None:
        path = (path or "").strip().strip('"')
        if not path:
            self.notify("Sin ruta: no se guardo nada.", severity="warning")
            return

        # Normalizar la base quitando una extension conocida (igual que
        # _offer_export en main.py), asi no se duplica .json.json/.html.html.
        base = path
        for ext in (".json", ".html"):
            if base.lower().endswith(ext):
                base = base[: -len(ext)]

        from reporting.export import export_json, export_html
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
