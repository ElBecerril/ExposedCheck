"""Punto de entrada CLI - Verificador de Datos Filtrados."""

import argparse
import getpass
import os
import sys

# Forzar UTF-8 en Windows para caracteres especiales de Rich
if sys.platform == "win32":
    os.system("")  # Habilita secuencias ANSI en Windows 10+
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

from checkers import (
    EmailChecker, UsernameChecker, PhoneChecker,
    PasswordChecker, ImageChecker, ProfileChecker,
)
from reporting import ConsoleReporter, RemediationGuide

console = Console(force_terminal=True)

BANNER = """
[bold cyan]
    ______                                __________              __
   / ____/  ______  ____  ________  ____/ / ____/ /_  ___  _____/ /__
  / __/ | |/_/ __ \\/ __ \\/ ___/ _ \\/ __  / /   / __ \\/ _ \\/ ___/ //_/
 / /____>  </ /_/ / /_/ (__  )  __/ /_/ / /___/ / / /  __/ /__/ ,<
/_____/_/|_/ .___/\\____/____/\\___/\\__,_/\\____/_/ /_/\\___/\\___/_/|_|
          /_/
[/bold cyan]
[dim]  Verificador de Datos Filtrados en Brechas de Seguridad[/dim]
[bold yellow]  by El_Becerril[/bold yellow]
"""

MENU = """
[bold]Que deseas verificar?[/bold]

  [cyan]1[/cyan] - Verificar email
  [cyan]2[/cyan] - Verificar nombre de usuario
  [cyan]3[/cyan] - Verificar numero de telefono
  [cyan]4[/cyan] - Verificar si un password esta filtrado
  [cyan]5[/cyan] - Busqueda inversa de imagenes (detectar uso de tus fotos)
  [cyan]6[/cyan] - Buscar perfiles duplicados en redes sociales
  [cyan]7[/cyan] - Verificacion completa (email + username + password)
  [cyan]0[/cyan] - Salir
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verifica si tus datos personales aparecen en brechas de seguridad conocidas.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python main.py                                        # Modo interactivo
  python main.py -e correo@ejemplo.com
  python main.py -e correo@ejemplo.com -u mi_usuario
  python main.py -e correo@ejemplo.com --check-password
  python main.py -e correo@ejemplo.com -u mi_usuario -t +34612345678
  python main.py --reverse-image ./mis_fotos/
  python main.py --search-profiles mi_usuario
        """,
    )
    parser.add_argument(
        "-e", "--email",
        help="Email a verificar",
    )
    parser.add_argument(
        "-u", "--username",
        help="Nombre de usuario a verificar",
    )
    parser.add_argument(
        "-t", "--phone",
        help="Numero de telefono a verificar (formato internacional: +34612345678)",
    )
    parser.add_argument(
        "--check-password",
        action="store_true",
        help="Verificar si un password esta comprometido (se pide de forma segura, nunca se muestra)",
    )
    parser.add_argument(
        "--reverse-image",
        metavar="RUTA",
        help="Busqueda inversa de imagen (ruta a archivo, carpeta, o URL)",
    )
    parser.add_argument(
        "--search-profiles",
        metavar="USERNAME",
        help="Buscar un username en 25+ plataformas para detectar perfiles duplicados",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="No abrir automaticamente URLs en el navegador (solo mostrar)",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Modo interactivo
# ---------------------------------------------------------------------------

def interactive_mode() -> None:
    """Modo interactivo guiado paso a paso."""
    console.print(BANNER)

    reporter = ConsoleReporter()
    remediation = RemediationGuide()

    while True:
        console.print(MENU)
        choice = Prompt.ask("[bold]Elige una opcion[/bold]", choices=["0", "1", "2", "3", "4", "5", "6", "7"], default="0")

        if choice == "0":
            console.print("\n[cyan]Hasta luego. Mantente seguro.[/cyan]\n")
            break

        elif choice == "1":
            _interactive_email(reporter, remediation)

        elif choice == "2":
            _interactive_username(reporter, remediation)

        elif choice == "3":
            _interactive_phone(reporter, remediation)

        elif choice == "4":
            _interactive_password()

        elif choice == "5":
            _interactive_image()

        elif choice == "6":
            _interactive_profiles()

        elif choice == "7":
            _interactive_full(reporter, remediation)

        # Preguntar si quiere hacer otra verificacion
        if choice != "0":
            console.print()
            again = Confirm.ask("[bold]Deseas hacer otra verificacion?[/bold]", default=True)
            if not again:
                console.print("\n[cyan]Hasta luego. Mantente seguro.[/cyan]\n")
                break


def _interactive_email(reporter: ConsoleReporter, remediation: RemediationGuide) -> None:
    email = Prompt.ask("\n[bold]Introduce tu email[/bold]").strip()
    if not email:
        console.print("[red]No se introdujo un email.[/red]")
        return

    console.rule(f"[bold]Verificando email: {email}[/bold]")
    checker = EmailChecker()
    report = checker.check(email)
    reporter.print_report(report)

    console.print()
    console.rule("[bold]Guia de Remediacion[/bold]")
    remediation.print_guide(report)


def _interactive_username(reporter: ConsoleReporter, remediation: RemediationGuide) -> None:
    username = Prompt.ask("\n[bold]Introduce tu nombre de usuario[/bold]").strip()
    if not username:
        console.print("[red]No se introdujo un username.[/red]")
        return

    console.rule(f"[bold]Verificando username: {username}[/bold]")
    checker = UsernameChecker()
    report = checker.check(username)
    reporter.print_report(report)

    console.print()
    console.rule("[bold]Guia de Remediacion[/bold]")
    remediation.print_guide(report)


def _interactive_phone(reporter: ConsoleReporter, remediation: RemediationGuide) -> None:
    console.print("\n[dim]Formato internacional, ejemplo: +521234567890[/dim]")
    phone = Prompt.ask("[bold]Introduce tu numero de telefono[/bold]").strip()
    if not phone:
        console.print("[red]No se introdujo un telefono.[/red]")
        return

    console.rule(f"[bold]Verificando telefono: {phone}[/bold]")
    checker = PhoneChecker()
    report = checker.check(phone)
    reporter.print_report(report)

    console.print()
    console.rule("[bold]Guia de Remediacion[/bold]")
    remediation.print_guide(report)


def _interactive_password() -> None:
    console.print(Panel(
        "[bold]Tu password NUNCA se envia completo.[/bold]\n"
        "Se usa una tecnica llamada k-anonymity: solo se envian los primeros\n"
        "caracteres del hash, nunca el password real.",
        title="[bold]Seguridad[/bold]",
        border_style="green",
    ))

    password = getpass.getpass("\nIntroduce el password a verificar (no se mostrara en pantalla): ")
    if not password:
        console.print("[red]No se introdujo un password.[/red]")
        return

    pw_checker = PasswordChecker()
    result = pw_checker.check(password)

    console.print()
    if result.is_compromised:
        lines = ["[bold red]Este password aparece en brechas de datos conocidas.[/bold red]"]
        if result.hibp_count > 0:
            lines.append(f"  HIBP Pwned Passwords: visto {result.hibp_count:,} veces")
        if result.xon_count > 0:
            lines.append("  XposedOrNot: encontrado en brechas")
        lines.append("\n[bold]Debes cambiar este password inmediatamente en todos los sitios donde lo uses.[/bold]")
        console.print(Panel("\n".join(lines), title="Resultado", border_style="red"))
    else:
        console.print(Panel(
            "[bold green]Este password NO aparece en brechas conocidas.[/bold green]\n"
            "Sin embargo, esto no garantiza que sea seguro. Usa passwords largos y unicos.",
            title="Resultado",
            border_style="green",
        ))


def _interactive_image() -> None:
    console.print(Panel(
        "Puedes verificar si alguien esta usando tus fotos en otros perfiles.\n\n"
        "[bold]Opciones:[/bold]\n"
        "  - Ruta a una foto:   C:\\Users\\tu_usuario\\foto.jpg\n"
        "  - Ruta a una carpeta con fotos:   C:\\Users\\tu_usuario\\mis_fotos\\\n"
        "  - URL de una imagen:   https://ejemplo.com/foto.jpg",
        title="[bold]Busqueda Inversa de Imagenes[/bold]",
        border_style="cyan",
    ))

    path = Prompt.ask("\n[bold]Introduce la ruta o URL de la imagen[/bold]").strip().strip('"')
    if not path:
        console.print("[red]No se introdujo una ruta.[/red]")
        return

    console.rule("[bold]Busqueda Inversa de Imagenes[/bold]")
    checker = ImageChecker()
    results = checker.check(path, auto_open=True)
    checker.print_results(results)


def _interactive_profiles() -> None:
    username = Prompt.ask("\n[bold]Introduce el nombre de usuario a buscar[/bold]").strip()
    if not username:
        console.print("[red]No se introdujo un username.[/red]")
        return

    console.rule(f"[bold]Buscando perfiles: {username}[/bold]")
    checker = ProfileChecker()
    results = checker.check(username)
    checker.print_results(results)


def _interactive_full(reporter: ConsoleReporter, remediation: RemediationGuide) -> None:
    """Verificacion completa: email + username + password."""
    console.print("\n[bold]Verificacion completa[/bold]")
    console.print("[dim]Deja en blanco los campos que no quieras verificar.[/dim]\n")

    email = Prompt.ask("[bold]Email[/bold]", default="").strip()
    username = Prompt.ask("[bold]Nombre de usuario[/bold]", default="").strip()

    check_pw = False
    if email or username:
        check_pw = Confirm.ask("[bold]Verificar tambien un password?[/bold]", default=False)

    if not email and not username:
        console.print("[red]Debes introducir al menos un email o username.[/red]")
        return

    all_reports = []

    if email:
        console.rule(f"[bold]Verificando email: {email}[/bold]")
        checker = EmailChecker()
        report = checker.check(email)

        if check_pw:
            password = getpass.getpass("\nIntroduce el password a verificar (no se mostrara): ")
            if password:
                pw_checker = PasswordChecker()
                report.password_result = pw_checker.check(password)

        reporter.print_report(report)
        all_reports.append(report)

    if username:
        console.rule(f"[bold]Verificando username: {username}[/bold]")
        checker = UsernameChecker()
        report = checker.check(username)
        reporter.print_report(report)
        all_reports.append(report)

    combined = _merge_reports(all_reports)
    if combined:
        console.print()
        console.rule("[bold]Guia de Remediacion y Eliminacion de Datos[/bold]")
        remediation.print_guide(combined)


# ---------------------------------------------------------------------------
# Modo CLI con argumentos
# ---------------------------------------------------------------------------

def cli_mode(args: argparse.Namespace) -> None:
    """Modo CLI tradicional con argumentos."""
    console.print(BANNER)

    reporter = ConsoleReporter()
    remediation = RemediationGuide()
    all_reports = []

    # --- Verificacion de Email ---
    if args.email:
        console.rule(f"[bold]Verificando email: {args.email}[/bold]")
        checker = EmailChecker()
        report = checker.check(args.email)

        if args.check_password:
            password = getpass.getpass("\nIntroduce el password a verificar (no se mostrara): ")
            if password:
                pw_checker = PasswordChecker()
                report.password_result = pw_checker.check(password)

        reporter.print_report(report)
        all_reports.append(report)

    # --- Verificacion de Username ---
    if args.username:
        console.rule(f"[bold]Verificando username: {args.username}[/bold]")
        checker = UsernameChecker()
        report = checker.check(args.username)
        reporter.print_report(report)
        all_reports.append(report)

    # --- Verificacion de Telefono ---
    if args.phone:
        console.rule(f"[bold]Verificando telefono: {args.phone}[/bold]")
        checker = PhoneChecker()
        report = checker.check(args.phone)
        reporter.print_report(report)
        all_reports.append(report)

    # --- Busqueda inversa de imagenes ---
    if args.reverse_image:
        console.rule("[bold]Busqueda Inversa de Imagenes[/bold]")
        checker = ImageChecker()
        auto_open = not args.no_open
        results = checker.check(args.reverse_image, auto_open=auto_open)
        checker.print_results(results)

    # --- Busqueda de perfiles duplicados ---
    if args.search_profiles:
        console.rule(f"[bold]Buscando perfiles: {args.search_profiles}[/bold]")
        checker = ProfileChecker()
        results = checker.check(args.search_profiles)
        checker.print_results(results)

    # --- Guia de Remediacion ---
    combined = _merge_reports(all_reports)
    if combined:
        console.print()
        console.rule("[bold]Guia de Remediacion y Eliminacion de Datos[/bold]")
        remediation.print_guide(combined)

    console.print()


def _merge_reports(reports: list):
    """Combina multiples reportes en uno para la guia de remediacion."""
    if not reports:
        return None

    if len(reports) == 1:
        return reports[0]

    from models import CheckReport
    combined = CheckReport(query="(multiples consultas)", query_type="email")
    for r in reports:
        combined.breaches.extend(r.breaches)
        combined.infostealers.extend(r.infostealers)
        combined.errors.extend(r.errors)
        if r.password_result and not combined.password_result:
            combined.password_result = r.password_result
    return combined


if __name__ == "__main__":
    try:
        args = parse_args()

        # Si no se paso ningun argumento, modo interactivo
        has_any = (
            args.email or args.username or args.phone
            or args.reverse_image or args.search_profiles or args.check_password
        )
        if has_any:
            cli_mode(args)
        else:
            interactive_mode()

    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelado por el usuario.[/yellow]")
        sys.exit(1)
