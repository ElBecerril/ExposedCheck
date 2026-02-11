"""Buscador de perfiles duplicados/falsos en multiples plataformas."""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from config import REQUEST_TIMEOUT, USER_AGENT

console = Console()

# Plataformas a verificar: (nombre, url_template, metodo_deteccion)
# metodo_deteccion:
#   "status" = 200 existe, 404 no existe
#   "redirect" = si redirige a otra pagina, no existe
#   "text:XXX" = si el texto XXX aparece en la respuesta, NO existe
PLATFORMS = [
    # Redes sociales principales
    ("Instagram", "https://www.instagram.com/{}/", "status"),
    ("Twitter/X", "https://x.com/{}", "status"),
    ("TikTok", "https://www.tiktok.com/@{}", "status"),
    ("Facebook", "https://www.facebook.com/{}", "text:page isn't available"),
    ("Reddit", "https://www.reddit.com/user/{}", "status"),
    ("Pinterest", "https://www.pinterest.com/{}/", "status"),
    ("Tumblr", "https://{}.tumblr.com", "status"),
    # Desarrollo / Tech
    ("GitHub", "https://github.com/{}", "status"),
    ("GitLab", "https://gitlab.com/{}", "status"),
    ("HackerOne", "https://hackerone.com/{}", "status"),
    ("Dev.to", "https://dev.to/{}", "status"),
    # Gaming
    ("Steam", "https://steamcommunity.com/id/{}", "text:could not be found"),
    ("Twitch", "https://www.twitch.tv/{}", "status"),
    # Profesional
    ("LinkedIn", "https://www.linkedin.com/in/{}", "status"),
    ("About.me", "https://about.me/{}", "status"),
    # Comunicacion
    ("Telegram", "https://t.me/{}", "text:can you see this page"),
    # Musica / Media
    ("Spotify", "https://open.spotify.com/user/{}", "status"),
    ("SoundCloud", "https://soundcloud.com/{}", "status"),
    # Foros / Comunidades
    ("Medium", "https://medium.com/@{}", "status"),
    ("Keybase", "https://keybase.io/{}", "status"),
    # Fotografia
    ("Flickr", "https://www.flickr.com/people/{}/", "status"),
    ("VSCO", "https://vsco.co/{}/gallery", "status"),
    # Otros
    ("Gravatar", "https://en.gravatar.com/{}", "status"),
    ("Patreon", "https://www.patreon.com/{}", "status"),
    ("Cash App", "https://cash.app/${}", "status"),
    ("Replit", "https://replit.com/@{}", "status"),
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def _check_platform(platform_name: str, url: str, method: str) -> dict:
    """Verifica si un username existe en una plataforma."""
    result = {
        "platform": platform_name,
        "url": url,
        "found": False,
        "error": None,
    }
    try:
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        if method == "status":
            result["found"] = resp.status_code == 200
        elif method.startswith("text:"):
            search_text = method[5:]
            result["found"] = resp.status_code == 200 and search_text.lower() not in resp.text.lower()
        elif method == "redirect":
            result["found"] = not resp.is_redirect and resp.status_code == 200

    except requests.exceptions.Timeout:
        result["error"] = "timeout"
    except requests.exceptions.ConnectionError:
        result["error"] = "conexion fallida"
    except Exception as e:
        result["error"] = str(e)[:50]

    return result


class ProfileChecker:
    """Busca un username en multiples plataformas para detectar perfiles."""

    def check(self, username: str, max_workers: int = 10) -> dict:
        """Busca el username en todas las plataformas.

        Args:
            username: Nombre de usuario a buscar.
            max_workers: Hilos concurrentes para las consultas.

        Returns:
            Dict con perfiles encontrados, no encontrados, y errores.
        """
        results = {"found": [], "not_found": [], "errors": [], "username": username}

        tasks = []
        for name, url_template, method in PLATFORMS:
            url = url_template.format(username)
            tasks.append((name, url, method))

        with console.status(f"[bold blue]Buscando '{username}' en {len(tasks)} plataformas..."):
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(_check_platform, name, url, method): name
                    for name, url, method in tasks
                }
                for future in as_completed(futures):
                    result = future.result()
                    if result["error"]:
                        results["errors"].append(result)
                    elif result["found"]:
                        results["found"].append(result)
                    else:
                        results["not_found"].append(result)

        # Ordenar por nombre de plataforma
        results["found"].sort(key=lambda x: x["platform"])
        results["not_found"].sort(key=lambda x: x["platform"])

        return results

    def print_results(self, results: dict) -> None:
        """Imprime los resultados de la busqueda de perfiles."""
        username = results["username"]
        found = results["found"]
        errors = results["errors"]

        # Panel de resumen
        total = len(PLATFORMS)
        found_count = len(found)
        error_count = len(errors)

        if found_count == 0:
            risk_color = "green"
            risk_text = "No se encontraron perfiles con este username"
        elif found_count <= 3:
            risk_color = "yellow"
            risk_text = f"Se encontraron {found_count} perfiles - verificar si son tuyos"
        else:
            risk_color = "bright_red"
            risk_text = f"Se encontraron {found_count} perfiles - revisar con atencion"

        console.print(Panel(
            f"[bold]Username:[/bold] {username}\n"
            f"[bold]Plataformas verificadas:[/bold] {total}\n"
            f"[bold]Perfiles encontrados:[/bold] [{risk_color}]{found_count}[/{risk_color}]\n"
            f"[bold]Errores de conexion:[/bold] {error_count}\n\n"
            f"[{risk_color}]{risk_text}[/{risk_color}]",
            title="[bold]Busqueda de Perfiles[/bold]",
            border_style=risk_color,
            box=box.DOUBLE,
        ))

        if found:
            table = Table(
                title="Perfiles Encontrados",
                box=box.ROUNDED,
                show_lines=True,
            )
            table.add_column("Plataforma", style="bold", max_width=15)
            table.add_column("URL del Perfil", max_width=60)
            table.add_column("Tuyo?", justify="center", max_width=8)

            for profile in found:
                table.add_row(
                    profile["platform"],
                    profile["url"],
                    "[yellow]?[/yellow]",
                )

            console.print(table)

            console.print(Panel(
                "[bold]Revisa cada perfil encontrado:[/bold]\n\n"
                "1. Abre cada URL y verifica si el perfil es tuyo\n"
                "2. Si encuentras un perfil que NO es tuyo pero usa tu nombre/foto:\n"
                "   - Captura pantalla como evidencia\n"
                "   - Reportalo en la plataforma como suplantacion de identidad\n"
                "   - Guarda la URL y fecha para posible denuncia\n"
                "3. Si hay perfiles viejos tuyos que ya no usas:\n"
                "   - Considera eliminarlos para reducir tu superficie de exposicion",
                title="[bold]Que hacer con los resultados[/bold]",
                border_style="cyan",
            ))

        if errors:
            console.print(f"\n[yellow]Plataformas con error de conexion ({error_count}):[/yellow]")
            for err in errors:
                console.print(f"  [dim]- {err['platform']}: {err['error']}[/dim]")
