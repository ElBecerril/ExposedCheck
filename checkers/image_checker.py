"""Busqueda inversa de imagenes en Yandex, Google y TinEye."""

import os
import webbrowser
import urllib.parse
from pathlib import Path

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from config import REQUEST_TIMEOUT

console = Console()

# Tiempo de vida del archivo temporal (1 hora)
LITTERBOX_URL = "https://litterbox.catbox.moe/resources/internals/api.php"
LITTERBOX_EXPIRY = "1h"

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}


def _upload_temp(file_path: str) -> str | None:
    """Sube una imagen a litterbox.catbox.moe (temporal, 1h).

    Retorna la URL publica o None si falla.
    """
    try:
        with open(file_path, "rb") as f:
            resp = requests.post(
                LITTERBOX_URL,
                data={"reqtype": "fileupload", "time": LITTERBOX_EXPIRY},
                files={"fileToUpload": (os.path.basename(file_path), f)},
                timeout=30,
            )
        if resp.status_code == 200 and resp.text.startswith("http"):
            return resp.text.strip()
    except Exception as e:
        console.print(f"  [yellow]Error subiendo {os.path.basename(file_path)}: {e}[/yellow]")
    return None


def _build_search_urls(image_url: str) -> dict[str, str]:
    """Genera URLs de busqueda inversa para cada motor."""
    encoded = urllib.parse.quote(image_url, safe="")
    return {
        "Yandex": f"https://yandex.com/images/search?rpt=imageview&url={encoded}",
        "Google": f"https://lens.google.com/uploadbyurl?url={encoded}",
        "TinEye": f"https://tineye.com/search?url={encoded}",
    }


def _get_images_from_path(path: str) -> list[str]:
    """Obtiene lista de imagenes desde un archivo o carpeta."""
    p = Path(path)
    if p.is_file() and p.suffix.lower() in IMAGE_EXTENSIONS:
        return [str(p)]
    if p.is_dir():
        images = []
        for ext in IMAGE_EXTENSIONS:
            images.extend(str(f) for f in p.glob(f"*{ext}"))
            images.extend(str(f) for f in p.glob(f"*{ext.upper()}"))
        return sorted(set(images))
    return []


class ImageChecker:
    """Busqueda inversa de imagenes para detectar uso no autorizado."""

    def check(self, path: str, auto_open: bool = True) -> dict:
        """Procesa imagenes y abre busquedas inversas.

        Args:
            path: Ruta a una imagen o carpeta con imagenes.
            auto_open: Si True, abre las URLs en el navegador automaticamente.

        Returns:
            Dict con resultados por imagen.
        """
        results = {"images": [], "errors": []}

        # Determinar si es URL o archivo/carpeta local
        if path.startswith("http://") or path.startswith("https://"):
            results["images"].append(self._process_url(path, auto_open))
            return results

        images = _get_images_from_path(path)
        if not images:
            results["errors"].append(f"No se encontraron imagenes en: {path}")
            return results

        console.print(f"\n[bold]Encontradas {len(images)} imagenes para verificar[/bold]\n")

        for img_path in images:
            result = self._process_local(img_path, auto_open)
            results["images"].append(result)

        return results

    def _process_url(self, url: str, auto_open: bool) -> dict:
        """Procesa una URL de imagen directamente."""
        search_urls = _build_search_urls(url)
        result = {
            "source": url,
            "type": "url",
            "search_urls": search_urls,
            "opened": False,
        }

        if auto_open:
            for engine, search_url in search_urls.items():
                webbrowser.open(search_url)
            result["opened"] = True

        return result

    def _process_local(self, file_path: str, auto_open: bool) -> dict:
        """Sube una imagen local temporalmente y genera busquedas."""
        filename = os.path.basename(file_path)
        result = {
            "source": file_path,
            "type": "local",
            "search_urls": {},
            "temp_url": None,
            "opened": False,
        }

        with console.status(f"[bold blue]Subiendo {filename} (temporal, expira en 1h)..."):
            temp_url = _upload_temp(file_path)

        if not temp_url:
            result["error"] = f"No se pudo subir {filename}"
            return result

        result["temp_url"] = temp_url
        search_urls = _build_search_urls(temp_url)
        result["search_urls"] = search_urls

        if auto_open:
            for engine, search_url in search_urls.items():
                webbrowser.open(search_url)
            result["opened"] = True

        return result

    def print_results(self, results: dict) -> None:
        """Imprime resumen de busquedas realizadas."""
        if results["errors"]:
            for err in results["errors"]:
                console.print(f"[red]{err}[/red]")
            return

        any_opened = any(img.get("opened") for img in results["images"])

        if any_opened:
            # Modo navegador: tabla resumida
            table = Table(
                title="Busqueda Inversa de Imagenes",
                box=box.ROUNDED,
                show_lines=True,
            )
            table.add_column("Imagen", style="bold", max_width=30)
            table.add_column("Estado", max_width=20)
            table.add_column("Motores", max_width=30)

            for img in results["images"]:
                source = os.path.basename(img["source"]) if img["type"] == "local" else img["source"][:50]
                if img.get("error"):
                    table.add_row(source, "[red]Error[/red]", img["error"])
                else:
                    engines = ", ".join(img["search_urls"].keys())
                    table.add_row(source, "[green]Abierto en navegador[/green]", engines)

            console.print(table)
        else:
            # Modo --no-open: imprimir URLs completas para copiar
            for img in results["images"]:
                source = os.path.basename(img["source"]) if img["type"] == "local" else img["source"]
                if img.get("error"):
                    console.print(f"[red]{source}: {img['error']}[/red]")
                    continue

                console.print(f"\n[bold]{source}[/bold]")
                for engine, url in img["search_urls"].items():
                    console.print(f"  {engine}: {url}")

        console.print()
        console.print(Panel(
            "[bold]Que buscar en los resultados:[/bold]\n\n"
            "- Perfiles en redes sociales que NO sean tuyos usando tu foto\n"
            "- Sitios de citas o contactos con tu imagen\n"
            "- Paginas web desconocidas usando tu foto\n\n"
            "[bold]Si encuentras un perfil falso:[/bold]\n"
            "- Reportalo directamente en la plataforma\n"
            "- Captura pantalla como evidencia (URL + contenido)\n"
            "- Denuncia ante la policia cibernetica si hay suplantacion",
            title="[bold]Guia de Verificacion[/bold]",
            border_style="cyan",
        ))
