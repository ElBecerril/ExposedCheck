"""Clasificacion de errores de proveedores.

El patron `except Exception as e: result["error"] = f"{proveedor}: {e}"` es
resistente (una fuente caida no tumba la consulta) pero esconde bugs: un
`AttributeError` del parser acababa presentado igual que un timeout, asi que
un fallo de programacion se leia como "la API no respondio".

Aqui se separan los tres casos:

- **red**: la peticion no llego o no volvio (timeout, DNS, conexion). Es lo
  esperable y se reporta tal cual, sin ruido.
- **parseo**: la respuesta llego pero no es JSON valido. Culpa del proveedor.
- **bug**: cualquier otra cosa (AttributeError, KeyError, TypeError...) es un
  fallo NUESTRO procesando la respuesta. Se marca como tal y se registra el
  traceback en el logger `exposedcheck`, para que no pase desapercibido.

Con `EXPOSEDCHECK_STRICT=1` los bugs se relanzan en vez de convertirse en
texto, para que salten en tests y en desarrollo.
"""

import logging
import os

import requests

logger = logging.getLogger("exposedcheck")


def _strict_mode() -> bool:
    """Lee la env var en cada llamada para que los tests puedan alternarla."""
    return os.getenv("EXPOSEDCHECK_STRICT", "").lower() not in ("", "0", "false", "no")


def classify_exception(exc: Exception) -> str:
    """Devuelve 'red', 'parseo' o 'bug' segun el tipo de excepcion."""
    # JSONDecodeError hereda de ValueError (y en requests tambien de
    # RequestException), asi que se comprueba antes que la red.
    if isinstance(exc, ValueError):
        return "parseo"
    if isinstance(exc, (requests.RequestException, OSError)):
        return "red"
    return "bug"


def describe_exception(provider: str, exc: Exception) -> str:
    """Traduce una excepcion al mensaje que va en la clave `error`.

    Relanza si es un bug y `EXPOSEDCHECK_STRICT` esta activo.
    """
    kind = classify_exception(exc)

    if kind == "red":
        # Mensaje historico: para fallos de red el texto de la excepcion ya
        # es informativo ("Connection refused", "timed out"...).
        return f"{provider}: {exc}"

    if kind == "parseo":
        logger.warning("%s: respuesta ilegible (%s)", provider, exc)
        return f"{provider}: respuesta ilegible, no es JSON valido"

    logger.exception("Bug procesando la respuesta de %s", provider)
    if _strict_mode():
        raise exc
    return (
        f"{provider}: error interno procesando la respuesta "
        f"({type(exc).__name__}: {exc})"
    )
