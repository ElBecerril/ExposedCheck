"""Utilidades para consultar providers de brechas en paralelo."""

from typing import Callable

from apis.errors import describe_exception


def run_provider(fn: Callable, *args, **kwargs) -> dict:
    """Ejecuta la llamada a un provider que devuelve dict, blindando el hilo.

    Los providers ya capturan sus errores y los devuelven en la clave
    `error`, pero si algo inesperado escapa (bug, excepcion no prevista) no
    debe tumbar al resto de las consultas en paralelo ni verse como "sin
    resultados". Se convierte en un dict con `error` para que el checker lo
    registre como fuente caida.
    """
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        owner = getattr(fn, "__self__", None)
        label = getattr(owner, "name", None) or type(owner).__name__ if owner is not None else "provider"
        return {"error": describe_exception(label, e)}
