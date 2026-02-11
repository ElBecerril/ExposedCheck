"""Clase base abstracta para proveedores de API."""

from abc import ABC, abstractmethod

import requests

from config import REQUEST_TIMEOUT, USER_AGENT


class BaseAPI(ABC):
    """Clase base para todos los proveedores de API."""

    name: str = "BaseAPI"

    def _get(self, url: str, params: dict | None = None, headers: dict | None = None) -> requests.Response:
        """Realiza una peticion GET con configuracion comun."""
        default_headers = {"User-Agent": USER_AGENT}
        if headers:
            default_headers.update(headers)
        return requests.get(
            url,
            params=params,
            headers=default_headers,
            timeout=REQUEST_TIMEOUT,
        )

    @abstractmethod
    def check(self, query: str) -> dict:
        """Ejecuta la verificacion. Debe retornar un dict con resultados."""
