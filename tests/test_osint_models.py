"""Tests de los checkers OSINT refactorizados a dataclasses.

El objetivo del refactor es separar datos de presentacion: cada checker
devuelve una dataclass (no un dict suelto), lo que habilita export JSON via
dataclasses.asdict() y hace testeable el ensamblado sin tocar la impresion.
"""

from dataclasses import asdict

from models import (
    ImageCheckReport, ImageSearchResult,
    ProfileHit, ProfileReport,
)
from checkers.image_checker import ImageChecker
from checkers.profile_checker import ProfileChecker, _check_platform


# --- ImageChecker --------------------------------------------------------

def test_image_url_devuelve_report(monkeypatch):
    checker = ImageChecker()
    # No abrir navegador durante el test.
    monkeypatch.setattr("checkers.image_checker.webbrowser.open", lambda u: None)

    report = checker.check("https://ejemplo.com/foto.jpg", auto_open=True)

    assert isinstance(report, ImageCheckReport)
    assert len(report.images) == 1
    img = report.images[0]
    assert isinstance(img, ImageSearchResult)
    assert img.type == "url"
    assert img.opened is True
    assert set(img.search_urls.keys()) == {"Yandex", "Google", "TinEye"}


def test_image_ruta_inexistente_reporta_error():
    checker = ImageChecker()
    report = checker.check("/ruta/que/no/existe", auto_open=False)
    assert report.images == []
    assert any("No se encontraron imagenes" in e for e in report.errors)


def test_image_report_es_serializable(monkeypatch):
    checker = ImageChecker()
    monkeypatch.setattr("checkers.image_checker.webbrowser.open", lambda u: None)
    report = checker.check("https://ejemplo.com/foto.jpg", auto_open=False)

    # El desbloqueo del refactor: asdict() produce un dict JSON-serializable.
    d = asdict(report)
    assert d["images"][0]["source"] == "https://ejemplo.com/foto.jpg"
    assert d["images"][0]["type"] == "url"


# --- ProfileChecker ------------------------------------------------------

class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


def test_check_platform_status_encontrado(monkeypatch):
    monkeypatch.setattr(
        "checkers.profile_checker.requests.get",
        lambda *a, **k: _Resp(200),
    )
    hit = _check_platform("GitHub", "https://github.com/user", "status")
    assert isinstance(hit, ProfileHit)
    assert hit.found is True
    assert hit.error is None


def test_check_platform_error_de_red(monkeypatch):
    import requests

    def boom(*a, **k):
        raise requests.exceptions.Timeout()

    monkeypatch.setattr("checkers.profile_checker.requests.get", boom)
    hit = _check_platform("GitHub", "https://github.com/user", "status")
    assert hit.found is False
    assert hit.error == "timeout"


def test_profile_check_clasifica_hits(monkeypatch):
    import requests

    # GitHub responde 200 (found); el resto revienta con ConnectionError.
    def fake_get(url, **k):
        if "github" in url:
            return _Resp(200)
        raise requests.exceptions.ConnectionError()

    monkeypatch.setattr("checkers.profile_checker.requests.get", fake_get)

    report = ProfileChecker().check("tester", max_workers=4)

    assert isinstance(report, ProfileReport)
    assert any(h.platform == "GitHub" for h in report.found)
    assert all(h.error for h in report.errors)
    # asdict serializa el reporte completo (desbloqueo para export JSON).
    assert asdict(report)["username"] == "tester"
