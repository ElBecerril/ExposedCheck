"""Tests de la TUI (Textual).

Los helpers de rendering son puros (sin runtime). La app se prueba con el
pilot headless de Textual (App.run_test), sin tocar la red.
"""

import asyncio
import io

from rich.console import Console, Group

from tui import (
    render_report, _risk_badge, ExposedCheckApp, FingerprintConfirmScreen,
)
from models import (
    CheckReport, PasswordResult, BreachDetail, ProfileReport, ProfileHit,
    ImageCheckReport, ImageSearchResult, EmailFinderResult, FoundEmail,
    FingerprintReport, InfostealerDetail,
)


def _to_text(renderable) -> str:
    buf = io.StringIO()
    Console(file=buf, width=100).print(renderable)
    return buf.getvalue()


# --- Rendering puro ------------------------------------------------------

def test_render_check_incluye_brecha_y_riesgo():
    r = CheckReport(query="x@y.com", query_type="email")
    r.breaches.append(BreachDetail(source_api="XON", breach_name="Adobe"))
    r.record_source("XposedOrNot")

    g = render_report("email", r)
    assert isinstance(g, Group)
    text = _to_text(g)
    assert "Adobe" in text
    assert "RIESGO MEDIO" in text


def test_render_check_sin_cobertura_no_concluyente():
    r = CheckReport(query="x@y.com", query_type="email")
    r.record_source("XposedOrNot", error="timeout")
    text = _to_text(render_report("email", r))
    assert "NO CONCLUYENTE" in text
    assert "sin datos" in text


def test_risk_badge_desconocido_advierte():
    assert "NO CONCLUYENTE" in _risk_badge("desconocido")


def test_render_password_comprometido():
    pw = PasswordResult(hibp_count=5, is_compromised=True)
    pw.record_source("HIBP")
    text = _to_text(render_report("password", pw))
    assert "COMPROMETIDO" in text


# --- Rendering puro: checks OSINT -----------------------------------------

def test_render_profiles_incluye_hallazgo_y_url():
    r = ProfileReport(username="fulano")
    r.found.append(ProfileHit(platform="GitHub", url="https://github.com/fulano", found=True))
    text = _to_text(render_report("profiles", r))
    assert "GitHub" in text
    assert "github.com/fulano" in text
    assert "1" in text


def test_render_profiles_marca_senal_debil():
    r = ProfileReport(username="fulano")
    r.found.append(ProfileHit(
        platform="Instagram", url="https://instagram.com/fulano", found=True, weak=True,
    ))
    text = _to_text(render_report("profiles", r))
    assert "señal débil" in text


def test_render_profiles_sin_hallazgos_es_limpio():
    r = ProfileReport(username="fulano")
    text = _to_text(render_report("profiles", r))
    assert "No se encontraron perfiles" in text


def test_render_image_muestra_urls_de_busqueda():
    r = ImageCheckReport()
    r.images.append(ImageSearchResult(
        source="https://ejemplo.com/foto.jpg",
        type="url",
        search_urls={"Yandex": "https://yandex.example/search", "Google": "https://google.example/lens"},
    ))
    text = _to_text(render_report("image", r))
    assert "yandex.example" in text


def test_render_image_con_error():
    r = ImageCheckReport(errors=["No se encontraron imagenes en: /tmp/nada"])
    text = _to_text(render_report("image", r))
    assert "No se encontraron imagenes" in text


def test_render_email_finder_incluye_email_y_confianza():
    r = EmailFinderResult(username="fulano")
    r.platforms_checked.append("GitHub")
    r.found_emails.append(FoundEmail(
        email="fulano@example.com", source="GitHub (perfil/commits)", confidence="ALTA",
    ))
    text = _to_text(render_report("email_finder", r))
    assert "fulano@example.com" in text
    assert "ALTA" in text


def test_render_email_finder_sin_hallazgos():
    r = EmailFinderResult(username="fulano")
    text = _to_text(render_report("email_finder", r))
    assert "No se encontraron emails" in text


def test_render_fingerprint_incluye_riesgo_y_brechas():
    r = FingerprintReport(email="x@y.com", domain="y.com", username_part="x")
    r.breaches.append(BreachDetail(source_api="XON", breach_name="Adobe"))
    text = _to_text(render_report("fingerprint", r))
    assert "Adobe" in text
    assert "MEDIO" in text


def test_render_fingerprint_infostealer_es_critico():
    r = FingerprintReport(email="x@y.com", domain="y.com", username_part="x")
    r.infostealers.append(InfostealerDetail(computer_name="PC-1"))
    text = _to_text(render_report("fingerprint", r))
    assert "CRITICO" in text
    assert "PC-1" in text


# --- App (pilot headless) ------------------------------------------------

def test_app_monta_y_toggle_password():
    async def go():
        from textual.widgets import Input, Select
        app = ExposedCheckApp()
        async with app.run_test() as pilot:
            assert app.query_one("#query", Input) is not None
            # Cambiar el tipo a password activa el modo oculto del input.
            app.query_one("#check-type", Select).value = "password"
            await pilot.pause()
            assert app.query_one("#query", Input).password is True

    asyncio.run(go())


def test_app_query_vacio_no_revienta():
    async def go():
        from textual.widgets import Button
        app = ExposedCheckApp()
        async with app.run_test() as pilot:
            # Pulsar "Verificar" sin valor: solo avisa, no lanza worker.
            await pilot.click("#run")
            await pilot.pause()
            assert app._last == {}

    asyncio.run(go())


# --- Etica: confirmacion del fingerprint ----------------------------------

def test_fingerprint_pide_confirmacion_antes_de_ejecutar(monkeypatch):
    """Elegir 'fingerprint' y pulsar Verificar debe abrir el modal de
    confirmacion en vez de lanzar el check directamente."""
    async def go():
        from textual.widgets import Select, Input

        called = {"ran": False}
        monkeypatch.setattr(
            ExposedCheckApp, "_start_check",
            lambda self, check_type, query: called.__setitem__("ran", True),
        )

        app = ExposedCheckApp()
        async with app.run_test() as pilot:
            app.query_one("#check-type", Select).value = "fingerprint"
            app.query_one("#query", Input).value = "x@y.com"
            await pilot.pause()
            await pilot.click("#run")
            await pilot.pause()

            # El modal de confirmacion debe estar en pantalla y el check
            # NO debe haberse lanzado todavia.
            assert isinstance(app.screen, FingerprintConfirmScreen)
            assert called["ran"] is False

    asyncio.run(go())


def test_fingerprint_cancelar_no_ejecuta_el_check(monkeypatch):
    """Si el usuario cancela el disclaimer, el fingerprint no debe correr."""
    async def go():
        from textual.widgets import Select, Input

        called = {"ran": False}
        monkeypatch.setattr(
            ExposedCheckApp, "_start_check",
            lambda self, check_type, query: called.__setitem__("ran", True),
        )

        app = ExposedCheckApp()
        async with app.run_test() as pilot:
            app.query_one("#check-type", Select).value = "fingerprint"
            app.query_one("#query", Input).value = "x@y.com"
            await pilot.pause()
            await pilot.click("#run")
            await pilot.pause()

            await pilot.click("#cancel")
            await pilot.pause()

            assert called["ran"] is False
            assert not isinstance(app.screen, FingerprintConfirmScreen)

    asyncio.run(go())


def test_fingerprint_confirmar_ejecuta_el_check(monkeypatch):
    """Si el usuario confirma el disclaimer, el fingerprint si debe correr."""
    async def go():
        from textual.widgets import Select, Input

        called = {}
        monkeypatch.setattr(
            ExposedCheckApp, "_start_check",
            lambda self, check_type, query: called.update(
                check_type=check_type, query=query,
            ),
        )

        app = ExposedCheckApp()
        async with app.run_test() as pilot:
            app.query_one("#check-type", Select).value = "fingerprint"
            app.query_one("#query", Input).value = "x@y.com"
            await pilot.pause()
            await pilot.click("#run")
            await pilot.pause()

            await pilot.click("#confirm")
            await pilot.pause()

            assert called == {"check_type": "fingerprint", "query": "x@y.com"}

    asyncio.run(go())
