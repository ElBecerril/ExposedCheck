"""Tests de la TUI (Textual).

Los helpers de rendering son puros (sin runtime). La app se prueba con el
pilot headless de Textual (App.run_test), sin tocar la red.
"""

import asyncio
import io

from rich.console import Console, Group

from tui import render_report, _risk_badge, ExposedCheckApp
from models import CheckReport, PasswordResult, BreachDetail


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
