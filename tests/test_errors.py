"""Tests de la clasificacion de errores de proveedores (apis/errors.py).

Lo importante: un bug del parser NO debe presentarse igual que un timeout.
"""

import json

import pytest
import requests

from apis.errors import classify_exception, describe_exception


# --- Clasificacion --------------------------------------------------------

@pytest.mark.parametrize("exc", [
    requests.exceptions.Timeout("timed out"),
    requests.exceptions.ConnectionError("dns"),
    requests.exceptions.RequestException("generico"),
    ConnectionError("Connection refused"),   # builtin (OSError)
    OSError("network unreachable"),
])
def test_fallos_de_red_se_clasifican_como_red(exc):
    assert classify_exception(exc) == "red"


@pytest.mark.parametrize("exc", [
    ValueError("Expecting value"),
    json.JSONDecodeError("Expecting value", "", 0),
])
def test_json_invalido_se_clasifica_como_parseo(exc):
    assert classify_exception(exc) == "parseo"


def test_json_decode_error_de_requests_es_parseo_no_red():
    """requests.exceptions.JSONDecodeError hereda de RequestException Y de
    ValueError; debe ganar el parseo, no la red."""
    exc = requests.exceptions.JSONDecodeError("Expecting value", "", 0)
    assert classify_exception(exc) == "parseo"


@pytest.mark.parametrize("exc", [
    AttributeError("'list' object has no attribute 'get'"),
    KeyError("result"),
    TypeError("string indices must be integers"),
    IndexError("list index out of range"),
])
def test_errores_de_programacion_se_clasifican_como_bug(exc):
    assert classify_exception(exc) == "bug"


# --- Mensajes -------------------------------------------------------------

def test_mensaje_de_red_conserva_el_texto_original():
    msg = describe_exception("LeakCheck", ConnectionError("boom"))
    assert msg == "LeakCheck: boom"


def test_mensaje_de_parseo_dice_que_no_es_json():
    msg = describe_exception("Hudson Rock", ValueError("Expecting value"))
    assert "Hudson Rock" in msg
    assert "JSON" in msg


def test_mensaje_de_bug_se_identifica_como_interno(monkeypatch):
    monkeypatch.delenv("EXPOSEDCHECK_STRICT", raising=False)
    msg = describe_exception("XposedOrNot", AttributeError("no attribute 'get'"))
    assert "error interno" in msg
    assert "AttributeError" in msg


def test_bug_se_registra_en_el_logger(caplog, monkeypatch):
    """El traceback debe quedar logueado: si no, el bug pasa desapercibido."""
    monkeypatch.delenv("EXPOSEDCHECK_STRICT", raising=False)
    with caplog.at_level("ERROR", logger="exposedcheck"):
        describe_exception("GitHub", AttributeError("boom"))
    assert any("GitHub" in r.message for r in caplog.records)
    assert any(r.exc_info for r in caplog.records)


# --- Modo estricto --------------------------------------------------------

def test_strict_relanza_los_bugs(monkeypatch):
    monkeypatch.setenv("EXPOSEDCHECK_STRICT", "1")
    with pytest.raises(AttributeError):
        describe_exception("LeakCheck", AttributeError("boom"))


def test_strict_no_afecta_a_los_fallos_de_red(monkeypatch):
    """Un timeout no es un bug: en estricto se sigue reportando, no revienta."""
    monkeypatch.setenv("EXPOSEDCHECK_STRICT", "1")
    assert describe_exception("LeakCheck", ConnectionError("boom")) == "LeakCheck: boom"


@pytest.mark.parametrize("valor", ["", "0", "false", "no"])
def test_strict_desactivado_no_relanza(monkeypatch, valor):
    monkeypatch.setenv("EXPOSEDCHECK_STRICT", valor)
    msg = describe_exception("LeakCheck", AttributeError("boom"))
    assert "error interno" in msg
