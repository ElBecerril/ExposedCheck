"""Tests de parsing de los password providers (HIBP, XposedOrNot).

Se mockea `_get` para no tocar la red. El foco es que cada codigo de
respuesta se traduzca al estado de cobertura correcto: en particular que un
fallo de red NO se confunda con "password no encontrado".
"""

import hashlib

from apis.hibp import HIBPPasswordsAPI
from apis.xposedornot import XposedOrNotAPI


class FakeResp:
    def __init__(self, status_code=200, text="", json_data=None):
        self.status_code = status_code
        self.text = text
        self._json = json_data

    def json(self):
        return self._json


def _patch_get(monkeypatch, api, resp_or_exc):
    def fake_get(url):
        if isinstance(resp_or_exc, Exception):
            raise resp_or_exc
        return resp_or_exc
    monkeypatch.setattr(api, "_get", fake_get)


# --- HIBP ----------------------------------------------------------------

def test_hibp_match_marca_comprometido(monkeypatch):
    api = HIBPPasswordsAPI()
    pw = "password123"
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    suffix = sha1[5:]
    _patch_get(monkeypatch, api, FakeResp(200, text=f"{suffix}:42\r\nABCDE:1"))

    result = api.check_password(pw)

    assert result.is_compromised is True
    assert result.hibp_count == 42
    assert result.sources_ok == ["HIBP"]
    assert result.sources_failed == []


def test_hibp_sin_match_es_ok_no_comprometido(monkeypatch):
    api = HIBPPasswordsAPI()
    _patch_get(monkeypatch, api, FakeResp(200, text="0000000000000000000000000000000000A:5"))

    result = api.check_password("otro-password")

    assert result.is_compromised is False
    assert result.hibp_count == 0
    assert result.sources_ok == ["HIBP"]


def test_hibp_http_error_cuenta_como_fuente_caida(monkeypatch):
    api = HIBPPasswordsAPI()
    _patch_get(monkeypatch, api, FakeResp(503, text=""))

    result = api.check_password("x")

    assert result.has_coverage is False
    assert result.sources_failed == ["HIBP"]
    assert result.is_compromised is False


def test_hibp_excepcion_de_red_cuenta_como_fuente_caida(monkeypatch):
    api = HIBPPasswordsAPI()
    _patch_get(monkeypatch, api, ConnectionError("boom"))

    result = api.check_password("x")

    assert result.has_coverage is False
    assert result.sources_failed == ["HIBP"]


# --- XposedOrNot ---------------------------------------------------------

def test_xon_404_es_respuesta_valida_sin_match(monkeypatch):
    api = XposedOrNotAPI()
    _patch_get(monkeypatch, api, FakeResp(404))

    result = api.check_password("x")

    assert result.is_compromised is False
    assert result.sources_ok == ["XposedOrNot"]
    assert result.sources_failed == []


def test_xon_http_error_no_404_es_fuente_caida(monkeypatch):
    api = XposedOrNotAPI()
    _patch_get(monkeypatch, api, FakeResp(500))

    result = api.check_password("x")

    assert result.has_coverage is False
    assert result.sources_failed == ["XposedOrNot"]


def test_xon_match_marca_comprometido(monkeypatch):
    api = XposedOrNotAPI()
    pw = "password123"
    sha3 = hashlib.sha3_512(pw.encode()).hexdigest().upper()
    _patch_get(monkeypatch, api, FakeResp(200, json_data=[sha3]))

    result = api.check_password(pw)

    assert result.is_compromised is True
    assert result.xon_count == 1
    assert result.sources_ok == ["XposedOrNot"]


def test_xon_excepcion_de_red_cuenta_como_fuente_caida(monkeypatch):
    api = XposedOrNotAPI()
    _patch_get(monkeypatch, api, TimeoutError("boom"))

    result = api.check_password("x")

    assert result.has_coverage is False
    assert result.sources_failed == ["XposedOrNot"]
