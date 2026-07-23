"""Tests de parsing de respuestas de API para LeakCheck, Hudson Rock y
BreachDirectory.

Se mockea la peticion HTTP (``_get`` para los proveedores que heredan de
``BaseAPI``; ``requests.get`` para ``BreachDirectoryAPI``, que no hereda de
``BaseAPI``) para no tocar la red. El foco es distinguir "sin resultados"
(``error`` es ``None``, listas vacias) de "fallo real" (``error`` con
mensaje), y verificar que ningun payload realista haga reventar el parser
con una excepcion no controlada.
"""

import pytest

from apis.leakcheck import LeakCheckAPI
from apis.hudsonrock import HudsonRockAPI
from checkers.base_phone import BreachDirectoryAPI


class FakeResp:
    def __init__(self, status_code=200, json_data=None, json_exc=None):
        self.status_code = status_code
        self._json = json_data
        self._json_exc = json_exc

    def json(self):
        if self._json_exc is not None:
            raise self._json_exc
        return self._json


def _patch_get(monkeypatch, api, resp_or_exc):
    """Mockea api._get (proveedores BaseAPI)."""
    def fake_get(*args, **kwargs):
        if isinstance(resp_or_exc, Exception):
            raise resp_or_exc
        return resp_or_exc
    monkeypatch.setattr(api, "_get", fake_get)


def _patch_requests_get(monkeypatch, resp_or_exc):
    """Mockea requests.get tal como lo usa checkers.base_phone."""
    import checkers.base_phone as base_phone_module

    def fake_get(*args, **kwargs):
        if isinstance(resp_or_exc, Exception):
            raise resp_or_exc
        return resp_or_exc
    monkeypatch.setattr(base_phone_module.requests, "get", fake_get)


# ===========================================================================
# LeakCheck (apis/leakcheck.py)
# ===========================================================================

def test_leakcheck_respuesta_feliz_parsea_breaches(monkeypatch):
    api = LeakCheckAPI()
    payload = {
        "success": True,
        "result": [
            {
                "name": "Adobe",
                "date": "2013-10-04",
                "fields": ["email", "password", "username"],
            },
            {
                # Algunos registros vienen sin "name", con "source" en su lugar
                "source": "LinkedIn",
                "date": "2012-05-05",
                "fields": ["email"],
            },
        ],
    }
    _patch_get(monkeypatch, api, FakeResp(200, json_data=payload))

    result = api.check("test@example.com")

    assert result["error"] is None
    assert len(result["breaches"]) == 2
    b0, b1 = result["breaches"]
    assert b0.source_api == "LeakCheck"
    assert b0.breach_name == "Adobe"
    assert b0.date == "2013-10-04"
    assert b0.exposed_data == ["email", "password", "username"]
    assert b0.risk_level == "medio"
    assert b1.breach_name == "LinkedIn"  # fallback a "source"


def test_leakcheck_query_solo_envia_check_param(monkeypatch):
    """El endpoint publico autodetecta email vs username: solo se manda
    check=<query>, sin distinguir query_type en los params de la request."""
    api = LeakCheckAPI()
    captured = {}

    def fake_get(url, params=None, headers=None):
        captured["url"] = url
        captured["params"] = params
        return FakeResp(200, json_data={"success": True, "result": []})

    monkeypatch.setattr(api, "_get", fake_get)

    api.check("someuser", query_type="username")

    assert captured["params"] == {"check": "someuser"}
    assert "check" in captured["params"]
    assert len(captured["params"]) == 1


def test_leakcheck_404_es_sin_resultados_sin_error(monkeypatch):
    api = LeakCheckAPI()
    _patch_get(monkeypatch, api, FakeResp(404))

    result = api.check("noexiste@example.com")

    assert result["error"] is None
    assert result["breaches"] == []


def test_leakcheck_success_false_not_found_es_sin_resultados(monkeypatch):
    """success=False con mensaje "Not found" en el campo "error" (NO "msg")
    debe tratarse como sin resultados, no como fallo."""
    api = LeakCheckAPI()
    payload = {"success": False, "error": "Not found"}
    _patch_get(monkeypatch, api, FakeResp(200, json_data=payload))

    result = api.check("test@example.com")

    assert result["error"] is None
    assert result["breaches"] == []


def test_leakcheck_success_false_con_mensaje_de_error_real(monkeypatch):
    """success=False con un mensaje de error real (rate limit) viene en el
    campo "error" de la respuesta, no en "msg"."""
    api = LeakCheckAPI()
    payload = {"success": False, "error": "Rate limit exceeded, retry later"}
    _patch_get(monkeypatch, api, FakeResp(200, json_data=payload))

    result = api.check("test@example.com")

    assert result["error"] == "LeakCheck: Rate limit exceeded, retry later"
    assert result["breaches"] == []


def test_leakcheck_success_false_usa_error_no_msg(monkeypatch):
    """Si el payload trae "msg" (formato de otras APIs) pero no "error", el
    codigo de LeakCheck NO debe leerlo como si fuera "error" salvo que sea el
    fallback. Verificamos que "error" tiene prioridad sobre "msg"."""
    api = LeakCheckAPI()
    payload = {"success": False, "error": "quota exceeded", "msg": "otro texto que no deberia usarse"}
    _patch_get(monkeypatch, api, FakeResp(200, json_data=payload))

    result = api.check("test@example.com")

    assert result["error"] == "LeakCheck: quota exceeded"


def test_leakcheck_429_rate_limit(monkeypatch):
    api = LeakCheckAPI()
    _patch_get(monkeypatch, api, FakeResp(429))

    result = api.check("test@example.com")

    assert result["error"] is not None
    assert "Limite" in result["error"]
    assert result["breaches"] == []


def test_leakcheck_http_error_generico(monkeypatch):
    api = LeakCheckAPI()
    _patch_get(monkeypatch, api, FakeResp(500))

    result = api.check("test@example.com")

    assert result["error"] == "LeakCheck: HTTP 500"


def test_leakcheck_json_malformado_no_revienta(monkeypatch):
    api = LeakCheckAPI()
    _patch_get(monkeypatch, api, FakeResp(200, json_exc=ValueError("Expecting value")))

    result = api.check("test@example.com")

    assert result["error"] is not None
    assert "LeakCheck" in result["error"]
    assert result["breaches"] == []


def test_leakcheck_excepcion_de_red_no_revienta(monkeypatch):
    api = LeakCheckAPI()
    _patch_get(monkeypatch, api, ConnectionError("boom"))

    result = api.check("test@example.com")

    assert result["error"] == "LeakCheck: boom"
    assert result["breaches"] == []


def test_leakcheck_success_false_sin_mensaje_no_deberia_ser_silencioso(monkeypatch):
    api = LeakCheckAPI()
    payload = {"success": False}
    _patch_get(monkeypatch, api, FakeResp(200, json_data=payload))

    result = api.check("test@example.com")

    # Comportamiento deseado: un success=False sin mensaje deberia marcarse
    # como error (fuente no confiable), no como "sin brechas".
    assert result["error"] is not None


# ===========================================================================
# Hudson Rock (apis/hudsonrock.py)
# ===========================================================================

def test_hudsonrock_respuesta_feliz_parsea_infostealers(monkeypatch):
    api = HudsonRockAPI()
    payload = {
        "stealers": [
            {
                "computer_name": "DESKTOP-ABC123",
                "operating_system": "Windows 10",
                "malware_path": "C:\\Users\\test\\AppData\\malware.exe",
                "date_compromised": "2023-01-15",
                "antiviruses": "Windows Defender",
            }
        ]
    }
    _patch_get(monkeypatch, api, FakeResp(200, json_data=payload))

    result = api.check("test@example.com", query_type="email")

    assert result["error"] is None
    assert len(result["infostealers"]) == 1
    info = result["infostealers"][0]
    assert info.computer_name == "DESKTOP-ABC123"
    assert info.operating_system == "Windows 10"
    assert info.malware_path == "C:\\Users\\test\\AppData\\malware.exe"
    assert info.date_compromised == "2023-01-15"
    assert info.antiviruses == "Windows Defender"


def test_hudsonrock_username_usa_endpoint_y_param_correcto(monkeypatch):
    api = HudsonRockAPI()
    captured = {}

    def fake_get(url, params=None, headers=None):
        captured["url"] = url
        captured["params"] = params
        return FakeResp(200, json_data={"stealers": []})

    monkeypatch.setattr(api, "_get", fake_get)

    api.check("someuser", query_type="username")

    assert captured["params"] == {"username": "someuser"}
    assert "search-by-username" in captured["url"]


def test_hudsonrock_sin_stealers_es_sin_resultados_sin_error(monkeypatch):
    api = HudsonRockAPI()
    _patch_get(monkeypatch, api, FakeResp(200, json_data={"stealers": []}))

    result = api.check("test@example.com")

    assert result["error"] is None
    assert result["infostealers"] == []


def test_hudsonrock_404_es_sin_resultados_sin_error(monkeypatch):
    api = HudsonRockAPI()
    _patch_get(monkeypatch, api, FakeResp(404))

    result = api.check("test@example.com")

    assert result["error"] is None
    assert result["infostealers"] == []


def test_hudsonrock_429_rate_limit(monkeypatch):
    api = HudsonRockAPI()
    _patch_get(monkeypatch, api, FakeResp(429))

    result = api.check("test@example.com")

    assert result["error"] is not None
    assert "Limite" in result["error"]


def test_hudsonrock_http_error_generico(monkeypatch):
    api = HudsonRockAPI()
    _patch_get(monkeypatch, api, FakeResp(500))

    result = api.check("test@example.com")

    assert result["error"] == "Hudson Rock: HTTP 500"


def test_hudsonrock_json_malformado_no_revienta(monkeypatch):
    api = HudsonRockAPI()
    _patch_get(monkeypatch, api, FakeResp(200, json_exc=ValueError("Expecting value")))

    result = api.check("test@example.com")

    assert result["error"] is not None
    assert "Hudson Rock" in result["error"]
    assert result["infostealers"] == []


def test_hudsonrock_campo_faltante_usa_defaults(monkeypatch):
    """Un stealer con campos faltantes no deberia reventar; se usan los
    valores por defecto de InfostealerDetail via .get(..., default)."""
    api = HudsonRockAPI()
    payload = {"stealers": [{"computer_name": "PC-1"}]}
    _patch_get(monkeypatch, api, FakeResp(200, json_data=payload))

    result = api.check("test@example.com")

    assert result["error"] is None
    info = result["infostealers"][0]
    assert info.computer_name == "PC-1"
    assert info.operating_system == ""
    assert info.date_compromised == "Desconocida"


def test_hudsonrock_respuesta_top_level_lista_deberia_parsear(monkeypatch):
    api = HudsonRockAPI()
    payload = [
        {
            "computer_name": "PC-1",
            "operating_system": "Windows 10",
            "malware_path": "x",
            "date_compromised": "2023-01-01",
            "antiviruses": "none",
        }
    ]
    _patch_get(monkeypatch, api, FakeResp(200, json_data=payload))

    result = api.check("test@example.com")

    # Comportamiento deseado: deberia parsear el stealer de la lista top-level
    # sin error y sin excepcion.
    assert result["error"] is None
    assert len(result["infostealers"]) == 1
    assert result["infostealers"][0].computer_name == "PC-1"


# ===========================================================================
# BreachDirectory (checkers/base_phone.py -- BreachDirectoryAPI)
# ===========================================================================

def test_breachdirectory_respuesta_feliz_parsea_breaches(monkeypatch):
    payload = {
        "success": True,
        "result": [
            {
                "sources": [
                    {"name": "SomeLeak", "date": "2020-01-01"},
                    {"name": "OtherLeak", "date": "2021-06-06"},
                ]
            }
        ],
    }
    _patch_requests_get(monkeypatch, FakeResp(200, json_data=payload))

    api = BreachDirectoryAPI()
    result = api.check("+5215512345678")

    assert result["error"] is None
    assert len(result["breaches"]) == 2
    b0, b1 = result["breaches"]
    assert b0.source_api == "BreachDirectory"
    assert b0.breach_name == "SomeLeak"
    assert b0.date == "2020-01-01"
    assert b0.exposed_data == ["telefono"]
    assert b0.risk_level == "alto"
    assert b1.breach_name == "OtherLeak"


def test_breachdirectory_sin_resultados_es_sin_error(monkeypatch):
    payload = {"success": True, "result": []}
    _patch_requests_get(monkeypatch, FakeResp(200, json_data=payload))

    api = BreachDirectoryAPI()
    result = api.check("+5215512345678")

    assert result["error"] is None
    assert result["breaches"] == []


def test_breachdirectory_success_false_es_sin_error_sin_breaches(monkeypatch):
    """success=False (p.ej. termino no encontrado) no debe generar error,
    solo lista vacia -- BreachDirectory no distingue este caso via mensaje."""
    payload = {"success": False}
    _patch_requests_get(monkeypatch, FakeResp(200, json_data=payload))

    api = BreachDirectoryAPI()
    result = api.check("+5215512345678")

    assert result["error"] is None
    assert result["breaches"] == []


def test_breachdirectory_429_limite_mensual(monkeypatch):
    _patch_requests_get(monkeypatch, FakeResp(429))

    api = BreachDirectoryAPI()
    result = api.check("+5215512345678")

    assert result["error"] is not None
    assert "Limite mensual" in result["error"]
    assert result["breaches"] == []


def test_breachdirectory_401_no_autorizado(monkeypatch):
    _patch_requests_get(monkeypatch, FakeResp(401))

    api = BreachDirectoryAPI()
    result = api.check("+5215512345678")

    assert result["error"] == "BreachDirectory: HTTP 401"
    assert result["breaches"] == []


def test_breachdirectory_404(monkeypatch):
    """A diferencia de LeakCheck/HudsonRock, base_phone.py no tiene un caso
    especial para 404: cae en el branch generico "else" y se reporta como
    error HTTP en vez de "sin resultados"."""
    _patch_requests_get(monkeypatch, FakeResp(404))

    api = BreachDirectoryAPI()
    result = api.check("+5215512345678")

    assert result["error"] == "BreachDirectory: HTTP 404"


def test_breachdirectory_json_malformado_no_revienta(monkeypatch):
    _patch_requests_get(monkeypatch, FakeResp(200, json_exc=ValueError("Expecting value")))

    api = BreachDirectoryAPI()
    result = api.check("+5215512345678")

    assert result["error"] is not None
    assert "BreachDirectory" in result["error"]
    assert result["breaches"] == []


def test_breachdirectory_excepcion_de_red_no_revienta(monkeypatch):
    _patch_requests_get(monkeypatch, ConnectionError("boom"))

    api = BreachDirectoryAPI()
    result = api.check("+5215512345678")

    assert result["error"] == "BreachDirectory: boom"
    assert result["breaches"] == []


def test_breachdirectory_result_como_dict_en_vez_de_lista(monkeypatch):
    payload = {
        "success": True,
        "result": {"sources": [{"name": "SomeLeak", "date": "2020-01-01"}]},
    }
    _patch_requests_get(monkeypatch, FakeResp(200, json_data=payload))

    api = BreachDirectoryAPI()
    result = api.check("+5215512345678")

    # Comportamiento deseado: deberia parsear igual, o al menos no perder
    # silenciosamente el breach real.
    assert result["error"] is None
    assert len(result["breaches"]) == 1
