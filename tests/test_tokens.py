"""Tests de soporte de tokens/API keys opcionales (GITHUB_TOKEN, HIBP_API_KEY).

Se mockea `_get` para no tocar la red (igual que test_providers.py). El foco
es verificar: (1) con token/key se manda la cabecera correcta, (2) sin
token/key no se manda ninguna cabecera de autenticacion, y (3) los codigos
401/403/429 se traducen a un `error` legible.
"""

import apis.github_osint as github_osint
import apis.hibp as hibp
from apis.github_osint import GitHubOsintAPI
from apis.hibp import HIBPPasswordsAPI


class FakeResp:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.text = text

    def json(self):
        return self._json


def _capture_get(monkeypatch, api, resp_by_url=None, default_resp=None):
    """Reemplaza `_get` y devuelve una lista donde se registra cada llamada
    (url, params, headers) para poder inspeccionarla despues.
    """
    calls = []

    def fake_get(url, params=None, headers=None):
        calls.append({"url": url, "params": params, "headers": headers or {}})
        if resp_by_url and url in resp_by_url:
            return resp_by_url[url]
        if default_resp is not None:
            return default_resp
        # Los endpoints de coleccion devuelven listas en la API real: usar
        # un dict aquí escondia KeyError/AttributeError en el parser.
        if url.endswith(("/repos", "/events/public")) or "/commits" in url:
            return FakeResp(200, json_data=[])
        return FakeResp(200, json_data={})

    monkeypatch.setattr(api, "_get", fake_get)
    return calls


# --- GitHub ----------------------------------------------------------------


def test_github_con_token_manda_authorization_bearer(monkeypatch):
    monkeypatch.setattr(github_osint, "GITHUB_TOKEN", "gh_faketoken123")
    api = GitHubOsintAPI()
    calls = _capture_get(monkeypatch, api)

    api.check("alguien")

    assert len(calls) >= 1
    for call in calls:
        assert call["headers"].get("Authorization") == "Bearer gh_faketoken123"


def test_github_sin_token_no_manda_authorization(monkeypatch):
    monkeypatch.setattr(github_osint, "GITHUB_TOKEN", "")
    api = GitHubOsintAPI()
    calls = _capture_get(monkeypatch, api)

    api.check("alguien")

    assert len(calls) >= 1
    for call in calls:
        assert "Authorization" not in call["headers"]


def test_github_401_token_invalido_es_error_legible(monkeypatch):
    monkeypatch.setattr(github_osint, "GITHUB_TOKEN", "gh_badtoken")
    api = GitHubOsintAPI()
    _capture_get(monkeypatch, api, default_resp=FakeResp(401))

    result = api.check("alguien")

    assert result["error"] is not None
    assert "GITHUB_TOKEN" in result["error"] or "invalido" in result["error"]


def test_github_403_sin_token_menciona_rate_limit_sin_key(monkeypatch):
    monkeypatch.setattr(github_osint, "GITHUB_TOKEN", "")
    api = GitHubOsintAPI()
    _capture_get(monkeypatch, api, default_resp=FakeResp(403))

    result = api.check("alguien")

    assert result["error"] is not None
    assert "sin API key" in result["error"]


def test_github_403_con_token_menciona_rate_limit_pese_a_key(monkeypatch):
    monkeypatch.setattr(github_osint, "GITHUB_TOKEN", "gh_faketoken123")
    api = GitHubOsintAPI()
    _capture_get(monkeypatch, api, default_resp=FakeResp(403))

    result = api.check("alguien")

    assert result["error"] is not None
    assert "pese a usar API key" in result["error"]


# --- HIBP breachedaccount ----------------------------------------------------


def test_hibp_con_key_manda_cabecera_hibp_api_key(monkeypatch):
    monkeypatch.setattr(hibp, "HIBP_API_KEY", "hibp_fakekey")
    api = HIBPPasswordsAPI()
    calls = _capture_get(monkeypatch, api, default_resp=FakeResp(200, json_data=[]))

    api.check_email("victima@example.com")

    assert len(calls) == 1
    assert calls[0]["headers"].get("hibp-api-key") == "hibp_fakekey"


def test_hibp_sin_key_no_manda_cabecera(monkeypatch):
    monkeypatch.setattr(hibp, "HIBP_API_KEY", "")
    api = HIBPPasswordsAPI()
    calls = _capture_get(monkeypatch, api, default_resp=FakeResp(401))

    api.check_email("victima@example.com")

    assert len(calls) == 1
    assert "hibp-api-key" not in calls[0]["headers"]


def test_hibp_401_sin_key_pide_configurar_key(monkeypatch):
    monkeypatch.setattr(hibp, "HIBP_API_KEY", "")
    api = HIBPPasswordsAPI()
    _capture_get(monkeypatch, api, default_resp=FakeResp(401))

    result = api.check_email("victima@example.com")

    assert result["error"] is not None
    assert "HIBP_API_KEY" in result["error"]
    assert result["breaches"] == []


def test_hibp_401_con_key_invalida_es_error_legible(monkeypatch):
    monkeypatch.setattr(hibp, "HIBP_API_KEY", "hibp_badkey")
    api = HIBPPasswordsAPI()
    _capture_get(monkeypatch, api, default_resp=FakeResp(401))

    result = api.check_email("victima@example.com")

    assert result["error"] is not None
    assert "invalida" in result["error"] or "expirada" in result["error"]


def test_hibp_403_es_error_legible(monkeypatch):
    monkeypatch.setattr(hibp, "HIBP_API_KEY", "hibp_fakekey")
    api = HIBPPasswordsAPI()
    _capture_get(monkeypatch, api, default_resp=FakeResp(403))

    result = api.check_email("victima@example.com")

    assert result["error"] is not None
    assert "403" in result["error"]


def test_hibp_429_es_error_legible(monkeypatch):
    monkeypatch.setattr(hibp, "HIBP_API_KEY", "hibp_fakekey")
    api = HIBPPasswordsAPI()
    _capture_get(monkeypatch, api, default_resp=FakeResp(429))

    result = api.check_email("victima@example.com")

    assert result["error"] is not None
    assert "429" in result["error"]


def test_hibp_200_con_breaches_las_retorna(monkeypatch):
    monkeypatch.setattr(hibp, "HIBP_API_KEY", "hibp_fakekey")
    api = HIBPPasswordsAPI()
    breaches = [
        {
            "Name": "ExampleBreach",
            "Title": "Example Breach",
            "BreachDate": "2019-03-01",
            "DataClasses": ["Email addresses", "Passwords"],
            "Domain": "example.com",
        }
    ]
    _capture_get(monkeypatch, api, default_resp=FakeResp(200, json_data=breaches))

    result = api.check_email("victima@example.com")

    assert result["error"] is None
    # Se normaliza a BreachDetail como el resto de proveedores, no JSON crudo.
    assert len(result["breaches"]) == 1
    b = result["breaches"][0]
    assert b.breach_name == "Example Breach"
    assert b.date == "2019-03-01"
    assert b.exposed_data == ["Email addresses", "Passwords"]
    assert b.source_api == "HIBP Pwned Passwords"


def test_hibp_404_es_sin_brechas(monkeypatch):
    monkeypatch.setattr(hibp, "HIBP_API_KEY", "hibp_fakekey")
    api = HIBPPasswordsAPI()
    _capture_get(monkeypatch, api, default_resp=FakeResp(404))

    result = api.check_email("victima@example.com")

    assert result["error"] is None
    assert result["breaches"] == []


def test_hibp_excepcion_de_red_se_propaga_como_error(monkeypatch):
    monkeypatch.setattr(hibp, "HIBP_API_KEY", "hibp_fakekey")
    api = HIBPPasswordsAPI()

    def raise_conn_error(url, params=None, headers=None):
        raise ConnectionError("boom")

    monkeypatch.setattr(api, "_get", raise_conn_error)

    result = api.check_email("victima@example.com")

    assert result["error"] is not None
    assert "boom" in result["error"]
