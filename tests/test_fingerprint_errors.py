"""Tests de propagacion de errores en EmailFingerprint.

El anti-patron que se corrigio: `except Exception: pass` hacia que un fallo
de red se viera como "no encontrado". Ahora los fallos se registran en la
lista `errors` (que se muestra al usuario), nunca se tragan en silencio.
"""

import requests

from checkers.email_fingerprint import EmailFingerprint


def test_gravatar_error_de_red_se_registra(monkeypatch):
    fp = EmailFingerprint()

    def boom(*a, **k):
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr("checkers.email_fingerprint.requests.get", boom)

    errors = []
    out = fp._check_gravatar("x@y.com", errors)

    # No se cuela como "sin gravatar": el fallo queda registrado.
    assert out is None
    assert any("Gravatar" in e for e in errors)


def test_servicio_que_revienta_se_registra_no_se_traga(monkeypatch):
    fp = EmailFingerprint()

    def boom(email):
        raise requests.exceptions.Timeout("slow")

    # Spotify revienta; los otros dos devuelven None (sin dato).
    monkeypatch.setattr(fp, "_check_spotify", boom)
    monkeypatch.setattr(fp, "_check_wordpress", lambda e: None)
    monkeypatch.setattr(fp, "_check_duolingo", lambda e: None)

    errors = []
    services = fp._check_services("x@y.com", errors)

    assert services == []  # ninguno confirmado
    assert any("Spotify" in e for e in errors)  # pero el fallo se ve


def test_servicio_registrado_se_reporta(monkeypatch):
    fp = EmailFingerprint()
    monkeypatch.setattr(fp, "_check_spotify", lambda e: True)
    monkeypatch.setattr(fp, "_check_wordpress", lambda e: False)
    monkeypatch.setattr(fp, "_check_duolingo", lambda e: None)

    errors = []
    services = fp._check_services("x@y.com", errors)

    assert {"service": "Spotify", "registered": True} in services
    assert {"service": "WordPress", "registered": False} in services
    assert errors == []
