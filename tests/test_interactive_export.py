"""Tests del ofrecimiento de export en modo interactivo (_offer_export)."""

import json

import main
from models import CheckReport


def _report():
    r = CheckReport(query="x@y.com", query_type="email")
    r.record_source("XposedOrNot")
    return r


def _fake_prompts(monkeypatch, confirm, fmt, path):
    """Simula las respuestas del usuario a Confirm/Prompt."""
    monkeypatch.setattr(main.Confirm, "ask", staticmethod(lambda *a, **k: confirm))

    answers = iter([fmt, path])
    monkeypatch.setattr(main.Prompt, "ask", staticmethod(lambda *a, **k: next(answers)))


def test_offer_export_declina_no_escribe(monkeypatch, tmp_path):
    # El usuario responde "no" al Confirm: no se pide nada mas ni se escribe.
    monkeypatch.setattr(main.Confirm, "ask", staticmethod(lambda *a, **k: False))
    main._offer_export({"email": _report()})
    assert list(tmp_path.iterdir()) == []


def test_offer_export_json(monkeypatch, tmp_path):
    out = tmp_path / "reporte"
    _fake_prompts(monkeypatch, confirm=True, fmt="json", path=str(out))

    main._offer_export({"email": _report()})

    written = out.with_suffix(".json")
    assert written.exists()
    data = json.loads(written.read_text(encoding="utf-8"))
    assert data["results"]["email"]["query"] == "x@y.com"


def test_offer_export_ambos_genera_dos_archivos(monkeypatch, tmp_path):
    out = tmp_path / "reporte"
    _fake_prompts(monkeypatch, confirm=True, fmt="ambos", path=str(out))

    main._offer_export({"email": _report()})

    assert out.with_suffix(".json").exists()
    assert out.with_suffix(".html").exists()


def test_offer_export_normaliza_extension_duplicada(monkeypatch, tmp_path):
    # El usuario escribe "reporte.json" y pide "ambos": no debe salir
    # "reporte.json.html" sino "reporte.json" + "reporte.html".
    out = tmp_path / "reporte.json"
    _fake_prompts(monkeypatch, confirm=True, fmt="ambos", path=str(out))

    main._offer_export({"email": _report()})

    assert (tmp_path / "reporte.json").exists()
    assert (tmp_path / "reporte.html").exists()
    assert not (tmp_path / "reporte.json.html").exists()


def test_offer_export_sin_resultados_no_pregunta(monkeypatch):
    # Con dict vacio no debe siquiera invocar Confirm.
    called = []
    monkeypatch.setattr(main.Confirm, "ask", staticmethod(lambda *a, **k: called.append(1)))
    main._offer_export({})
    assert called == []
