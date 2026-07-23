"""Tests del export HTML."""

from reporting.export import render_html, build_payload, export_html
from models import (
    CheckReport, BreachDetail, ProfileReport, ProfileHit, FingerprintReport, DomainInfo,
)


def test_html_tiene_estructura_y_metadata():
    r = CheckReport(query="x@y.com", query_type="email")
    r.record_source("XposedOrNot")
    doc = render_html(build_payload({"email": r}))

    assert doc.startswith("<!DOCTYPE html>")
    assert "ExposedCheck" in doc
    assert "generado" in doc
    assert "</html>" in doc


def test_html_muestra_badge_de_riesgo():
    r = CheckReport(query="x@y.com", query_type="email")
    r.breaches.append(BreachDetail(source_api="XON", breach_name="Adobe"))
    r.record_source("XposedOrNot")
    doc = render_html(build_payload({"email": r}))

    # overall_risk == "medio" -> badge con su color y texto en mayusculas.
    assert "badge" in doc
    assert "MEDIO" in doc


def test_html_escapa_contenido_peligroso():
    r = ProfileReport(username="<script>alert(1)</script>")
    doc = render_html(build_payload({"profiles": r}))

    # El username malicioso no debe aparecer como tag ejecutable.
    assert "<script>alert(1)</script>" not in doc
    assert "&lt;script&gt;" in doc


def test_html_lista_de_dicts_se_vuelve_tabla():
    r = ProfileReport(username="tester")
    r.found.append(ProfileHit(platform="GitHub", url="http://gh/tester", found=True))
    doc = render_html(build_payload({"profiles": r}))

    assert "table" in doc
    assert "GitHub" in doc
    assert "platform" in doc  # cabecera de columna


def test_export_html_round_trip(tmp_path):
    r = FingerprintReport(
        email="u@x.com",
        domain_info=DomainInfo(exists=True, mx_records=[(10, "mx.x.com")], type="Otro"),
    )
    out = tmp_path / "reporte.html"
    export_html({"fingerprint": r}, str(out))

    content = out.read_text(encoding="utf-8")
    assert content.startswith("<!DOCTYPE html>")
    assert "u@x.com" in content
