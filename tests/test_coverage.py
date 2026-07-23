"""Tests de la logica de cobertura de fuentes.

Cubren el nucleo de la feature: distinguir "sin brechas" de "no se pudo
consultar ninguna fuente". Toda la logica aqui es pura (sin red).
"""

from models import BreachDetail, CheckReport, InfostealerDetail, PasswordResult


def _breach(name="Adobe"):
    return BreachDetail(source_api="XposedOrNot", breach_name=name)


# --- record_source: contabilidad basica ---------------------------------

def test_record_source_ok_va_a_sources_ok():
    r = CheckReport(query="x@y.com", query_type="email")
    r.record_source("XposedOrNot")
    assert r.sources_ok == ["XposedOrNot"]
    assert r.sources_failed == []
    assert r.errors == []


def test_record_source_con_error_va_a_failed_y_errors():
    r = CheckReport(query="x@y.com", query_type="email")
    r.record_source("LeakCheck", error="rate limit")
    assert r.sources_failed == ["LeakCheck"]
    assert r.sources_ok == []
    # El error tambien se propaga a la lista legacy de errores.
    assert r.errors == ["rate limit"]


# --- has_coverage / is_partial ------------------------------------------

def test_sin_fuentes_no_hay_cobertura():
    r = CheckReport(query="x@y.com", query_type="email")
    assert r.has_coverage is False
    assert r.is_partial is False


def test_todas_las_fuentes_fallan_no_hay_cobertura():
    r = CheckReport(query="x@y.com", query_type="email")
    r.record_source("XposedOrNot", error="timeout")
    r.record_source("LeakCheck", error="rate limit")
    assert r.has_coverage is False
    assert r.is_partial is False  # parcial requiere al menos una OK


def test_una_ok_una_falla_es_parcial():
    r = CheckReport(query="x@y.com", query_type="email")
    r.record_source("XposedOrNot")
    r.record_source("LeakCheck", error="rate limit")
    assert r.has_coverage is True
    assert r.is_partial is True


def test_todas_ok_no_es_parcial():
    r = CheckReport(query="x@y.com", query_type="email")
    r.record_source("XposedOrNot")
    r.record_source("LeakCheck")
    assert r.has_coverage is True
    assert r.is_partial is False


# --- overall_risk: el corazon de la feature -----------------------------

def test_cero_brechas_sin_cobertura_es_desconocido():
    """El bug que arregla la feature: 0 brechas sin fuentes != limpio."""
    r = CheckReport(query="x@y.com", query_type="email")
    r.record_source("XposedOrNot", error="timeout")
    assert r.overall_risk == "desconocido"


def test_cero_brechas_con_cobertura_es_limpio():
    r = CheckReport(query="x@y.com", query_type="email")
    r.record_source("XposedOrNot")
    assert r.overall_risk == "limpio"


def test_cero_brechas_parcial_sigue_siendo_limpio():
    r = CheckReport(query="x@y.com", query_type="email")
    r.record_source("XposedOrNot")
    r.record_source("LeakCheck", error="rate limit")
    assert r.overall_risk == "limpio"


def test_una_brecha_es_medio_aunque_falten_fuentes():
    r = CheckReport(query="x@y.com", query_type="email")
    r.breaches.append(_breach())
    r.record_source("XposedOrNot")
    r.record_source("LeakCheck", error="rate limit")
    assert r.overall_risk == "medio"


def test_cinco_brechas_es_alto():
    r = CheckReport(query="x@y.com", query_type="email")
    r.breaches.extend(_breach(f"b{i}") for i in range(5))
    r.record_source("XposedOrNot")
    assert r.overall_risk == "alto"


def test_infostealer_es_critico_aunque_no_haya_cobertura():
    """Un infostealer detectado manda a critico por encima de todo."""
    r = CheckReport(query="x@y.com", query_type="email")
    r.infostealers.append(InfostealerDetail(computer_name="PC"))
    assert r.overall_risk == "critico"


# --- PasswordResult ------------------------------------------------------

def test_password_sin_cobertura():
    pw = PasswordResult()
    pw.record_source("HIBP", error="net")
    pw.record_source("XposedOrNot", error="net")
    assert pw.has_coverage is False


def test_password_con_una_fuente_ok():
    pw = PasswordResult()
    pw.record_source("HIBP")
    pw.record_source("XposedOrNot", error="net")
    assert pw.has_coverage is True
