"""Tests de _merge_reports: al combinar reportes hay que arrastrar las
fuentes (dedupeadas), o el combinado se veria "sin cobertura"."""

from main import _merge_reports
from models import CheckReport


def test_merge_arrastra_y_dedupea_fuentes():
    r1 = CheckReport(query="a@y.com", query_type="email")
    r1.record_source("XposedOrNot")
    r1.record_source("LeakCheck", error="rate limit")

    r2 = CheckReport(query="b@y.com", query_type="email")
    r2.record_source("XposedOrNot")  # duplicado: no debe repetirse
    r2.record_source("Hudson Rock")

    combined = _merge_reports([r1, r2])

    assert combined.sources_ok == ["XposedOrNot", "Hudson Rock"]
    assert combined.sources_failed == ["LeakCheck"]
    assert combined.has_coverage is True


def test_merge_un_solo_reporte_se_devuelve_tal_cual():
    r = CheckReport(query="a@y.com", query_type="email")
    r.record_source("XposedOrNot")
    assert _merge_reports([r]) is r


def test_merge_lista_vacia_es_none():
    assert _merge_reports([]) is None
