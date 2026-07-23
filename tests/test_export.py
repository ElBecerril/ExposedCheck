"""Tests del export JSON.

El refactor a dataclasses habilito serializar cualquier reporte con asdict;
este export ademas inyecta las propiedades computadas (overall_risk, etc.) y
envuelve todo con metadata.
"""

import json

from reporting.export import serialize_report, build_payload, export_json
from models import (
    CheckReport, BreachDetail, ProfileReport, ProfileHit, FingerprintReport, DomainInfo,
)


def test_serialize_incluye_propiedades_computadas():
    r = CheckReport(query="x@y.com", query_type="email")
    r.breaches.append(BreachDetail(source_api="XON", breach_name="Adobe"))
    r.record_source("XposedOrNot")

    d = serialize_report(r)

    # Campos normales via asdict.
    assert d["query"] == "x@y.com"
    assert d["breaches"][0]["breach_name"] == "Adobe"
    # Propiedades computadas inyectadas (asdict no las trae).
    assert d["overall_risk"] == "medio"
    assert d["total_breaches"] == 1
    assert d["has_coverage"] is True


def test_serialize_rechaza_no_dataclass():
    try:
        serialize_report({"no": "soy dataclass"})
        assert False, "deberia lanzar TypeError"
    except TypeError:
        pass


def test_build_payload_tiene_metadata_y_resultados():
    r = CheckReport(query="user", query_type="username")
    payload = build_payload({"username": r})

    assert payload["tool"] == "ExposedCheck"
    assert "version" in payload
    assert "generated_at" in payload
    assert "username" in payload["results"]


def test_export_json_round_trip(tmp_path):
    r = ProfileReport(username="tester")
    r.found.append(ProfileHit(platform="GitHub", url="http://gh/tester", found=True))

    out = tmp_path / "reporte.json"
    export_json({"profiles": r}, str(out))

    # Se puede releer como JSON valido.
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["tool"] == "ExposedCheck"
    assert data["results"]["profiles"]["username"] == "tester"
    assert data["results"]["profiles"]["found"][0]["platform"] == "GitHub"


def test_export_fingerprint_serializable(tmp_path):
    # El reporte mas anidado: si algo no fuera serializable, esto reventaria.
    r = FingerprintReport(
        email="u@x.com",
        domain_info=DomainInfo(exists=True, mx_records=[(10, "mx.x.com")], type="Otro"),
    )
    out = tmp_path / "fp.json"
    export_json({"fingerprint": r}, str(out))

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["results"]["fingerprint"]["domain_info"]["exists"] is True
    # La tupla (10, "mx") se serializa como array JSON.
    assert data["results"]["fingerprint"]["domain_info"]["mx_records"][0] == [10, "mx.x.com"]
