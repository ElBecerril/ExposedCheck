"""Export de reportes a JSON.

Aprovecha que todos los checkers devuelven dataclasses: dataclasses.asdict()
serializa el arbol completo. Ademas se inyectan las propiedades computadas
utiles (overall_risk, etc.) que asdict no incluye por no ser campos.
"""

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone

from config import APP_NAME, APP_VERSION

# Propiedades computadas (no son campos, asdict las omite) que vale la pena
# incluir en el JSON cuando el reporte las expone.
_COMPUTED_PROPS = ("overall_risk", "total_breaches", "has_coverage", "is_partial")


def serialize_report(report) -> dict:
    """Convierte un reporte (dataclass) en un dict JSON-serializable."""
    if not is_dataclass(report):
        raise TypeError(f"Se esperaba una dataclass, no {type(report).__name__}")
    data = asdict(report)
    for prop in _COMPUTED_PROPS:
        if hasattr(type(report), prop):
            data[prop] = getattr(report, prop)
    return data


def build_payload(results: dict) -> dict:
    """Arma el payload completo con metadata + resultados por tipo de check.

    Args:
        results: dict {tipo_de_check: reporte_dataclass}.
    """
    return {
        "tool": APP_NAME,
        "version": APP_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": {name: serialize_report(r) for name, r in results.items()},
    }


def export_json(results: dict, path: str) -> None:
    """Escribe los reportes como JSON en `path` (UTF-8, indentado)."""
    payload = build_payload(results)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
