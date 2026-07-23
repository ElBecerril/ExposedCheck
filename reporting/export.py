"""Export de reportes a JSON.

Aprovecha que todos los checkers devuelven dataclasses: dataclasses.asdict()
serializa el arbol completo. Ademas se inyectan las propiedades computadas
utiles (overall_risk, etc.) que asdict no incluye por no ser campos.
"""

import html
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


# --- Export HTML ---------------------------------------------------------

# Riesgo -> color hex (equivalente aproximado a los colores de RISK_LEVELS).
_RISK_COLORS = {
    "critico": "#e53935",
    "alto": "#fb8c00",
    "medio": "#fdd835",
    "bajo": "#7cb342",
    "limpio": "#43a047",
    "desconocido": "#9e9e9e",
}

# Etiquetas legibles para las secciones (clave interna -> titulo).
_SECTION_LABELS = {
    "email": "Email",
    "username": "Username",
    "phone": "Telefono",
    "password": "Password",
    "image": "Busqueda inversa de imagenes",
    "profiles": "Perfiles",
    "fingerprint": "Fingerprint de email",
    "email_finder": "Emails asociados al username",
}


def _h(value) -> str:
    """Escapa un valor para insertarlo en HTML."""
    return html.escape(str(value))


def _render_value(value) -> str:
    """Renderiza recursivamente un valor (dict/list/escalar) como HTML."""
    if isinstance(value, dict):
        rows = "".join(
            f"<tr><th>{_h(k)}</th><td>{_render_value(v)}</td></tr>"
            for k, v in value.items()
        )
        return f"<table class='kv'>{rows}</table>"

    if isinstance(value, list):
        if not value:
            return "<span class='empty'>&mdash;</span>"
        # Lista de dicts homogeneos -> tabla con columnas.
        if all(isinstance(item, dict) for item in value):
            cols = []
            for item in value:
                for k in item:
                    if k not in cols:
                        cols.append(k)
            head = "".join(f"<th>{_h(c)}</th>" for c in cols)
            body = "".join(
                "<tr>" + "".join(f"<td>{_render_value(item.get(c))}</td>" for c in cols) + "</tr>"
                for item in value
            )
            return f"<table class='rows'><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
        # Lista de escalares -> <ul>.
        items = "".join(f"<li>{_render_value(v)}</li>" for v in value)
        return f"<ul>{items}</ul>"

    if value is None:
        return "<span class='empty'>&mdash;</span>"
    if isinstance(value, bool):
        return "si" if value else "no"
    return _h(value)


def _render_section(name: str, data: dict) -> str:
    """Renderiza una seccion (un tipo de check) con badge de riesgo si aplica."""
    label = _SECTION_LABELS.get(name, name)
    badge = ""
    risk = data.get("overall_risk") if isinstance(data, dict) else None
    if risk:
        color = _RISK_COLORS.get(risk, "#9e9e9e")
        badge = f"<span class='badge' style='background:{color}'>{_h(risk.upper())}</span>"
    return (
        f"<section><h2>{_h(label)} {badge}</h2>{_render_value(data)}</section>"
    )


def render_html(payload: dict) -> str:
    """Construye el documento HTML completo a partir del payload."""
    sections = "".join(
        _render_section(name, data) for name, data in payload["results"].items()
    )
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_h(payload['tool'])} - Reporte</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: system-ui, sans-serif; background:#121212; color:#e0e0e0;
         margin:0; padding:2rem; line-height:1.5; }}
  header {{ border-bottom:1px solid #333; padding-bottom:1rem; margin-bottom:2rem; }}
  header h1 {{ margin:0 0 .25rem; }}
  .meta {{ color:#9e9e9e; font-size:.9rem; }}
  section {{ margin-bottom:2.5rem; }}
  h2 {{ border-left:4px solid #555; padding-left:.6rem; }}
  .badge {{ font-size:.8rem; padding:.15rem .5rem; border-radius:.4rem;
           color:#111; font-weight:700; vertical-align:middle; }}
  table {{ border-collapse:collapse; margin:.5rem 0; max-width:100%; }}
  table.kv th {{ text-align:left; color:#bbb; padding:.2rem .8rem .2rem 0;
                vertical-align:top; white-space:nowrap; }}
  table.rows {{ width:100%; }}
  table.rows th {{ text-align:left; background:#1e1e1e; padding:.4rem .6rem;
                  border-bottom:1px solid #333; }}
  table.rows td {{ padding:.4rem .6rem; border-bottom:1px solid #222;
                  vertical-align:top; }}
  ul {{ margin:.2rem 0; padding-left:1.2rem; }}
  .empty {{ color:#666; }}
  a {{ color:#64b5f6; }}
</style>
</head>
<body>
<header>
  <h1>{_h(payload['tool'])} &mdash; Reporte</h1>
  <div class="meta">version {_h(payload['version'])} &middot; generado {_h(payload['generated_at'])}</div>
</header>
{sections}
</body>
</html>
"""


def export_html(results: dict, path: str) -> None:
    """Escribe los reportes como pagina HTML autocontenida en `path`."""
    payload = build_payload(results)
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(payload))
