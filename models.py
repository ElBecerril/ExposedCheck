"""Modelos de datos del proyecto."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BreachDetail:
    """Detalle de una brecha de seguridad."""
    source_api: str
    breach_name: str
    date: str = "Desconocida"
    exposed_data: list[str] = field(default_factory=list)
    risk_level: str = "medio"
    description: str = ""
    industry: str = ""
    logo_url: str = ""


@dataclass
class InfostealerDetail:
    """Detalle de una infeccion por infostealer (Hudson Rock)."""
    computer_name: str = ""
    operating_system: str = ""
    malware_path: str = ""
    date_compromised: str = "Desconocida"
    antiviruses: str = ""


@dataclass
class PasswordResult:
    """Resultado de verificacion de password."""
    hibp_count: int = 0
    xon_count: int = 0
    is_compromised: bool = False


@dataclass
class CheckReport:
    """Reporte completo de verificacion."""
    query: str
    query_type: str  # "email", "username", "phone"
    breaches: list[BreachDetail] = field(default_factory=list)
    infostealers: list[InfostealerDetail] = field(default_factory=list)
    password_result: Optional[PasswordResult] = None
    errors: list[str] = field(default_factory=list)

    @property
    def total_breaches(self) -> int:
        return len(self.breaches)

    @property
    def has_infostealers(self) -> bool:
        return len(self.infostealers) > 0

    @property
    def overall_risk(self) -> str:
        if self.has_infostealers:
            return "critico"
        if self.total_breaches >= 5:
            return "alto"
        if self.total_breaches >= 1:
            return "medio"
        return "limpio"
