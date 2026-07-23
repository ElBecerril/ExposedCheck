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
    sources_ok: list[str] = field(default_factory=list)
    sources_failed: list[str] = field(default_factory=list)

    def record_source(self, name: str, error: Optional[str] = None) -> None:
        """Registra el resultado de consultar una fuente."""
        if error:
            self.sources_failed.append(name)
        else:
            self.sources_ok.append(name)

    @property
    def has_coverage(self) -> bool:
        """True si al menos una fuente respondio."""
        return len(self.sources_ok) > 0


@dataclass
class CheckReport:
    """Reporte completo de verificacion."""
    query: str
    query_type: str  # "email", "username", "phone"
    breaches: list[BreachDetail] = field(default_factory=list)
    infostealers: list[InfostealerDetail] = field(default_factory=list)
    password_result: Optional[PasswordResult] = None
    errors: list[str] = field(default_factory=list)
    # Fuentes que respondieron correctamente y fuentes que fallaron o se
    # omitieron (sin API key, rate limit, timeout). Sin esto no se puede
    # distinguir "no hay brechas" de "no se pudo consultar nada".
    sources_ok: list[str] = field(default_factory=list)
    sources_failed: list[str] = field(default_factory=list)

    def record_source(self, name: str, error: Optional[str] = None) -> None:
        """Registra el resultado de consultar una fuente."""
        if error:
            self.sources_failed.append(name)
            self.errors.append(error)
        else:
            self.sources_ok.append(name)

    @property
    def total_breaches(self) -> int:
        return len(self.breaches)

    @property
    def has_infostealers(self) -> bool:
        return len(self.infostealers) > 0

    @property
    def has_coverage(self) -> bool:
        """True si al menos una fuente respondio."""
        return len(self.sources_ok) > 0

    @property
    def is_partial(self) -> bool:
        """True si alguna fuente respondio pero otras fallaron."""
        return self.has_coverage and len(self.sources_failed) > 0

    @property
    def overall_risk(self) -> str:
        if self.has_infostealers:
            return "critico"
        if self.total_breaches >= 5:
            return "alto"
        if self.total_breaches >= 1:
            return "medio"
        # Cero hallazgos solo significa "limpio" si alguien contesto.
        if not self.has_coverage:
            return "desconocido"
        return "limpio"


@dataclass
class EmailFinderResult:
    """Resultado de busqueda de email asociado a un username."""
    username: str
    found_emails: list[dict] = field(default_factory=list)       # {email, source, confidence, breach_count}
    candidate_results: list[dict] = field(default_factory=list)  # candidatos no encontrados
    platforms_checked: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class ProfileHit:
    """Resultado de buscar un username en una plataforma."""
    platform: str
    url: str
    found: bool = False
    weak: bool = False  # 200 es senal debil en esta plataforma (confirmar manual)
    error: Optional[str] = None


@dataclass
class ProfileReport:
    """Reporte de busqueda de perfiles de un username en varias plataformas."""
    username: str
    found: list[ProfileHit] = field(default_factory=list)
    not_found: list[ProfileHit] = field(default_factory=list)
    errors: list[ProfileHit] = field(default_factory=list)


@dataclass
class ImageSearchResult:
    """Busqueda inversa de una sola imagen."""
    source: str
    type: str  # "url" | "local"
    search_urls: dict = field(default_factory=dict)  # {motor: url}
    temp_url: Optional[str] = None
    opened: bool = False
    error: Optional[str] = None


@dataclass
class ImageCheckReport:
    """Reporte de busqueda inversa de una o varias imagenes."""
    images: list[ImageSearchResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
