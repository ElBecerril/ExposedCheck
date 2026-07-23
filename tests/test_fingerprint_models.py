"""Tests del refactor de EmailFingerprint a dataclasses.

Un FingerprintReport poblado pasado por print_results ejercita todos los
accesos por atributo: si quedara un acceso estilo dict (data["x"]), esto
reventaria. Ademas se valida la serializabilidad via asdict (export JSON).
"""

from dataclasses import asdict

from models import (
    FingerprintReport, DomainInfo, GravatarProfile,
    GitHubUser, GitHubPresence, GitLabPresence, ServiceRegistration,
    BreachDetail, InfostealerDetail, ProfileHit,
)
from checkers.email_fingerprint import EmailFingerprint


def _populated_report():
    return FingerprintReport(
        email="user@example.com",
        domain="example.com",
        username_part="user",
        domain_info=DomainInfo(exists=True, mx_records=[(10, "mx.example.com")], type="Google Workspace"),
        gravatar=GravatarProfile(
            display_name="User", username="user", profile_url="http://g/u",
            about="hola", location="MX",
            accounts=[{"platform": "twitter", "url": "http://t/u"}],
        ),
        breaches=[BreachDetail(source_api="XON", breach_name="Adobe", exposed_data=["email"])],
        infostealers=[InfostealerDetail(computer_name="PC")],
        github_presence=GitHubPresence(found=True, users=[GitHubUser(username="user", profile_url="http://gh/u")]),
        gitlab_presence=GitLabPresence(found=True, username="user"),
        registered_services=[ServiceRegistration(service="Spotify", registered=True)],
        profiles_found=[ProfileHit(platform="GitHub", url="http://gh/u", found=True)],
        errors=["algo fallo"],
    )


def test_print_results_no_revienta_con_report_poblado():
    fp = EmailFingerprint()
    # Si algun acceso quedo como dict, esto lanzaria TypeError/KeyError.
    fp.print_results(_populated_report())


def test_print_results_no_revienta_con_report_vacio():
    fp = EmailFingerprint()
    fp.print_results(FingerprintReport(email="x@y.com", domain="y.com", username_part="x"))


def test_fingerprint_report_serializable():
    d = asdict(_populated_report())
    assert d["email"] == "user@example.com"
    assert d["domain_info"]["type"] == "Google Workspace"
    assert d["github_presence"]["users"][0]["username"] == "user"
    assert d["registered_services"][0]["service"] == "Spotify"
    assert d["profiles_found"][0]["platform"] == "GitHub"


def test_check_domain_devuelve_dataclass_para_dominio_conocido():
    fp = EmailFingerprint()
    errors = []
    info = fp._check_domain("gmail.com", errors)
    assert isinstance(info, DomainInfo)
    assert info.exists is True
    assert info.type == "Google Gmail"


def test_check_git_platforms_puebla_dataclasses(monkeypatch):
    fp = EmailFingerprint()

    class Resp:
        status_code = 200

        @staticmethod
        def json():
            return {"total_count": 1, "items": [
                {"login": "user", "html_url": "http://gh/user", "avatar_url": "http://a"}
            ]}

    monkeypatch.setattr("checkers.email_fingerprint.requests.get", lambda *a, **k: Resp())
    # GitLab: sin error -> presencia encontrada.
    monkeypatch.setattr(fp.gitlab, "check", lambda u: {"error": None})

    report = FingerprintReport(email="user@x.com")
    fp._check_git_platforms("user@x.com", report)

    assert isinstance(report.github_presence, GitHubPresence)
    assert report.github_presence.found is True
    assert report.github_presence.users[0].username == "user"
    assert isinstance(report.gitlab_presence, GitLabPresence)
    assert report.gitlab_presence.found is True
