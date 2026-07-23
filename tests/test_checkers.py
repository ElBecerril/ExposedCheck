"""Tests de los checkers paralelizados (email/username/password).

Los providers se consultan en paralelo pero el reporte debe ensamblarse en
orden fijo y determinista. Se mockean los providers (sin red).
"""

from checkers.email_checker import EmailChecker
from checkers.username_checker import UsernameChecker
from checkers.password_checker import PasswordChecker
from checkers.parallel import run_provider
from models import BreachDetail, InfostealerDetail, PasswordResult


def _breach(name, api="X"):
    return BreachDetail(source_api=api, breach_name=name)


# --- run_provider (helper de blindaje) ----------------------------------

def test_run_provider_pasa_resultado_normal():
    class P:
        def check(self, q):
            return {"error": None, "breaches": [1]}
    assert run_provider(P().check, "q") == {"error": None, "breaches": [1]}


def test_run_provider_convierte_excepcion_en_error():
    class P:
        def check(self, q):
            raise RuntimeError("boom")
    out = run_provider(P().check, "q")
    assert out["error"] == "P: boom"


# --- EmailChecker --------------------------------------------------------

def test_email_ensambla_en_orden_fijo_y_dedupea(monkeypatch):
    checker = EmailChecker()
    # XON (primario) trae Adobe; LeakCheck trae Adobe (dup) + LinkedIn.
    monkeypatch.setattr(
        checker.xon, "check",
        lambda e: {"error": None, "breaches": [_breach("Adobe")]},
    )
    monkeypatch.setattr(
        checker.leakcheck, "check",
        lambda e, query_type=None: {
            "error": None,
            "breaches": [_breach("adobe"), _breach("LinkedIn")],
        },
    )
    monkeypatch.setattr(
        checker.hudson, "check",
        lambda e, query_type=None: {
            "error": None,
            "infostealers": [InfostealerDetail(computer_name="PC")],
        },
    )

    report = checker.check("x@y.com")

    # Orden fijo: XON primero, luego LeakCheck (sin duplicar Adobe).
    assert [b.breach_name for b in report.breaches] == ["Adobe", "LinkedIn"]
    assert report.sources_ok == ["XposedOrNot", "LeakCheck", "Hudson Rock"]
    assert len(report.infostealers) == 1


def test_email_provider_que_revienta_es_fuente_caida(monkeypatch):
    checker = EmailChecker()

    def boom(e):
        raise ConnectionError("down")

    monkeypatch.setattr(checker.xon, "check", boom)
    monkeypatch.setattr(
        checker.leakcheck, "check",
        lambda e, query_type=None: {"error": None, "breaches": [_breach("LinkedIn")]},
    )
    monkeypatch.setattr(
        checker.hudson, "check",
        lambda e, query_type=None: {"error": None, "infostealers": []},
    )

    report = checker.check("x@y.com")

    # XON caido no tumba a los hermanos: LeakCheck sigue aportando.
    assert "XposedOrNot" in report.sources_failed
    assert report.sources_ok == ["LeakCheck", "Hudson Rock"]
    assert [b.breach_name for b in report.breaches] == ["LinkedIn"]
    assert report.has_coverage is True
    assert report.is_partial is True


# --- UsernameChecker -----------------------------------------------------

def test_username_ensambla_hudson_primario(monkeypatch):
    checker = UsernameChecker()
    monkeypatch.setattr(
        checker.hudson, "check",
        lambda u, query_type=None: {
            "error": None,
            "infostealers": [InfostealerDetail(computer_name="PC")],
        },
    )
    monkeypatch.setattr(
        checker.leakcheck, "check",
        lambda u, query_type=None: {"error": "rate limit", "breaches": []},
    )

    report = checker.check("user")

    assert report.sources_ok == ["Hudson Rock"]
    assert report.sources_failed == ["LeakCheck"]
    assert report.is_partial is True


# --- PasswordChecker -----------------------------------------------------

def test_password_combina_ambas_fuentes_en_orden(monkeypatch):
    checker = PasswordChecker()

    def hibp_ok(pw):
        r = PasswordResult()
        r.hibp_count = 3
        r.record_source("HIBP")
        return r

    def xon_fail(pw):
        r = PasswordResult()
        r.record_source("XposedOrNot", error="net")
        return r

    monkeypatch.setattr(checker.hibp, "check_password", hibp_ok)
    monkeypatch.setattr(checker.xon, "check_password", xon_fail)

    result = checker.check("secret")

    assert result.hibp_count == 3
    assert result.is_compromised is True
    assert result.sources_ok == ["HIBP"]
    assert result.sources_failed == ["XposedOrNot"]
