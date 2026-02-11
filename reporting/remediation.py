"""Guia de remediacion y eliminacion de datos."""

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich import box

from models import CheckReport

console = Console()

# Links de privacidad/eliminacion de servicios comunes
PRIVACY_LINKS = {
    "facebook": "https://www.facebook.com/help/delete_account",
    "linkedin": "https://www.linkedin.com/help/linkedin/answer/63",
    "twitter": "https://help.twitter.com/en/managing-your-account/how-to-deactivate-twitter-account",
    "adobe": "https://www.adobe.com/privacy/opt-out.html",
    "dropbox": "https://help.dropbox.com/accounts-billing/settings-sign-in/delete-account",
    "canva": "https://www.canva.com/help/article/delete-account",
    "myspace": "https://myspace.com/pages/privacy",
    "tumblr": "https://www.tumblr.com/settings/account",
    "spotify": "https://support.spotify.com/us/article/close-account/",
    "zynga": "https://www.zynga.com/privacy/privacy-center",
}

GDPR_EMAIL_TEMPLATE = """
Asunto: Solicitud de eliminacion de datos personales (GDPR Art. 17 / CCPA)

Estimado/a responsable de proteccion de datos:

Me dirijo a ustedes para ejercer mi derecho de supresion ("derecho al olvido") conforme
al Articulo 17 del Reglamento General de Proteccion de Datos (RGPD/GDPR) de la Union
Europea, y/o mi derecho de eliminacion bajo la Ley de Privacidad del Consumidor de
California (CCPA), segun aplique.

Solicito que eliminen de forma permanente todos los datos personales que almacenen
sobre mi persona, incluyendo pero no limitado a:

- Direccion de correo electronico: {email}
- Nombre de usuario: {username}
- Numero de telefono: {phone}
- Cualquier otro dato personal asociado a estos identificadores

Les informo que tengo conocimiento de que mis datos fueron expuestos en una brecha de
seguridad que afecto a su servicio. Solicito la eliminacion completa de mi cuenta y todos
los datos asociados.

Conforme a la normativa vigente, disponen de 30 dias para responder a esta solicitud.

Atentamente,
[Tu nombre completo]
[Tu direccion - opcional pero recomendado para verificacion]

Fecha: {date}
""".strip()


class RemediationGuide:
    """Genera guia de remediacion personalizada segun el reporte."""

    def print_guide(self, report: CheckReport) -> None:
        """Imprime guia de remediacion completa."""
        if report.total_breaches == 0 and not report.has_infostealers:
            console.print(Panel(
                "[green]No se encontraron brechas. Tus datos no aparecen en las bases consultadas.[/green]\n\n"
                "[bold]Recomendaciones preventivas:[/bold]\n"
                "- Usa un gestor de passwords (Bitwarden, KeePass)\n"
                "- Activa autenticacion de dos factores (2FA) en todas tus cuentas\n"
                "- Monitorea periodicamente tus datos con esta herramienta",
                title="[bold green]Sin brechas detectadas[/bold green]",
                border_style="green",
            ))
            return

        console.print()
        self._print_immediate_actions(report)
        console.print()
        self._print_data_specific_advice(report)
        console.print()
        self._print_privacy_links(report)
        console.print()
        self._print_gdpr_template(report)

        if report.query_type == "phone" or self._phone_exposed(report):
            console.print()
            self._print_sim_swapping_advice()

    def _print_immediate_actions(self, report: CheckReport) -> None:
        """Acciones inmediatas segun nivel de riesgo."""
        actions = [
            "1. **Cambia inmediatamente** los passwords de las cuentas afectadas",
            "2. **Activa 2FA** (autenticacion de dos factores) en todas las cuentas - preferiblemente con app (no SMS)",
            "3. **Revisa la actividad reciente** de tus cuentas en busca de accesos no autorizados",
            "4. **No reutilices passwords** - usa un gestor de passwords (Bitwarden, KeePass)",
        ]

        if report.has_infostealers:
            actions.extend([
                "5. **Escanea tu equipo** con un antivirus actualizado (Malwarebytes, Windows Defender full scan)",
                "6. **Cierra todas las sesiones** activas en todos los servicios",
                "7. **Revoca tokens y cookies** - cambia passwords DESDE UN DISPOSITIVO LIMPIO",
            ])

        md = Markdown("\n".join(actions))
        console.print(Panel(
            md,
            title="[bold]Acciones Inmediatas[/bold]",
            border_style="bright_red" if report.has_infostealers else "yellow",
            box=box.DOUBLE,
        ))

    def _print_data_specific_advice(self, report: CheckReport) -> None:
        """Consejos especificos segun tipo de datos expuestos."""
        all_exposed = set()
        for breach in report.breaches:
            for data in breach.exposed_data:
                all_exposed.add(data.lower().strip())

        advice = []
        if any(x in all_exposed for x in ["password", "passwords", "hashed passwords", "contraseña"]):
            advice.append("**Passwords expuestos**: Cambia el password en TODOS los sitios donde uses el mismo. Usa passwords unicos.")

        if any(x in all_exposed for x in ["email", "emails", "email addresses", "correo"]):
            advice.append("**Email expuesto**: Espera aumento de phishing y spam. Configura filtros. No hagas clic en links sospechosos.")

        if any(x in all_exposed for x in ["phone", "phone numbers", "telefono", "phones"]):
            advice.append("**Telefono expuesto**: Riesgo de SIM swapping y vishing. Configura PIN de seguridad con tu operador.")

        if any(x in all_exposed for x in ["ip address", "ip addresses", "ip"]):
            advice.append("**IP expuesta**: Considera usar una VPN. Tu ubicacion aproximada puede haber sido comprometida.")

        if any(x in all_exposed for x in ["physical address", "address", "direccion"]):
            advice.append("**Direccion fisica expuesta**: Monitorea correspondencia sospechosa. Ten precaucion con contactos no solicitados.")

        if any(x in all_exposed for x in ["credit card", "credit cards", "tarjeta"]):
            advice.append("**Tarjeta de credito expuesta**: Contacta a tu banco INMEDIATAMENTE. Solicita nueva tarjeta. Monitorea movimientos.")

        if any(x in all_exposed for x in ["social security number", "ssn", "dni", "nif"]):
            advice.append("**Documento de identidad expuesto**: Alto riesgo de suplantacion. Contacta a las autoridades y congela tu credito.")

        if advice:
            md = Markdown("\n\n".join(advice))
            console.print(Panel(
                md,
                title="[bold]Recomendaciones segun Datos Expuestos[/bold]",
                border_style="yellow",
            ))

    def _print_privacy_links(self, report: CheckReport) -> None:
        """Links de eliminacion de cuentas para servicios afectados."""
        matched = {}
        for breach in report.breaches:
            name_lower = breach.breach_name.lower()
            for service, link in PRIVACY_LINKS.items():
                if service in name_lower:
                    matched[service.capitalize()] = link

        if not matched:
            return

        lines = ["Links para eliminar tu cuenta o datos en servicios afectados:\n"]
        for service, link in sorted(matched.items()):
            lines.append(f"- **{service}**: {link}")

        md = Markdown("\n".join(lines))
        console.print(Panel(
            md,
            title="[bold]Eliminacion de Cuentas[/bold]",
            border_style="blue",
        ))

    def _print_gdpr_template(self, report: CheckReport) -> None:
        """Plantilla de email GDPR lista para enviar."""
        email_val = report.query if report.query_type == "email" else "[tu email]"
        username_val = report.query if report.query_type == "username" else "[tu username]"
        phone_val = report.query if report.query_type == "phone" else "[tu telefono]"

        from datetime import date
        template = GDPR_EMAIL_TEMPLATE.format(
            email=email_val,
            username=username_val,
            phone=phone_val,
            date=date.today().isoformat(),
        )

        console.print(Panel(
            template,
            title="[bold]Plantilla Email GDPR Art. 17 - Derecho al Olvido[/bold]",
            subtitle="Copia y envia al DPO (Data Protection Officer) del servicio afectado",
            border_style="cyan",
            box=box.DOUBLE,
        ))

    def _print_sim_swapping_advice(self) -> None:
        """Consejos anti-SIM swapping."""
        advice = """**Tu numero de telefono esta expuesto. Protegete del SIM Swapping:**

1. **Contacta a tu operador** (Movistar, Vodafone, Orange, etc.) y solicita:
   - PIN/password de seguridad obligatorio para cambios en la cuenta
   - Bloqueo de portabilidad no autorizada
   - Notificacion por email ante cualquier cambio

2. **No uses SMS como 2FA** si es posible - cambia a app autenticadora (Google Authenticator, Authy)

3. **Senales de alerta de SIM swap:**
   - Pierdes senal de movil repentinamente
   - Recibes SMS de "bienvenida" de tu operador sin haberlo solicitado
   - No puedes hacer llamadas ni enviar mensajes

4. **Si sospechas un SIM swap:**
   - Contacta a tu operador INMEDIATAMENTE desde otro telefono
   - Cambia passwords de cuentas bancarias y email
   - Denuncia ante la policia"""

        md = Markdown(advice)
        console.print(Panel(
            md,
            title="[bold red]Proteccion Anti-SIM Swapping[/bold red]",
            border_style="red",
            box=box.DOUBLE,
        ))

    @staticmethod
    def _phone_exposed(report: CheckReport) -> bool:
        """Verifica si algun dato expuesto incluye telefono."""
        for breach in report.breaches:
            for data in breach.exposed_data:
                if any(x in data.lower() for x in ["phone", "telefono", "mobile"]):
                    return True
        return False
