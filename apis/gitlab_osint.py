"""GitLab API - Extraccion de email publico desde perfiles."""

from config import GITLAB_API_URL
from .base import BaseAPI


class GitLabOsintAPI(BaseAPI):
    """Busca email publico asociado a un username en GitLab."""

    name = "GitLab"

    def check(self, username: str) -> dict:
        """Busca public_email en el perfil publico de GitLab.

        Args:
            username: Nombre de usuario de GitLab.

        Returns:
            Dict con lista de emails encontrados y posibles errores.
        """
        result = {"emails": [], "error": None}

        try:
            resp = self._get(
                f"{GITLAB_API_URL}/users",
                params={"username": username},
            )

            if resp.status_code == 403:
                result["error"] = "GitLab: rate limit alcanzado"
                return result
            if resp.status_code != 200:
                result["error"] = f"GitLab: HTTP {resp.status_code}"
                return result

            users = resp.json()
            if not users:
                result["error"] = "GitLab: usuario no encontrado"
                return result

            user = users[0]
            public_email = user.get("public_email", "")
            if public_email:
                result["emails"].append(public_email)

            # Intentar obtener mas detalles del perfil
            user_id = user.get("id")
            if user_id:
                detail_resp = self._get(f"{GITLAB_API_URL}/users/{user_id}")
                if detail_resp.status_code == 200:
                    detail = detail_resp.json()
                    detail_email = detail.get("public_email", "")
                    if detail_email and detail_email not in result["emails"]:
                        result["emails"].append(detail_email)

        except Exception as e:
            result["error"] = f"GitLab: {e}"

        return result
