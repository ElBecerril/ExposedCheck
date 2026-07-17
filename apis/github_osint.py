"""GitHub API - Extraccion de emails publicos desde perfiles y commits."""

from config import GITHUB_API_URL
from .base import BaseAPI


class GitHubOsintAPI(BaseAPI):
    """Busca emails asociados a un username en GitHub."""

    name = "GitHub"

    def check(self, username: str) -> dict:
        """Busca emails en perfil publico, commits de repos y eventos.

        Args:
            username: Nombre de usuario de GitHub.

        Returns:
            Dict con lista de emails encontrados y posibles errores.
        """
        result = {"emails": [], "error": None}
        found_emails = set()

        try:
            # 1. Perfil publico
            resp = self._get(f"{GITHUB_API_URL}/users/{username}")
            if resp.status_code == 404:
                result["error"] = "GitHub: usuario no encontrado"
                return result
            if resp.status_code == 403:
                result["error"] = "GitHub: rate limit alcanzado (60 req/hr sin API key)"
                return result
            if resp.status_code != 200:
                result["error"] = f"GitHub: HTTP {resp.status_code}"
                return result

            profile = resp.json()
            if profile.get("email"):
                found_emails.add(profile["email"])

            # 2. Commits en repos publicos (hasta 5 repos mas recientes)
            repos_resp = self._get(
                f"{GITHUB_API_URL}/users/{username}/repos",
                params={"sort": "pushed", "per_page": 5},
            )
            if repos_resp.status_code == 200:
                repos = repos_resp.json()
                for repo in repos[:5]:
                    commits_resp = self._get(
                        f"{GITHUB_API_URL}/repos/{username}/{repo['name']}/commits",
                        params={"author": username, "per_page": 5},
                    )
                    if commits_resp.status_code == 200:
                        commits = commits_resp.json()
                        for commit in commits:
                            commit_data = commit.get("commit", {})
                            author = commit_data.get("author", {})
                            email = author.get("email", "")
                            if email and not self._is_noreply(email):
                                found_emails.add(email)

            # 3. Eventos publicos (push events contienen emails en commits)
            events_resp = self._get(
                f"{GITHUB_API_URL}/users/{username}/events/public",
                params={"per_page": 10},
            )
            if events_resp.status_code == 200:
                events = events_resp.json()
                for event in events:
                    if event.get("type") == "PushEvent":
                        payload = event.get("payload", {})
                        for commit in payload.get("commits", []):
                            email = commit.get("author", {}).get("email", "")
                            if email and not self._is_noreply(email):
                                found_emails.add(email)

        except Exception as e:
            result["error"] = f"GitHub: {e}"

        result["emails"] = list(found_emails)
        return result

    @staticmethod
    def _is_noreply(email: str) -> bool:
        """Filtra emails noreply de GitHub y genericos."""
        email_lower = email.lower()
        return (
            "noreply" in email_lower
            or email_lower.endswith("@users.noreply.github.com")
            or email_lower == ""
        )
