"""Async client for the GitHub REST API.

Handles issue listing, commenting, and PR detection. Keeps the
orchestrator decoupled from HTTP details.
"""

from __future__ import annotations

import httpx
import structlog

from vuln_remediation.config import Settings
from vuln_remediation.models import GitHubIssue

logger = structlog.get_logger()

GITHUB_API = "https://api.github.com"


class GitHubAPIError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"GitHub API error {status_code}: {detail}")


class GitHubClient:
    """Async wrapper around the GitHub REST API.

    Usage:
        async with GitHubClient(settings) as gh:
            issues = await gh.list_open_issues()
    """

    def __init__(self, settings: Settings) -> None:
        self._owner = settings.github_owner
        self._repo = settings.github_repo_name
        self._client = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {settings.github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=httpx.Timeout(30.0, connect=10.0),
        )

    async def __aenter__(self) -> GitHubClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Issues
    # ------------------------------------------------------------------

    async def list_open_issues(self, labels: str = "") -> list[GitHubIssue]:
        """List open issues, optionally filtered by label."""
        params: dict[str, str] = {"state": "open", "per_page": "100"}
        if labels:
            params["labels"] = labels

        resp = await self._client.get(
            f"{GITHUB_API}/repos/{self._owner}/{self._repo}/issues",
            params=params,
        )
        self._check(resp)

        issues: list[GitHubIssue] = []
        for item in resp.json():
            if "pull_request" in item:
                continue
            issues.append(
                GitHubIssue(
                    number=item["number"],
                    title=item["title"],
                    body=item.get("body"),
                    html_url=item["html_url"],
                    labels=[lbl["name"] for lbl in item.get("labels", [])],
                    state=item["state"],
                )
            )
        return issues

    async def get_issue(self, issue_number: int) -> GitHubIssue:
        """Get a single issue by number."""
        resp = await self._client.get(
            f"{GITHUB_API}/repos/{self._owner}/{self._repo}/issues/{issue_number}",
        )
        self._check(resp)
        item = resp.json()
        return GitHubIssue(
            number=item["number"],
            title=item["title"],
            body=item.get("body"),
            html_url=item["html_url"],
            labels=[lbl["name"] for lbl in item.get("labels", [])],
            state=item["state"],
        )

    async def add_comment(self, issue_number: int, body: str) -> None:
        """Post a comment on an issue."""
        resp = await self._client.post(
            f"{GITHUB_API}/repos/{self._owner}/{self._repo}/issues/{issue_number}/comments",
            json={"body": body},
        )
        self._check(resp)
        logger.info("github_comment_posted", issue=issue_number)

    async def list_pull_requests(self, state: str = "open") -> list[dict[str, object]]:
        """List pull requests for the repo."""
        resp = await self._client.get(
            f"{GITHUB_API}/repos/{self._owner}/{self._repo}/pulls",
            params={"state": state, "per_page": "100"},
        )
        self._check(resp)
        return resp.json()  # type: ignore[no-any-return]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check(resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            detail = resp.text
            try:
                detail = resp.json().get("message", resp.text)
            except Exception:
                pass
            raise GitHubAPIError(resp.status_code, str(detail))
