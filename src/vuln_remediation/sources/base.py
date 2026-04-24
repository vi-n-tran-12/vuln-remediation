"""Protocol for issue/vulnerability sources (GitHub, Jira, etc.)."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from vuln_remediation.models import GitHubIssue as Issue


@runtime_checkable
class IssueSource(Protocol):
    """Interface for discovering and interacting with vulnerability issues."""

    async def list_open_issues(self, labels: str = "") -> list[Issue]: ...
    async def get_issue(self, issue_number: int) -> Issue: ...
    async def add_comment(self, issue_number: int, body: str) -> None: ...
    async def close(self) -> None: ...
