"""Protocol for task persistence backends (JSON file, DB, etc.)."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from vuln_remediation.models import RemediationTask


@runtime_checkable
class PersistenceBackend(Protocol):
    """Interface for persisting remediation tasks and artifacts."""

    def load_tasks(self) -> dict[int, RemediationTask]: ...
    def save_tasks(self, tasks: dict[int, RemediationTask]) -> None: ...
    def save_session_log(
        self,
        issue_number: int,
        title: str,
        session_url: str | None,
        pr_url: str | None,
        status: str,
        updated_at: str,
        messages: list[tuple[str, str]],
    ) -> str: ...
    def save_attachment(self, issue_number: int, filename: str, content: bytes) -> str: ...
