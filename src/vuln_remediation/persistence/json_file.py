"""JSON file persistence backend.

Stores tasks as JSON on disk. No external database required.
Swap with a different PersistenceBackend implementation for production.
"""

from __future__ import annotations

import json
from pathlib import Path

from vuln_remediation.models import RemediationTask


class JsonFilePersistence:
    """Persists tasks and artifacts to local JSON files."""

    def __init__(self, data_dir: Path = Path("data")) -> None:
        self._data_dir = data_dir
        self._tasks_file = data_dir / "tasks.json"

    def load_tasks(self) -> dict[int, RemediationTask]:
        if not self._tasks_file.exists():
            return {}
        raw = json.loads(self._tasks_file.read_text())
        return {int(k): RemediationTask.model_validate(v) for k, v in raw.items()}

    def save_tasks(self, tasks: dict[int, RemediationTask]) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        serialized = {str(k): v.model_dump(mode="json") for k, v in tasks.items()}
        self._tasks_file.write_text(json.dumps(serialized, indent=2, default=str))

    def save_session_log(
        self,
        issue_number: int,
        title: str,
        session_url: str | None,
        pr_url: str | None,
        status: str,
        updated_at: str,
        messages: list[tuple[str, str]],
    ) -> str:
        log_dir = self._data_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"issue-{issue_number}.md"

        lines = [
            f"# Session Log: Issue #{issue_number}",
            f"**{title}**\n",
            f"- Session: {session_url}",
            f"- PR: {pr_url or 'N/A'}",
            f"- Status: {status}",
            f"- Completed: {updated_at}\n",
            "---\n",
        ]
        for role, content in messages:
            lines.append(f"### {role.upper()}\n\n{content}\n")

        log_path.write_text("\n".join(lines))
        return str(log_path)

    def save_attachment(self, issue_number: int, filename: str, content: bytes) -> str:
        attach_dir = self._data_dir / "logs" / f"issue-{issue_number}-attachments"
        attach_dir.mkdir(parents=True, exist_ok=True)
        path = attach_dir / filename
        path.write_bytes(content)
        return str(path)
