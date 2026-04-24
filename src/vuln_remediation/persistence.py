"""Task persistence layer.

Stores tasks as JSON on disk. No external database required.
Swap this module to use Postgres/Redis/etc in production.
"""

from __future__ import annotations

import json
from pathlib import Path

from vuln_remediation.models import RemediationTask

DATA_DIR = Path("data")
TASKS_FILE = DATA_DIR / "tasks.json"


def load_tasks() -> dict[int, RemediationTask]:
    """Load tasks from disk. Keyed by issue number."""
    if not TASKS_FILE.exists():
        return {}
    raw = json.loads(TASKS_FILE.read_text())
    return {int(k): RemediationTask.model_validate(v) for k, v in raw.items()}


def save_tasks(tasks: dict[int, RemediationTask]) -> None:
    """Persist tasks to disk."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    serialized = {str(k): v.model_dump(mode="json") for k, v in tasks.items()}
    TASKS_FILE.write_text(json.dumps(serialized, indent=2, default=str))


def save_session_log(issue_number: int, title: str, session_url: str | None,
                     pr_url: str | None, status: str, updated_at: str,
                     messages: list[tuple[str, str]]) -> str:
    """Save session conversation to a markdown file. Returns the file path."""
    log_dir = DATA_DIR / "logs"
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


def save_attachment(issue_number: int, filename: str, content: bytes) -> str:
    """Save a session attachment to disk. Returns the file path."""
    attach_dir = DATA_DIR / "logs" / f"issue-{issue_number}-attachments"
    attach_dir.mkdir(parents=True, exist_ok=True)
    path = attach_dir / filename
    path.write_bytes(content)
    return str(path)
