"""GitHub notification service.

Posts status updates to GitHub issues as the remediation progresses.
"""

from __future__ import annotations

import structlog

from vuln_remediation.models import RemediationTask
from vuln_remediation.sources.base import IssueSource

logger = structlog.get_logger()


class GitHubNotifier:
    """Posts lifecycle updates to GitHub issues."""

    def __init__(self, issue_source: IssueSource) -> None:
        self._source = issue_source

    async def on_dispatched(self, task: RemediationTask) -> None:
        await self._source.add_comment(
            task.issue_number,
            f"🤖 **Automated remediation started**\n\n"
            f"Devin is working on this issue.\n"
            f"Session: {task.session_url}",
        )

    async def on_completed(self, task: RemediationTask) -> None:
        comment = "✅ **Remediation complete**\n\n"
        if task.pr_url:
            comment += f"Pull request: {task.pr_url}\n"
        else:
            comment += (
                "Devin completed the session without opening a PR. "
                "This may mean the vulnerability could not be reproduced. "
                f"Check the [session log]({task.session_url}) for details.\n"
            )
        if task.attachments:
            comment += "\n**Artifacts:**\n"
            for name in task.attachments:
                comment += f"- `{name}`\n"
            comment += f"\n[View full audit log]({task.session_url})"
        await self._source.add_comment(task.issue_number, comment)

    async def on_needs_input(self, task: RemediationTask) -> None:
        await self._source.add_comment(
            task.issue_number,
            f"⏸️ **Devin needs your input**\n\n"
            f"The session is waiting for human guidance.\n"
            f"[Respond in Devin]({task.session_url})",
        )

    async def on_failed(self, task: RemediationTask) -> None:
        await self._source.add_comment(
            task.issue_number,
            f"❌ **Remediation failed**\n\n"
            f"Session status: `{task.error}`\n"
            f"Debug: {task.session_url}",
        )
