"""Orchestrator: the core state machine that drives remediation.

Thin coordination layer — delegates to protocol-based backends:
  - AgentClient for session management
  - IssueSource for issue discovery
  - NotificationSink for status updates
  - PersistenceBackend for task storage
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any

import structlog

from vuln_remediation.agents.base import AgentClient
from vuln_remediation.models import (
    DevinSessionStatus,
    GitHubIssue,
    RemediationTask,
    TaskStatus,
)
from vuln_remediation.notifications.base import NotificationSink
from vuln_remediation.persistence.base import PersistenceBackend
from vuln_remediation.sources.base import IssueSource

logger = structlog.get_logger()

GRACE_PERIOD_MINUTES = 5
RETRY_COOLDOWN_MINUTES = 10
PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _detect_priority(title: str, body: str) -> str:
    """Detect severity/priority from issue title and body text."""
    text = (title + " " + body).lower()
    if "critical" in text:
        return "critical"
    if "high" in text:
        return "high"
    if "low" in text:
        return "low"
    return "medium"


def build_prompt(issue: GitHubIssue, repo: str) -> str:
    """Build a session prompt from a GitHub issue."""
    return (
        f"Repository: https://github.com/{repo}\n\n"
        f"## Issue #{issue.number}: {issue.title}\n\n"
        f"{issue.body or 'No description provided.'}\n\n"
        f"---\n"
        f'Fix this vulnerability and open a PR with "Fixes #{issue.number}" in the body.'
    )


class Orchestrator:
    """Drives the issue → agent session → PR lifecycle.

    All dependencies are injected via constructor — swap implementations
    to change agent backend, issue source, notification channel, or storage.
    """

    def __init__(
        self,
        *,
        agent: AgentClient,
        source: IssueSource,
        notifier: NotificationSink,
        persistence: PersistenceBackend,
        repo: str,
        max_concurrent_sessions: int = 3,
        playbook_id: str | None = None,
    ) -> None:
        self._agent = agent
        self._source = source
        self._notifier = notifier
        self._persistence = persistence
        self._repo = repo
        self._max_concurrent = max_concurrent_sessions
        self._playbook_id = playbook_id
        self._tasks = persistence.load_tasks()
        self._lock = asyncio.Lock()

    async def close(self) -> None:
        await self._agent.close()
        await self._source.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_once(self) -> list[RemediationTask]:
        """Single pass: discover → dispatch → poll → save."""
        async with self._lock:
            await self._discover_issues()
            await self._dispatch_pending()
            await self._poll_running()
            self._persistence.save_tasks(self._tasks)
        return list(self._tasks.values())

    def get_tasks(self) -> list[RemediationTask]:
        return sorted(
            self._tasks.values(),
            key=lambda t: PRIORITY_ORDER.get(t.priority, 2),
        )

    def get_metrics(self) -> dict[str, Any]:
        tasks = list(self._tasks.values())
        completed = [t for t in tasks if t.status == TaskStatus.COMPLETED]
        total = len(tasks)

        avg_duration = 0.0
        if completed:
            durations = [(t.updated_at - t.created_at).total_seconds() / 60 for t in completed]
            avg_duration = sum(durations) / len(durations)

        return {
            "total_tasks": total,
            "pending": sum(1 for t in tasks if t.status == TaskStatus.PENDING),
            "running": sum(1 for t in tasks if t.status in (TaskStatus.SESSION_CREATED, TaskStatus.RUNNING)),
            "needs_input": sum(1 for t in tasks if t.status == TaskStatus.NEEDS_INPUT),
            "completed": len(completed),
            "failed": sum(1 for t in tasks if t.status == TaskStatus.FAILED),
            "success_rate": round(len(completed) / total, 2) if total else 0.0,
            "avg_remediation_minutes": round(avg_duration, 1),
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Discover
    # ------------------------------------------------------------------

    async def _discover_issues(self) -> None:
        try:
            issues = await self._source.list_open_issues(labels="security")
        except Exception:
            logger.exception("discover_issues_failed")
            return

        for issue in issues:
            if issue.number not in self._tasks:
                self._tasks[issue.number] = RemediationTask(
                    issue_number=issue.number,
                    issue_title=issue.title,
                    issue_url=issue.html_url,
                    priority=_detect_priority(issue.title, issue.body or ""),
                )
                logger.info("issue_discovered", issue=issue.number, title=issue.title)
            else:
                task = self._tasks[issue.number]
                if task.status == TaskStatus.FAILED:
                    minutes_since_failure = (
                        datetime.now(timezone.utc) - task.updated_at
                    ).total_seconds() / 60
                    if minutes_since_failure >= RETRY_COOLDOWN_MINUTES:
                        task.transition(TaskStatus.PENDING)
                        task.error = None
                        logger.info("task_retry", issue=issue.number)

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    async def _dispatch_pending(self) -> None:
        running = sum(1 for t in self._tasks.values()
                      if t.status in (TaskStatus.SESSION_CREATED, TaskStatus.RUNNING))

        for task in self._tasks.values():
            if task.status != TaskStatus.PENDING:
                continue
            if running >= self._max_concurrent:
                break
            await self._dispatch_task(task)
            running += 1

    async def _dispatch_task(self, task: RemediationTask) -> None:
        try:
            issue = await self._source.get_issue(task.issue_number)
            prompt = build_prompt(issue, self._repo)
            session = await self._agent.create_session(prompt, playbook_id=self._playbook_id)

            task.transition(
                TaskStatus.SESSION_CREATED,
                session_id=session.session_id,
                session_url=session.url,
            )
            await self._notifier.on_dispatched(task)
            logger.info("task_dispatched", issue=task.issue_number, session_id=session.session_id)
        except Exception as exc:
            task.transition(TaskStatus.FAILED, error=f"Dispatch failed: {exc}")
            logger.exception("dispatch_failed", issue=task.issue_number)

    # ------------------------------------------------------------------
    # Poll
    # ------------------------------------------------------------------

    async def _poll_running(self) -> None:
        for task in self._tasks.values():
            if task.status not in (TaskStatus.SESSION_CREATED, TaskStatus.RUNNING, TaskStatus.NEEDS_INPUT):
                continue
            if not task.session_id:
                continue
            try:
                status = await self._agent.get_session(task.session_id)
                await self._handle_status(task, status)
            except Exception:
                logger.exception("poll_failed", session_id=task.session_id)

    async def _handle_status(self, task: RemediationTask, status: DevinSessionStatus) -> None:
        handler = {
            "new": self._on_running,
            "running": self._on_running,
            "exit": self._on_exit,
            "suspended": self._on_suspended,
            "error": self._on_error,
        }.get(status.status)

        if handler:
            await handler(task, status)
        else:
            logger.warning("unknown_session_status", status=status.status, session_id=task.session_id)

    async def _on_running(self, task: RemediationTask, status: DevinSessionStatus) -> None:
        if task.status != TaskStatus.RUNNING:
            task.transition(TaskStatus.RUNNING)

        if not status.pull_requests:
            return

        if task.pr_url is None:
            task.pr_url = status.pull_requests[-1]
            task.transition(TaskStatus.RUNNING, pr_url=task.pr_url)
            logger.info("pr_detected_waiting", issue=task.issue_number, pr_url=task.pr_url)
        else:
            minutes_elapsed = (datetime.now(timezone.utc) - task.updated_at).total_seconds() / 60
            if minutes_elapsed >= GRACE_PERIOD_MINUTES:
                await self._complete_task(task, status.pull_requests[-1])

    async def _on_exit(self, task: RemediationTask, status: DevinSessionStatus) -> None:
        pr_url = (
            status.pull_requests[-1] if status.pull_requests
            else await self._find_pr_url(task.session_id)  # type: ignore[arg-type]
        )
        await self._complete_task(task, pr_url)

    async def _on_suspended(self, task: RemediationTask, status: DevinSessionStatus) -> None:
        if task.status != TaskStatus.NEEDS_INPUT:
            task.transition(TaskStatus.NEEDS_INPUT)
            try:
                await self._notifier.on_needs_input(task)
            except Exception:
                logger.warning("needs_input_notification_failed", issue=task.issue_number)
            logger.warning("task_needs_input", issue=task.issue_number)

    async def _on_error(self, task: RemediationTask, status: DevinSessionStatus) -> None:
        task.transition(TaskStatus.FAILED, error=f"Session {status.status}")
        try:
            await self._notifier.on_failed(task)
        except Exception:
            logger.warning("failure_notification_failed", issue=task.issue_number)
        logger.warning("task_failed", issue=task.issue_number, status=status.status)

    # ------------------------------------------------------------------
    # Completion
    # ------------------------------------------------------------------

    async def _complete_task(self, task: RemediationTask, pr_url: str | None) -> None:
        await self._save_log(task)
        if task.session_id:
            try:
                await self._agent.send_message(
                    task.session_id,
                    "PR is submitted and the issue is resolved. Please finish this session.",
                )
            except Exception:
                logger.warning("send_finish_message_failed", session_id=task.session_id)
            await self._agent.close_session(task.session_id)
        task.transition(TaskStatus.COMPLETED, pr_url=pr_url)
        try:
            await self._notifier.on_completed(task)
        except Exception:
            logger.warning("completion_notification_failed", issue=task.issue_number)
        logger.info("task_completed", issue=task.issue_number, pr_url=pr_url)

    async def _save_log(self, task: RemediationTask) -> None:
        if not task.session_id:
            return
        try:
            messages = await self._agent.get_messages(task.session_id)
            task.log_file = self._persistence.save_session_log(
                issue_number=task.issue_number,
                title=task.issue_title,
                session_url=task.session_url,
                pr_url=task.pr_url,
                status=task.status,
                updated_at=task.updated_at.isoformat(),
                messages=[(m.role or "unknown", m.content or "") for m in messages],
            )

            saved_names: list[str] = []
            attachments = await self._agent.get_attachments(task.session_id)
            for att in attachments:
                name = att.get("name", "unknown")
                url = att.get("url", "")
                if not url:
                    continue
                try:
                    content = await self._agent.download_attachment(url)
                    self._persistence.save_attachment(task.issue_number, name, content)
                    saved_names.append(name)
                    logger.info("attachment_saved", issue=task.issue_number, name=name)
                except Exception:
                    logger.warning("attachment_download_failed", issue=task.issue_number, name=name)

            task.attachments = saved_names
            logger.info("session_log_saved", issue=task.issue_number, attachments=len(attachments))
        except Exception:
            logger.exception("session_log_save_failed", issue=task.issue_number)

    async def _find_pr_url(self, session_id: str) -> str | None:
        """Fallback: search session messages for a GitHub PR URL."""
        try:
            messages = await self._agent.get_messages(session_id)
            pattern = re.compile(
                rf"https://github\.com/{re.escape(self._repo)}/pull/\d+"
            )
            for msg in reversed(messages):
                if msg.content and (match := pattern.search(msg.content)):
                    return match.group(0)
        except Exception:
            logger.exception("pr_url_search_failed", session_id=session_id)
        return None
