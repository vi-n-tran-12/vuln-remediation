"""Orchestrator: the core state machine that drives remediation.

Thin coordination layer — delegates to:
  - DevinClient for session management
  - GitHubClient for issue discovery
  - Notifier for GitHub comments
  - persistence module for task storage
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any

import structlog

from vuln_remediation.config import Settings
from vuln_remediation.devin_client import DevinClient
from vuln_remediation.github_client import GitHubClient
from vuln_remediation.models import (
    DevinSessionStatus,
    GitHubIssue,
    RemediationTask,
    TaskStatus,
)
from vuln_remediation.notifier import Notifier
from vuln_remediation.persistence import load_tasks, save_attachment, save_session_log, save_tasks

logger = structlog.get_logger()

GRACE_PERIOD_MINUTES = 5

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


RETRY_COOLDOWN_MINUTES = 10


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def build_prompt(issue: GitHubIssue, repo: str) -> str:
    """Build a Devin session prompt from a GitHub issue.

    The playbook provides remediation instructions. This prompt only
    supplies the issue-specific context: repo URL, issue body with
    affected files, attack scenario, and proposed fix.
    """
    return (
        f"Repository: https://github.com/{repo}\n\n"
        f"## Issue #{issue.number}: {issue.title}\n\n"
        f"{issue.body or 'No description provided.'}\n\n"
        f"---\n"
        f'Fix this vulnerability and open a PR with "Fixes #{issue.number}" in the body.'
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    """Drives the issue → Devin session → PR lifecycle."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._devin = DevinClient(settings)
        self._github = GitHubClient(settings)
        self._notifier = Notifier(self._github)
        self._tasks = load_tasks()
        self._playbook_id: str | None = None
        self._initialized = False
        self._lock = asyncio.Lock()

    async def close(self) -> None:
        await self._devin.close()
        await self._github.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_once(self) -> list[RemediationTask]:
        """Single pass: discover → dispatch → poll → save.

        Guarded by a lock so concurrent webhook + poller calls don't race.
        """
        async with self._lock:
            await self._ensure_initialized()
            await self._discover_issues()
            await self._dispatch_pending()
            await self._poll_running()
            save_tasks(self._tasks)
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
    # Setup
    # ------------------------------------------------------------------

    async def _ensure_initialized(self) -> None:
        """One-time setup: create playbook and knowledge note in Devin.

        Idempotent — checks for existing resources before creating new ones.
        """
        if self._initialized:
            return
        self._initialized = True

        try:
            existing = await self._devin.list_playbooks()
            for pb in existing:
                if pb.get("title") == "Security Vulnerability Remediation":
                    self._playbook_id = pb.get("playbook_id")  # type: ignore[assignment]
                    logger.info("playbook_reused", playbook_id=self._playbook_id)
                    return

            self._playbook_id = await self._devin.create_playbook(
                name="Security Vulnerability Remediation",
                instructions=(
                    "You are triaging and remediating a security vulnerability.\n\n"
                    "## Phase 1: Validate the vulnerability\n"
                    "1. Clone the repository\n"
                    "2. Read the GitHub issue carefully — it describes the vulnerability, "
                    "affected code, and an attack scenario\n"
                    "3. Set up a local environment to reproduce the issue:\n"
                    "   - Install dependencies\n"
                    "   - Spin up the application (or the relevant subsystem) in a sandbox\n"
                    "4. Attempt to reproduce the attack scenario described in the issue\n"
                    "5. Document your findings:\n"
                    "   - Could you reproduce the vulnerability? What did you observe?\n"
                    "   - If you could NOT reproduce it, stop here. Post a comment on the "
                    "GitHub issue explaining what you tried, what you observed, and why "
                    "the vulnerability may not be exploitable as described. Then finish.\n\n"
                    "## Phase 2: Fix the vulnerability (only if validated)\n"
                    "6. Implement the fix described in the issue\n"
                    "7. Write unit tests that verify the vulnerability is closed:\n"
                    "   - Write a test that reproduces the attack scenario\n"
                    "   - Confirm the test fails without your fix and passes with it\n"
                    "   - Test edge cases (e.g. malformed input, boundary values)\n"
                    "8. Run the existing test suite to ensure nothing is broken\n"
                    "9. Open a pull request that references the issue "
                    '(use "Fixes #N" in the PR body)\n'
                    "10. In the PR description, include:\n"
                    "   - Reproduction steps you used to validate the vulnerability\n"
                    "   - What the fix does and why\n"
                    "   - How the tests verify the fix\n\n"
                    "Constraints:\n"
                    "- Only modify files directly related to the fix\n"
                    "- Follow the existing code style and conventions\n"
                    "- Do not refactor unrelated code\n"
                    "- Keep the PR focused and reviewable\n"
                    "- After opening the PR (or posting the comment), finish the session"
                ),
            )

            await self._ensure_knowledge_note()
        except Exception:
            logger.exception("setup_failed")

    async def _ensure_knowledge_note(self) -> None:
        """Create knowledge note if it doesn't already exist."""
        existing = await self._devin.list_knowledge_notes()
        for note in existing:
            if note.get("name") == "Apache Superset Codebase":
                logger.info("knowledge_note_reused", note_id=note.get("note_id"))
                return

        await self._devin.create_knowledge_note(
            name="Apache Superset Codebase",
            trigger="When working on the Apache Superset repository",
            body=(
                "Apache Superset is a data exploration and visualization platform.\n\n"
                "Key directories:\n"
                "- superset/security/ — authentication, authorization, RLS, guest tokens\n"
                "- superset/connectors/sqla/ — SQLAlchemy connector, query building\n"
                "- superset/db_engine_specs/ — database engine specifications\n"
                "- superset/utils/network.py — hostname/port validation utilities\n"
                "- superset/sql/parse.py — SQL parsing and sanitize_clause()\n"
                "- superset/config.py — all configuration defaults\n"
                "- superset/initialization/__init__.py — startup checks\n\n"
                "Testing:\n"
                "- Tests are in tests/unit_tests/ and tests/integration_tests/\n"
                "- Run with: pytest tests/unit_tests/\n"
                "- The fork has no CI workflows — run tests locally before opening PRs"
            ),
        )

    # ------------------------------------------------------------------
    # Discover
    # ------------------------------------------------------------------

    async def _discover_issues(self) -> None:
        try:
            issues = await self._github.list_open_issues(labels="security")
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
                # Retry failed tasks after cooldown
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
            if running >= self._settings.max_concurrent_sessions:
                break
            await self._dispatch_task(task)
            running += 1

    async def _dispatch_task(self, task: RemediationTask) -> None:
        try:
            issue = await self._github.get_issue(task.issue_number)
            prompt = build_prompt(issue, self._settings.github_repo)
            session = await self._devin.create_session(prompt, playbook_id=self._playbook_id)

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
                status = await self._devin.get_session(task.session_id)
                await self._handle_status(task, status)
            except Exception:
                logger.exception("poll_failed", session_id=task.session_id)

    async def _handle_status(self, task: RemediationTask, status: DevinSessionStatus) -> None:
        """Route session status to the appropriate handler."""
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
            # First time seeing a PR — record it, start grace period
            task.pr_url = status.pull_requests[-1]
            task.transition(TaskStatus.RUNNING, pr_url=task.pr_url)
            logger.info("pr_detected_waiting", issue=task.issue_number, pr_url=task.pr_url)
        else:
            # PR already seen — close after grace period
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
        """Finalize a task: save log, ask Devin to finish, close session, notify GitHub.

        Each step is independently guarded so a failure in one (e.g. sending
        a message) doesn't prevent the others (e.g. closing the session).
        """
        await self._save_log(task)
        if task.session_id:
            try:
                await self._devin.send_message(
                    task.session_id,
                    "PR is submitted and the issue is resolved. Please finish this session.",
                )
            except Exception:
                logger.warning("send_finish_message_failed", session_id=task.session_id)
            await self._devin.close_session(task.session_id)
        task.transition(TaskStatus.COMPLETED, pr_url=pr_url)
        try:
            await self._notifier.on_completed(task)
        except Exception:
            logger.warning("completion_notification_failed", issue=task.issue_number)
        logger.info("task_completed", issue=task.issue_number, pr_url=pr_url)

    async def _save_log(self, task: RemediationTask) -> None:
        """Save session conversation and attachments for audit."""
        if not task.session_id:
            return
        try:
            # Save conversation log
            messages = await self._devin.get_messages(task.session_id)
            task.log_file = save_session_log(
                issue_number=task.issue_number,
                title=task.issue_title,
                session_url=task.session_url,
                pr_url=task.pr_url,
                status=task.status,
                updated_at=task.updated_at.isoformat(),
                messages=[(m.role or "unknown", m.content or "") for m in messages],
            )

            # Save attachments (test output, screenshots, generated files)
            saved_names: list[str] = []
            attachments = await self._devin.get_attachments(task.session_id)
            for att in attachments:
                name = att.get("name", "unknown")
                url = att.get("url", "")
                if not url:
                    continue
                try:
                    content = await self._devin.download_attachment(url)
                    save_attachment(task.issue_number, name, content)
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
            messages = await self._devin.get_messages(session_id)
            pattern = re.compile(
                rf"https://github\.com/{re.escape(self._settings.github_repo)}/pull/\d+"
            )
            for msg in reversed(messages):
                if msg.content and (match := pattern.search(msg.content)):
                    return match.group(0)
        except Exception:
            logger.exception("pr_url_search_failed", session_id=session_id)
        return None
